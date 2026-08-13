//! Shielded transaction builder: spend notes, produce signed v3 tx hex.

use crate::fees;
use crate::keys::{self, GenericAddress};
use crate::sapling::prover::SaplingProver;
use crate::sapling::sync::DEPTH;
use crate::wallet::{SerializedNote, WalletData};
use incrementalmerkletree::frontier::CommitmentTree;
use pivx_primitives::consensus::{BlockHeight, Network, NetworkConstants};
use pivx_primitives::memo::MemoBytes;
use pivx_primitives::merkle_tree::read_incremental_witness;
use pivx_primitives::transaction::builder::{BuildConfig, Builder};
use pivx_primitives::transaction::components::transparent::builder::TransparentSigningSet;
use pivx_primitives::transaction::fees::fixed::FeeRule;
use pivx_primitives::zip32::Scope;
use pivx_protocol::memo::Memo;
use pivx_protocol::value::Zatoshis;
use rand_core::OsRng;
use sapling::note::Note;
use sapling::{Anchor, Node};
use std::error::Error;
use std::io::Cursor;
use std::str::FromStr;

/// Result of selecting which shield notes to spend for a given send.
///
/// `indexes` are positions into the input `notes` slice in the order
/// the notes should be spent. `fee` is exactly what the builder will
/// charge given the chosen `(transparent_outs, sapling_outs)` shape.
/// `total` is the sum of selected note values (>= amount + fee).
#[derive(Debug, Clone)]
pub struct ShieldSelection {
    pub indexes: Vec<usize>,
    pub fee: u64,
    pub total: u64,
}

/// Pick which shield notes to spend.
///
/// Selection order is **non-memo first, then ascending value**:
/// matches `create_shield_transaction`'s spend order. The estimator
/// (`Wallet.estimateSendShieldFee`) uses the same function, so a
/// fee returned by the estimator is the fee a follow-up
/// `sendShield(amount, ...)` will actually charge against the same
/// note set.
///
/// `transparent_outs` and `sapling_outs` are the destination shape:
/// for shield→shield use `(0, 2)` (dest + change); for
/// shield→transparent use `(1, 2)` (dest transparent + change shield).
pub fn select_shield_notes(
    notes: &[SerializedNote],
    amount: u64,
    transparent_outs: u64,
    sapling_outs: u64,
) -> Result<ShieldSelection, Box<dyn Error>> {
    let mut indexed: Vec<(usize, u64, bool)> = notes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let value = n
                .note
                .get("value")
                .and_then(|v| v.as_u64())
                .ok_or("note JSON missing 'value' field")?;
            let has_memo = n.memo.as_ref().is_some_and(|m| !m.is_empty());
            Ok::<_, Box<dyn Error>>((i, value, has_memo))
        })
        .collect::<Result<Vec<_>, _>>()?;
    indexed.sort_by_key(|(_, value, has_memo)| (*has_memo, *value));

    let mut selected = Vec::new();
    let mut total: u64 = 0;
    let mut fee: u64 = 0;
    for (i, value, _) in &indexed {
        selected.push(*i);
        total = total.saturating_add(*value);
        fee = fees::estimate_fee(0, transparent_outs, selected.len() as u64, sapling_outs);
        if total >= amount.saturating_add(fee) {
            return Ok(ShieldSelection {
                indexes: selected,
                fee,
                total,
            });
        }
    }
    Err(format!(
        "insufficient shield balance: have {} sat, need {} sat (amount) + {} sat (fee)",
        total, amount, fee
    )
    .into())
}

/// One recipient of a shield-sourced send.
///
/// `address` may be either a shield (`ps1...`) or transparent (`D...`)
/// address: a single transaction can pay a mix of both, since the funds come
/// from shield notes either way.
///
/// `memo` is only meaningful for shield destinations; PIVX has nowhere to put
/// a memo on a transparent output, so a non-empty memo alongside a transparent
/// address is rejected rather than silently dropped.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct ShieldRecipient {
    pub address: String,
    #[tsify(type = "bigint")]
    pub amount: u64,
    #[serde(default)]
    pub memo: String,
}

/// Recipients split by destination pool, with the output counts the fee model
/// needs.
struct ResolvedShieldOutputs {
    /// `(address, amount, encoded memo)` in caller order.
    ///
    /// Memos are encoded here rather than in the builder so that a memo which
    /// cannot be encoded is rejected at resolution time, which means the fee
    /// estimator rejects it too, instead of quoting a fee for a send that would
    /// later fail to build.
    outputs: Vec<(GenericAddress, u64, MemoBytes)>,
    transparent_outs: u64,
    sapling_outs: u64,
    total_amount: u64,
}

/// Decode and validate recipients, and work out the output shape for fee
/// estimation.
///
/// The sapling output count is `shield recipients + 1` for change, floored at
/// 2. The floor matters: a Sapling bundle pads to two outputs with a dummy
/// note, so a single-shield-output send still pays for two. That floor is what
/// the previous fixed `(_, 2)` shape encoded, and dropping it would
/// under-estimate the fee and strand transactions unconfirmed.
fn resolve_shield_recipients(
    recipients: &[ShieldRecipient],
    network: &Network,
) -> Result<ResolvedShieldOutputs, Box<dyn Error>> {
    if recipients.is_empty() {
        return Err("No recipients provided".into());
    }

    let mut outputs = Vec::with_capacity(recipients.len());
    let mut transparent_outs = 0u64;
    let mut shield_outs = 0u64;
    let mut total_amount = 0u64;

    for r in recipients {
        if r.amount == 0 {
            return Err(format!("Recipient {} has a zero amount", r.address).into());
        }
        total_amount = total_amount
            .checked_add(r.amount)
            .ok_or("Recipient amounts overflow u64")?;

        let decoded = keys::decode_generic_address(&r.address)?;
        let memo_bytes = match decoded {
            GenericAddress::Shield(_) => {
                shield_outs += 1;
                if r.memo.is_empty() {
                    MemoBytes::empty()
                } else {
                    // Encoding here is the validation: a Sapling memo field is
                    // 512 bytes, and the limit is on encoded *bytes*, so a
                    // short string of multi-byte characters can still overflow
                    // it. Rejecting at resolution keeps the estimator and the
                    // builder in agreement about what is sendable.
                    Memo::from_str(&r.memo)
                        .map_err(|e| {
                            format!(
                                "Invalid memo for recipient {} ({} bytes): {}",
                                r.address,
                                r.memo.len(),
                                e
                            )
                        })?
                        .encode()
                }
            }
            GenericAddress::Transparent(ref addr) => {
                if !r.memo.is_empty() {
                    return Err(format!(
                        "Recipient {} is transparent but carries a memo: transparent outputs \
                         cannot hold memos",
                        r.address
                    )
                    .into());
                }
                // A shield-source transaction still emits a real transparent
                // output, and `IsStandardTx` judges it by the same rule: dust
                // in `vout` makes the whole transaction non-standard, so no
                // node relays it, whatever the inputs were. The transparent
                // builders reject this at `resolve_outputs`; without the same
                // check here a shield send is the one way to build an
                // unrelayable transaction and only find out at broadcast.
                //
                // Sized from the script the builder will actually emit, so a
                // P2SH destination is measured as P2SH rather than assumed to
                // be P2PKH.
                let script_len = addr.script().0.len();
                if fees::is_dust(r.amount, script_len) {
                    return Err(format!(
                        "Recipient {} is below the dust threshold: {} sat, minimum {} sat. A \
                         transaction containing a dust output is non-standard and will not \
                         relay.",
                        r.address,
                        r.amount,
                        fees::dust_threshold(script_len)
                    )
                    .into());
                }
                transparent_outs += 1;
                MemoBytes::empty()
            }
        };
        outputs.push((decoded, r.amount, memo_bytes));
    }

    debug_assert_eq!(
        network.hrp_sapling_payment_address(),
        Network::MainNetwork.hrp_sapling_payment_address(),
        "shield recipient resolution assumes mainnet HRPs"
    );

    Ok(ResolvedShieldOutputs {
        outputs,
        transparent_outs,
        sapling_outs: sapling_out_count(shield_outs),
        total_amount,
    })
}

/// Sapling outputs the builder is charged for, given `shield_outs` recipients.
///
/// Two adjustments, both of which a fee estimate has to make or it will quote
/// less than the transaction costs:
///
///  * **Plus one for change.** Any remainder returns as a shield note, and that
///    note is an output like any other. A max send is the one case that emits
///    none, so it over-pays by one output's worth; that is the direction that
///    keeps the figure buildable.
///  * **At least two.** The Sapling builder pads a bundle out to two outputs,
///    so a send with no shield recipients at all still carries two.
///
/// One definition, shared by [`resolve_shield_recipients`] and
/// [`max_shield_spendable_to_many`], so an estimate cannot drift from what the
/// builder charges.
fn sapling_out_count(shield_outs: u64) -> u64 {
    (shield_outs + 1).max(2)
}

/// Sum of every note's value, or `None` if any of them cannot be read.
///
/// `None` rather than a partial total on purpose: [`select_shield_notes`]
/// errors on an unreadable note, so a wallet holding one cannot build at all,
/// and reporting a spendable figure against it would offer an amount the
/// builder then refuses.
fn total_note_value(notes: &[SerializedNote]) -> Option<u64> {
    notes.iter().try_fold(0u64, |acc, n| {
        let value = n.note.get("value").and_then(|v| v.as_u64())?;
        acc.checked_add(value)
    })
}

/// Largest amount a shield-source send can pay to `to_address` after fee.
///
/// The shield counterpart to
/// [`crate::transparent::builder::max_sendable_transparent`], and the answer to
/// "empty my shield balance". Both branches of `maxSendableSat` compute from
/// *transparent* UTXOs (a `ps1…` destination there prices a shielding send), so
/// before this there was no accessor for spending notes and callers had to
/// solve `shieldBalanceSat - estimateSendShieldFee` by hand. Amount and fee are
/// mutually dependent, because the fee grows with the number of notes selection
/// reaches for, which is exactly the arithmetic that produces off-by-one errors.
///
/// Returns 0 when nothing can be sent: no notes, a fee that swallows the
/// balance, a note whose value cannot be read, an unparseable destination, or a
/// remainder that would be dust at a transparent destination. A UI can treat 0
/// as "disable the control".
///
/// Routes on the destination, since a transparent recipient adds a transparent
/// output to the fee model and a shield one adds a Sapling output.
pub fn max_shield_spendable(wallet: &WalletData, to_address: &str) -> u64 {
    match keys::decode_generic_address(to_address) {
        Ok(GenericAddress::Transparent(addr)) => {
            let max = max_shield_spendable_to_many(wallet, 1, 0);
            // Same dust rule the builder now applies to a transparent recipient
            // of a shield send: below the threshold the send would be refused,
            // so offering the figure would be offering an unbuildable amount.
            if max < fees::dust_threshold(addr.script().0.len()) {
                return 0;
            }
            max
        }
        Ok(GenericAddress::Shield(_)) => max_shield_spendable_to_many(wallet, 0, 1),
        Err(_) => 0,
    }
}

/// Largest *total* a shield-source send to the given recipient shape can pay.
///
/// Split the result across recipients however you like, as long as the parts
/// sum to it and each transparent part clears its dust threshold.
///
/// Spends every note, so the fee is priced for all of them. Selection may still
/// stop short of that if the remaining notes are worth less than the 384,000 sat
/// each one adds to the fee, in which case the leftover simply returns as
/// change; the amount is paid either way, which is what the figure promises.
pub fn max_shield_spendable_to_many(
    wallet: &WalletData,
    transparent_outs: u64,
    shield_outs: u64,
) -> u64 {
    if wallet.unspent_notes.is_empty() || transparent_outs + shield_outs == 0 {
        return 0;
    }
    let Some(total) = total_note_value(&wallet.unspent_notes) else {
        return 0;
    };
    let fee = fees::estimate_fee(
        0,
        transparent_outs,
        wallet.unspent_notes.len() as u64,
        sapling_out_count(shield_outs),
    );
    total.saturating_sub(fee)
}

/// The `(transparent_outs, sapling_outs, recipient_total)` a recipient list
/// implies, for callers that need to estimate a fee without building.
///
/// Exposed so the fee estimator and the builder derive the output shape from
/// the same code. A fee returned against this shape is exactly what
/// [`create_shield_transaction_to_many`] will charge for the same recipients.
pub fn shield_recipient_fee_shape(
    recipients: &[ShieldRecipient],
) -> Result<(u64, u64, u64), Box<dyn Error>> {
    let resolved = resolve_shield_recipients(recipients, &Network::MainNetwork)?;
    Ok((
        resolved.transparent_outs,
        resolved.sapling_outs,
        resolved.total_amount,
    ))
}

/// Result of building a shield transaction.
#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct TransactionResult {
    pub txhex: String,
    pub nullifiers: Vec<String>,
    pub amount: u64,
    pub fee: u64,
}

/// Build and sign a shield transaction spending from the wallet's notes.
///
/// `prover` must be supplied by the caller (see [`crate::sapling::prover::verify_and_load_params`]).
/// `block_height` should be set to the chain tip + 1, fetched by the consumer.
pub fn create_shield_transaction(
    wallet: &mut WalletData,
    to_address: &str,
    amount: u64,
    memo: &str,
    block_height: u32,
    prover: &SaplingProver,
) -> Result<TransactionResult, Box<dyn Error>> {
    create_shield_transaction_to_many(
        wallet,
        &[ShieldRecipient {
            address: to_address.to_string(),
            amount,
            memo: memo.to_string(),
        }],
        block_height,
        prover,
    )
}

/// Multi-recipient form of [`create_shield_transaction`]: spend the wallet's
/// notes across any number of destinations in one transaction.
///
/// Recipients may mix shield (`ps1...`) and transparent (`D...`) addresses
/// freely: the funds come from shield notes either way, so unlike the
/// transparent builders there is no need to split the send. Each shield
/// recipient may carry its own memo.
///
/// Outputs are added in the order given, with shield change appended last.
/// `TransactionResult::amount` is the recipient total, excluding change and
/// fee.
///
/// `prover` must be supplied by the caller (see
/// [`crate::sapling::prover::verify_and_load_params`]). `block_height` should
/// be the chain tip + 1, fetched by the consumer.
pub fn create_shield_transaction_to_many(
    wallet: &mut WalletData,
    recipients: &[ShieldRecipient],
    block_height: u32,
    prover: &SaplingProver,
) -> Result<TransactionResult, Box<dyn Error>> {
    let extsk = wallet.derive_extsk()?;
    let network = Network::MainNetwork;

    let resolved = resolve_shield_recipients(recipients, &network)?;
    let amount = resolved.total_amount;

    // Single source of truth for which notes to spend and what fee
    // to charge: shared with `Wallet.estimateSendShieldFee` so the
    // estimator and the builder never disagree.
    let selection = select_shield_notes(
        &wallet.unspent_notes,
        amount,
        resolved.transparent_outs,
        resolved.sapling_outs,
    )?;
    let total = selection.total;
    let fee = selection.fee;

    // Anchor from the first selected note's witness.
    let first_idx = *selection
        .indexes
        .first()
        .ok_or("No spendable notes available")?;
    let first_witness_hex = &wallet.unspent_notes[first_idx].witness;
    let anchor = {
        let witness = read_incremental_witness::<Node, _, { DEPTH }>(Cursor::new(
            crate::simd::hex::hex_string_to_bytes(first_witness_hex),
        ))?;
        Anchor::from_bytes(witness.root().to_bytes())
            .into_option()
            .unwrap_or(Anchor::empty_tree())
    };

    let mut builder = Builder::new(
        network,
        BlockHeight::from_u32(block_height),
        BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: None,
        },
    );
    let transparent_signing_set = TransparentSigningSet::new();

    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let fvk = dfvk.fvk().clone();
    let nk = dfvk.to_nk(Scope::External);

    // Parse Note + IncrementalWitness only for selected notes (M8).
    let mut nullifiers = Vec::with_capacity(selection.indexes.len());
    for &idx in &selection.indexes {
        let serialized = &wallet.unspent_notes[idx];
        let note: Note = serde_json::from_value(serialized.note.clone())?;
        let witness = read_incremental_witness::<Node, _, { DEPTH }>(Cursor::new(
            crate::simd::hex::hex_string_to_bytes(&serialized.witness),
        ))?;
        builder
            .add_sapling_spend::<FeeRule>(
                fvk.clone(),
                note.clone(),
                witness.path().ok_or("Empty commitment tree")?,
            )
            .map_err(|_| "Failed to add sapling spend")?;
        let nullifier = note.nf(&nk, witness.witnessed_position().into());
        nullifiers.push(crate::simd::hex::bytes_to_hex_string(&nullifier.to_vec()));
    }

    // `select_shield_notes` guarantees total >= amount + fee, so this cannot
    // underflow, but it is subtraction on caller-influenced values, so keep
    // it checked rather than relying on that invariant holding forever.
    let change_amount = total
        .checked_sub(amount)
        .and_then(|v| v.checked_sub(fee))
        .ok_or("Selected notes do not cover amount plus fee")?;
    let change_amount = Zatoshis::from_u64(change_amount).map_err(|_| "Invalid change")?;

    for (addr, out_amount, memo_bytes) in &resolved.outputs {
        let send_amount = Zatoshis::from_u64(*out_amount).map_err(|_| "Invalid amount")?;
        match addr {
            GenericAddress::Transparent(addr) => {
                builder
                    .add_transparent_output(addr, send_amount)
                    .map_err(|e| format!("Failed to add transparent output: {:?}", e))?;
            }
            GenericAddress::Shield(addr) => {
                // Memo already validated and encoded by
                // `resolve_shield_recipients`, so there is nothing here that
                // can fail differently from what the estimator saw.
                builder
                    .add_sapling_output::<FeeRule>(
                        None,
                        *addr,
                        send_amount,
                        memo_bytes.clone(),
                    )
                    .map_err(|_| "Failed to add sapling output")?;
            }
        }
    }

    if change_amount.is_positive() {
        let extfvk = keys::decode_extfvk(&wallet.extfvk)?;
        let (_idx, change_addr) = extfvk.to_diversifiable_full_viewing_key().default_address();
        builder
            .add_sapling_output::<FeeRule>(None, change_addr, change_amount, MemoBytes::empty())
            .map_err(|_| "Failed to add change output")?;
    }

    let result = builder.build(
        &transparent_signing_set,
        &[extsk],
        &[],
        OsRng,
        &prover.spend,
        &prover.output,
        &FeeRule::non_standard(Zatoshis::from_u64(fee).map_err(|_| "Invalid fee")?),
    )?;

    let mut tx_hex = vec![];
    result.transaction().write(&mut tx_hex)?;

    Ok(TransactionResult {
        txhex: crate::simd::hex::bytes_to_hex_string(&tx_hex),
        nullifiers,
        amount,
        fee,
    })
}

// Re-export for convenience: callers often want the tree DEPTH constant when
// constructing/reading commitment trees alongside the builder.
pub use crate::sapling::sync::DEPTH as COMMITMENT_TREE_DEPTH;

/// Read a commitment tree from its hex-encoded form. Used by transparent
/// builders when the destination is a shield address (they need an anchor).
pub fn read_tree_hex(tree_hex: &str) -> Result<CommitmentTree<Node, { DEPTH }>, Box<dyn Error>> {
    let bytes = crate::simd::hex::hex_string_to_bytes(tree_hex);
    Ok(pivx_primitives::merkle_tree::read_commitment_tree(Cursor::new(bytes))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::SerializedNote;

    /// Build a SerializedNote whose JSON `note` field carries the given
    /// `value`. The other fields are placeholders: `select_shield_notes`
    /// only reads `note["value"]` and `memo`, so this is sufficient.
    fn note(value: u64, memo: Option<&str>) -> SerializedNote {
        SerializedNote {
            note: serde_json::json!({ "value": value }),
            witness: String::new(),
            nullifier: String::new(),
            memo: memo.map(|s| s.to_string()),
            height: 0,
        }
    }

    #[test]
    fn empty_notes_returns_error() {
        let result = select_shield_notes(&[], 100, 0, 2);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("insufficient"), "unexpected error: {}", msg);
    }

    #[test]
    fn insufficient_balance_returns_error() {
        let notes = vec![note(50, None), note(30, None)];
        // 80 sat available, requesting 1000: fee ~2 KB at 1000 sat/byte
        // dwarfs balance regardless of selection.
        let result = select_shield_notes(&notes, 1000, 0, 2);
        assert!(result.is_err());
    }

    #[test]
    fn sort_order_non_memo_first_then_ascending() {
        // Mix of memo'd and non-memo'd notes at varying values. The
        // selection should walk non-memo notes ascending, then memo'd
        // notes ascending. Use big-enough notes that a single one
        // covers the send so we can pin the *first* selected index.
        let notes = vec![
            note(5_000_000, Some("hello")), // 0: memo'd, mid value
            note(10_000_000, None),         // 1: no memo, large
            note(3_000_000, None),          // 2: no memo, small  ← should win
            note(6_000_000, Some("hi")),    // 3: memo'd, large
        ];
        // Need amount + fee covered by a single note. Fee for (0, 0, 1, 2)
        // = 1000 * (2*948 + 1*384 + 100) = 2_380_000. So 3M will cover
        // amount=500_000 + fee=2_380_000.
        let sel = select_shield_notes(&notes, 500_000, 0, 2).unwrap();
        assert_eq!(sel.indexes, vec![2], "expected to pick smallest non-memo note first");
    }

    #[test]
    fn sort_order_picks_non_memo_even_when_memo_is_smaller() {
        // Distinguishes "non-memo first" from "smallest first": the
        // memo'd note (idx 0) has a SMALLER value than the non-memo
        // note (idx 1), so a value-only sort would pick idx 0 first.
        // The correct order picks idx 1 first because it has no memo,
        // even though it's larger.
        //
        // 4M (non-memo) covers amount=1M + fee 2.38M = 3.38M.
        let notes = vec![
            note(2_000_000, Some("memo")), // 0: SMALLER but memo'd
            note(4_000_000, None),         // 1: LARGER but no-memo  ← should win
        ];
        let sel = select_shield_notes(&notes, 1_000_000, 0, 2).unwrap();
        assert_eq!(
            sel.indexes[0], 1,
            "non-memo notes must rank ahead of memo'd notes even when the memo'd note is smaller"
        );
    }

    #[test]
    fn selection_walks_until_total_covers_amount_plus_fee() {
        // Several non-memo notes; selection should accumulate inputs
        // until total >= amount + fee.
        //
        // Fee for (0,0,n,2) = 1000 * (2*948 + n*384 + 100)
        //                    = 1_996_000 + 384_000 * n
        //
        // amount = 100_000, notes 4 × 2M = 8M total:
        //   n=1: total=2M, need=100k + 2_380k = 2_480k → fails
        //   n=2: total=4M, need=100k + 2_764k = 2_864k → ok
        let notes = vec![
            note(2_000_000, None),
            note(2_000_000, None),
            note(2_000_000, None),
            note(2_000_000, None),
        ];
        let sel = select_shield_notes(&notes, 100_000, 0, 2).unwrap();
        assert_eq!(sel.indexes.len(), 2);
        assert!(sel.total >= 100_000 + sel.fee);
    }

    #[test]
    fn fee_matches_estimate_fee_for_selection_shape() {
        let notes = vec![note(10_000_000, None), note(5_000_000, None)];
        // (t_in=0, t_out=0, s_in=1, s_out=2)
        let sel = select_shield_notes(&notes, 1_000_000, 0, 2).unwrap();
        let expected = crate::fees::estimate_fee(0, 0, sel.indexes.len() as u64, 2);
        assert_eq!(sel.fee, expected, "fee must match estimate_fee for the chosen shape");
    }

    #[test]
    fn shape_change_changes_fee() {
        // Same notes, different destination shape: shield→transparent
        // adds 1 transparent output. Fee should differ by exactly
        // 34_000 sat (= 1 t-out × 34 bytes × 1000 sat/byte).
        let notes = vec![note(10_000_000, None)];
        let to_shield = select_shield_notes(&notes, 100_000, 0, 2).unwrap();
        let to_transparent = select_shield_notes(&notes, 100_000, 1, 2).unwrap();
        assert_eq!(to_transparent.fee - to_shield.fee, 34_000);
    }

    #[test]
    fn missing_value_field_propagates_error() {
        let bad = SerializedNote {
            note: serde_json::json!({ "not_value": 100 }),
            witness: String::new(),
            nullifier: String::new(),
            memo: None,
            height: 0,
        };
        let err = select_shield_notes(&[bad], 1, 0, 2).unwrap_err();
        assert!(err.to_string().contains("'value'"), "unexpected error: {}", err);
    }
}
