//! Shielded transaction builder — spend notes, produce signed v3 tx hex.

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
/// Selection order is **non-memo first, then ascending value** —
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
    let extsk = wallet.derive_extsk()?;
    let network = Network::MainNetwork;

    let (transparent_output_count, sapling_output_count) =
        if to_address.starts_with(network.hrp_sapling_payment_address()) {
            (0u64, 2u64)
        } else {
            (1u64, 2u64)
        };

    // Single source of truth for which notes to spend and what fee
    // to charge — shared with `Wallet.estimateSendShieldFee` so the
    // estimator and the builder never disagree.
    let selection = select_shield_notes(
        &wallet.unspent_notes,
        amount,
        transparent_output_count,
        sapling_output_count,
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

    let send_amount = Zatoshis::from_u64(amount).map_err(|_| "Invalid amount")?;
    let change_amount =
        Zatoshis::from_u64(total - amount - fee).map_err(|_| "Invalid change")?;

    let to = keys::decode_generic_address(to_address)?;
    match to {
        GenericAddress::Transparent(addr) => {
            builder
                .add_transparent_output(&addr, send_amount)
                .map_err(|e| format!("Failed to add transparent output: {:?}", e))?;
        }
        GenericAddress::Shield(addr) => {
            let memo_bytes = if memo.is_empty() {
                MemoBytes::empty()
            } else {
                Memo::from_str(memo)
                    .map_err(|e| format!("Invalid memo: {}", e))?
                    .encode()
            };
            builder
                .add_sapling_output::<FeeRule>(None, addr, send_amount, memo_bytes)
                .map_err(|_| "Failed to add sapling output")?;
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
    /// `value`. The other fields are placeholders — `select_shield_notes`
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
        // 80 sat available, requesting 1000 — fee ~2 KB at 1000 sat/byte
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
