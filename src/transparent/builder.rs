//! Transparent transaction builders (v3 via librustpivx + raw v1 P2PKH).
//!
//! `create_transparent_transaction` wraps librustpivx's v3 builder; it
//! supports both transparent→transparent and transparent→shield destinations
//! (the latter requires a Sapling prover).
//!
//! `create_raw_transparent_transaction` bypasses the v3 builder and produces
//! a raw v1 P2PKH transaction: needed because PIVX nodes reject v3 txs
//! that don't carry Sapling data.

use crate::fees;
use crate::keys::{self, GenericAddress};
use crate::sapling::builder::read_tree_hex;
use crate::sapling::prover::SaplingProver;
use crate::transparent::tx::write_varint;
use crate::wallet::{SerializedUTXO, WalletData};
use pivx_primitives::consensus::{BlockHeight, MAIN_NETWORK, NetworkConstants};
use pivx_primitives::memo::MemoBytes;
use pivx_primitives::transaction::builder::{BuildConfig, Builder};
use pivx_primitives::transaction::components::transparent::builder::TransparentSigningSet;
use pivx_primitives::transaction::fees::fixed::FeeRule;
use pivx_protocol::value::Zatoshis;
use rand_core::OsRng;
use sapling::Anchor;
use sha2::{Digest, Sha256};
use std::error::Error;
use zcash_transparent::bundle::OutPoint;

/// A reference to a UTXO that was consumed by a transparent send:
/// the (txid, vout) pair the wallet uses to mark its UTXO set after
/// broadcast. Named-field struct so generated TS bindings get
/// `{txid: string, vout: number}[]` instead of `[string, number][]`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SpentOutpoint {
    pub txid: String,
    pub vout: u32,
}

/// Result of building a transparent transaction.
#[derive(Debug, serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct TransparentTransactionResult {
    pub txhex: String,
    /// UTXOs consumed by this tx: remove from the wallet after broadcast
    /// via [`crate::wallet::WalletData::finalize_transparent_send`].
    pub spent: Vec<SpentOutpoint>,
    /// Total paid to recipients, excluding change and fee. For a
    /// multi-recipient send this is the sum across all recipients.
    pub amount: u64,
    pub fee: u64,
}

/// One recipient of a transparent send.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct Recipient {
    /// Transparent (`D...`) destination address.
    pub address: String,
    #[tsify(type = "bigint")]
    pub amount: u64,
}

/// A fully-resolved transaction output: value plus the exact scriptPubKey
/// bytes that will be serialized.
///
/// Resolving recipients into this shape *once* is what keeps the signature
/// honest. The signed preimage and the emitted transaction are both produced
/// from the same `&[TxOutput]` by [`write_outputs`], so the two cannot drift
/// apart, which was a live hazard while the output shape was open-coded
/// separately in `compute_sighash` and in each builder's writer.
#[derive(Clone, Debug)]
pub(crate) struct TxOutput {
    pub(crate) value: u64,
    pub(crate) script: Vec<u8>,
}

/// Serialize an output list in consensus form: count, then `value ||
/// script_len || script` per output.
///
/// Single source of truth for output bytes: used by both the sighash
/// preimage and the final transaction body. Do not inline this.
pub(crate) fn write_outputs(buf: &mut Vec<u8>, outputs: &[TxOutput]) {
    write_varint(buf, outputs.len() as u64);
    for out in outputs {
        buf.extend_from_slice(&out.value.to_le_bytes());
        write_varint(buf, out.script.len() as u64);
        buf.extend_from_slice(&out.script);
    }
}

/// Resolve recipients to outputs, appending a change output when non-dust.
///
/// Recipient order is preserved; change is always last. Rejects an empty
/// recipient list and zero-value payments, both of which would otherwise
/// produce a transaction the network rejects for reasons that are hard to
/// trace back here.
fn resolve_outputs(
    recipients: &[Recipient],
    change: u64,
    change_script: &[u8],
) -> Result<Vec<TxOutput>, Box<dyn Error>> {
    if recipients.is_empty() {
        return Err("No recipients provided".into());
    }

    let mut outputs = Vec::with_capacity(recipients.len() + 1);
    for r in recipients {
        if r.amount == 0 {
            return Err(format!("Recipient {} has a zero amount", r.address).into());
        }
        let script = keys::address_to_p2pkh_script(&r.address)?;
        // A dust output makes the whole transaction non-standard, so no node
        // relays it. Better to refuse than to hand back bytes that cannot be
        // broadcast.
        if fees::is_dust(r.amount, script.len()) {
            return Err(format!(
                "Recipient {} is below the dust threshold: {} sat, minimum {} sat. A transaction \
                 containing a dust output is non-standard and will not relay.",
                r.address,
                r.amount,
                fees::dust_threshold(script.len())
            )
            .into());
        }
        outputs.push(TxOutput { value: r.amount, script });
    }

    // Dust change is dropped rather than emitted: keeping it would make the
    // transaction unrelayable, so the remainder goes to the miner as fee. This
    // is what the reference wallets do, and it is why the caller's fee can come
    // out slightly above the estimate.
    if change > 0 && !fees::is_dust(change, change_script.len()) {
        outputs.push(TxOutput {
            value: change,
            script: change_script.to_vec(),
        });
    }

    Ok(outputs)
}

/// Sum recipient amounts, rejecting overflow.
///
/// Amounts reach here from JS callers, so the total is not trustworthy
/// without a checked add.
fn total_recipient_amount(recipients: &[Recipient]) -> Result<u64, Box<dyn Error>> {
    recipients
        .iter()
        .try_fold(0u64, |acc, r| acc.checked_add(r.amount))
        .ok_or_else(|| "Recipient amounts overflow u64".into())
}

/// A UTXO selection plus the fee and recipient total it implies.
struct TransparentSelection {
    selected: Vec<SerializedUTXO>,
    /// Sum of the selected UTXOs.
    total: u64,
    fee: u64,
    /// Sum paid to recipients, excluding change and fee.
    amount: u64,
}

/// Validate recipients and select UTXOs largest-first until they cover the
/// recipient total plus fee.
///
/// Shared by [`create_raw_transparent_transaction_to_many`] and
/// [`estimate_raw_transparent_fee_to_many`], because the fee depends on how
/// many inputs selection ends up reaching for, so an estimator that did its
/// own selection could quote a different fee than the builder charges.
fn select_transparent_utxos(
    wallet: &WalletData,
    recipients: &[Recipient],
) -> Result<TransparentSelection, Box<dyn Error>> {
    if recipients.is_empty() {
        return Err("No recipients provided".into());
    }
    for r in recipients {
        if r.address.starts_with(MAIN_NETWORK.hrp_sapling_payment_address()) {
            return Err(format!(
                "Shield recipient {} is not supported in a multi-recipient transparent send: \
                 use create_shielding_transaction for shield destinations",
                r.address
            )
            .into());
        }
        if r.amount == 0 {
            return Err(format!("Recipient {} has a zero amount", r.address).into());
        }
        // Reject an unusable address before doing any selection work, so the
        // estimator and the builder fail on the same input for the same reason.
        keys::address_to_p2pkh_script(&r.address)?;
    }

    let amount = total_recipient_amount(recipients)?;

    validate_outpoints(&wallet.unspent_utxos)?;
    let utxos = spendable_utxos(wallet);
    if utxos.is_empty() {
        return Err(no_spendable_utxos_error(wallet));
    }

    // Output count for the fee model: recipients plus a possible change
    // output. Assuming change up front can only over-estimate the fee, which
    // is the safe direction: under-estimating strands the tx unconfirmed.
    let fee_output_count = recipients.len() + 1;

    let mut selected: Vec<SerializedUTXO> = Vec::new();
    let mut total: u64 = 0;

    for utxo in &utxos {
        selected.push(utxo.clone());
        // checked_add: see the matching guard in
        // create_shielding_transaction: UTXOs come from explorers,
        // not internal code, so we can't trust their values to fit.
        total = total
            .checked_add(utxo.amount)
            .ok_or("UTXO total overflow: explorer returned malformed amounts")?;
        let fee = fees::estimate_raw_transparent_fee(selected.len(), fee_output_count);
        if total >= amount.saturating_add(fee) {
            break;
        }
    }

    let fee = fees::estimate_raw_transparent_fee(selected.len(), fee_output_count);
    let needed = amount
        .checked_add(fee)
        .ok_or("Amount plus fee overflows u64")?;
    if total < needed {
        // Coins parked at another HD slot are the one exclusion a caller is
        // unlikely to have accounted for: the other two (delegated, immature)
        // have their own balance accessors that a UI is already showing, while
        // a rotating consumer's funds simply are not in `total` and nothing
        // else on this path would say why.
        let rotated = wallet.get_rotated_balance();
        let elsewhere = if rotated > 0 {
            format!(
                ". A further {rotated} sat sits at HD slots other than 0/0 and is not \
                 selectable here: spend it with sendTransparentFromUtxos"
            )
        } else {
            String::new()
        };
        return Err(format!(
            "Insufficient public balance. Have: {} sat, need: {} sat + {} sat fee{}",
            total, amount, fee, elsewhere
        )
        .into());
    }

    Ok(TransparentSelection { selected, total, fee, amount })
}

/// Fee that [`create_raw_transparent_transaction_to_many`] will charge for
/// `recipients` against the wallet's current UTXO set.
///
/// Errs for the same reasons the builder would: no recipients, a zero amount,
/// an invalid or shield address, duplicate outpoints, or insufficient funds,
/// so a successful estimate means the send itself will get as far as signing.
///
/// A lower bound where dust is concerned: change below the dust threshold is
/// dropped to the miner rather than emitted as an output no node would relay,
/// which raises the fee actually paid by the dropped amount. The estimator
/// cannot know that before the outputs are resolved.
/// `TransparentTransactionResult::fee` always reports the true figure.
pub fn estimate_raw_transparent_fee_to_many(
    wallet: &WalletData,
    recipients: &[Recipient],
) -> Result<u64, Box<dyn Error>> {
    Ok(select_transparent_utxos(wallet, recipients)?.fee)
}

/// The UTXOs an ordinary transparent send may select from, largest first.
///
/// Delegated outputs are excluded: they are P2CS, not P2PKH, so signing one in
/// an ordinary send produces a transaction the network rejects. They remain
/// redeemable via [`create_coldstake_withdrawal`]. Immature coinstake outputs
/// are excluded for a different reason: they exist and are ours, but the
/// network will not accept a spend of them until they are deep enough.
///
/// Outputs tagged to an HD slot other than `0/0` are excluded for a third
/// reason: every wallet-state builder signs with the key at `0/0` and pays
/// change back to it, so an output received at `0/5` would be signed against
/// the wrong script. That is the same class of failure as the P2CS case, a
/// transaction the network refuses, and it is invisible without the tag
/// because a P2PKH UTXO carries no hint of which address received it.
/// Untagged outputs still qualify: see [`SerializedUTXO::matches_slot`].
///
/// Every selection path shares this, so a caller sizing an amount against
/// [`WalletData::get_transparent_balance`] (which applies the same filter)
/// cannot be offered coins the builder will then refuse.
pub(crate) fn spendable_utxos(wallet: &WalletData) -> Vec<SerializedUTXO> {
    let mut utxos: Vec<SerializedUTXO> = wallet
        .unspent_utxos
        .iter()
        .filter(|u| {
            !crate::wallet::is_delegated_utxo(u) && u.is_mature() && u.matches_slot(0, 0)
        })
        .cloned()
        .collect();
    utxos.sort_by_key(|u| std::cmp::Reverse(u.amount));
    utxos
}

/// Why there is nothing to spend, for the case where [`spendable_utxos`] comes
/// back empty but the wallet is not.
fn no_spendable_utxos_error(wallet: &WalletData) -> Box<dyn Error> {
    let delegated = wallet.get_delegated_balance();
    let immature = wallet.get_immature_balance();
    if delegated > 0 {
        return format!(
            "No spendable transparent UTXOs: {delegated} sat is delegated for cold \
             staking and must be withdrawn before it can be spent"
        )
        .into();
    }
    if immature > 0 {
        return format!(
            "No spendable transparent UTXOs: {immature} sat is in coinstake outputs that \
             have not reached maturity yet"
        )
        .into();
    }
    let rotated = wallet.get_rotated_balance();
    if rotated > 0 {
        return format!(
            "No spendable transparent UTXOs: {rotated} sat sits at HD slots other than 0/0, \
             which an ordinary send cannot sign for. Spend it with sendTransparentFromUtxos, \
             passing that slot's fromChange/fromIndex and only its outputs"
        )
        .into();
    }
    "No transparent UTXOs available".into()
}

/// Largest amount a transparent send to `recipient_count` recipients can pay
/// right now, after the fee that send will charge.
///
/// This is the number a "send max" control should offer. It is computed from
/// the same filtered UTXO set and the same fee model the builder uses, so the
/// figure is always buildable: passing it straight to
/// [`create_raw_transparent_transaction_to_many`] leaves exactly zero change.
///
/// Returns 0 when nothing can be sent, which includes the case where the fee
/// swallows the balance and the case where what is left would be dust (an
/// output below [`fees::dust_threshold`] is non-standard, so the send would be
/// refused). A UI can treat 0 as "disable the control".
///
/// Conservative, never optimistic, in one edge case: when the wallet holds
/// outputs worth less than they cost to spend, selection stops before reaching
/// them and the true maximum is marginally higher than this. The difference is
/// smaller than the fee of one input.
pub fn max_sendable_transparent(wallet: &WalletData, recipient_count: usize) -> u64 {
    let utxos = spendable_utxos(wallet);
    if utxos.is_empty() || recipient_count == 0 {
        return 0;
    }
    let Some(total) = utxos.iter().try_fold(0u64, |a, u| a.checked_add(u.amount)) else {
        return 0;
    };
    // Recipients plus a possible change output, matching `select_transparent_utxos`.
    // A max send emits no change, so this over-estimates by one output's worth,
    // which is the direction that keeps the figure buildable.
    let fee = fees::estimate_raw_transparent_fee(utxos.len(), recipient_count + 1);
    let max = total.saturating_sub(fee);
    // 25 bytes: the P2PKH script every ordinary recipient is paid with.
    if max < fees::dust_threshold(25) {
        return 0;
    }
    max
}

/// Largest amount [`create_shielding_transaction`] can move into a shield
/// address right now, after fee.
///
/// The shield counterpart to [`max_sendable_transparent`], differing only in
/// the fee model: a shielding transaction pays for Sapling outputs rather than
/// transparent ones.
pub fn max_shieldable_transparent(wallet: &WalletData) -> u64 {
    let utxos = spendable_utxos(wallet);
    if utxos.is_empty() {
        return 0;
    }
    let Some(total) = utxos.iter().try_fold(0u64, |a, u| a.checked_add(u.amount)) else {
        return 0;
    };
    // Matches `create_shielding_transaction`: 0 transparent outputs, 2 sapling.
    let fee = fees::estimate_fee(utxos.len() as u64, 0, 0, 2);
    total.saturating_sub(fee)
}

/// Reject a UTXO set that cannot be turned into valid prevouts.
///
/// Two failures, both of which produce a transaction rather than an error if
/// they get through, which is why they are checked together at the one point
/// every build path already passes through. Adding a build path without this
/// call is the mistake this consolidation exists to prevent.
///
/// **Malformed txids.** A txid is decoded with the unchecked SIMD hex decoder
/// and written straight into the prevout. Non-hex decodes to garbage and an
/// odd length drops a nibble, so a bad txid yields either a structurally
/// corrupt transaction (the prevout is not 32 bytes, and every byte after it
/// shifts) or a well-formed one spending an outpoint that does not exist. The
/// sighash is computed over the same wrong bytes, so the transaction is
/// internally consistent and nothing downstream disagrees. It fails at
/// broadcast, reported as missing inputs, which reads like a stale UTXO set
/// rather than bad data. See [`SerializedUTXO::has_valid_txid`].
///
/// **Duplicate outpoints.** An outpoint can only be spent once. A set
/// containing a duplicate makes the wallet believe it holds twice the funds it
/// does, and produces a transaction that spends one output twice, which the
/// network rejects outright.
///
/// [`crate::wallet::parse_blockbook_utxos`] screens both at ingest, because
/// explorers really do emit duplicates mid-confirmation. This guard covers the
/// paths that bypass the parser: `sendTransparentFromUtxos*`, where the caller
/// hands in an exact set, and any `setUtxos` call built by other means.
///
/// Erroring rather than silently dropping is deliberate here. When a caller
/// supplies the set explicitly, either fault means their own accounting is
/// wrong: they have almost certainly computed recipient amounts against a total
/// that includes the bad entry. Quietly shrinking their inputs would build a
/// transaction that does not match what they asked for.
pub(crate) fn validate_outpoints(utxos: &[SerializedUTXO]) -> Result<(), Box<dyn Error>> {
    for u in utxos {
        if !u.has_valid_txid() {
            return Err(format!(
                "UTXO has a malformed txid {:?}: expected 64 hex characters, got {}. Signing \
                 against it would produce a transaction spending an outpoint that does not \
                 exist, which the network reports as missing inputs rather than as bad data",
                u.txid,
                u.txid.len(),
            )
            .into());
        }
    }
    for (i, u) in utxos.iter().enumerate() {
        if utxos[..i]
            .iter()
            .any(|prev| prev.vout == u.vout && prev.txid == u.txid)
        {
            return Err(format!(
                "Duplicate UTXO {}:{} in the input set: an outpoint cannot be spent twice",
                u.txid, u.vout
            )
            .into());
        }
    }
    Ok(())
}

/// Reject inputs the key at `(from_change, from_index)` cannot sign for.
///
/// `sendTransparentFromUtxos*` derives exactly one key and signs every input
/// with it. Hand it an output that was received at a different address and the
/// result is a well-formed transaction with a signature that satisfies no
/// input: the node rejects it, and the caller sees a broadcast failure with
/// nothing pointing at the cause. That is the failure mode rotation invites,
/// since a rotating consumer holds outputs at many slots at once and picks the
/// set by hand.
///
/// Two independent checks, because each catches what the other cannot:
///
///  * **The slot tag.** Authoritative when present, and the only signal
///    available for the ordinary case where explorers return no script. Absent
///    means unknown and passes, preserving the existing contract that the
///    caller vouches for the set (see [`SerializedUTXO::matches_slot`]).
///  * **The scriptPubKey.** Independent of any bookkeeping the caller may have
///    got wrong, so it catches a mis-tagged input as readily as an untagged
///    one. Only available when the consumer joined scripts on, which the cold
///    staking flows already require.
fn reject_foreign_slot_utxos(
    utxos: &[SerializedUTXO],
    from_change: u32,
    from_index: u32,
    own_address: &str,
    own_script: &[u8],
) -> Result<(), Box<dyn Error>> {
    for u in utxos {
        if !u.matches_slot(from_change, from_index) {
            // `matches_slot` only returns false for a tagged UTXO, so the
            // fallback is unreachable and the slot named below is the real one.
            let slot = u.hd_slot.unwrap_or_default();
            return Err(format!(
                "UTXO {}:{} was received at HD slot {}/{}, but this send signs with the key at \
                 {from_change}/{from_index} ({own_address}). Build one transaction per slot, or \
                 drop the hdSlot tag if the outputs are not actually slot-specific",
                u.txid, u.vout, slot.change, slot.index,
            )
            .into());
        }

        // Empty means "unknown", never "mismatch": most explorers omit it.
        if u.script.is_empty() {
            continue;
        }
        let script = crate::simd::hex::hex_string_to_bytes(&u.script);
        if script == own_script {
            continue;
        }
        // P2CS is caught earlier by the delegated-output guard, so anything
        // reaching here that is not this key's P2PKH is unspendable by this
        // path whatever it is. Name the owning address when the script is a
        // readable P2PKH, since that is the case a rotating caller hits.
        let owner = parse_p2pkh_hash(&script)
            .map(|h| {
                format!(
                    "is paid to {}",
                    crate::transparent::coldstake::encode_checked(
                        crate::params::PIVX_PUBKEY_PREFIX,
                        &h
                    )
                )
            })
            .unwrap_or_else(|| "is not a P2PKH output".to_string());
        return Err(format!(
            "UTXO {}:{} {}, which the key at {from_change}/{from_index} ({own_address}) cannot \
             sign for. Signing it anyway would produce a transaction the network rejects",
            u.txid, u.vout, owner,
        )
        .into());
    }
    Ok(())
}

/// The hash160 inside a standard P2PKH scriptPubKey, if that is what this is.
fn parse_p2pkh_hash(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() != 25 || script[..3] != [0x76, 0xa9, 0x14] || script[23..] != [0x88, 0xac] {
        return None;
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&script[3..23]);
    Some(hash)
}

/// Build and sign a shielding transaction: transparent inputs → shield output(s).
///
/// This is the only path through the v3 builder: pure transparent→transparent
/// sends take the raw v1 P2PKH path (see [`create_raw_transparent_transaction`])
/// because PIVX nodes reject v3 txs with no Sapling data.
///
/// The caller must supply a loaded Sapling prover: the tx carries a real
/// Sapling output bundle, so Groth16 proofs are mandatory.
///
/// Returns an error if `to_address` is a transparent address; such calls
/// should go through [`create_raw_transparent_transaction`] instead.
pub fn create_shielding_transaction(
    wallet: &mut WalletData,
    bip39_seed: &[u8],
    to_address: &str,
    amount: u64,
    block_height: u32,
    prover: &SaplingProver,
) -> Result<TransparentTransactionResult, Box<dyn Error>> {
    let to = keys::decode_generic_address(to_address)?;
    let shield_addr = match to {
        GenericAddress::Shield(a) => a,
        GenericAddress::Transparent(_) => {
            return Err(
                "create_shielding_transaction only supports shield destinations; \
                 use create_raw_transparent_transaction for transparent destinations"
                    .into(),
            );
        }
    };

    let network = MAIN_NETWORK;

    let (own_address, _pubkey_bytes, privkey_bytes) =
        keys::transparent_key_from_bip39_seed(bip39_seed, 0, 0)?;

    let sk = secp256k1::SecretKey::from_slice(&privkey_bytes)
        .map_err(|e| format!("Invalid private key: {e}"))?;

    let own_transparent = keys::decode_generic_address(&own_address)?;
    let own_script = match &own_transparent {
        GenericAddress::Transparent(addr) => addr.script(),
        _ => return Err("Own address is not transparent".into()),
    };

    validate_outpoints(&wallet.unspent_utxos)?;
    let utxos = spendable_utxos(wallet);
    if utxos.is_empty() {
        return Err(no_spendable_utxos_error(wallet));
    }

    // Shield dest: 0 transparent outs, 2 sapling outs (destination + change-back-to-self would
    // need a shield change address, but currently change goes back as transparent).
    let transparent_output_count: u64 = 0;
    let sapling_output_count: u64 = 2;

    let mut selected: Vec<SerializedUTXO> = Vec::new();
    let mut total: u64 = 0;
    let mut fee: u64 = 0;

    for utxo in &utxos {
        selected.push(utxo.clone());
        // checked_add: explorer responses are untrusted input; a
        // malicious or buggy Blockbook serving u64::MAX in `amount`
        // could overflow the running total. Surface as a clear
        // "explorer is broken" error rather than a debug-build panic
        // or a release-build silent wrap to a small balance.
        total = total
            .checked_add(utxo.amount)
            .ok_or("UTXO total overflow: explorer returned malformed amounts")?;
        fee = fees::estimate_fee(
            selected.len() as u64,
            transparent_output_count,
            0,
            sapling_output_count,
        );
        // Checked, for the same reason the amounts above are: `amount` comes
        // from a JS caller. An unchecked `amount + fee` wraps in release, and a
        // wrap to a small number makes this loop break early and the guard
        // below pass, at which point `total - amount - fee` underflows into a
        // colossal change output. The transparent selector already uses checked
        // arithmetic here; this path was the one that did not.
        let needed = amount
            .checked_add(fee)
            .ok_or("Amount plus fee overflows u64")?;
        if total >= needed {
            break;
        }
    }

    let needed = amount
        .checked_add(fee)
        .ok_or("Amount plus fee overflows u64")?;
    if total < needed {
        return Err(format!(
            "Insufficient public balance. Have: {} sat, need: {} sat (amount) + {} sat (fee)",
            total, amount, fee
        )
        .into());
    }

    let change = total - needed;

    let sapling_anchor = if crate::sapling::tree::is_empty_tree_hex(&wallet.commitment_tree) {
        Anchor::empty_tree()
    } else {
        let tree = read_tree_hex(&wallet.commitment_tree)?;
        Anchor::from_bytes(tree.root().to_bytes())
            .into_option()
            .unwrap_or(Anchor::empty_tree())
    };

    let mut builder = Builder::new(
        network,
        BlockHeight::from_u32(block_height),
        BuildConfig::Standard {
            sapling_anchor: Some(sapling_anchor),
            orchard_anchor: None,
        },
    );

    let mut signing_set = TransparentSigningSet::new();
    let builder_pk = signing_set.add_key(sk);

    for utxo in &selected {
        let mut txid_bytes = crate::simd::hex::hex_string_to_bytes(&utxo.txid);
        txid_bytes.reverse();
        // `validate_outpoints` has already guaranteed 32 bytes, so this is
        // belt-and-braces, but the failure mode it replaces is bad enough to be
        // worth the four lines: `copy_from_slice` panics on a length mismatch,
        // and a panic in wasm poisons the module. The wallet would be dead for
        // the rest of the page's life, not merely unable to build this one
        // transaction.
        let hash: [u8; 32] = txid_bytes.as_slice().try_into().map_err(|_| {
            format!(
                "UTXO {}:{} has a txid that is not 32 bytes",
                utxo.txid, utxo.vout
            )
        })?;
        let outpoint = OutPoint::new(hash, utxo.vout);

        let txout = zcash_transparent::bundle::TxOut {
            value: Zatoshis::from_u64(utxo.amount).map_err(|_| "Invalid amount")?,
            script_pubkey: own_script.clone(),
        };

        builder
            .add_transparent_input(builder_pk, outpoint, txout)
            .map_err(|e| format!("Failed to add transparent input: {:?}", e))?;
    }

    let send_amount = Zatoshis::from_u64(amount).map_err(|_| "Invalid amount")?;
    builder
        .add_sapling_output::<FeeRule>(None, shield_addr, send_amount, MemoBytes::empty())
        .map_err(|_| "Failed to add shield output")?;

    if change > 0 {
        let change_amount = Zatoshis::from_u64(change).map_err(|_| "Invalid change")?;
        if let GenericAddress::Transparent(addr) = &own_transparent {
            builder
                .add_transparent_output(addr, change_amount)
                .map_err(|e| format!("Failed to add change: {:?}", e))?;
        }
    }

    let fee_rule = FeeRule::non_standard(Zatoshis::from_u64(fee).map_err(|_| "Invalid fee")?);
    let result = builder.build(
        &signing_set,
        &[],
        &[],
        OsRng,
        &prover.spend,
        &prover.output,
        &fee_rule,
    )?;

    let mut tx_hex = vec![];
    result.transaction().write(&mut tx_hex)?;

    let spent: Vec<SpentOutpoint> = selected.iter().map(|u| SpentOutpoint { txid: u.txid.clone(), vout: u.vout }).collect();

    Ok(TransparentTransactionResult {
        txhex: crate::simd::hex::bytes_to_hex_string(&tx_hex),
        spent,
        amount,
        fee,
    })
}

/// Build a signed transparent transaction: canonical entry for any spend
/// from transparent UTXOs.
///
/// For transparent destinations (`D...`): produces a raw v1 P2PKH transaction
/// signed with ECDSA / SIGHASH_ALL. No Sapling machinery is touched:
/// `block_height_for_shield` and `prover_for_shield` are ignored. Consumers
/// can pass `0` and `None`.
///
/// For shield destinations (`ps1...`): delegates to
/// [`create_shielding_transaction`]. Both `block_height_for_shield` (the
/// chain tip) and `prover_for_shield` (a loaded Sapling prover) are required.
pub fn create_raw_transparent_transaction(
    wallet: &mut WalletData,
    bip39_seed: &[u8],
    to_address: &str,
    amount: u64,
    block_height_for_shield: u32,
    prover_for_shield: Option<&SaplingProver>,
) -> Result<TransparentTransactionResult, Box<dyn Error>> {
    if to_address.starts_with(MAIN_NETWORK.hrp_sapling_payment_address()) {
        let prover = prover_for_shield.ok_or(
            "Shield destination requires a Sapling prover (call verify_and_load_params first)",
        )?;
        return create_shielding_transaction(
            wallet,
            bip39_seed,
            to_address,
            amount,
            block_height_for_shield,
            prover,
        );
    }

    create_raw_transparent_transaction_to_many(
        wallet,
        bip39_seed,
        &[Recipient {
            address: to_address.to_string(),
            amount,
        }],
    )
}

/// Multi-recipient form of [`create_raw_transparent_transaction`]: one v1
/// P2PKH transaction paying any number of transparent addresses from the
/// wallet's own UTXO set.
///
/// Selects UTXOs largest-first until the total covers every recipient plus the
/// fee, then pays each recipient in the order given, with any remainder
/// returning to the wallet's own address as a final change output.
///
/// Transparent destinations only. Shield outputs need the v3 builder and a
/// Sapling prover, and mixing the two in one transaction is not supported:
/// see [`create_shielding_transaction`].
///
/// `TransparentTransactionResult::amount` is the sum paid to recipients,
/// excluding change and fee.
pub fn create_raw_transparent_transaction_to_many(
    wallet: &mut WalletData,
    bip39_seed: &[u8],
    recipients: &[Recipient],
) -> Result<TransparentTransactionResult, Box<dyn Error>> {
    let (own_address, pubkey_bytes, privkey_bytes) =
        keys::transparent_key_from_bip39_seed(bip39_seed, 0, 0)?;
    let own_script = keys::address_to_p2pkh_script(&own_address)?;

    let selection = select_transparent_utxos(wallet, recipients)?;
    let (selected, amount, fee) = (selection.selected, selection.amount, selection.fee);

    let change = selection.total - amount - fee;
    let outputs = resolve_outputs(recipients, change, &own_script)?;
    // `resolve_outputs` drops dust change rather than emitting an unrelayable
    // output, so the fee actually paid is whatever the outputs did not claim.
    let fee = selection.total - outputs.iter().map(|o| o.value).sum::<u64>();
    let signing_inputs: Vec<SigningInput> = selected
        .iter()
        .map(|u| SigningInput::p2pkh(u.clone(), &own_script))
        .collect();
    let txhex = sign_and_serialize(&signing_inputs, &outputs, &pubkey_bytes, &privkey_bytes)?;

    let spent: Vec<SpentOutpoint> = selected
        .iter()
        .map(|u| SpentOutpoint {
            txid: u.txid.clone(),
            vout: u.vout,
        })
        .collect();

    Ok(TransparentTransactionResult {
        txhex,
        spent,
        amount,
        fee,
    })
}

/// Build and sign a v1 P2PKH transparent transaction from a specific HD
/// slot, spending a caller-supplied set of UTXOs.
///
/// Distinct from [`create_raw_transparent_transaction`] in two ways:
///
///  1. **Custom HD index.** Signs with the key at
///     `m/44'/119'/0'/from_change/from_index` rather than the wallet's
///     default `(0, 0)`. Lets callers spend from any HD-derived address,
///     which is useful for any consumer that maintains multiple receive
///     addresses (payment processors, hierarchical-deterministic
///     accounting, etc.).
///
///  2. **Caller-supplied UTXOs.** Doesn't read `WalletData` at all.
///     The caller hands in exactly the UTXOs they want to spend; the
///     function applies no selection on top.
///
/// One slot per call: every input is signed with the one key, so a set
/// spanning several addresses has to be split into one transaction each.
/// Inputs that visibly belong elsewhere (by `hd_slot` tag or by
/// `scriptPubKey`) are rejected rather than signed into a transaction the
/// network would refuse.
///
/// Single recipient, single source. Any leftover (`total - amount -
/// fee`) becomes a change output back to the *source* address (where
/// the funds came from). Pass `amount = total - fee` to get exactly
/// one output with no change.
///
/// Returns the same `TransparentTransactionResult` shape as the wallet-
/// state-aware sibling, including the `spent` list so the caller can
/// reconcile its own UTXO bookkeeping.
pub fn create_raw_transparent_transaction_from_utxos(
    bip39_seed: &[u8],
    from_change: u32,
    from_index: u32,
    utxos: &[SerializedUTXO],
    to_address: &str,
    amount: u64,
) -> Result<TransparentTransactionResult, Box<dyn Error>> {
    create_raw_transparent_transaction_from_utxos_to_many(
        bip39_seed,
        from_change,
        from_index,
        utxos,
        &[Recipient {
            address: to_address.to_string(),
            amount,
        }],
    )
}

/// Multi-recipient form of [`create_raw_transparent_transaction_from_utxos`]:
/// spends a caller-supplied UTXO set from a specific HD slot across any number
/// of transparent recipients.
///
/// Every supplied UTXO is spent: no selection is applied. Recipients are paid
/// in the order given; any remainder after fee returns to the *source* address
/// as a final change output. Pass recipient amounts summing to `total - fee` to
/// get no change output at all.
///
/// All inputs must belong to the one slot; see
/// [`create_raw_transparent_transaction_from_utxos`].
///
/// `TransparentTransactionResult::amount` is the sum paid to recipients,
/// excluding change and fee.
pub fn create_raw_transparent_transaction_from_utxos_to_many(
    bip39_seed: &[u8],
    from_change: u32,
    from_index: u32,
    utxos: &[SerializedUTXO],
    recipients: &[Recipient],
) -> Result<TransparentTransactionResult, Box<dyn Error>> {
    if utxos.is_empty() {
        return Err("No UTXOs provided".into());
    }
    // Every supplied UTXO is spent, so a repeated outpoint here would go
    // straight into the transaction as a double-spend.
    validate_outpoints(utxos)?;

    // A delegated output cannot be spent by this path: it is P2CS, and signing
    // it against a P2PKH preimage yields a transaction the network rejects.
    // Erroring rather than skipping, because the caller named this exact set and
    // silently dropping one would produce a transaction that does not match what
    // they asked for.
    for u in utxos {
        if crate::wallet::is_delegated_utxo(u) {
            return Err(format!(
                "UTXO {}:{} is delegated for cold staking and cannot be spent as an ordinary \
                 output: use create_coldstake_withdrawal to redeem it",
                u.txid, u.vout
            )
            .into());
        }
        // Same reasoning: the caller named this set, so an immature input is
        // reported rather than dropped. Unlike the delegated case this one
        // resolves on its own, so the error says when.
        if !u.is_mature() {
            return Err(format!(
                "UTXO {}:{} comes from a coinstake and is not mature. It has {} of the {} \
                 confirmations needed, so it becomes spendable in {} block(s)",
                u.txid,
                u.vout,
                u.confirmations,
                crate::params::COINBASE_MATURITY + 1,
                u.blocks_until_mature(),
            )
            .into());
        }
    }

    for r in recipients {
        if r.address.starts_with(MAIN_NETWORK.hrp_sapling_payment_address()) {
            return Err(format!(
                "Shield recipient {} is not supported in a raw transparent send",
                r.address
            )
            .into());
        }
    }

    let amount = total_recipient_amount(recipients)?;

    let (own_address, pubkey_bytes, privkey_bytes) =
        keys::transparent_key_from_bip39_seed(bip39_seed, from_change, from_index)?;
    let own_script = keys::address_to_p2pkh_script(&own_address)?;

    reject_foreign_slot_utxos(utxos, from_change, from_index, &own_address, &own_script)?;

    // Sum all provided UTXOs: every one of them gets spent. Refund
    // addresses are single-use so there's nothing to leave behind.
    let total: u64 = utxos.iter().try_fold(0u64, |acc, u| {
        acc.checked_add(u.amount)
            .ok_or("UTXO total overflow: caller passed malformed amounts")
    })?;

    // Fee assumes a change output; if it turns out to be zero the tx is
    // simply smaller than budgeted, which over-pays rather than under-pays.
    let fee = fees::estimate_raw_transparent_fee(utxos.len(), recipients.len() + 1);
    let needed = amount
        .checked_add(fee)
        .ok_or("Amount plus fee overflows u64")?;
    if total < needed {
        return Err(format!(
            "Insufficient UTXOs. Have: {} sat, need: {} sat + {} sat fee",
            total, amount, fee
        )
        .into());
    }

    let change = total - needed;
    let selected = utxos.to_vec();
    let outputs = resolve_outputs(recipients, change, &own_script)?;
    // See the note in the wallet-state path: dropped dust change raises the fee.
    let fee = total - outputs.iter().map(|o| o.value).sum::<u64>();
    let signing_inputs: Vec<SigningInput> = selected
        .iter()
        .map(|u| SigningInput::p2pkh(u.clone(), &own_script))
        .collect();
    let txhex = sign_and_serialize(&signing_inputs, &outputs, &pubkey_bytes, &privkey_bytes)?;

    let spent: Vec<SpentOutpoint> = selected
        .iter()
        .map(|u| SpentOutpoint {
            txid: u.txid.clone(),
            vout: u.vout,
        })
        .collect();

    Ok(TransparentTransactionResult {
        txhex,
        spent,
        amount,
        fee,
    })
}

/// Compute SIGHASH_ALL for a specific input in a v1 transparent tx.
///
/// Takes the already-resolved output list rather than a destination/change
/// pair, so the preimage commits to exactly the bytes [`write_outputs`] will
/// emit into the transaction body: however many outputs there are.
fn compute_sighash(
    inputs: &[SigningInput],
    signing_index: usize,
    outputs: &[TxOutput],
) -> [u8; 32] {
    let mut preimage = Vec::new();

    preimage.extend_from_slice(&1u32.to_le_bytes()); // version
    write_varint(&mut preimage, inputs.len() as u64);
    for (i, input) in inputs.iter().enumerate() {
        let mut txid_bytes = crate::simd::hex::hex_string_to_bytes(&input.utxo.txid);
        txid_bytes.reverse();
        preimage.extend_from_slice(&txid_bytes);
        preimage.extend_from_slice(&input.utxo.vout.to_le_bytes());

        // The input being signed commits to the scriptPubKey it is spending,
        // which for a delegated output is the 51-byte P2CS script, not a P2PKH
        // one. Every other input contributes an empty script.
        if i == signing_index {
            write_varint(&mut preimage, input.prevout_script.len() as u64);
            preimage.extend_from_slice(&input.prevout_script);
        } else {
            preimage.push(0x00);
        }
        preimage.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    }

    write_outputs(&mut preimage, outputs);

    preimage.extend_from_slice(&0u32.to_le_bytes()); // locktime
    preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

    let hash1 = Sha256::digest(&preimage);
    let hash2 = Sha256::digest(hash1);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash2);
    result
}

/// Sign every input and emit the finished v1 transaction body.
///
/// Shared by all the raw transparent builders: they differ in how they pick
/// UTXOs and recipients, not in how a signed transaction is laid out. Keeping
/// the signing loop in one place means the sighash and the serialized body are
/// always produced from the same `outputs` slice.
/// One input to sign, with everything that differs between input types.
///
/// Two things vary and both must vary together: the `scriptPubKey` committed to
/// in this input's sighash preimage, and whether the redeem script carries the
/// cold-staking branch selector. Signing a P2CS input against a P2PKH preimage
/// produces a signature the network rejects, so they are carried on one struct
/// rather than passed as independent arguments that could disagree.
pub(crate) struct SigningInput {
    pub(crate) utxo: SerializedUTXO,
    /// The `scriptPubKey` being spent. Goes into the preimage at this input's
    /// position; every other input contributes an empty script.
    pub(crate) prevout_script: Vec<u8>,
    /// Insert `OP_FALSE` between signature and pubkey, selecting the `OP_ELSE`
    /// (owner) branch of a P2CS script. False for ordinary P2PKH inputs.
    pub(crate) cold_stake_owner: bool,
}

impl SigningInput {
    /// An ordinary P2PKH input paying the wallet's own key.
    pub(crate) fn p2pkh(utxo: SerializedUTXO, own_script: &[u8]) -> Self {
        SigningInput {
            utxo,
            prevout_script: own_script.to_vec(),
            cold_stake_owner: false,
        }
    }
}

/// Sign every input and emit the finished v1 transaction body.
///
/// Shared by all the raw transparent builders: they differ in how they pick
/// inputs and outputs, not in how a signed transaction is laid out. Keeping the
/// signing loop in one place means the sighash and the serialized body are
/// always produced from the same `outputs` slice.
pub(crate) fn sign_and_serialize(
    inputs: &[SigningInput],
    outputs: &[TxOutput],
    pubkey_bytes: &[u8],
    privkey_bytes: &[u8],
) -> Result<String, Box<dyn Error>> {
    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(privkey_bytes)
        .map_err(|e| format!("Invalid private key: {e}"))?;

    let mut signed_tx = Vec::new();
    signed_tx.extend_from_slice(&1u32.to_le_bytes()); // version
    write_varint(&mut signed_tx, inputs.len() as u64);

    for (input_idx, input) in inputs.iter().enumerate() {
        let mut txid_bytes = crate::simd::hex::hex_string_to_bytes(&input.utxo.txid);
        txid_bytes.reverse();
        signed_tx.extend_from_slice(&txid_bytes);
        signed_tx.extend_from_slice(&input.utxo.vout.to_le_bytes());

        let sighash = compute_sighash(inputs, input_idx, outputs);

        let msg = secp256k1::Message::from_digest(sighash);
        let sig = secp.sign_ecdsa(&msg, &sk);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL

        // Built by the same function the cold-staking module exposes, so there
        // is one definition of the redeem-script layout rather than two that
        // could drift.
        let script_sig = if input.cold_stake_owner {
            crate::transparent::coldstake::build_p2cs_owner_script_sig(&sig_bytes, pubkey_bytes)
        } else {
            crate::transparent::coldstake::build_p2pkh_script_sig(&sig_bytes, pubkey_bytes)
        };
        write_varint(&mut signed_tx, script_sig.len() as u64);
        signed_tx.extend_from_slice(&script_sig);

        signed_tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
    }

    write_outputs(&mut signed_tx, outputs);
    signed_tx.extend_from_slice(&0u32.to_le_bytes()); // locktime

    Ok(crate::simd::hex::bytes_to_hex_string(&signed_tx))
}
