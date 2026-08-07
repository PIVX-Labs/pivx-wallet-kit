//! Transparent transaction builders (v3 via librustpivx + raw v1 P2PKH).
//!
//! `create_transparent_transaction` wraps librustpivx's v3 builder; it
//! supports both transparent→transparent and transparent→shield destinations
//! (the latter requires a Sapling prover).
//!
//! `create_raw_transparent_transaction` bypasses the v3 builder and produces
//! a raw v1 P2PKH transaction — needed because PIVX nodes reject v3 txs
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

/// A reference to a UTXO that was consumed by a transparent send —
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
    /// UTXOs consumed by this tx — remove from the wallet after broadcast
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
/// apart — which was a live hazard while the output shape was open-coded
/// separately in `compute_sighash` and in each builder's writer.
#[derive(Clone, Debug)]
struct TxOutput {
    value: u64,
    script: Vec<u8>,
}

/// Serialize an output list in consensus form: count, then `value ||
/// script_len || script` per output.
///
/// Single source of truth for output bytes — used by both the sighash
/// preimage and the final transaction body. Do not inline this.
fn write_outputs(buf: &mut Vec<u8>, outputs: &[TxOutput]) {
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
        outputs.push(TxOutput {
            value: r.amount,
            script: keys::address_to_p2pkh_script(&r.address)?,
        });
    }

    if change > 0 {
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

/// Reject a UTXO set containing the same outpoint more than once.
///
/// An outpoint can only be spent once. A set containing a duplicate makes the
/// wallet believe it holds twice the funds it does, and produces a transaction
/// that spends one output twice — which the network rejects outright.
///
/// [`crate::wallet::parse_blockbook_utxos`] already collapses duplicates,
/// because explorers really do emit them mid-confirmation. This guard covers
/// the paths that bypass the parser: `sendTransparentFromUtxos*`, where the
/// caller hands in an exact set, and any `setUtxos` call built by other means.
///
/// Erroring rather than silently deduplicating is deliberate here. When a
/// caller supplies the set explicitly, a duplicate means their own accounting
/// is wrong — they have almost certainly computed recipient amounts against the
/// doubled total. Quietly halving their inputs would build a transaction that
/// does not match what they asked for.
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
/// many inputs selection ends up reaching for — so an estimator that did its
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
                "Shield recipient {} is not supported in a multi-recipient transparent send — \
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

    reject_duplicate_outpoints(&wallet.unspent_utxos)?;
    let mut utxos = wallet.unspent_utxos.clone();
    utxos.sort_by_key(|u| std::cmp::Reverse(u.amount));
    if utxos.is_empty() {
        return Err("No transparent UTXOs available".into());
    }

    // Output count for the fee model: recipients plus a possible change
    // output. Assuming change up front can only over-estimate the fee, which
    // is the safe direction — under-estimating strands the tx unconfirmed.
    let fee_output_count = recipients.len() + 1;

    let mut selected: Vec<SerializedUTXO> = Vec::new();
    let mut total: u64 = 0;

    for utxo in &utxos {
        selected.push(utxo.clone());
        // checked_add: see the matching guard in
        // create_shielding_transaction — UTXOs come from explorers,
        // not internal code, so we can't trust their values to fit.
        total = total
            .checked_add(utxo.amount)
            .ok_or("UTXO total overflow — explorer returned malformed amounts")?;
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
        return Err(format!(
            "Insufficient public balance. Have: {} sat, need: {} sat + {} sat fee",
            total, amount, fee
        )
        .into());
    }

    Ok(TransparentSelection { selected, total, fee, amount })
}

/// Fee that [`create_raw_transparent_transaction_to_many`] will charge for
/// `recipients` against the wallet's current UTXO set.
///
/// Errs for the same reasons the builder would — no recipients, a zero amount,
/// an invalid or shield address, duplicate outpoints, or insufficient funds —
/// so a successful estimate means the send itself will get as far as signing.
pub fn estimate_raw_transparent_fee_to_many(
    wallet: &WalletData,
    recipients: &[Recipient],
) -> Result<u64, Box<dyn Error>> {
    Ok(select_transparent_utxos(wallet, recipients)?.fee)
}

fn reject_duplicate_outpoints(utxos: &[SerializedUTXO]) -> Result<(), Box<dyn Error>> {
    for (i, u) in utxos.iter().enumerate() {
        if utxos[..i]
            .iter()
            .any(|prev| prev.vout == u.vout && prev.txid == u.txid)
        {
            return Err(format!(
                "Duplicate UTXO {}:{} in the input set — an outpoint cannot be spent twice",
                u.txid, u.vout
            )
            .into());
        }
    }
    Ok(())
}

/// Build and sign a shielding transaction: transparent inputs → shield output(s).
///
/// This is the only path through the v3 builder — pure transparent→transparent
/// sends take the raw v1 P2PKH path (see [`create_raw_transparent_transaction`])
/// because PIVX nodes reject v3 txs with no Sapling data.
///
/// The caller must supply a loaded Sapling prover — the tx carries a real
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

    reject_duplicate_outpoints(&wallet.unspent_utxos)?;
    let mut utxos = wallet.unspent_utxos.clone();
    utxos.sort_by_key(|u| std::cmp::Reverse(u.amount));
    if utxos.is_empty() {
        return Err("No transparent UTXOs available".into());
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
            .ok_or("UTXO total overflow — explorer returned malformed amounts")?;
        fee = fees::estimate_fee(
            selected.len() as u64,
            transparent_output_count,
            0,
            sapling_output_count,
        );
        if total >= amount + fee {
            break;
        }
    }

    if total < amount + fee {
        return Err(format!(
            "Insufficient public balance. Have: {} sat, need: {} sat (amount) + {} sat (fee)",
            total, amount, fee
        )
        .into());
    }

    let change = total - amount - fee;

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
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&txid_bytes);
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

/// Build a signed transparent transaction — canonical entry for any spend
/// from transparent UTXOs.
///
/// For transparent destinations (`D...`): produces a raw v1 P2PKH transaction
/// signed with ECDSA / SIGHASH_ALL. No Sapling machinery is touched —
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
/// Sapling prover, and mixing the two in one transaction is not supported —
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
    let txhex = sign_and_serialize(
        &selected,
        &outputs,
        &own_script,
        &pubkey_bytes,
        &privkey_bytes,
    )?;

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
///     default `(0, 0)`. Lets callers spend from any HD-derived address
///     — useful for any consumer that maintains multiple receive
///     addresses (payment processors, hierarchical-deterministic
///     accounting, etc.).
///
///  2. **Caller-supplied UTXOs.** Doesn't read `WalletData` at all.
///     The caller hands in exactly the UTXOs they want to spend; the
///     function applies no selection on top.
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
/// Every supplied UTXO is spent — no selection is applied. Recipients are paid
/// in the order given; any remainder after fee returns to the *source* address
/// as a final change output. Pass recipient amounts summing to `total - fee` to
/// get no change output at all.
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
    reject_duplicate_outpoints(utxos)?;

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

    // Sum all provided UTXOs — every one of them gets spent. Refund
    // addresses are single-use so there's nothing to leave behind.
    let total: u64 = utxos.iter().try_fold(0u64, |acc, u| {
        acc.checked_add(u.amount)
            .ok_or("UTXO total overflow — caller passed malformed amounts")
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
    let txhex = sign_and_serialize(
        &selected,
        &outputs,
        &own_script,
        &pubkey_bytes,
        &privkey_bytes,
    )?;

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
/// emit into the transaction body — however many outputs there are.
fn compute_sighash(
    inputs: &[SerializedUTXO],
    own_script: &[u8],
    signing_index: usize,
    outputs: &[TxOutput],
) -> [u8; 32] {
    let mut preimage = Vec::new();

    preimage.extend_from_slice(&1u32.to_le_bytes()); // version
    write_varint(&mut preimage, inputs.len() as u64);
    for (i, utxo) in inputs.iter().enumerate() {
        let mut txid_bytes = crate::simd::hex::hex_string_to_bytes(&utxo.txid);
        txid_bytes.reverse();
        preimage.extend_from_slice(&txid_bytes);
        preimage.extend_from_slice(&utxo.vout.to_le_bytes());

        if i == signing_index {
            write_varint(&mut preimage, own_script.len() as u64);
            preimage.extend_from_slice(own_script);
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
fn sign_and_serialize(
    selected: &[SerializedUTXO],
    outputs: &[TxOutput],
    own_script: &[u8],
    pubkey_bytes: &[u8],
    privkey_bytes: &[u8],
) -> Result<String, Box<dyn Error>> {
    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(privkey_bytes)
        .map_err(|e| format!("Invalid private key: {e}"))?;

    let mut signed_tx = Vec::new();
    signed_tx.extend_from_slice(&1u32.to_le_bytes()); // version
    write_varint(&mut signed_tx, selected.len() as u64);

    for (input_idx, utxo) in selected.iter().enumerate() {
        let mut txid_bytes = crate::simd::hex::hex_string_to_bytes(&utxo.txid);
        txid_bytes.reverse();
        signed_tx.extend_from_slice(&txid_bytes);
        signed_tx.extend_from_slice(&utxo.vout.to_le_bytes());

        let sighash = compute_sighash(selected, own_script, input_idx, outputs);

        let msg = secp256k1::Message::from_digest(sighash);
        let sig = secp.sign_ecdsa(&msg, &sk);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL

        let script_sig_len = sig_bytes.len() + pubkey_bytes.len() + 2;
        write_varint(&mut signed_tx, script_sig_len as u64);
        signed_tx.push(sig_bytes.len() as u8);
        signed_tx.extend_from_slice(&sig_bytes);
        signed_tx.push(pubkey_bytes.len() as u8);
        signed_tx.extend_from_slice(pubkey_bytes);

        signed_tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
    }

    write_outputs(&mut signed_tx, outputs);
    signed_tx.extend_from_slice(&0u32.to_le_bytes()); // locktime

    Ok(crate::simd::hex::bytes_to_hex_string(&signed_tx))
}
