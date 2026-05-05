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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SpentOutpoint {
    pub txid: String,
    pub vout: u32,
}

/// Result of building a transparent transaction.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TransparentTransactionResult {
    pub txhex: String,
    /// UTXOs consumed by this tx — remove from the wallet after broadcast
    /// via [`crate::wallet::WalletData::finalize_transparent_send`].
    pub spent: Vec<SpentOutpoint>,
    pub amount: u64,
    pub fee: u64,
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
        total += utxo.amount;
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

    let (own_address, pubkey_bytes, privkey_bytes) =
        keys::transparent_key_from_bip39_seed(bip39_seed, 0, 0)?;

    let to_script = keys::address_to_p2pkh_script(to_address)?;
    let own_script = keys::address_to_p2pkh_script(&own_address)?;

    let mut utxos = wallet.unspent_utxos.clone();
    utxos.sort_by_key(|u| std::cmp::Reverse(u.amount));
    if utxos.is_empty() {
        return Err("No transparent UTXOs available".into());
    }

    let mut selected: Vec<SerializedUTXO> = Vec::new();
    let mut total: u64 = 0;

    for utxo in &utxos {
        selected.push(utxo.clone());
        total += utxo.amount;
        let fee = fees::estimate_raw_transparent_fee(selected.len(), 2);
        if total >= amount + fee {
            break;
        }
    }

    let fee = fees::estimate_raw_transparent_fee(selected.len(), 2);
    if total < amount + fee {
        return Err(format!(
            "Insufficient public balance. Have: {} sat, need: {} sat + {} sat fee",
            total, amount, fee
        )
        .into());
    }

    let change = total - amount - fee;

    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&privkey_bytes)
        .map_err(|e| format!("Invalid private key: {e}"))?;

    let mut signed_tx = Vec::new();
    signed_tx.extend_from_slice(&1u32.to_le_bytes()); // version
    write_varint(&mut signed_tx, selected.len() as u64);

    let output_count: u64 = if change > 0 { 2 } else { 1 };

    for (input_idx, utxo) in selected.iter().enumerate() {
        let mut txid_bytes = crate::simd::hex::hex_string_to_bytes(&utxo.txid);
        txid_bytes.reverse();
        signed_tx.extend_from_slice(&txid_bytes);
        signed_tx.extend_from_slice(&utxo.vout.to_le_bytes());

        let sighash =
            compute_sighash(&selected, &own_script, input_idx, amount, change, &to_script);

        let msg = secp256k1::Message::from_digest(sighash);
        let sig = secp.sign_ecdsa(&msg, &sk);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL

        let script_sig_len = sig_bytes.len() + pubkey_bytes.len() + 2;
        write_varint(&mut signed_tx, script_sig_len as u64);
        signed_tx.push(sig_bytes.len() as u8);
        signed_tx.extend_from_slice(&sig_bytes);
        signed_tx.push(pubkey_bytes.len() as u8);
        signed_tx.extend_from_slice(&pubkey_bytes);

        signed_tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
    }

    write_varint(&mut signed_tx, output_count);
    signed_tx.extend_from_slice(&amount.to_le_bytes());
    write_varint(&mut signed_tx, to_script.len() as u64);
    signed_tx.extend_from_slice(&to_script);
    if change > 0 {
        signed_tx.extend_from_slice(&change.to_le_bytes());
        write_varint(&mut signed_tx, own_script.len() as u64);
        signed_tx.extend_from_slice(&own_script);
    }

    // Locktime
    signed_tx.extend_from_slice(&0u32.to_le_bytes());

    let spent: Vec<SpentOutpoint> = selected.iter().map(|u| SpentOutpoint { txid: u.txid.clone(), vout: u.vout }).collect();

    Ok(TransparentTransactionResult {
        txhex: crate::simd::hex::bytes_to_hex_string(&signed_tx),
        spent,
        amount,
        fee,
    })
}

/// Compute SIGHASH_ALL for a specific input in a v1 transparent tx.
fn compute_sighash(
    inputs: &[SerializedUTXO],
    own_script: &[u8],
    signing_index: usize,
    amount: u64,
    change: u64,
    to_script: &[u8],
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

    let output_count: u64 = if change > 0 { 2 } else { 1 };
    write_varint(&mut preimage, output_count);
    preimage.extend_from_slice(&amount.to_le_bytes());
    write_varint(&mut preimage, to_script.len() as u64);
    preimage.extend_from_slice(to_script);
    if change > 0 {
        preimage.extend_from_slice(&change.to_le_bytes());
        write_varint(&mut preimage, own_script.len() as u64);
        preimage.extend_from_slice(own_script);
    }

    preimage.extend_from_slice(&0u32.to_le_bytes()); // locktime
    preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

    let hash1 = Sha256::digest(&preimage);
    let hash2 = Sha256::digest(hash1);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash2);
    result
}
