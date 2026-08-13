//! Delegation transactions: transparent inputs → one P2CS output.
//!
//! A delegation is a normal transaction with an unusual output script, so the
//! risk is the same as any transparent send: the signature must commit to the
//! outputs actually emitted. The signature check here re-derives the sighash
//! from the finished bytes rather than calling the builder's own hashing code,
//! for the same reason as `transparent_sighash.rs`: a verifier that reuses the
//! code under test agrees with itself even when both are wrong.
//!
//! The P2CS output makes this stricter than a P2PKH send in one way: a
//! signature covering a *different* script than the one serialized would still
//! look plausible to any check that only inspects lengths and totals.

mod common;
use common::{decode, verify_all_signatures as verify_signatures};

use pivx_wallet_kit::keys;
use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::coldstake::{
    ColdStakeVariant, MIN_COLDSTAKING_AMOUNT, P2CS_SCRIPT_LEN, addresses_from_p2cs_script,
    create_delegation_transaction, encode_staking_address, estimate_delegation_fee, is_p2cs,
    is_p2cs_lof, parse_p2cs_script,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const STAKER: [u8; 20] = [0xAA; 20];

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn utxo(letter: &str, vout: u32, amount: u64) -> SerializedUTXO {
    SerializedUTXO {
        txid: letter.repeat(64),
        vout,
        amount,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    }
}

fn wallet_with(utxos: Vec<SerializedUTXO>) -> WalletData {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = utxos;
    w
}

fn staking_addr() -> String {
    encode_staking_address(&STAKER)
}

// --- tests ------------------------------------------------------------------

/// The delegation must produce a valid P2CS output naming the requested staker
/// and the wallet's own key as owner, with a signature that commits to it.
#[test]
fn delegation_produces_a_signed_p2cs_output() {
    let mut w = wallet_with(vec![utxo("a", 0, 500_000_000)]);
    let amount = 200_000_000u64; // 2 PIV

    let result =
        create_delegation_transaction(&mut w, &seed(), &staking_addr(), amount, ColdStakeVariant::Lof)
            .expect("delegation should build");

    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert!(tx.consumed_all, "trailing or missing bytes");
    assert_eq!(tx.version, 1);
    assert_eq!(tx.outputs.len(), 2, "delegation + change");

    // Output 0 is the delegation.
    let (value, script) = (&tx.outputs[0].value, &tx.outputs[0].script_pubkey);
    assert_eq!(*value, amount);
    assert_eq!(script.len(), P2CS_SCRIPT_LEN);
    assert!(is_p2cs(script), "output 0 is not a P2CS script");
    assert!(is_p2cs_lof(script), "should default to the LOF variant");

    let hashes = parse_p2cs_script(script).unwrap();
    assert_eq!(hashes.staker, STAKER, "delegated to the wrong staker");

    // The owner must be this wallet's own key, or the delegation is unspendable
    // by its creator.
    let own = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    let own_pkh = bs58::decode(&own).into_vec().unwrap()[1..21].to_vec();
    assert_eq!(hashes.owner.to_vec(), own_pkh, "owner is not the wallet's own key");

    // Change returns to the wallet as plain P2PKH.
    let change_script = &tx.outputs[1].script_pubkey;
    assert_eq!(change_script.len(), 25);
    assert_eq!(&change_script[3..23], &own_pkh[..]);

    // And the signature covers all of it.
    assert_eq!(verify_signatures(&tx), 1);

    // Value conservation.
    let out_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
    assert_eq!(500_000_000 - out_total, result.fee);
    assert_eq!(result.amount, amount);
}

/// The addresses recovered from the built script must be the staking address
/// asked for and the wallet's own transparent address.
#[test]
fn recovered_addresses_match_the_request() {
    let mut w = wallet_with(vec![utxo("a", 0, 500_000_000)]);
    let staking = staking_addr();

    let result =
        create_delegation_transaction(&mut w, &seed(), &staking, 150_000_000, ColdStakeVariant::Lof)
            .unwrap();
    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    let (recovered_staking, recovered_owner) = addresses_from_p2cs_script(&tx.outputs[0].script_pubkey).unwrap();

    assert_eq!(recovered_staking, staking);
    assert_eq!(recovered_owner, keys::get_transparent_address(TEST_MNEMONIC).unwrap());
}

/// Tampering with the P2CS script after signing must invalidate: the check
/// that proves the signature really covers the delegation script and not just
/// its length.
#[test]
fn altering_the_delegation_script_invalidates_the_signature() {
    let mut w = wallet_with(vec![utxo("a", 0, 500_000_000)]);
    let result =
        create_delegation_transaction(&mut w, &seed(), &staking_addr(), 200_000_000, ColdStakeVariant::Lof)
            .unwrap();
    let mut tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(verify_signatures(&tx), 1);

    // Repoint the delegation at a different staker, keeping every length identical.
    tx.outputs[0].script_pubkey[6] ^= 0xff;

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_signatures(&tx);
    }))
    .is_err();
    assert!(panicked, "signature did not commit to the staker hash");
}

/// A delegation with no change is a different output count and therefore a
/// different sighash.
#[test]
fn delegation_without_change() {
    let total = 300_000_000u64;
    let w0 = wallet_with(vec![utxo("a", 0, total)]);
    let fee = estimate_delegation_fee(&w0, &staking_addr(), MIN_COLDSTAKING_AMOUNT).unwrap();

    let mut w = wallet_with(vec![utxo("a", 0, total)]);
    let amount = total - fee;
    let result =
        create_delegation_transaction(&mut w, &seed(), &staking_addr(), amount, ColdStakeVariant::Lof)
            .unwrap();

    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(tx.outputs.len(), 1, "expected no change output");
    assert!(is_p2cs(&tx.outputs[0].script_pubkey));
    assert_eq!(verify_signatures(&tx), 1);
}

/// Multiple inputs: each must commit to its own preimage position.
#[test]
fn delegation_across_several_inputs() {
    let mut w = wallet_with(vec![
        utxo("a", 0, 100_000_000),
        utxo("b", 1, 100_000_000),
        utxo("c", 2, 100_000_000),
    ]);
    let result =
        create_delegation_transaction(&mut w, &seed(), &staking_addr(), 250_000_000, ColdStakeVariant::Lof)
            .unwrap();

    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert!(tx.inputs.len() >= 3);
    assert_eq!(verify_signatures(&tx), tx.inputs.len());
    assert!(is_p2cs(&tx.outputs[0].script_pubkey));
}

/// The estimator must charge what the builder charges, including the P2CS
/// output surcharge and the cost of extra inputs.
#[test]
fn estimator_matches_the_builder() {
    for utxo_count in 1..=4usize {
        let utxos: Vec<SerializedUTXO> =
            (0..utxo_count).map(|i| utxo("a", i as u32, 200_000_000)).collect();
        let amount = 150_000_000u64 * utxo_count as u64;

        let w0 = wallet_with(utxos.clone());
        let quoted = match estimate_delegation_fee(&w0, &staking_addr(), amount) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut w = wallet_with(utxos);
        let built =
            create_delegation_transaction(&mut w, &seed(), &staking_addr(), amount, ColdStakeVariant::Lof)
                .unwrap();
        assert_eq!(quoted, built.fee, "{utxo_count} utxos");
    }
}

/// The fee must exceed a same-shape P2PKH send, because the P2CS output is
/// larger. Under-charging is what strands a transaction unconfirmed.
#[test]
fn delegation_fee_exceeds_the_p2pkh_equivalent() {
    let w = wallet_with(vec![utxo("a", 0, 500_000_000)]);
    let delegation = estimate_delegation_fee(&w, &staking_addr(), 200_000_000).unwrap();
    let p2pkh = pivx_wallet_kit::fees::estimate_raw_transparent_fee(1, 2);

    assert!(
        delegation > p2pkh,
        "delegation fee {delegation} should exceed the P2PKH-shaped {p2pkh}"
    );
    assert_eq!(
        delegation - p2pkh,
        (pivx_wallet_kit::fees::P2CS_OUTPUT_EXTRA_BYTES as u64) * 10,
        "the difference should be exactly the declared surcharge at 10 sat/byte"
    );
}

#[test]
fn rejects_invalid_delegations() {
    let staking = staking_addr();
    let owner = keys::get_transparent_address(TEST_MNEMONIC).unwrap();

    // Below the 1 PIV minimum.
    let mut w = wallet_with(vec![utxo("a", 0, 500_000_000)]);
    let err = create_delegation_transaction(
        &mut w, &seed(), &staking, MIN_COLDSTAKING_AMOUNT - 1, ColdStakeVariant::Lof,
    )
    .expect_err("below-minimum delegation must be rejected")
    .to_string();
    assert!(err.contains("minimum"), "got: {err}");

    // An owner address in the staking slot.
    let mut w = wallet_with(vec![utxo("a", 0, 500_000_000)]);
    assert!(
        create_delegation_transaction(&mut w, &seed(), &owner, 200_000_000, ColdStakeVariant::Lof)
            .is_err(),
        "a D-address must not be accepted as the staker"
    );

    // Corrupted staking address.
    let mut w = wallet_with(vec![utxo("a", 0, 500_000_000)]);
    let typo = {
        let mut raw = bs58::decode(&staking).into_vec().unwrap();
        raw[5] ^= 0x01;
        bs58::encode(raw).into_string()
    };
    assert!(
        create_delegation_transaction(&mut w, &seed(), &typo, 200_000_000, ColdStakeVariant::Lof)
            .is_err(),
        "a mistyped staking address must be rejected"
    );

    // Insufficient funds.
    let mut w = wallet_with(vec![utxo("a", 0, 150_000_000)]);
    assert!(
        create_delegation_transaction(&mut w, &seed(), &staking, 900_000_000, ColdStakeVariant::Lof)
            .is_err()
    );

    // No UTXOs at all.
    let mut w = wallet_with(vec![]);
    assert!(
        create_delegation_transaction(&mut w, &seed(), &staking, 200_000_000, ColdStakeVariant::Lof)
            .is_err()
    );

    // Duplicate outpoints.
    let mut w = wallet_with(vec![utxo("a", 0, 500_000_000), utxo("a", 0, 500_000_000)]);
    assert!(
        create_delegation_transaction(&mut w, &seed(), &staking, 200_000_000, ColdStakeVariant::Lof)
            .is_err(),
        "duplicate outpoints must be rejected on the delegation path too"
    );
}

/// The V6 variant must be selectable and still sign correctly, so switching
/// after activation is a one-line change rather than new work.
#[test]
fn v6_variant_builds_and_signs() {
    let mut w = wallet_with(vec![utxo("a", 0, 500_000_000)]);
    let result =
        create_delegation_transaction(&mut w, &seed(), &staking_addr(), 200_000_000, ColdStakeVariant::V6)
            .unwrap();

    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert!(is_p2cs(&tx.outputs[0].script_pubkey));
    assert!(!is_p2cs_lof(&tx.outputs[0].script_pubkey), "V6 must not use the LOF opcode");
    assert_eq!(tx.outputs[0].script_pubkey[4], 0xd2);
    assert_eq!(verify_signatures(&tx), 1);
}
