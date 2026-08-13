//! Withdrawing a delegation: P2CS inputs → an ordinary P2PKH output.
//!
//! Two things distinguish this from every other transparent spend, and both are
//! silent failures if wrong:
//!
//! 1. The sighash commits to the **P2CS** `scriptPubKey`, not a P2PKH one. Sign
//!    against the wrong prevout script and the signature is well-formed,
//!    verifies against nothing the network will check, and the transaction is
//!    rejected, with the coins still locked.
//! 2. The redeem script carries `OP_FALSE` to select the owner branch. Omit it
//!    and the script takes the staking branch, comparing the owner's key hash
//!    against the staker's.
//!
//! So the verifier here uses the real P2CS script as the prevout. A signature
//! that validates under it could not have been produced against a P2PKH
//! preimage, which is what makes this test meaningful rather than circular.

mod common;
use common::{decode, split_script_sig, verify_with_prevouts};

use pivx_wallet_kit::keys;
use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::coldstake::{
    ColdStakeVariant, build_p2cs_script, create_coldstake_withdrawal,
    create_delegation_transaction, encode_staking_address, estimate_coldstake_withdrawal_fee,
    is_p2cs,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const STAKER: [u8; 20] = [0xAA; 20];

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn owner_hash(change: u32, index: u32) -> [u8; 20] {
    pivx_wallet_kit::transparent::coldstake::owner_hash_from_seed(&seed(), change, index).unwrap()
}

/// A delegated UTXO owned by the key at `change/index`.
fn delegated_utxo(letter: &str, vout: u32, amount: u64, change: u32, index: u32) -> SerializedUTXO {
    let script = build_p2cs_script(&STAKER, &owner_hash(change, index), ColdStakeVariant::Lof);
    SerializedUTXO {
        txid: letter.repeat(64),
        vout,
        amount,
        script: simd::hex::bytes_to_hex_string(&script),
        height: 5_000_000,
        ..Default::default()
    }
}

fn wallet_with(utxos: Vec<SerializedUTXO>) -> WalletData {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = utxos;
    w
}

fn to_address() -> String {
    keys::get_transparent_address(TEST_MNEMONIC).unwrap()
}

// --- tests ------------------------------------------------------------------

/// The core guarantee: the signature validates against the P2CS prevout script,
/// and the redeem script selects the owner branch.
#[test]
fn withdrawal_signs_against_the_p2cs_script() {
    let utxo = delegated_utxo("a", 0, 500_000_000, 0, 0);
    let prevout = simd::hex::hex_string_to_bytes(&utxo.script);
    assert!(is_p2cs(&prevout));

    let result = create_coldstake_withdrawal(
        &seed(), 0, 0, std::slice::from_ref(&utxo), &to_address(), 200_000_000,
    )
    .expect("withdrawal should build");

    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert!(tx.consumed_all, "trailing or missing bytes");
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 2, "destination + change");

    // Destination is an ordinary P2PKH output: the delegation is over.
    assert_eq!(tx.outputs[0].script_pubkey.len(), 25);
    assert!(!is_p2cs(&tx.outputs[0].script_pubkey));
    assert_eq!(tx.outputs[0].value, 200_000_000);

    assert_eq!(verify_with_prevouts(&tx, &[prevout]), 1);

    let out_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
    assert_eq!(500_000_000 - out_total, result.fee);
}

/// Every input of a real withdrawal must carry the `OP_FALSE` branch selector.
///
/// Without it the script takes the `OP_IF` branch and compares the owner's key
/// hash against the *staker's*, which cannot match. Asserted on transactions the
/// builder actually produced, not on the helper that constructs the redeem
/// script, so the wiring between them is covered too.
#[test]
fn every_withdrawal_input_carries_the_owner_branch_selector() {
    let utxos = vec![
        delegated_utxo("a", 0, 200_000_000, 0, 0),
        delegated_utxo("b", 1, 200_000_000, 0, 0),
    ];
    let result =
        create_coldstake_withdrawal(&seed(), 0, 0, &utxos, &to_address(), 300_000_000).unwrap();
    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));

    assert_eq!(tx.inputs.len(), 2);
    for (i, input) in tx.inputs.iter().enumerate() {
        let (_, _, has_selector) = split_script_sig(&input.script_sig);
        assert!(
            has_selector,
            "input {i}: no OP_FALSE: this redeem script selects the staking branch"
        );
    }
}

/// The converse: an ordinary P2PKH spend must *not* carry the selector, or the
/// script would try to take a branch that is not there.
#[test]
fn ordinary_spends_do_not_carry_the_selector() {
    use pivx_wallet_kit::transparent::builder::{
        Recipient, create_raw_transparent_transaction_from_utxos_to_many,
    };

    let plain = SerializedUTXO {
        txid: "f".repeat(64),
        vout: 0,
        amount: 100_000_000,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    };
    let result = create_raw_transparent_transaction_from_utxos_to_many(
        &seed(),
        0,
        0,
        &[plain],
        &[Recipient { address: to_address(), amount: 50_000_000 }],
    )
    .unwrap();

    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    let (_, _, has_selector) = split_script_sig(&tx.inputs[0].script_sig);
    assert!(!has_selector, "an ordinary P2PKH input must not carry OP_FALSE");
}

/// A signature made against a P2PKH preimage must NOT validate under the P2CS
/// prevout. This is what proves the previous test is not passing by accident:
/// the two preimages genuinely differ.
#[test]
fn a_p2pkh_preimage_would_not_satisfy_the_p2cs_input() {
    let utxo = delegated_utxo("b", 0, 500_000_000, 0, 0);
    let p2cs = simd::hex::hex_string_to_bytes(&utxo.script);

    let result = create_coldstake_withdrawal(
        &seed(), 0, 0, std::slice::from_ref(&utxo), &to_address(), 200_000_000,
    )
    .unwrap();
    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));

    // Correct prevout verifies.
    assert_eq!(verify_with_prevouts(&tx, std::slice::from_ref(&p2cs)), 1);

    // The P2PKH script for the same owner key does not.
    let p2pkh = pivx_wallet_kit::transparent::coldstake::p2pkh_script_from_hash(&owner_hash(0, 0));
    assert_ne!(p2pkh, p2cs);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_with_prevouts(&tx, &[p2pkh]);
    }))
    .is_err();
    assert!(
        panicked,
        "the signature verified under a P2PKH preimage too: the sighash is not committing to \
         the P2CS script"
    );
}

/// End to end: delegate, then spend that exact output back. The delegation's
/// own output becomes the withdrawal's input, so the two halves must agree on
/// the script byte-for-byte.
#[test]
fn delegate_then_withdraw_round_trip() {
    let staking = encode_staking_address(&STAKER);
    let mut w = wallet_with(vec![SerializedUTXO {
        txid: "c".repeat(64),
        vout: 0,
        amount: 500_000_000,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    }]);

    let delegation =
        create_delegation_transaction(&mut w, &seed(), &staking, 300_000_000, ColdStakeVariant::Lof)
            .expect("delegation should build");
    let dtx = decode(&simd::hex::hex_string_to_bytes(&delegation.txhex));
    let (value, p2cs_script) = (dtx.outputs[0].value, dtx.outputs[0].script_pubkey.clone());
    assert!(is_p2cs(&p2cs_script), "delegation output should be P2CS");

    // Feed that output straight back in as a delegated UTXO.
    let delegated = SerializedUTXO {
        txid: "d".repeat(64), // stand-in for the delegation's txid
        vout: 0,
        amount: value,
        script: simd::hex::bytes_to_hex_string(&p2cs_script),
        height: 5_000_001,
        ..Default::default()
    };

    let withdrawal = create_coldstake_withdrawal(
        &seed(), 0, 0, std::slice::from_ref(&delegated), &to_address(), 100_000_000,
    )
    .expect("withdrawing the delegation we just built should work");

    let wtx = decode(&simd::hex::hex_string_to_bytes(&withdrawal.txhex));
    assert_eq!(verify_with_prevouts(&wtx, &[p2cs_script]), 1);
    assert!(!is_p2cs(&wtx.outputs[0].script_pubkey), "withdrawal output should be plain P2PKH");
}

/// Several delegated inputs, each committing to its own script at its own
/// position.
#[test]
fn withdrawal_across_several_delegated_inputs() {
    let utxos = vec![
        delegated_utxo("a", 0, 200_000_000, 0, 0),
        delegated_utxo("b", 1, 200_000_000, 0, 0),
        delegated_utxo("c", 2, 200_000_000, 0, 0),
    ];
    let prevouts: Vec<Vec<u8>> = utxos
        .iter()
        .map(|u| simd::hex::hex_string_to_bytes(&u.script))
        .collect();

    let result =
        create_coldstake_withdrawal(&seed(), 0, 0, &utxos, &to_address(), 500_000_000).unwrap();
    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));

    assert_eq!(tx.inputs.len(), 3);
    assert_eq!(verify_with_prevouts(&tx, &prevouts), 3);
}

/// Withdrawal from a non-default HD slot, since a delegation's owner need not be
/// index 0.
#[test]
fn withdrawal_from_a_non_default_hd_slot() {
    let utxo = delegated_utxo("e", 0, 500_000_000, 0, 7);
    let prevout = simd::hex::hex_string_to_bytes(&utxo.script);

    let result = create_coldstake_withdrawal(
        &seed(), 0, 7, std::slice::from_ref(&utxo), &to_address(), 200_000_000,
    )
    .expect("slot 0/7 owns this delegation");
    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(verify_with_prevouts(&tx, &[prevout]), 1);
}

/// Tampering after signing must invalidate.
#[test]
fn altering_a_withdrawal_invalidates_it() {
    let utxo = delegated_utxo("f", 0, 500_000_000, 0, 0);
    let prevout = simd::hex::hex_string_to_bytes(&utxo.script);
    let result = create_coldstake_withdrawal(
        &seed(), 0, 0, std::slice::from_ref(&utxo), &to_address(), 200_000_000,
    )
    .unwrap();

    let mut tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(verify_with_prevouts(&tx, std::slice::from_ref(&prevout)), 1);

    tx.outputs[0].value += 1; // one satoshi
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_with_prevouts(&tx, &[prevout]);
    }))
    .is_err();
    assert!(panicked, "verifier accepted a tampered withdrawal");
}

#[test]
fn withdrawal_fee_exceeds_the_p2pkh_equivalent() {
    for n in 1..=4usize {
        let cold = estimate_coldstake_withdrawal_fee(n);
        let p2pkh = pivx_wallet_kit::fees::estimate_raw_transparent_fee(n, 2);
        assert!(cold > p2pkh, "{n} inputs: {cold} should exceed {p2pkh}");
        // Exactly one extra byte per input, at 10 sat/byte.
        assert_eq!(cold - p2pkh, (n as u64) * 10);
    }
}

#[test]
fn rejects_invalid_withdrawals() {
    let to = to_address();
    let good = delegated_utxo("a", 0, 500_000_000, 0, 0);

    // No UTXOs.
    assert!(create_coldstake_withdrawal(&seed(), 0, 0, &[], &to, 1_000).is_err());

    // Zero amount.
    assert!(
        create_coldstake_withdrawal(&seed(), 0, 0, std::slice::from_ref(&good), &to, 0).is_err()
    );

    // Missing script: the sighash needs it and it cannot be inferred.
    let mut no_script = good.clone();
    no_script.script = String::new();
    let err = create_coldstake_withdrawal(&seed(), 0, 0, &[no_script], &to, 1_000)
        .expect_err("a UTXO with no script must be rejected")
        .to_string();
    assert!(err.contains("no script"), "got: {err}");

    // A P2PKH script is not a delegation.
    let mut p2pkh_utxo = good.clone();
    p2pkh_utxo.script = simd::hex::bytes_to_hex_string(
        &pivx_wallet_kit::transparent::coldstake::p2pkh_script_from_hash(&owner_hash(0, 0)),
    );
    assert!(
        create_coldstake_withdrawal(&seed(), 0, 0, &[p2pkh_utxo], &to, 1_000).is_err(),
        "a P2PKH input must not be accepted as a delegation"
    );

    // Owned by a different key: signing it would produce a transaction the
    // network rejects, so it fails up front instead.
    let foreign = delegated_utxo("b", 0, 500_000_000, 0, 9);
    let err = create_coldstake_withdrawal(&seed(), 0, 0, &[foreign], &to, 1_000)
        .expect_err("a delegation owned by another key must be rejected")
        .to_string();
    assert!(err.contains("cannot sign"), "got: {err}");

    // Insufficient funds.
    let small = delegated_utxo("c", 0, 1_000_000, 0, 0);
    assert!(create_coldstake_withdrawal(&seed(), 0, 0, &[small], &to, 900_000_000).is_err());

    // Duplicate outpoints.
    assert!(
        create_coldstake_withdrawal(&seed(), 0, 0, &[good.clone(), good.clone()], &to, 1_000)
            .is_err(),
        "duplicate outpoints must be rejected on the withdrawal path too"
    );

    // Corrupted destination address.
    let bad_to = {
        let mut raw = bs58::decode(&to).into_vec().unwrap();
        raw[5] ^= 0x01;
        bs58::encode(raw).into_string()
    };
    assert!(
        create_coldstake_withdrawal(&seed(), 0, 0, std::slice::from_ref(&good), &bad_to, 1_000)
            .is_err()
    );
}

/// A V6-variant delegation must be withdrawable too: both variants are
/// spendable by the same owner path.
#[test]
fn withdraws_a_v6_variant_delegation() {
    let script = build_p2cs_script(&STAKER, &owner_hash(0, 0), ColdStakeVariant::V6);
    let utxo = SerializedUTXO {
        txid: "a".repeat(64),
        vout: 0,
        amount: 500_000_000,
        script: simd::hex::bytes_to_hex_string(&script),
        height: 5_000_000,
        ..Default::default()
    };

    let result = create_coldstake_withdrawal(
        &seed(), 0, 0, std::slice::from_ref(&utxo), &to_address(), 200_000_000,
    )
    .expect("a V6 delegation should be withdrawable");
    let tx = decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(verify_with_prevouts(&tx, &[script]), 1);
}
