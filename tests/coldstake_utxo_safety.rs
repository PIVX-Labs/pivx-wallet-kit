//! Delegated outputs must never be spent as ordinary ones.
//!
//! A P2CS output is indexed under its *owner's* address, so an explorer lists it
//! alongside ordinary UTXOs: verified against a live third-party delegation,
//! which appears in `/api/v2/utxo/<owner>` exactly like any other output. A
//! wallet that refreshes its UTXO set after delegating therefore holds a mix,
//! and selecting the delegated one for a plain send produces a transaction the
//! network rejects: the signature would be made against a P2PKH preimage while
//! the output being spent is P2CS.
//!
//! Detection requires the UTXO's `script`, which no explorer returns from its
//! UTXO endpoint, so when the script is absent a delegated output is genuinely
//! indistinguishable from an ordinary one. These tests pin the behaviour for the
//! case where it *is* known, which is the case a cold-staking consumer can and
//! should arrange, by joining `/api/v2/tx/{txid}` → `vout[n].hex` onto each
//! entry before `parse_blockbook_utxos` sees it.

use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_from_utxos_to_many,
    create_raw_transparent_transaction_to_many, estimate_raw_transparent_fee_to_many,
};
use pivx_wallet_kit::transparent::coldstake::{
    ColdStakeVariant, build_p2cs_script, create_delegation_transaction, encode_staking_address,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData, is_delegated_utxo};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const STAKER: [u8; 20] = [0xAA; 20];

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn owner_hash() -> [u8; 20] {
    pivx_wallet_kit::transparent::coldstake::owner_hash_from_seed(&seed(), 0, 0).unwrap()
}

fn ordinary(letter: &str, vout: u32, amount: u64) -> SerializedUTXO {
    SerializedUTXO {
        txid: letter.repeat(64),
        vout,
        amount,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    }
}

fn delegated(letter: &str, vout: u32, amount: u64) -> SerializedUTXO {
    let script = build_p2cs_script(&STAKER, &owner_hash(), ColdStakeVariant::Lof);
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
    pivx_wallet_kit::keys::get_transparent_address(TEST_MNEMONIC).unwrap()
}

fn recipients(amount: u64) -> Vec<Recipient> {
    vec![Recipient { address: to_address(), amount }]
}

#[test]
fn a_delegated_utxo_is_recognised() {
    assert!(is_delegated_utxo(&delegated("a", 0, 100)));
    assert!(!is_delegated_utxo(&ordinary("a", 0, 100)));

    // An unknown script is treated as ordinary: the direction that preserves
    // existing behaviour for consumers who never touch cold staking.
    let mut unknown = delegated("a", 0, 100);
    unknown.script = String::new();
    assert!(!is_delegated_utxo(&unknown));

    // A P2PKH script is not a delegation.
    let mut p2pkh = delegated("a", 0, 100);
    p2pkh.script = simd::hex::bytes_to_hex_string(
        &pivx_wallet_kit::transparent::coldstake::p2pkh_script_from_hash(&owner_hash()),
    );
    assert!(!is_delegated_utxo(&p2pkh));
}

/// Balance splits into spendable and delegated. Reporting delegated coins as
/// spendable is what makes a wallet offer to send funds no plain transaction can
/// reach.
#[test]
fn balance_separates_spendable_from_delegated() {
    let w = wallet_with(vec![
        ordinary("a", 0, 10_000_000),
        delegated("b", 1, 300_000_000),
        ordinary("c", 2, 5_000_000),
    ]);

    assert_eq!(w.get_transparent_balance(), 15_000_000, "delegated coins must not count as spendable");
    assert_eq!(w.get_delegated_balance(), 300_000_000);
}

/// The core regression: an ordinary send must not select a delegated output,
/// even when it is by far the largest and selection is largest-first.
#[test]
fn ordinary_sends_skip_delegated_outputs() {
    let mut w = wallet_with(vec![
        delegated("d", 0, 300_000_000), // largest: selection would take it first
        ordinary("e", 1, 50_000_000),
    ]);

    let result = create_raw_transparent_transaction_to_many(&mut w, &seed(), &recipients(10_000_000))
        .expect("the ordinary UTXO alone should cover this");

    assert_eq!(result.spent.len(), 1);
    assert_eq!(
        result.spent[0].txid,
        "e".repeat(64),
        "the delegated output was selected for an ordinary send"
    );
}

/// If only delegated funds remain, the error must say so rather than reporting a
/// bare shortfall: the coins exist, they just need withdrawing first.
#[test]
fn a_wholly_delegated_wallet_explains_itself() {
    let mut w = wallet_with(vec![delegated("d", 0, 300_000_000)]);

    let err = create_raw_transparent_transaction_to_many(&mut w, &seed(), &recipients(1_000_000))
        .expect_err("nothing is spendable")
        .to_string();

    assert!(
        err.contains("delegated"),
        "error should name the delegation as the reason, got: {err}"
    );
}

/// The estimator must agree with the builder about what is spendable, or it
/// quotes fees for sends that cannot happen.
#[test]
fn the_estimator_also_skips_delegated_outputs() {
    let mut w = wallet_with(vec![
        delegated("d", 0, 300_000_000),
        ordinary("e", 1, 50_000_000),
    ]);

    let quoted = estimate_raw_transparent_fee_to_many(&w, &recipients(10_000_000)).unwrap();
    let built =
        create_raw_transparent_transaction_to_many(&mut w, &seed(), &recipients(10_000_000)).unwrap();
    assert_eq!(quoted, built.fee);

    // And it refuses when only delegated funds remain.
    let w2 = wallet_with(vec![delegated("d", 0, 300_000_000)]);
    assert!(estimate_raw_transparent_fee_to_many(&w2, &recipients(1_000_000)).is_err());
}

/// The from-UTXOs path takes an explicit set, so a delegated entry is a caller
/// error and must be reported rather than silently dropped: dropping it would
/// build a transaction that does not match what was asked for.
#[test]
fn the_from_utxos_path_rejects_delegated_inputs() {
    let err = create_raw_transparent_transaction_from_utxos_to_many(
        &seed(),
        0,
        0,
        &[ordinary("a", 0, 50_000_000), delegated("d", 1, 300_000_000)],
        &recipients(10_000_000),
    )
    .expect_err("a delegated input must be rejected here")
    .to_string();

    assert!(err.contains("delegated"), "got: {err}");
    assert!(err.contains("withdrawal") || err.contains("withdraw"), "should point at the remedy: {err}");
}

/// A delegation is funded from ordinary outputs; an already-delegated one must
/// be withdrawn before it can be re-delegated.
#[test]
fn delegating_skips_already_delegated_outputs() {
    let staking = encode_staking_address(&STAKER);

    let mut w = wallet_with(vec![
        delegated("d", 0, 900_000_000),
        ordinary("e", 1, 500_000_000),
    ]);
    let result =
        create_delegation_transaction(&mut w, &seed(), &staking, 200_000_000, ColdStakeVariant::Lof)
            .expect("the ordinary UTXO should fund this");
    assert_eq!(result.spent[0].txid, "e".repeat(64), "re-delegated an existing delegation");

    // With nothing ordinary left, it must fail rather than reuse the delegation.
    let mut w2 = wallet_with(vec![delegated("d", 0, 900_000_000)]);
    assert!(
        create_delegation_transaction(&mut w2, &seed(), &staking, 200_000_000, ColdStakeVariant::Lof)
            .is_err()
    );
}

/// Consumers who never populate `script` see exactly the behaviour they had
/// before cold staking existed: the guard cannot help them, and must not
/// change anything either.
#[test]
fn wallets_without_scripts_behave_as_before() {
    let mut w = wallet_with(vec![ordinary("a", 0, 100_000_000), ordinary("b", 1, 50_000_000)]);

    assert_eq!(w.get_transparent_balance(), 150_000_000);
    assert_eq!(w.get_delegated_balance(), 0);

    let result =
        create_raw_transparent_transaction_to_many(&mut w, &seed(), &recipients(120_000_000))
            .expect("both UTXOs are spendable");
    assert_eq!(result.spent.len(), 2);
}
