//! What a "send max" control may offer.
//!
//! The failure this guards against is not a crash, it is a UI and a builder
//! disagreeing. A wallet that derives "max" by summing its own UTXO list counts
//! delegated and immature outputs that no builder will select, offers the user
//! that inflated figure, and then refuses the send the user asked for. Nothing
//! catches it in testing, because a wallet with no delegations and no staking
//! history sees the two numbers agree.
//!
//! So the property under test throughout is: whatever `max_sendable_transparent`
//! returns, the builder accepts.

use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::builder::{
    Recipient, TransparentTransactionResult, create_raw_transparent_transaction_to_many,
    estimate_raw_transparent_fee_to_many, max_sendable_transparent, max_shieldable_transparent,
};
use pivx_wallet_kit::transparent::coldstake::{ColdStakeVariant, build_p2cs_script};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};
use std::error::Error;

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
    SerializedUTXO {
        script: simd::hex::bytes_to_hex_string(&build_p2cs_script(
            &STAKER,
            &owner_hash(),
            ColdStakeVariant::Lof,
        )),
        ..ordinary(letter, vout, amount)
    }
}

/// A coinstake output `confirmations` deep. Below 101 it is immature.
fn coinstake(letter: &str, vout: u32, amount: u64, confirmations: u32) -> SerializedUTXO {
    SerializedUTXO { coinstake: true, confirmations, ..ordinary(letter, vout, amount) }
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

/// Building mutates the wallet (it marks inputs spent), and `WalletData` is not
/// `Clone`, so each attempt gets a fresh one over the same UTXO set.
fn build(
    utxos: Vec<SerializedUTXO>,
    rs: &[Recipient],
) -> Result<TransparentTransactionResult, Box<dyn Error>> {
    let mut w = wallet_with(utxos);
    create_raw_transparent_transaction_to_many(&mut w, &seed(), rs)
}

/// The core contract: the figure offered is a figure the builder will build.
#[test]
fn the_maximum_is_buildable() {
    let utxos =
        vec![ordinary("a", 0, 10_000_000), ordinary("b", 1, 3_000_000), ordinary("c", 2, 500_000)];

    let max = max_sendable_transparent(&wallet_with(utxos.clone()), 1);
    assert!(max > 0);

    build(utxos, &recipients(max)).expect("the advertised maximum must be spendable");
}

/// One satoshi more must not be, or the figure is not the maximum.
#[test]
fn one_satoshi_above_the_maximum_is_refused() {
    let utxos = vec![ordinary("a", 0, 10_000_000), ordinary("b", 1, 3_000_000)];

    let max = max_sendable_transparent(&wallet_with(utxos.clone()), 1);
    let err = build(utxos, &recipients(max + 1)).expect_err("max + 1 must not build");
    assert!(err.to_string().contains("Insufficient"), "unexpected error: {err}");
}

/// A max send consumes the whole spendable balance, so the fee it pays is
/// exactly the difference. No change output, nothing stranded.
#[test]
fn the_maximum_leaves_no_change() {
    let utxos = vec![ordinary("a", 0, 10_000_000), ordinary("b", 1, 3_000_000)];
    let w = wallet_with(utxos.clone());

    let spendable = w.get_transparent_balance();
    let max = max_sendable_transparent(&w, 1);

    assert_eq!(
        max + build(utxos, &recipients(max)).unwrap().fee,
        spendable,
        "amount plus the fee actually paid must account for every spendable sat"
    );
}

/// The regression the tester hit: delegated and immature coins inflate a
/// hand-rolled sum, and the difference is exactly what the builder refuses.
#[test]
fn delegated_and_immature_coins_are_not_offered() {
    let utxos = vec![
        ordinary("a", 0, 10_000_000),
        delegated("b", 1, 300_000_000),
        coinstake("c", 2, 50_000_000, 19),
    ];
    let w = wallet_with(utxos.clone());

    let naive: u64 = w.unspent_utxos.iter().map(|u| u.amount).sum();
    let max = max_sendable_transparent(&w, 1);

    assert!(max < 10_000_000, "the fee must come out of the one spendable output");
    assert!(
        max < naive - 350_000_000,
        "max {max} must exclude the delegated 300000000 and immature 50000000 sat, not just the fee"
    );

    // And the inflated figure really would have been refused.
    build(utxos, &recipients(naive))
        .expect_err("summing the raw UTXO list must not produce a spendable amount");
}

/// A coinstake that has matured is ordinary again, and rejoins the maximum.
#[test]
fn maturity_releases_coins_back_into_the_maximum() {
    let immature = vec![ordinary("a", 0, 10_000_000), coinstake("c", 2, 5_000_000, 100)];
    let mature = vec![ordinary("a", 0, 10_000_000), coinstake("c", 2, 5_000_000, 101)];

    let before = max_sendable_transparent(&wallet_with(immature), 1);
    let after = max_sendable_transparent(&wallet_with(mature.clone()), 1);

    assert!(before < 10_000_000, "100 confirmations is one short: still held back");
    assert!(after > 14_000_000, "101 confirmations releases it");

    build(mature, &recipients(after)).expect("the released figure must still be buildable");
}

/// Nothing to send is 0, not an error and not a negative-shaped underflow.
#[test]
fn nothing_spendable_is_zero() {
    assert_eq!(max_sendable_transparent(&wallet_with(vec![]), 1), 0);

    let all_delegated = wallet_with(vec![delegated("b", 1, 300_000_000)]);
    assert_eq!(max_sendable_transparent(&all_delegated, 1), 0);

    let all_immature = wallet_with(vec![coinstake("c", 2, 50_000_000, 3)]);
    assert_eq!(max_sendable_transparent(&all_immature, 1), 0);

    // A balance the fee would swallow whole.
    let tiny = wallet_with(vec![ordinary("a", 0, 1_000)]);
    assert_eq!(max_sendable_transparent(&tiny, 1), 0);
}

/// A remainder below the dust threshold is unrelayable, so offering it would
/// send the user into the same "your own UI lied" failure by another route.
#[test]
fn a_dust_sized_maximum_is_reported_as_zero() {
    // Enough to cover the fee (2280 sat for one input and two outputs), but
    // what survives it is under the 5460 sat dust threshold.
    let w = wallet_with(vec![ordinary("a", 0, 7_000)]);

    assert_eq!(max_sendable_transparent(&w, 1), 0, "a dust maximum must read as nothing sendable");

    // Confirm the premise: had we offered it, the builder would have refused.
    let spendable = w.get_transparent_balance();
    let fee = estimate_raw_transparent_fee_to_many(&w, &recipients(1_000)).unwrap();
    assert!(spendable > fee, "the fee alone must not have swallowed the balance");
    assert!(spendable - fee < 5_460, "the remainder must genuinely be dust");
}

/// More recipients means more outputs, means a bigger fee, means a smaller
/// total to divide between them.
#[test]
fn more_recipients_lower_the_maximum() {
    let utxos = vec![ordinary("a", 0, 10_000_000), ordinary("b", 1, 3_000_000)];
    let w = wallet_with(utxos.clone());

    let one = max_sendable_transparent(&w, 1);
    let four = max_sendable_transparent(&w, 4);
    assert!(four < one, "four recipients cost more to pay than one");

    // Split the four-recipient maximum evenly and confirm it builds. The
    // remainder goes to the first recipient so the parts sum exactly.
    let each = four / 4;
    let mut rs = vec![Recipient { address: to_address(), amount: each + four % 4 }];
    rs.extend((0..3).map(|_| Recipient { address: to_address(), amount: each }));
    assert_eq!(rs.iter().map(|r| r.amount).sum::<u64>(), four);

    build(utxos, &rs).expect("the four-recipient maximum must be buildable across four recipients");
}

/// Zero recipients is not a send. Guard the arithmetic rather than the caller.
#[test]
fn zero_recipients_is_zero() {
    let w = wallet_with(vec![ordinary("a", 0, 10_000_000)]);
    assert_eq!(max_sendable_transparent(&w, 0), 0);
}

/// The shield variant prices Sapling outputs, so it differs from the
/// transparent one, but applies the same filter.
#[test]
fn shielding_has_its_own_maximum_and_the_same_filter() {
    let w = wallet_with(vec![ordinary("a", 0, 10_000_000), delegated("b", 1, 300_000_000)]);

    let max = max_shieldable_transparent(&w);
    assert!(max > 0);
    assert!(max < 10_000_000, "delegated coins must not be shieldable either");
    assert_ne!(max, max_sendable_transparent(&w, 1), "a shielding fee is not a transparent one");
}

/// Uneconomical inputs make the figure conservative, never optimistic: the
/// direction where the builder still says yes.
#[test]
fn a_wallet_full_of_tiny_outputs_still_builds() {
    let mut utxos = vec![ordinary("a", 0, 10_000_000)];
    utxos.extend((0..40).map(|i| ordinary("b", i, 2_000)));

    let max = max_sendable_transparent(&wallet_with(utxos.clone()), 1);
    assert!(max > 0);
    build(utxos, &recipients(max))
        .expect("a maximum computed over uneconomical inputs must still build");
}
