//! Every built transaction must pay at least the network's relay minimum.
//!
//! PIVX charges the minimum against the **actual serialized size**, at 10
//! satoshis per byte. The crate's fee model approximates that size from
//! component counts, and an approximation that comes in under the real thing
//! produces a transaction a node rejects outright.
//!
//! That is not hypothetical: `withdrawColdStakeKeepingRest` shipped a model
//! that budgeted a 34-byte P2PKH change output while actually emitting a
//! 60-byte P2CS one, and mainnet answered
//! `insufficient fee: 2290 < 2520`. Local tests all passed, because none of
//! them compared the fee to the bytes.
//!
//! So this file does exactly that, for every builder, across shapes that vary
//! the thing the model has to guess: input count, output count, and output
//! script size.

mod common;

use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_from_utxos_to_many,
    create_raw_transparent_transaction_to_many,
};
use pivx_wallet_kit::transparent::coldstake::{
    ColdStakeVariant, WithdrawalChange, build_p2cs_script, create_coldstake_withdrawal,
    create_coldstake_withdrawal_with_change, create_delegation_transaction,
    encode_staking_address, owner_hash_from_seed,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// `minRelayTxFee` in satoshis per byte, as PIVX applies it to the serialized
/// transaction.
const MIN_RELAY_SAT_PER_BYTE: u64 = 10;

const STAKER: [u8; 20] = [0xAA; 20];
const COIN: u64 = 100_000_000;

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn owner() -> [u8; 20] {
    owner_hash_from_seed(&seed(), 0, 0).unwrap()
}

fn to_address() -> String {
    pivx_wallet_kit::keys::get_transparent_address(TEST_MNEMONIC).unwrap()
}

fn staking_addr() -> String {
    encode_staking_address(&STAKER)
}

fn utxo(letter: &str, vout: u32, amount: u64) -> SerializedUTXO {
    SerializedUTXO { txid: letter.repeat(64), vout, amount, script: String::new(), height: 5_000_000, ..Default::default() }
}

fn delegated(letter: &str, vout: u32, amount: u64) -> SerializedUTXO {
    let script = build_p2cs_script(&STAKER, &owner(), ColdStakeVariant::Lof);
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

/// The assertion this whole file exists for.
fn assert_fee_covers_size(label: &str, txhex: &str, fee: u64) {
    let bytes = simd::hex::hex_string_to_bytes(txhex).len() as u64;
    let minimum = bytes * MIN_RELAY_SAT_PER_BYTE;
    assert!(
        fee >= minimum,
        "{label}: fee {fee} sat is below the relay minimum for {bytes} bytes ({minimum} sat): \
         a node would reject this with `insufficient fee: {fee} < {minimum}`"
    );
}

#[test]
fn transparent_sends_cover_the_relay_minimum() {
    for recipients in 1..=6usize {
        for utxo_count in 1..=3usize {
            let utxos: Vec<SerializedUTXO> =
                (0..utxo_count).map(|i| utxo("a", i as u32, 50 * COIN)).collect();
            let rs: Vec<Recipient> = (0..recipients)
                .map(|_| Recipient { address: to_address(), amount: COIN })
                .collect();

            let mut w = wallet_with(utxos);
            let Ok(r) = create_raw_transparent_transaction_to_many(&mut w, &seed(), &rs) else {
                continue;
            };
            assert_fee_covers_size(&format!("{recipients} recipients / {utxo_count} utxos"), &r.txhex, r.fee);
        }
    }
}

#[test]
fn from_utxos_sends_cover_the_relay_minimum() {
    for utxo_count in 1..=5usize {
        let utxos: Vec<SerializedUTXO> =
            (0..utxo_count).map(|i| utxo("b", i as u32, 20 * COIN)).collect();
        let r = create_raw_transparent_transaction_from_utxos_to_many(
            &seed(),
            0,
            0,
            &utxos,
            &[Recipient { address: to_address(), amount: 10 * COIN }],
        )
        .unwrap();
        assert_fee_covers_size(&format!("from-utxos, {utxo_count} inputs"), &r.txhex, r.fee);
    }
}

/// Delegations vary output count via the 500 PIV split, which is exactly the
/// kind of shape the flat model has to guess at.
#[test]
fn delegations_cover_the_relay_minimum() {
    for amount_piv in [1u64, 5, 499, 500, 501, 1_000, 1_200, 2_500] {
        let amount = amount_piv * COIN;
        let mut w = wallet_with(vec![utxo("c", 0, 5_000 * COIN)]);
        let r = create_delegation_transaction(
            &mut w, &seed(), &staking_addr(), amount, ColdStakeVariant::Lof,
        )
        .unwrap_or_else(|e| panic!("{amount_piv} PIV: {e}"));
        assert_fee_covers_size(&format!("delegate {amount_piv} PIV"), &r.txhex, r.fee);
    }
}

/// Plain withdrawals: P2CS inputs, P2PKH outputs.
#[test]
fn plain_withdrawals_cover_the_relay_minimum() {
    for n in 1..=4usize {
        let utxos: Vec<SerializedUTXO> =
            (0..n).map(|i| delegated("d", i as u32, 100 * COIN)).collect();
        let r = create_coldstake_withdrawal(
            &seed(), 0, 0, &utxos, &to_address(), 50 * COIN,
        )
        .unwrap();
        assert_fee_covers_size(&format!("plain withdrawal, {n} inputs"), &r.txhex, r.fee);
    }
}

/// The regression. Re-delegated change is a 51-byte P2CS script, not a 25-byte
/// P2PKH one: the case that was under-charged on mainnet.
#[test]
fn withdrawals_with_delegated_change_cover_the_relay_minimum() {
    let staking = staking_addr();

    for n in 1..=4usize {
        for withdraw_piv in [10u64, 50, 200] {
            let utxos: Vec<SerializedUTXO> =
                (0..n).map(|i| delegated("e", i as u32, 500 * COIN)).collect();

            let r = create_coldstake_withdrawal_with_change(
                &seed(),
                0,
                0,
                &utxos,
                &to_address(),
                withdraw_piv * COIN,
                WithdrawalChange::Delegate(&staking),
            )
            .unwrap();

            assert_fee_covers_size(
                &format!("delegated-change withdrawal, {n} inputs, withdraw {withdraw_piv} PIV"),
                &r.txhex,
                r.fee,
            );
        }
    }
}

/// The shape mainnet rejected: one 500 PIV delegation in, 200 PIV out,
/// remainder re-delegated. That transaction was 252 bytes and needed 2520 sat;
/// the builder offered 2290.
///
/// The size is asserted as a range rather than a constant because DER
/// signatures are 70-72 bytes depending on the r and s values, so an otherwise
/// identical transaction varies by a couple of bytes between keys. That
/// variance is precisely why the fee model needs headroom per input rather than
/// an exact byte count.
#[test]
fn the_shape_mainnet_rejected_now_pays_enough() {
    let staking = staking_addr();
    let utxos = vec![delegated("f", 0, 500 * COIN)];

    let r = create_coldstake_withdrawal_with_change(
        &seed(), 0, 0, &utxos, &to_address(), 200 * COIN,
        WithdrawalChange::Delegate(&staking),
    )
    .unwrap();

    let bytes = simd::hex::hex_string_to_bytes(&r.txhex).len();
    assert!(
        (250..=254).contains(&bytes),
        "expected roughly the 252-byte mainnet shape, got {bytes}: re-check the arithmetic"
    );
    assert!(
        r.fee >= 2_520,
        "fee {} sat is below the 2520 sat mainnet demanded for this shape",
        r.fee
    );
    assert_fee_covers_size("the mainnet-rejected shape", &r.txhex, r.fee);
}

/// Signature length varies, so the model must keep headroom on *every* input
/// rather than sizing to a lucky signature. Builds the same shape from many
/// different keys and checks the fee covers each result.
#[test]
fn fee_holds_across_signature_length_variation() {
    let mut sizes = std::collections::HashSet::new();

    for index in 0..40u32 {
        let hash = owner_hash_from_seed(&seed(), 0, index).unwrap();
        let script = build_p2cs_script(&STAKER, &hash, ColdStakeVariant::Lof);
        let utxos = vec![SerializedUTXO {
            txid: "ab".repeat(32),
            vout: 0,
            amount: 500 * COIN,
            script: simd::hex::bytes_to_hex_string(&script),
            height: 5_000_000,
            ..Default::default()
        }];

        let r = create_coldstake_withdrawal_with_change(
            &seed(), 0, index, &utxos, &to_address(), 200 * COIN,
            WithdrawalChange::Delegate(&staking_addr()),
        )
        .unwrap();

        sizes.insert(simd::hex::hex_string_to_bytes(&r.txhex).len());
        assert_fee_covers_size(&format!("hd slot 0/{index}"), &r.txhex, r.fee);
    }

    assert!(
        sizes.len() > 1,
        "expected signature length to vary across keys; if it never does, this test is not \
         exercising what it claims"
    );
}

/// Delegated change costs more than plain change, and the difference is the
/// P2CS output surcharge, not a coincidence of rounding.
#[test]
fn delegated_change_costs_the_p2cs_surcharge_more() {
    let staking = staking_addr();
    let utxos = vec![delegated("e", 0, 500 * COIN)];

    let plain = create_coldstake_withdrawal(&seed(), 0, 0, &utxos, &to_address(), 200 * COIN)
        .unwrap();
    let delegated_change = create_coldstake_withdrawal_with_change(
        &seed(), 0, 0, &utxos, &to_address(), 200 * COIN,
        WithdrawalChange::Delegate(&staking),
    )
    .unwrap();

    assert_eq!(
        delegated_change.fee - plain.fee,
        (pivx_wallet_kit::fees::P2CS_OUTPUT_EXTRA_BYTES as u64) * MIN_RELAY_SAT_PER_BYTE,
        "the extra cost should be exactly the P2CS output surcharge"
    );
}
