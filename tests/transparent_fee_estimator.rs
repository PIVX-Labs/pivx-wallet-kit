//! `estimate_raw_transparent_fee_to_many` must never disagree with the builder.
//!
//! The transparent fee depends on how many inputs selection reaches for, which
//! depends on the recipient total — so an estimator doing its own selection
//! could quote a fee the builder then contradicts. Both go through
//! `select_transparent_utxos` for that reason, and these tests pin the
//! agreement rather than trusting it.

use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_to_many, estimate_raw_transparent_fee_to_many,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn wallet_with(utxos: Vec<SerializedUTXO>) -> WalletData {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = utxos;
    w
}

fn utxo(letter: &str, vout: u32, amount: u64) -> SerializedUTXO {
    SerializedUTXO {
        txid: letter.repeat(64),
        vout,
        amount,
        script: String::new(),
        height: 5_000_000,
    }
}

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC)
        .unwrap()
        .to_seed("")
        .to_vec()
}

fn payee(index: u32) -> String {
    pivx_wallet_kit::keys::transparent_key_from_bip39_seed(&seed(), 0, 100 + index)
        .unwrap()
        .0
}

fn recipients(n: u32, each: u64) -> Vec<Recipient> {
    (0..n)
        .map(|i| Recipient { address: payee(i), amount: each })
        .collect()
}

/// Across recipient counts and UTXO shapes, the quoted fee must equal the
/// charged fee exactly.
#[test]
fn estimate_matches_what_the_builder_charges() {
    for n in 1..=8u32 {
        for utxo_count in 1..=4usize {
            let utxos: Vec<SerializedUTXO> = (0..utxo_count)
                .map(|i| utxo("a", i as u32, 50_000_000))
                .collect();
            let rs = recipients(n, 1_000_000);

            let mut w = wallet_with(utxos);
            let quoted = match estimate_raw_transparent_fee_to_many(&w, &rs) {
                Ok(f) => f,
                Err(_) => continue, // insufficient funds for this shape
            };
            let built =
                create_raw_transparent_transaction_to_many(&mut w, &seed(), &rs).unwrap();

            assert_eq!(
                quoted, built.fee,
                "{n} recipients / {utxo_count} utxos: quoted {quoted} but charged {}",
                built.fee
            );
        }
    }
}

/// The fee must track the number of inputs selection actually needs, not just
/// the recipient count. A larger send that forces a second UTXO costs more.
#[test]
fn estimate_grows_when_selection_needs_more_inputs() {
    let w = wallet_with(vec![
        utxo("a", 0, 10_000_000),
        utxo("b", 1, 10_000_000),
        utxo("c", 2, 10_000_000),
    ]);

    let one_input = estimate_raw_transparent_fee_to_many(&w, &recipients(1, 5_000_000)).unwrap();
    let two_inputs = estimate_raw_transparent_fee_to_many(&w, &recipients(1, 15_000_000)).unwrap();
    let three_inputs = estimate_raw_transparent_fee_to_many(&w, &recipients(1, 25_000_000)).unwrap();

    assert!(
        one_input < two_inputs && two_inputs < three_inputs,
        "fee should grow with input count: {one_input} / {two_inputs} / {three_inputs}"
    );
}

/// More recipients means more outputs means a higher fee, monotonically.
#[test]
fn estimate_is_monotonic_in_recipient_count() {
    let w = wallet_with(vec![utxo("a", 0, 10_000_000_000)]);
    let mut previous = 0u64;
    for n in 1..=20u32 {
        let fee = estimate_raw_transparent_fee_to_many(&w, &recipients(n, 1_000_000)).unwrap();
        assert!(fee > previous, "fee did not grow from {} to {n} recipients", n - 1);
        previous = fee;
    }
}

/// The estimator must reject exactly what the builder rejects. A quote that
/// succeeds where the send fails is worse than no quote at all.
#[test]
fn estimate_rejects_everything_the_builder_rejects() {
    let good = payee(0);

    let cases: Vec<(&str, Vec<Recipient>, Vec<SerializedUTXO>)> = vec![
        ("empty recipient list", vec![], vec![utxo("a", 0, 50_000_000)]),
        (
            "zero amount",
            vec![Recipient { address: good.clone(), amount: 0 }],
            vec![utxo("a", 0, 50_000_000)],
        ),
        (
            "summed overflow",
            vec![
                Recipient { address: good.clone(), amount: u64::MAX },
                Recipient { address: good.clone(), amount: 1 },
            ],
            vec![utxo("a", 0, 50_000_000)],
        ),
        (
            "malformed address",
            vec![Recipient { address: "not-an-address".into(), amount: 1_000 }],
            vec![utxo("a", 0, 50_000_000)],
        ),
        (
            "insufficient funds",
            vec![Recipient { address: good.clone(), amount: 99_000_000_000 }],
            vec![utxo("a", 0, 50_000_000)],
        ),
        ("no utxos", vec![Recipient { address: good.clone(), amount: 1_000 }], vec![]),
        (
            "duplicate outpoint in the wallet's set",
            vec![Recipient { address: good, amount: 1_000 }],
            vec![utxo("a", 0, 50_000_000), utxo("a", 0, 50_000_000)],
        ),
    ];

    for (name, rs, utxos) in cases {
        let mut w = wallet_with(utxos);
        let estimate_err = estimate_raw_transparent_fee_to_many(&w, &rs).is_err();
        let build_err = create_raw_transparent_transaction_to_many(&mut w, &seed(), &rs).is_err();

        assert!(estimate_err, "{name}: estimator accepted it");
        assert!(build_err, "{name}: builder accepted it");
        assert_eq!(
            estimate_err, build_err,
            "{name}: estimator and builder disagree on acceptability"
        );
    }
}

/// Estimating must not mutate the wallet — a caller may quote several shapes
/// before choosing one.
#[test]
fn estimating_does_not_disturb_the_wallet() {
    let w = wallet_with(vec![utxo("a", 0, 50_000_000), utxo("b", 1, 50_000_000)]);
    let before = w.get_transparent_balance();
    let utxos_before = w.unspent_utxos.len();

    for n in 1..=5u32 {
        let _ = estimate_raw_transparent_fee_to_many(&w, &recipients(n, 1_000_000));
    }

    assert_eq!(w.get_transparent_balance(), before);
    assert_eq!(w.unspent_utxos.len(), utxos_before);
}
