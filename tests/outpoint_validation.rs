//! A malformed txid must never reach a signature.
//!
//! A transaction id arrives as a hex string from an explorer or, on the
//! caller-supplied paths, from the consumer directly. It is decoded with
//! `hex_string_to_bytes`, the crate's unchecked SIMD decoder, and written
//! straight into the prevout. Nothing about that decode is fallible: a non-hex
//! character becomes a garbage byte and an odd-length string drops its trailing
//! nibble, both silently.
//!
//! The consequences differ by path and neither is loud:
//!
//!  * **Raw v1 (transparent).** The prevout is written at whatever length came
//!    back. At 31 or 33 bytes every subsequent byte of the transaction shifts,
//!    so the emitted hex is not a transaction at all. The sighash is computed
//!    over the same wrong bytes, so it is self-consistent garbage and nothing
//!    internal disagrees.
//!  * **Raw v1, still 32 bytes.** A non-hex txid of the right length decodes to
//!    32 garbage bytes, giving a *structurally valid* transaction that spends an
//!    outpoint which does not exist. The node reports missing inputs, which
//!    reads like a stale UTXO set rather than bad data.
//!  * **v3 (shielding).** `copy_from_slice` into a `[u8; 32]` panics on a length
//!    mismatch. In wasm a panic poisons the module, so the wallet is dead for
//!    the rest of the page's life rather than merely unable to build this one
//!    transaction.
//!
//! The repo's own tests were building garbage prevouts from `"h".repeat(64)`
//! until the guard added here caught them, which is the whole argument for
//! having it: nothing else in the system was positioned to notice.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_from_utxos,
    create_raw_transparent_transaction_to_many, estimate_raw_transparent_fee_to_many,
};
use pivx_wallet_kit::transparent::coldstake::{
    ColdStakeVariant, build_p2cs_script, create_coldstake_withdrawal,
    create_delegation_transaction, encode_staking_address, owner_hash_from_seed,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn to_address() -> String {
    keys::pubkey_to_pivx_address(&[0x02; 33])
}

fn utxo(txid: &str, amount: u64) -> SerializedUTXO {
    SerializedUTXO {
        txid: txid.to_string(),
        vout: 0,
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

fn one(amount: u64) -> Vec<Recipient> {
    vec![Recipient { address: to_address(), amount }]
}

/// Every shape of txid that is not 32 bytes of hex, with why it is plausible.
fn malformed() -> Vec<(&'static str, String)> {
    vec![
        ("odd length", "a".repeat(63)),
        ("truncated", "abcd".to_string()),
        ("empty", String::new()),
        ("0x-prefixed", format!("0x{}", "ab".repeat(32))),
        ("non-hex, right length", "z".repeat(64)),
        ("non-hex letter", "h".repeat(64)),
        ("too long", "ab".repeat(33)),
        ("whitespace", format!(" {} ", "ab".repeat(31))),
    ]
}

#[test]
fn a_well_formed_txid_is_accepted_in_either_case() {
    // Uppercase hex decodes identically, so it must not be rejected: some
    // explorers and hand-built sets use it.
    for txid in ["ab".repeat(32), "AB".repeat(32), "aBcD".repeat(16)] {
        create_raw_transparent_transaction_from_utxos(
            &seed(),
            0,
            0,
            &[utxo(&txid, 500_000)],
            &to_address(),
            100_000,
        )
        .unwrap_or_else(|e| panic!("valid txid {txid} was rejected: {e}"));
    }
}

#[test]
fn the_caller_supplied_builder_refuses_every_malformed_txid() {
    for (why, txid) in malformed() {
        let err = create_raw_transparent_transaction_from_utxos(
            &seed(),
            0,
            0,
            &[utxo(&txid, 500_000)],
            &to_address(),
            100_000,
        )
        .expect_err(&format!("{why}: a malformed txid was signed instead of refused"));
        assert!(
            err.to_string().contains("malformed txid"),
            "{why}: wrong error, got {err}"
        );
    }
}

#[test]
fn the_wallet_state_builder_refuses_every_malformed_txid() {
    // Reached via `setUtxos`, which takes a caller-built set and applies none
    // of the parser's screening.
    for (why, txid) in malformed() {
        let mut w = wallet_with(vec![utxo(&txid, 500_000)]);
        let err = create_raw_transparent_transaction_to_many(&mut w, &seed(), &one(100_000))
            .expect_err(&format!("{why}: a malformed txid was signed instead of refused"));
        assert!(
            err.to_string().contains("malformed txid"),
            "{why}: wrong error, got {err}"
        );
    }
}

#[test]
fn the_estimator_refuses_what_the_builder_refuses() {
    // The estimator shares the selector, so it has to fail for the same reason
    // rather than quoting a fee for a transaction that cannot be built.
    let w = wallet_with(vec![utxo(&"z".repeat(64), 500_000)]);
    let err = estimate_raw_transparent_fee_to_many(&w, &one(100_000)).unwrap_err();
    assert!(err.to_string().contains("malformed txid"), "got {err}");
}

#[test]
fn delegation_refuses_a_malformed_txid() {
    let mut w = wallet_with(vec![utxo(&"z".repeat(64), 900_000_000)]);
    let err = create_delegation_transaction(
        &mut w,
        &seed(),
        &encode_staking_address(&[0xAA; 20]),
        500_000_000,
        ColdStakeVariant::Lof,
    )
    .unwrap_err();
    assert!(err.to_string().contains("malformed txid"), "got {err}");
}

#[test]
fn withdrawal_refuses_a_malformed_txid() {
    let owner = owner_hash_from_seed(&seed(), 0, 0).unwrap();
    let script = build_p2cs_script(&[0xAA; 20], &owner, ColdStakeVariant::Lof);
    let delegated = SerializedUTXO {
        script: simd::hex::bytes_to_hex_string(&script),
        ..utxo(&"a".repeat(63), 900_000_000)
    };
    let err = create_coldstake_withdrawal(
        &seed(),
        0,
        0,
        &[delegated],
        &to_address(),
        400_000_000,
    )
    .unwrap_err();
    assert!(err.to_string().contains("malformed txid"), "got {err}");
}

#[test]
fn the_parser_drops_malformed_txids_at_ingest() {
    // The first line of defence, and the quiet one: a bad entry never reaches a
    // balance. The builder guard is the loud backstop for sets that bypass it.
    for (why, txid) in malformed() {
        let raw = vec![serde_json::json!({
            "txid": txid,
            "vout": 0,
            "value": "500000",
            "height": 5_000_000,
        })];
        assert!(
            wallet::parse_blockbook_utxos(&raw).is_empty(),
            "{why}: a malformed txid was ingested"
        );
    }

    // The mirror: a good one still gets through.
    let raw = vec![serde_json::json!({
        "txid": "ab".repeat(32),
        "vout": 0,
        "value": "500000",
        "height": 5_000_000,
    })];
    assert_eq!(wallet::parse_blockbook_utxos(&raw).len(), 1);
}

#[test]
fn a_valid_transaction_parses_back_to_exactly_its_own_length() {
    // The property a malformed txid breaks: the emitted bytes have to be a
    // transaction. A short or long prevout shifts everything after it, so
    // walking the structure lands somewhere other than the end of the buffer.
    let result = create_raw_transparent_transaction_from_utxos(
        &seed(),
        0,
        0,
        &[utxo(&"ab".repeat(32), 500_000)],
        &to_address(),
        100_000,
    )
    .unwrap();
    let bytes = simd::hex::hex_string_to_bytes(&result.txhex);

    let mut p = 4usize; // version
    let n_in = bytes[p] as usize;
    p += 1;
    for _ in 0..n_in {
        p += 32 + 4; // prevout: txid + vout
        let script_len = bytes[p] as usize;
        p += 1 + script_len + 4; // scriptSig + sequence
    }
    let n_out = bytes[p] as usize;
    p += 1;
    for _ in 0..n_out {
        p += 8; // value
        let script_len = bytes[p] as usize;
        p += 1 + script_len;
    }
    p += 4; // locktime

    assert_eq!(
        p,
        bytes.len(),
        "the transaction does not parse to its own length: a length prefix disagrees \
         with the bytes that follow it"
    );
}

// ---------------------------------------------------------------------------
// Explorer field coercion
// ---------------------------------------------------------------------------

fn parse_one(entry: serde_json::Value) -> Vec<SerializedUTXO> {
    wallet::parse_blockbook_utxos(&[entry])
}

#[test]
fn vout_is_read_as_a_string_or_a_number() {
    // `value` was already read both ways because Blockbook revisions differ.
    // `vout` decides which output is spent, so a string form silently becoming
    // 0 would sign for the wrong outpoint of the right transaction: a real
    // output, just not the one that was selected.
    for form in [serde_json::json!(3), serde_json::json!("3")] {
        let got = parse_one(serde_json::json!({
            "txid": "ab".repeat(32), "vout": form, "value": "500000", "height": 5_000_000,
        }));
        assert_eq!(got.len(), 1, "entry was dropped");
        assert_eq!(got[0].vout, 3, "vout did not survive as 3");
    }
}

#[test]
fn an_unparseable_vout_drops_the_entry_rather_than_defaulting_to_zero() {
    for bad in [
        serde_json::json!("not-a-number"),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!(null),
    ] {
        let got = parse_one(serde_json::json!({
            "txid": "ab".repeat(32), "vout": bad, "value": "500000", "height": 5_000_000,
        }));
        assert!(got.is_empty(), "an unparseable vout was silently read as 0");
    }
}

#[test]
fn value_and_confirmations_are_read_as_strings_or_numbers() {
    let got = parse_one(serde_json::json!({
        "txid": "ab".repeat(32),
        "vout": 0,
        "value": 500_000,
        "height": "5000000",
        "confirmations": "150",
        "coinstake": true,
    }));
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].amount, 500_000);
    assert_eq!(got[0].height, 5_000_000);
    // A string `confirmations` reading as 0 would hold a long-matured coinstake
    // back forever: safe, but the coins never become spendable and nothing says
    // why. 150 is past the 101 a coinstake needs.
    assert_eq!(got[0].confirmations, 150);
    assert!(got[0].is_mature(), "a coinstake 150 deep should be spendable");
}

#[test]
fn an_absent_vout_still_defaults_to_zero() {
    // Pre-existing behaviour, kept deliberately: absent is not the same as
    // present-and-wrong.
    let got = parse_one(serde_json::json!({
        "txid": "ab".repeat(32), "value": "500000", "height": 5_000_000,
    }));
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].vout, 0);
}
