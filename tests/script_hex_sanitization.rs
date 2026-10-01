//! Caller-supplied `scriptPubKey` hex, on the assumption that none of it is
//! trustworthy.
//!
//! UTXOs arrive from block explorers, and through `setUtxos` straight from a
//! JavaScript caller. `hex_string_to_bytes` is an unchecked SIMD decoder, so
//! whatever reaches it is decoded as though it were well formed. The failure
//! that matters is not a panic but a script classified on bytes nobody
//! supplied, because that classification decides which outputs are spendable.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::transparent::builder::{Recipient, create_raw_transparent_transaction_to_many};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed_bytes() -> Vec<u8> {
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

fn good_address() -> String {
    keys::get_transparent_address(TEST_MNEMONIC).unwrap()
}

#[test]
fn absurd_utxo_script_data_does_not_crash_selection() {
    let to = good_address();

    let hostile_scripts = [
        String::new(),
        "zz".repeat(32),              // not hex
        "ab".repeat(10_000),          // enormous
        "a".to_string(),              // odd length
        "00".to_string(),             // trivially short
        "ff".repeat(520),             // past the script size limit
    ];

    for s in hostile_scripts {
        let mut u = utxo("a", 0, 10_000_000);
        u.script = s.clone();
        let mut w = wallet_with(vec![u]);
        let rs = vec![Recipient { address: to.clone(), amount: 1_000_000 }];
        // Must not panic. Success or a clear error are both fine.
        let _ = create_raw_transparent_transaction_to_many(&mut w, &seed_bytes(), &rs);
    }
}

/// Found by `absurd_utxo_script_data_does_not_crash_selection`.
///
/// `hex_string_to_bytes` is an unchecked SIMD decoder: odd-length input trips a
/// debug assertion and, in release, silently drops the trailing nibble so the
/// script is classified on bytes nobody supplied. `parse_blockbook_utxos`
/// guarded against it at ingest, but `setUtxos` takes entries straight from a
/// JS caller and the docs specifically tell cold-staking consumers to join
/// `script` on themselves from a second explorer call, which never passes
/// through that guard.
#[test]
fn malformed_script_hex_is_reduced_to_unknown_not_decoded() {
    for raw in ["a", "abc", "zz", "xyz!", "ABCDEF0", "\u{feff}00"] {
        assert_eq!(
            wallet::sanitize_script_hex(raw),
            "",
            "{raw:?} is not decodable hex and must read as unknown"
        );
    }
    // Well-formed hex survives, normalised to lower case.
    assert_eq!(wallet::sanitize_script_hex("AABB"), "aabb");
    assert_eq!(wallet::sanitize_script_hex(""), "");
}

#[test]
fn a_utxo_carrying_malformed_script_hex_is_not_classified_as_delegated() {
    // The classification decides whether an output is excluded from ordinary
    // spending, so it must not run on garbage.
    for raw in ["a", "zz", "abc"] {
        let mut u = utxo("a", 0, 10_000_000);
        u.script = raw.to_string();
        assert!(
            !wallet::is_delegated_utxo(&u),
            "{raw:?} must read as unknown, not be decoded into a classification"
        );
    }
}
