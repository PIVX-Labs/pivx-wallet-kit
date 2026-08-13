//! The persisted seed and mnemonic must not share a keystream.
//!
//! `encrypt_secrets` protects two secrets under one key. Both were previously
//! run through a SHA256-CTR keystream that started its counter at zero on every
//! call, so the seed and the first 32 bytes of the mnemonic were XORed against
//! the *same* bytes. XORing the two stored ciphertexts cancels the keystream
//! and yields `seed XOR mnemonic[0..32]` to anyone holding the file, with no
//! key involved: a two-time pad.
//!
//! From the file alone that is not a practical break: the mnemonic's first 32
//! characters have 2^67.3 possibilities over the BIP39 English list, and each
//! costs a ZIP32 derivation to test against the plaintext `extfvk`. What it
//! destroys is the margin. Two situations that should be survivable become
//! total compromise of the shield seed with no search at all: a mnemonic prefix
//! leaking by some other route, and a second secret known under the same key,
//! which yields the keystream and so every other wallet encrypted with it. The
//! intended native key is machine-derived, so wallets on one machine share it.
//!
//! Bounded to the shield side: the stored seed is `bip39_seed[..32]`, which
//! drives Sapling but not the BIP32 transparent tree.
//!
//! A per-encryption nonce and a per-field domain tag fix both. These tests pin
//! the properties rather than the construction, so a future cipher change has
//! to keep them.

use pivx_wallet_kit::simd;
use pivx_wallet_kit::wallet::{self, WalletData};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// The persisted ciphertexts, as a consumer would find them on disk.
fn ciphertexts(json: &str) -> (Vec<u8>, Vec<u8>) {
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    let seed: Vec<u8> = v["seed"]
        .as_array()
        .expect("seed is serialized as a byte array")
        .iter()
        .map(|x| x.as_u64().unwrap() as u8)
        .collect();
    let mnemonic = simd::hex::hex_string_to_bytes(v["mnemonic"].as_str().unwrap());
    (seed, mnemonic)
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

#[test]
fn the_seed_and_mnemonic_do_not_share_a_keystream() {
    let w = wallet::import_wallet(MNEMONIC, 5_000_000).unwrap();
    let json = wallet::serialize_encrypted(&w, &key(0x42)).unwrap();
    let (ct_seed, ct_mnemonic) = ciphertexts(&json);

    // Under a shared keystream this is exactly `seed XOR mnemonic[0..32]`, and
    // the mnemonic's bytes are known ASCII from a 2048-word list.
    let leak = xor(&ct_seed, &ct_mnemonic[..32]);

    let restored = wallet::deserialize_encrypted(&json, &key(0x42)).unwrap();
    let plain_seed = seed_of(&restored);
    let expected_if_broken = xor(&plain_seed, &MNEMONIC.as_bytes()[..32]);

    assert_ne!(
        leak, expected_if_broken,
        "XORing the two ciphertexts recovers seed XOR mnemonic: the fields share a keystream"
    );
}

#[test]
fn two_wallets_under_one_key_do_not_share_a_keystream() {
    // The native path derives the key from the machine id, so this is the
    // normal case there, not an exotic one.
    let a = wallet::import_wallet(MNEMONIC, 5_000_000).unwrap();
    let b = wallet::import_wallet(OTHER_MNEMONIC, 5_000_000).unwrap();
    let shared = key(0x99);

    let ja = wallet::serialize_encrypted(&a, &shared).unwrap();
    let jb = wallet::serialize_encrypted(&b, &shared).unwrap();

    let leak = xor(&ciphertexts(&ja).0, &ciphertexts(&jb).0);
    let expected_if_broken = xor(
        &seed_of(&wallet::deserialize_encrypted(&ja, &shared).unwrap()),
        &seed_of(&wallet::deserialize_encrypted(&jb, &shared).unwrap()),
    );

    assert_ne!(
        leak, expected_if_broken,
        "two wallets under one key XOR to leak seedA XOR seedB"
    );
}

#[test]
fn encrypting_the_same_wallet_twice_gives_different_ciphertext() {
    // Without a nonce the output is a pure function of (wallet, key), so an
    // observer can tell that two files are the same wallet, and that a wallet
    // did not change between two backups.
    let w = wallet::import_wallet(MNEMONIC, 5_000_000).unwrap();
    let first = wallet::serialize_encrypted(&w, &key(0x42)).unwrap();
    let second = wallet::serialize_encrypted(&w, &key(0x42)).unwrap();

    assert_ne!(
        ciphertexts(&first).0,
        ciphertexts(&second).0,
        "re-encrypting is byte-identical: there is no nonce"
    );

    // Both must still decrypt to the same wallet.
    for json in [&first, &second] {
        let restored = wallet::deserialize_encrypted(json, &key(0x42)).unwrap();
        assert_eq!(restored.get_mnemonic(), MNEMONIC);
    }
}

#[test]
fn the_round_trip_still_works_and_the_wrong_key_still_fails() {
    let w = wallet::import_wallet(MNEMONIC, 5_000_000).unwrap();
    let json = wallet::serialize_encrypted(&w, &key(0x42)).unwrap();

    let restored = wallet::deserialize_encrypted(&json, &key(0x42)).unwrap();
    assert_eq!(restored.get_mnemonic(), MNEMONIC);
    assert_eq!(restored.extfvk, w.extfvk);
    assert_eq!(seed_of(&restored), seed_of(&w));

    // `WalletData` has no `Debug` (it carries secrets), so unwrap_err is out.
    let err = match wallet::deserialize_encrypted(&json, &key(0x43)) {
        Ok(_) => panic!("a wrong key decrypted the wallet"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("wrong key"),
        "a wrong key must be reported, not silently produce garbage: {err}"
    );
}

#[test]
fn a_nonce_is_persisted_and_is_gone_again_after_decrypting() {
    // The invariant the reader depends on: a nonce is present exactly when the
    // secret fields hold ciphertext.
    let w = wallet::import_wallet(MNEMONIC, 5_000_000).unwrap();
    assert!(w.cipher_nonce.is_none(), "a fresh wallet holds plaintext");

    let json = wallet::serialize_encrypted(&w, &key(0x42)).unwrap();
    let on_disk: serde_json::Value = serde_json::from_str(&json).unwrap();
    let nonce = on_disk["cipherNonce"].as_str().expect("no nonce was persisted");
    assert_eq!(
        simd::hex::hex_string_to_bytes(nonce).len(),
        wallet::CIPHER_NONCE_LEN
    );

    let restored = wallet::deserialize_encrypted(&json, &key(0x42)).unwrap();
    assert!(
        restored.cipher_nonce.is_none(),
        "the nonce outlived the ciphertext it belonged to"
    );
}

#[test]
fn a_wallet_encrypted_before_the_nonce_existed_still_opens() {
    // Backward compatibility, built by hand in the legacy format: one keystream
    // from `crypt`, no nonce field. Any wallet already persisted by a consumer
    // looks like this, and refusing it would strand funds behind a file the kit
    // itself wrote.
    let k = key(0x42);
    let w = wallet::import_wallet(MNEMONIC, 5_000_000).unwrap();

    let mut legacy: serde_json::Value = serde_json::to_value(&w).unwrap();
    let legacy_seed = wallet::crypt(&seed_of(&w), &k);
    let legacy_mnemonic = wallet::crypt(MNEMONIC.as_bytes(), &k);
    legacy["seed"] = serde_json::json!(legacy_seed);
    legacy["mnemonic"] = serde_json::json!(simd::hex::bytes_to_hex_string(&legacy_mnemonic));
    legacy.as_object_mut().unwrap().remove("cipherNonce");

    let restored = wallet::deserialize_encrypted(&legacy.to_string(), &k)
        .expect("a legacy-format wallet must still decrypt");
    assert_eq!(restored.get_mnemonic(), MNEMONIC);
    assert_eq!(seed_of(&restored), seed_of(&w));

    // A wrong key against a legacy file must still be caught by the extfvk
    // check rather than silently yielding garbage.
    assert!(wallet::deserialize_encrypted(&legacy.to_string(), &key(0x43)).is_err());
}

#[test]
fn re_saving_a_legacy_wallet_writes_it_in_the_new_format() {
    // The migration path: open old, save new, and the leak is gone without the
    // consumer doing anything.
    let k = key(0x42);
    let w = wallet::import_wallet(MNEMONIC, 5_000_000).unwrap();

    let mut legacy: serde_json::Value = serde_json::to_value(&w).unwrap();
    legacy["seed"] = serde_json::json!(wallet::crypt(&seed_of(&w), &k));
    legacy["mnemonic"] =
        serde_json::json!(simd::hex::bytes_to_hex_string(&wallet::crypt(MNEMONIC.as_bytes(), &k)));
    legacy.as_object_mut().unwrap().remove("cipherNonce");

    let opened = wallet::deserialize_encrypted(&legacy.to_string(), &k).unwrap();
    let resaved = wallet::serialize_encrypted(&opened, &k).unwrap();

    let v: serde_json::Value = serde_json::from_str(&resaved).unwrap();
    assert!(v["cipherNonce"].is_string(), "the re-saved wallet has no nonce");

    let (ct_seed, ct_mnemonic) = ciphertexts(&resaved);
    let leak = xor(&ct_seed, &ct_mnemonic[..32]);
    let expected_if_broken = xor(&seed_of(&w), &MNEMONIC.as_bytes()[..32]);
    assert_ne!(leak, expected_if_broken, "the re-saved wallet still leaks");
}

#[test]
fn a_corrupted_nonce_is_reported_rather_than_used() {
    let k = key(0x42);
    let w = wallet::import_wallet(MNEMONIC, 5_000_000).unwrap();
    let json = wallet::serialize_encrypted(&w, &k).unwrap();

    let mut broken: serde_json::Value = serde_json::from_str(&json).unwrap();
    broken["cipherNonce"] = serde_json::json!("abcd");

    let err = match wallet::deserialize_encrypted(&broken.to_string(), &k) {
        Ok(_) => panic!("a corrupted nonce was used anyway"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("nonce"),
        "a truncated nonce must be named, not silently padded: {err}"
    );
}

/// The plaintext seed of a decrypted wallet, via its serialized form (the field
/// is crate-private).
fn seed_of(w: &WalletData) -> Vec<u8> {
    serde_json::to_value(w).unwrap()["seed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u8)
        .collect()
}
