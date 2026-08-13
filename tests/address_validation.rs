//! Address validation for the transparent script builder.
//!
//! Every one of these cases was accepted before validation was added, and each
//! one sends funds somewhere they cannot be recovered from. They are grouped
//! here because they share a root cause: `address_to_p2pkh_script` decoded
//! base58 without verifying the Base58Check checksum or the version byte, so
//! anything that happened to decode to 25 bytes was treated as a spendable
//! PIVX P2PKH destination.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::params::PIVX_PUBKEY_PREFIX;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn valid_address() -> String {
    keys::get_transparent_address(TEST_MNEMONIC).unwrap()
}

/// Base58Check-encode a 21-byte version+hash payload.
fn b58check(payload: &[u8]) -> String {
    let checksum = Sha256::digest(Sha256::digest(payload));
    let mut full = payload.to_vec();
    full.extend_from_slice(&checksum[..4]);
    bs58::encode(full).into_string()
}

/// Re-encode raw 25 bytes without recomputing the checksum, so a corrupted
/// address can be produced.
fn b58_raw(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

fn decode_raw(address: &str) -> Vec<u8> {
    bs58::decode(address).into_vec().unwrap()
}

/// A valid address must still work: the validation must not be so strict it
/// rejects real addresses.
#[test]
fn accepts_a_valid_address() {
    let addr = valid_address();
    let script = keys::address_to_p2pkh_script(&addr).expect("valid address must be accepted");

    assert_eq!(script.len(), 25);
    assert_eq!(&script[..3], &[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 PUSH20
    assert_eq!(&script[23..], &[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
    assert_eq!(&script[3..23], &decode_raw(&addr)[1..21]);
}

/// A typo in the *payload* is the case that costs money: it silently changes
/// the pubkey hash, so the output pays a hash nobody holds a key for. Observed
/// pre-fix: `c48ec77a11...` became `c48ec77a10...` and was accepted.
#[test]
fn rejects_a_single_byte_payload_typo() {
    let addr = valid_address();
    let good_script = keys::address_to_p2pkh_script(&addr).unwrap();

    // Flip one bit in each payload byte in turn; every one must be rejected.
    for i in 1..21 {
        let mut raw = decode_raw(&addr);
        raw[i] ^= 0x01;
        let typo = b58_raw(&raw);

        match keys::address_to_p2pkh_script(&typo) {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("checksum"),
                    "byte {i}: expected a checksum error, got: {msg}"
                );
            }
            Ok(script) => panic!(
                "byte {i}: accepted a mistyped address, paying {} instead of {}",
                hex(&script[3..23]),
                hex(&good_script[3..23])
            ),
        }
    }
}

/// A typo confined to the checksum bytes does not change the destination, but
/// must still be rejected: it is indistinguishable from a payload typo from
/// the user's point of view, and accepting it means the checksum is not being
/// checked at all.
#[test]
fn rejects_a_checksum_only_typo() {
    let addr = valid_address();
    for i in 21..25 {
        let mut raw = decode_raw(&addr);
        raw[i] ^= 0xff;
        let corrupted = b58_raw(&raw);
        assert!(
            keys::address_to_p2pkh_script(&corrupted).is_err(),
            "byte {i}: a corrupted checksum must be rejected"
        );
    }
}

/// A PIVX P2SH address carries a *script* hash. Wrapping it in a P2PKH script
/// demands a public key whose hash equals that script hash, which nothing will
/// ever satisfy: the output is unspendable forever.
#[test]
fn rejects_pivx_p2sh_address() {
    let pkh = decode_raw(&valid_address())[1..21].to_vec();
    let mut payload = vec![13u8]; // PIVX P2SH version byte
    payload.extend_from_slice(&pkh);
    let p2sh = b58check(&payload);

    let err = keys::address_to_p2pkh_script(&p2sh)
        .expect_err("a P2SH address must not be built as P2PKH")
        .to_string();
    assert!(
        err.contains("version byte"),
        "error should name the version byte, got: {err}"
    );
}

/// Addresses from other networks decode and checksum cleanly but are not PIVX
/// transparent addresses. Accepting them pays a hash the sender did not intend
/// for this chain.
#[test]
fn rejects_addresses_from_other_networks() {
    let pkh = decode_raw(&valid_address())[1..21].to_vec();

    // 0x00 = Bitcoin P2PKH, 0x05 = Bitcoin P2SH, 0x6f = Bitcoin testnet P2PKH,
    // 0x1c = one off from PIVX's 0x1e, the kind of near-miss a bad constant gives.
    for version in [0x00u8, 0x05, 0x6f, 0x1c, 0x41] {
        assert_ne!(version, PIVX_PUBKEY_PREFIX);
        let mut payload = vec![version];
        payload.extend_from_slice(&pkh);
        let foreign = b58check(&payload);
        assert!(
            keys::address_to_p2pkh_script(&foreign).is_err(),
            "version byte {version:#04x} must be rejected"
        );
    }
}

/// Every version byte other than PIVX's must be refused. Exhaustive, because a
/// single accepted prefix is a permanent loss of funds.
#[test]
fn accepts_only_the_pivx_pubkey_version_byte() {
    let pkh = decode_raw(&valid_address())[1..21].to_vec();
    let mut accepted = Vec::new();

    for version in 0u8..=255 {
        let mut payload = vec![version];
        payload.extend_from_slice(&pkh);
        if keys::address_to_p2pkh_script(&b58check(&payload)).is_ok() {
            accepted.push(version);
        }
    }

    assert_eq!(
        accepted,
        vec![PIVX_PUBKEY_PREFIX],
        "exactly one version byte should be accepted"
    );
}

/// Structurally malformed input must error rather than panic: these arrive
/// from JS callers, so an index-out-of-bounds would be a wasm trap.
#[test]
fn rejects_malformed_input_without_panicking() {
    let cases = [
        "",
        "0",                                    // not in the base58 alphabet
        "D",                                    // far too short
        "IlO0",                                 // ambiguous characters
        "DAHTQAV8QJcPP49c7LCf1NnstR4tzxae7e!",   // trailing junk
        "ps1svpr9fpg3juhvd3024544qc8eqrvwqllm8u9r58ylrh43jznzkyhen2p6t7ru0gh0lj75m5vhat",
        &"1".repeat(200),
        &"D".repeat(64),
    ];
    for c in cases {
        assert!(
            keys::address_to_p2pkh_script(c).is_err(),
            "expected an error for input {c:?}"
        );
    }
}

/// An all-zero pubkey hash is well-formed and correctly checksummed, so it is
/// accepted. Recorded deliberately: it is unspendable in practice, but it is a
/// valid address and rejecting it would mean second-guessing the caller.
#[test]
fn accepts_well_formed_address_with_zero_hash() {
    let mut payload = vec![PIVX_PUBKEY_PREFIX];
    payload.extend_from_slice(&[0u8; 20]);
    assert!(keys::address_to_p2pkh_script(&b58check(&payload)).is_ok());
}

/// Round-trip: a script built from a derived key's hash must match the script
/// built from that key's address, so validation has not changed what is emitted
/// for legitimate input.
#[test]
fn script_matches_hash_of_the_derived_pubkey() {
    let mnemonic = bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.to_seed("");

    for index in [0u32, 1, 5, 99] {
        let (address, pubkey, _priv) =
            keys::transparent_key_from_bip39_seed(&seed, 0, index).unwrap();
        let script = keys::address_to_p2pkh_script(&address).unwrap();
        let expected = Ripemd160::digest(Sha256::digest(&pubkey));
        assert_eq!(
            &script[3..23],
            &expected[..],
            "index {index}: script hash does not match hash160(pubkey)"
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
