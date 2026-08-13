//! P2CS script construction and parsing, checked against PIVX Core's layout.
//!
//! These assertions encode Core's rules directly rather than round-tripping our
//! own builder against our own parser, which would pass just as happily on a
//! script that is internally consistent and wrong. A cold-staking output is
//! locked behind two hashes: getting their order or offsets wrong yields coins
//! either unspendable or spendable by the staker, and neither failure is
//! visible without checking against the consensus definition.
//!
//! Reference: `MatchPayToColdStaking` and `CScript::IsPayToColdStaking` in PIVX
//! Core, cross-checked against MyPIVXWallet's `isP2CS` / `addColdStakeOutput`.

use pivx_wallet_kit::params::{PIVX_PUBKEY_PREFIX, PIVX_STAKING_PREFIX};
use pivx_wallet_kit::transparent::coldstake::{
    self, ColdStakeVariant, P2CS_SCRIPT_LEN, addresses_from_p2cs_script, build_p2cs_owner_script_sig,
    build_p2cs_script, decode_owner_address, decode_staking_address, encode_staking_address,
    is_p2cs, is_p2cs_lof, p2cs_script_from_addresses, parse_p2cs_script,
};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Distinct, recognisable hashes so a swap is obvious in a failure message.
const STAKER: [u8; 20] = [0xAA; 20];
const OWNER: [u8; 20] = [0xBB; 20];

/// Byte-for-byte against Core's `GetScriptForStakeDelegationLOF`:
/// `OP_DUP OP_HASH160 OP_ROT OP_IF OP_CHECKCOLDSTAKEVERIFY_LOF <staker>
///  OP_ELSE <owner> OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG`
#[test]
fn lof_script_matches_cores_byte_layout() {
    let script = build_p2cs_script(&STAKER, &OWNER, ColdStakeVariant::Lof);

    assert_eq!(script.len(), P2CS_SCRIPT_LEN, "Core requires exactly 51 bytes");

    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x76, 0xa9, 0x7b, 0x63, 0xd1, 0x14]);
    expected.extend_from_slice(&STAKER);
    expected.extend_from_slice(&[0x67, 0x14]);
    expected.extend_from_slice(&OWNER);
    expected.extend_from_slice(&[0x68, 0x88, 0xac]);

    assert_eq!(script, expected, "script does not match Core's LOF layout");
}

#[test]
fn v6_script_differs_only_in_the_verify_opcode() {
    let lof = build_p2cs_script(&STAKER, &OWNER, ColdStakeVariant::Lof);
    let v6 = build_p2cs_script(&STAKER, &OWNER, ColdStakeVariant::V6);

    assert_eq!(lof[4], 0xd1, "LOF must use OP_CHECKCOLDSTAKEVERIFY_LOF");
    assert_eq!(v6[4], 0xd2, "V6 must use OP_CHECKCOLDSTAKEVERIFY");

    // Everything else identical.
    assert_eq!(lof[..4], v6[..4]);
    assert_eq!(lof[5..], v6[5..]);
    assert!(is_p2cs(&lof) && is_p2cs(&v6), "both variants are valid P2CS");
    assert!(is_p2cs_lof(&lof));
    assert!(!is_p2cs_lof(&v6));
}

/// Core: `stakerPubKeyHash = script[6..26]`, `ownerPubKeyHash = script[28..48]`.
/// Asserted on the raw offsets, not via our own parser.
#[test]
fn hashes_sit_at_cores_offsets() {
    let script = build_p2cs_script(&STAKER, &OWNER, ColdStakeVariant::Lof);

    assert_eq!(&script[6..26], &STAKER, "staker hash must occupy bytes 6..26");
    assert_eq!(&script[28..48], &OWNER, "owner hash must occupy bytes 28..48");

    let parsed = parse_p2cs_script(&script).unwrap();
    assert_eq!(parsed.staker, STAKER);
    assert_eq!(parsed.owner, OWNER);
}

/// The staker/owner ordering is the single most damaging thing to get wrong, so
/// it is asserted through the address layer too: the `OP_IF` branch must render
/// as `S...` and the `OP_ELSE` branch as `D...`.
#[test]
fn if_branch_is_the_staker_and_else_branch_is_the_owner() {
    let staking_addr = encode_staking_address(&STAKER);
    let owner_addr = {
        // Build a D-address for OWNER via a round-trip through the script.
        let s = build_p2cs_script(&STAKER, &OWNER, ColdStakeVariant::Lof);
        addresses_from_p2cs_script(&s).unwrap().1
    };

    assert!(staking_addr.starts_with('S'), "staking address should render as S..., got {staking_addr}");
    assert!(owner_addr.starts_with('D'), "owner address should render as D..., got {owner_addr}");

    let script = p2cs_script_from_addresses(&staking_addr, &owner_addr, ColdStakeVariant::Lof)
        .expect("addresses should build a script");

    assert_eq!(&script[6..26], &STAKER, "S-address must land in the OP_IF branch");
    assert_eq!(&script[28..48], &OWNER, "D-address must land in the OP_ELSE branch");

    let (back_staking, back_owner) = addresses_from_p2cs_script(&script).unwrap();
    assert_eq!(back_staking, staking_addr);
    assert_eq!(back_owner, owner_addr);
}

/// Swapping the arguments must not silently produce a valid-looking script:
/// a staking address in the owner position is rejected on its version byte.
#[test]
fn swapped_addresses_are_rejected() {
    let staking_addr = encode_staking_address(&STAKER);
    let owner_addr = addresses_from_p2cs_script(
        &build_p2cs_script(&STAKER, &OWNER, ColdStakeVariant::Lof),
    )
    .unwrap()
    .1;

    // Correct order works.
    assert!(p2cs_script_from_addresses(&staking_addr, &owner_addr, ColdStakeVariant::Lof).is_ok());

    // Swapped does not.
    let err = p2cs_script_from_addresses(&owner_addr, &staking_addr, ColdStakeVariant::Lof)
        .expect_err("swapping staker and owner must be rejected")
        .to_string();
    assert!(
        err.contains("staking address"),
        "error should say the staking slot got a non-staking address, got: {err}"
    );
}

#[test]
fn staking_addresses_round_trip() {
    for byte in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
        let hash = [byte; 20];
        let addr = encode_staking_address(&hash);
        assert!(addr.starts_with('S'), "{addr} should start with S");
        assert_eq!(decode_staking_address(&addr).unwrap(), hash);
    }
}

/// Version bytes are enforced in both directions: an owner address is not a
/// staking address and vice versa.
#[test]
fn address_decoders_enforce_their_version_byte() {
    let hash = [0x42u8; 20];
    let staking = encode_staking_address(&hash);
    let owner = addresses_from_p2cs_script(
        &build_p2cs_script(&STAKER, &hash, ColdStakeVariant::Lof),
    )
    .unwrap()
    .1;

    assert!(decode_staking_address(&staking).is_ok());
    assert!(decode_owner_address(&owner).is_ok());

    assert!(
        decode_staking_address(&owner).is_err(),
        "a D-address must not decode as a staking address"
    );
    assert!(
        decode_owner_address(&staking).is_err(),
        "an S-address must not decode as an owner address"
    );
    assert_ne!(PIVX_STAKING_PREFIX, PIVX_PUBKEY_PREFIX);
}

/// Same checksum discipline as the P2PKH path: a delegation locks coins behind
/// two hashes, so a typo in either is unrecoverable.
#[test]
fn corrupted_staking_addresses_are_rejected() {
    let addr = encode_staking_address(&STAKER);

    // Flip one byte of the payload at a time; every one must fail the checksum.
    for i in 1..21 {
        let mut raw = bs58::decode(&addr).into_vec().unwrap();
        raw[i] ^= 0x01;
        let typo = bs58::encode(raw).into_string();
        assert!(
            decode_staking_address(&typo).is_err(),
            "byte {i}: a mistyped staking address was accepted"
        );
    }

    // And corruption confined to the checksum bytes.
    for i in 21..25 {
        let mut raw = bs58::decode(&addr).into_vec().unwrap();
        raw[i] ^= 0xff;
        let corrupted = bs58::encode(raw).into_string();
        assert!(decode_staking_address(&corrupted).is_err(), "byte {i}");
    }
}

/// `is_p2cs` mirrors Core's exact-length rule: a script that merely starts like
/// P2CS is not P2CS.
#[test]
fn is_p2cs_requires_the_exact_shape() {
    let good = build_p2cs_script(&STAKER, &OWNER, ColdStakeVariant::Lof);
    assert!(is_p2cs(&good));

    let mut too_long = good.clone();
    too_long.push(0x00);
    assert!(!is_p2cs(&too_long), "52 bytes must not match");

    let mut too_short = good.clone();
    too_short.pop();
    assert!(!is_p2cs(&too_short), "50 bytes must not match");

    // Each structural opcode matters.
    for idx in [0usize, 1, 2, 3, 4, 5, 26, 27, 48, 49, 50] {
        let mut broken = good.clone();
        broken[idx] ^= 0xff;
        assert!(!is_p2cs(&broken), "corrupting byte {idx} should break the match");
    }

    // A P2PKH script is not P2CS.
    let p2pkh = coldstake::p2pkh_script_from_hash(&OWNER);
    assert!(!is_p2cs(&p2pkh));
    assert!(parse_p2cs_script(&p2pkh).is_err());
}

/// The owner's redeem script differs from a P2PKH scriptSig by exactly one
/// `OP_FALSE` byte, positioned between the signature and the pubkey.
#[test]
fn owner_script_sig_inserts_op_false_between_signature_and_pubkey() {
    let sig = vec![0x30u8; 71]; // DER signature + hashtype, length is illustrative
    let pubkey = vec![0x02u8; 33];

    let script_sig = build_p2cs_owner_script_sig(&sig, &pubkey);

    let mut expected = Vec::new();
    expected.push(sig.len() as u8);
    expected.extend_from_slice(&sig);
    expected.push(0x00); // OP_FALSE: selects the OP_ELSE (owner) branch
    expected.push(pubkey.len() as u8);
    expected.extend_from_slice(&pubkey);

    assert_eq!(script_sig, expected);

    // Exactly one byte longer than the P2PKH equivalent.
    let p2pkh_len = 1 + sig.len() + 1 + pubkey.len();
    assert_eq!(
        script_sig.len(),
        p2pkh_len + 1,
        "the cold-stake scriptSig should add exactly one byte"
    );
    assert_eq!(script_sig[1 + sig.len()], 0x00, "OP_FALSE must directly follow the signature");
}

/// Real P2CS outputs taken from PIVX mainnet, with the staking and owner
/// addresses the network actually recorded.
///
/// This is the assertion that catches a self-consistent-but-wrong model: the
/// tests above build a script and parse it back with the same code, which would
/// agree with itself even if the branch order were inverted. These bytes were
/// produced by PIVX Core, not by this crate.
///
/// `SdgQDpS8jDRJDX8yK8m9KnTMarsE84zdsy` is independently recognisable: it is
/// the `defaultColdStakingAddress` MyPIVXWallet ships in `chain_params.json`.
const MAINNET_P2CS: &[(u32, &str, &str, &str)] = &[
    (
        5_520_501,
        "76a97b63d114b3be8567d0190c67ca4675a0019089c55fe695f967140cf46021b92c86ed30079270c6598352053bafd66888ac",
        "SdgQDpS8jDRJDX8yK8m9KnTMarsE84zdsy",
        "D6KbQ4wnrF3xV7DrSPCrhR6WcfYnJ34tF6",
    ),
    (
        5_520_500,
        "76a97b63d114c0f123aed6538a8426eca14bf80d967c0df54c416714d1bdaf81184b74e02365b7d2da2b668d8da140736888ac",
        "SetBeLBfJ5eK2k8fCwYbTxfjgDoUi6vCFq",
        "DQG6zwBd2oUNeJaw3znW5a3Avc2J3SEkFV",
    ),
    (
        5_520_498,
        "76a97b63d114b3be8567d0190c67ca4675a0019089c55fe695f9671432544966996713628cba6c58ace894c27bca2d346888ac",
        "SdgQDpS8jDRJDX8yK8m9KnTMarsE84zdsy",
        "D9jDJCD4uQuZdZWYxYYsH8M7UwxVwiPcZo",
    ),
    (
        5_520_497,
        "76a97b63d114b3be8567d0190c67ca4675a0019089c55fe695f96714b0518641ebf35b540648a3b6fcee70833502d6676888ac",
        "SdgQDpS8jDRJDX8yK8m9KnTMarsE84zdsy",
        "DMDP8SNSM9GJMHu5LYvVPv6pkzyfAoXEGg",
    ),
];

#[test]
fn parses_real_mainnet_p2cs_outputs() {
    for (height, hex, expect_staker, expect_owner) in MAINNET_P2CS {
        let script = pivx_wallet_kit::simd::hex::hex_string_to_bytes(hex);

        assert_eq!(script.len(), P2CS_SCRIPT_LEN, "block {height}");
        assert!(is_p2cs(&script), "block {height}: not recognised as P2CS");

        let (staker, owner) = addresses_from_p2cs_script(&script)
            .unwrap_or_else(|e| panic!("block {height}: {e}"));
        assert_eq!(&staker, expect_staker, "block {height}: staking address");
        assert_eq!(&owner, expect_owner, "block {height}: owner address");
    }
}

/// Every real output observed uses the LOF opcode, which is the empirical
/// counterpart to the source reading: Core picks LOF whenever `UPGRADE_V6_0` is
/// inactive, and V6 is set to `NO_ACTIVATION_HEIGHT` on every network. If this
/// ever fails, V6 has activated and the default emitted variant should change.
#[test]
fn mainnet_outputs_use_the_lof_variant() {
    for (height, hex, _, _) in MAINNET_P2CS {
        let script = pivx_wallet_kit::simd::hex::hex_string_to_bytes(hex);
        assert!(
            is_p2cs_lof(&script),
            "block {height}: expected the LOF opcode while v6.0 is unactivated"
        );
    }
}

/// Rebuilding from the parsed addresses must reproduce the on-chain bytes
/// exactly: the round-trip that proves the builder and the network agree.
#[test]
fn rebuilding_real_outputs_is_byte_identical() {
    for (height, hex, _, _) in MAINNET_P2CS {
        let script = pivx_wallet_kit::simd::hex::hex_string_to_bytes(hex);
        let (staker, owner) = addresses_from_p2cs_script(&script).unwrap();

        let variant = if is_p2cs_lof(&script) {
            ColdStakeVariant::Lof
        } else {
            ColdStakeVariant::V6
        };
        let rebuilt = p2cs_script_from_addresses(&staker, &owner, variant).unwrap();

        assert_eq!(
            rebuilt, script,
            "block {height}: rebuilt script differs from the one on chain"
        );
    }
}

/// A delegation built from a real derived key must name that key as owner, so
/// the withdrawing path can actually sign for it.
#[test]
fn owner_hash_matches_the_derived_key() {
    let seed = bip39::Mnemonic::parse_normalized(TEST_MNEMONIC)
        .unwrap()
        .to_seed("");

    for index in [0u32, 1, 7, 100] {
        let (address, pubkey, _priv) =
            pivx_wallet_kit::keys::transparent_key_from_bip39_seed(&seed, 0, index).unwrap();

        let from_seed = coldstake::owner_hash_from_seed(&seed, 0, index).unwrap();
        let from_address = decode_owner_address(&address).unwrap();
        assert_eq!(from_seed, from_address, "index {index}");

        // And it is genuinely hash160(pubkey).
        use ripemd::Ripemd160;
        use sha2::{Digest, Sha256};
        let expected = Ripemd160::digest(Sha256::digest(&pubkey));
        assert_eq!(&from_seed[..], &expected[..], "index {index}");

        // The P2CS script's owner branch must equal the P2PKH hash for the same
        // key: that equality is what lets the owner redeem.
        let script = build_p2cs_script(&STAKER, &from_seed, ColdStakeVariant::Lof);
        let p2pkh = coldstake::p2pkh_script_from_hash(&from_seed);
        assert_eq!(&script[28..48], &p2pkh[3..23]);
    }
}
