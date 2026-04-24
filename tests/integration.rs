//! Integration tests exercising the kit against real PIVX mainnet transactions.
//!
//! Fixtures in `tests/fixtures/` are raw tx hex pulled from Blockbook:
//! - `tx_transparent.hex` — `c6ff49f9...` (shield → transparent, 1 sapling spend, 1 transparent output)
//! - `tx_shield.hex`      — `69dc1691...` (pure shield, 1 spend + 2 outputs, ~0.024 PIV fee)
//!
//! These are *real* on-chain txs; they let us verify parsing, tree updates,
//! and (where applicable) the full shield handling pipeline without needing
//! network access at test time.

use pivx_wallet_kit::*;

const TX_TRANSPARENT_HEX: &str = include_str!("fixtures/tx_transparent.hex");
const TX_SHIELD_HEX: &str = include_str!("fixtures/tx_shield.hex");

fn decode_fixture(hex_contents: &str) -> Vec<u8> {
    simd::hex::hex_string_to_bytes(hex_contents.trim())
}

// ---------------------------------------------------------------------------
// Hex primitives
// ---------------------------------------------------------------------------

#[test]
fn hex_roundtrip_32_bytes() {
    let bytes = [0xdeu8; 32];
    let hex = simd::hex::bytes_to_hex_string(&bytes);
    let decoded = simd::hex::hex_string_to_bytes(&hex);
    assert_eq!(decoded, bytes);
}

#[test]
fn hex_roundtrip_arbitrary_length() {
    for len in [0, 1, 5, 16, 17, 31, 33, 100, 1000] {
        let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
        let hex = simd::hex::bytes_to_hex_string(&bytes);
        assert_eq!(hex.len(), len * 2, "hex string length mismatch for {}", len);
        let decoded = simd::hex::hex_string_to_bytes(&hex);
        assert_eq!(decoded, bytes, "roundtrip mismatch at length {}", len);
    }
}

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_lookup_behaves_correctly() {
    let first_h = checkpoints::MAINNET_CHECKPOINTS[0].0;
    // Queries below the first checkpoint fall back to the first one.
    for query in [0, first_h - 1] {
        let (h, tree) = checkpoints::get_checkpoint(query);
        assert!(!tree.is_empty());
        assert_eq!(h, first_h, "below-first query should return first checkpoint");
    }
    // Queries above the first checkpoint return something <= the query.
    for query in [first_h, 3_000_000, 5_000_000, 10_000_000] {
        let (h, _) = checkpoints::get_checkpoint(query);
        assert!(h <= query);
        assert!(h >= first_h);
    }
}

#[test]
fn checkpoint_below_first_returns_first() {
    let (h, tree) = checkpoints::get_checkpoint(-1);
    let (first_h, first_tree) = checkpoints::MAINNET_CHECKPOINTS[0];
    assert_eq!(h, first_h);
    assert_eq!(tree, first_tree);
}

#[test]
fn checkpoint_latest_is_reachable() {
    // The last checkpoint should be selectable by querying at a very high height.
    let (h, _) = checkpoints::get_checkpoint(i32::MAX);
    let latest = checkpoints::MAINNET_CHECKPOINTS.last().unwrap();
    assert_eq!(h, latest.0);
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// BIP39 test vector — a known mnemonic whose transparent address we can verify derives consistently.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn derive_transparent_address_from_mnemonic() {
    let addr = keys::get_transparent_address(TEST_MNEMONIC).expect("derive transparent addr");
    assert!(
        addr.starts_with('D'),
        "PIVX transparent address should start with 'D', got: {}",
        addr
    );
    assert_eq!(addr.len(), 34, "PIVX address should be 34 chars, got: {}", addr.len());
    // Deterministic — derive twice, expect identical.
    let addr2 = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    assert_eq!(addr, addr2);
}

#[test]
fn derive_shield_address_from_mnemonic() {
    let mnemonic = bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap();
    let mut bip39_seed = mnemonic.to_seed("");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bip39_seed[..32]);
    let extsk = keys::spending_key_from_seed(&seed, params::PIVX_COIN_TYPE, 0).unwrap();
    let extfvk = keys::full_viewing_key(&extsk);
    let encoded_extfvk = keys::encode_extfvk(&extfvk);
    let shield_addr = keys::get_default_address(&encoded_extfvk).unwrap();
    assert!(
        shield_addr.starts_with("ps"),
        "PIVX shield address should start with 'ps', got: {}",
        shield_addr
    );
    // Zero out seed
    for b in bip39_seed.iter_mut() {
        *b = 0;
    }
    for b in seed.iter_mut() {
        *b = 0;
    }
}

#[test]
fn decode_transparent_address_roundtrips_to_script() {
    let addr = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    let script = keys::address_to_p2pkh_script(&addr).unwrap();
    // P2PKH: OP_DUP OP_HASH160 0x14 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG = 25 bytes.
    assert_eq!(script.len(), 25);
    assert_eq!(script[0], 0x76);
    assert_eq!(script[1], 0xa9);
    assert_eq!(script[2], 0x14);
    assert_eq!(script[23], 0x88);
    assert_eq!(script[24], 0xac);
}

// ---------------------------------------------------------------------------
// Wallet state + crypt round-trip
// ---------------------------------------------------------------------------

#[test]
fn wallet_create_import_match() {
    let created = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    let reimported = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    assert_eq!(created.extfvk, reimported.extfvk);
    assert_eq!(created.birthday_height, reimported.birthday_height);
    assert_eq!(created.last_block, reimported.last_block);
}

#[test]
fn wallet_crypt_roundtrip() {
    let key = [0x42u8; 32];
    let plaintext = b"super secret seed phrase material across multiple blocks, more than 32 bytes for sure";
    let ciphertext = wallet::crypt(plaintext, &key);
    let decrypted = wallet::crypt(&ciphertext, &key);
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
}

#[test]
fn wallet_encrypt_decrypt_secrets_roundtrip() {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    let original_mnemonic = w.get_mnemonic().to_string();
    let original_extfvk = w.extfvk.clone();

    let key = [0xA5u8; 32];
    wallet::encrypt_secrets(&mut w, &key).unwrap();
    // Encrypted mnemonic is now hex-encoded ciphertext, not the original string.
    assert_ne!(w.get_mnemonic(), original_mnemonic);

    wallet::decrypt_secrets(&mut w, &key).unwrap();
    assert_eq!(w.get_mnemonic(), original_mnemonic);
    assert_eq!(w.extfvk, original_extfvk);
}

#[test]
fn wallet_decrypt_wrong_key_fails() {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    let key = [0xA5u8; 32];
    wallet::encrypt_secrets(&mut w, &key).unwrap();

    let wrong_key = [0x99u8; 32];
    let err = wallet::decrypt_secrets(&mut w, &wrong_key);
    assert!(err.is_err(), "decrypt with wrong key should fail");
}

/// Wrong-key decrypt must leave the wallet's encrypted state intact so the
/// caller can retry with a different key without reloading from disk.
#[test]
fn wallet_decrypt_wrong_key_does_not_corrupt_state() {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    let key = [0xA5u8; 32];
    wallet::encrypt_secrets(&mut w, &key).unwrap();

    // Snapshot the encrypted state.
    let encrypted_mnemonic = w.get_mnemonic().to_string();

    let wrong_key = [0x99u8; 32];
    let _ = wallet::decrypt_secrets(&mut w, &wrong_key);

    // State should be untouched — mnemonic still the encrypted hex string.
    assert_eq!(w.get_mnemonic(), encrypted_mnemonic);

    // Retry with the right key should now succeed cleanly.
    wallet::decrypt_secrets(&mut w, &key).unwrap();
    assert_eq!(w.get_mnemonic(), TEST_MNEMONIC);
}

/// Full disk round-trip: encrypt → serialize to JSON → deserialize → decrypt.
/// Catches regressions like a JSON roundtrip dropping the 32-byte seed.
#[test]
fn wallet_disk_roundtrip_preserves_decryption() {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    let original_extfvk = w.extfvk.clone();
    let key = [0x12u8; 32];

    wallet::encrypt_secrets(&mut w, &key).unwrap();
    let json = serde_json::to_string(&w).unwrap();

    let mut w2: wallet::WalletData = serde_json::from_str(&json).unwrap();
    wallet::decrypt_secrets(&mut w2, &key).unwrap();
    assert_eq!(w2.get_mnemonic(), TEST_MNEMONIC);
    assert_eq!(w2.extfvk, original_extfvk);
}

#[test]
fn clone_for_encryption_is_independent() {
    let w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    let mut clone = w.clone_for_encryption();
    let key = [0x33u8; 32];
    wallet::encrypt_secrets(&mut clone, &key).unwrap();

    // The original should still be plaintext.
    assert_eq!(w.get_mnemonic(), TEST_MNEMONIC);
    // The clone should not match the plaintext anymore.
    assert_ne!(clone.get_mnemonic(), TEST_MNEMONIC);
}

#[test]
fn wallet_reset_to_checkpoint_clears_state() {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_notes.push(wallet::SerializedNote {
        note: serde_json::json!({"value": 1000}),
        witness: "00".into(),
        nullifier: "deadbeef".into(),
        memo: None,
        height: 1234,
    });
    w.last_block = 9_999_999;
    wallet::reset_to_checkpoint(&mut w).unwrap();
    assert!(w.unspent_notes.is_empty());
    assert!(w.last_block <= w.birthday_height);
}

// ---------------------------------------------------------------------------
// Fees
// ---------------------------------------------------------------------------

#[test]
fn fee_estimation_scales_with_sapling_io() {
    let base = fees::estimate_fee(0, 0, 0, 0);
    let one_sapling = fees::estimate_fee(0, 0, 0, 1);
    assert!(one_sapling > base);

    let two_sapling = fees::estimate_fee(0, 0, 0, 2);
    assert!(two_sapling > one_sapling);
    // Linear in outputs.
    assert_eq!(two_sapling - one_sapling, one_sapling - base);
}

#[test]
fn raw_transparent_fee_is_sane() {
    let one_in = fees::estimate_raw_transparent_fee(1, 2);
    let two_in = fees::estimate_raw_transparent_fee(2, 2);
    assert!(two_in > one_in);
    // Should be in a reasonable sat range (well under 1 PIV).
    assert!(one_in < 100_000_000);
}

// ---------------------------------------------------------------------------
// Real transaction parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_real_transparent_tx_v3() {
    use pivx_primitives::consensus::BranchId;
    use pivx_primitives::transaction::Transaction;
    use std::io::Cursor;

    let bytes = decode_fixture(TX_TRANSPARENT_HEX);
    assert!(bytes.len() > 100, "transparent tx bytes too short");

    // PIVX v3 type 0: first 4 bytes = 0x03 0x00 0x00 0x00 (LE u32 = 3).
    assert_eq!(&bytes[0..4], &[0x03, 0x00, 0x00, 0x00]);

    let tx = Transaction::read(Cursor::new(&bytes), BranchId::Sapling)
        .expect("should parse PIVX v3 tx");
    // This particular tx has a sapling spend revealing funds to a transparent output.
    assert_eq!(
        tx.transparent_bundle().map(|t| t.vout.len()).unwrap_or(0),
        1,
        "expected exactly 1 transparent output"
    );
    assert!(tx.sapling_bundle().is_some(), "expected a Sapling bundle");
}

#[test]
fn parse_real_shield_tx_v3() {
    use pivx_primitives::consensus::BranchId;
    use pivx_primitives::transaction::Transaction;
    use std::io::Cursor;

    let bytes = decode_fixture(TX_SHIELD_HEX);
    assert!(bytes.len() > 100, "shield tx bytes too short");
    assert_eq!(&bytes[0..4], &[0x03, 0x00, 0x00, 0x00]);

    let tx = Transaction::read(Cursor::new(&bytes), BranchId::Sapling)
        .expect("should parse PIVX v3 shield tx");
    let bundle = tx.sapling_bundle().expect("shield tx must have sapling bundle");
    assert_eq!(bundle.shielded_spends().len(), 1);
    assert_eq!(bundle.shielded_outputs().len(), 2);
}

// ---------------------------------------------------------------------------
// Shield block processing with real fixtures
// ---------------------------------------------------------------------------

/// Feeding the real shield tx through `handle_blocks` with a *random* viewing
/// key should: (1) not panic, (2) produce no decrypted notes, (3) extract the
/// spent nullifier, (4) advance the commitment tree.
#[test]
fn handle_blocks_processes_real_shield_tx_without_key() {
    let tx_bytes = decode_fixture(TX_SHIELD_HEX);

    // Derive a random extfvk from a throwaway mnemonic — guaranteed not to be
    // the actual recipient of this tx.
    let random = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();

    // Start with the empty tree (just to exercise the path — the real tree
    // would be one from just before this tx's block).
    let tree_hex = checkpoints::MAINNET_CHECKPOINTS[0].1;
    let block = sapling::sync::ShieldBlock {
        height: 5_000_000,
        txs: vec![tx_bytes],
    };

    let result =
        sapling::sync::handle_blocks(tree_hex, vec![block], &random.extfvk, &[]).unwrap();

    // No decryption because the key is random.
    assert!(result.new_notes.is_empty());
    // But the spend nullifier should have been surfaced.
    assert_eq!(result.nullifiers.len(), 1);
    // The tree should have advanced (no longer equal to the starting root).
    let root_before = sapling::tree::get_sapling_root(tree_hex).unwrap();
    let root_after = sapling::tree::get_sapling_root(&result.commitment_tree).unwrap();
    assert_ne!(
        root_before, root_after,
        "tree root should advance after appending 2 output commitments"
    );
}

#[test]
fn handle_blocks_processes_real_transparent_tx_without_notes() {
    // The c6ff... tx reveals some PIV to a transparent output AND shields the
    // remainder back as a sapling change output. Processing should surface
    // the spend nullifier and advance the tree by the change output.
    let tx_bytes = decode_fixture(TX_TRANSPARENT_HEX);

    let random = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    let tree_hex = checkpoints::MAINNET_CHECKPOINTS[0].1;
    let block = sapling::sync::ShieldBlock {
        height: 5_000_000,
        txs: vec![tx_bytes],
    };

    let result =
        sapling::sync::handle_blocks(tree_hex, vec![block], &random.extfvk, &[]).unwrap();

    assert_eq!(result.nullifiers.len(), 1, "tx has 1 sapling spend");
    // Random key → no decrypted notes.
    assert!(result.new_notes.is_empty());
    // Commitment tree should be a valid hex string (non-empty).
    assert!(!result.commitment_tree.is_empty());
}

// ---------------------------------------------------------------------------
// Shield stream parser
// ---------------------------------------------------------------------------

/// The kit must let consumers build pure transparent→transparent transactions
/// without ever loading the Sapling prover. Enforced by this test, which
/// constructs a wallet with a synthetic transparent UTXO and drives the raw
/// v1 P2PKH path — if the kit ever accidentally re-requires a prover here,
/// this test will fail because we pass `None`.
#[test]
fn transparent_to_transparent_tx_needs_no_prover() {
    use pivx_wallet_kit::transparent::builder::create_raw_transparent_transaction;
    use pivx_wallet_kit::wallet::SerializedUTXO;

    let mnemonic = bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap();
    let bip39_seed = mnemonic.to_seed("");

    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos.push(SerializedUTXO {
        // A fake but well-formed 64-char txid.
        txid: "a".repeat(64),
        vout: 0,
        amount: 500_000_000, // 5 PIV
        script: String::new(),
        height: 5_000_000,
    });

    // Destination is the same wallet's transparent address — guaranteed to
    // be a `D...` address, triggering the raw v1 path.
    let dest = w.get_transparent_address().unwrap();

    let result = create_raw_transparent_transaction(
        &mut w,
        &bip39_seed,
        &dest,
        100_000_000, // 1 PIV
        0,           // block_height_for_shield — unused for transparent dest
        None,        // prover_for_shield — unused for transparent dest
    )
    .expect("pure transparent tx should build without prover");

    assert!(!result.txhex.is_empty());
    assert_eq!(result.amount, 100_000_000);
    assert_eq!(result.spent.len(), 1);
    // Raw v1 tx: version byte 0x01 0x00 0x00 0x00.
    let tx_bytes = simd::hex::hex_string_to_bytes(&result.txhex);
    assert_eq!(&tx_bytes[0..4], &[0x01, 0x00, 0x00, 0x00]);
}

/// Shield destinations must reject `prover_for_shield = None`.
#[test]
fn transparent_to_shield_requires_prover() {
    use pivx_wallet_kit::transparent::builder::create_raw_transparent_transaction;
    use pivx_wallet_kit::wallet::SerializedUTXO;

    let mnemonic = bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap();
    let bip39_seed = mnemonic.to_seed("");

    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos.push(SerializedUTXO {
        txid: "a".repeat(64),
        vout: 0,
        amount: 500_000_000,
        script: String::new(),
        height: 5_000_000,
    });

    // Destination is a shield address; prover_for_shield = None must error.
    let mnemonic = bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&mnemonic.to_seed("")[..32]);
    let extsk = keys::spending_key_from_seed(&seed, params::PIVX_COIN_TYPE, 0).unwrap();
    let extfvk = keys::full_viewing_key(&extsk);
    let shield_dest = keys::get_default_address(&keys::encode_extfvk(&extfvk)).unwrap();

    let err = create_raw_transparent_transaction(
        &mut w,
        &bip39_seed,
        &shield_dest,
        100_000_000,
        0,
        None,
    );
    assert!(err.is_err(), "shield dest without prover should error");
}

#[test]
fn is_empty_tree_hex_accepts_all_known_empty_forms() {
    assert!(sapling::tree::is_empty_tree_hex(""));
    assert!(sapling::tree::is_empty_tree_hex("00"));
    assert!(sapling::tree::is_empty_tree_hex("000000"));
    // A populated frontier-hex is not empty.
    let (_, populated) = checkpoints::get_checkpoint(5_000_000);
    assert!(!sapling::tree::is_empty_tree_hex(populated));
}

#[test]
fn parse_shield_stream_synthetic_compact() {
    // Hand-craft a minimal valid stream: [block header(0x5d + height)][tx(0x04 + 0 spends + 0 outputs)].
    // Each packet: [4-byte LE length][payload].
    let mut stream = Vec::new();

    // Block header (5 bytes: 0x5d + 4-byte height)
    let block_payload = [0x5du8, 0xE0, 0x93, 0x04, 0x00]; // height 300_000
    stream.extend_from_slice(&(block_payload.len() as u32).to_le_bytes());
    stream.extend_from_slice(&block_payload);

    // Compact tx with 0 spends + 0 outputs (3 bytes: 0x04, 0, 0).
    let tx_payload = [0x04u8, 0, 0];
    stream.extend_from_slice(&(tx_payload.len() as u32).to_le_bytes());
    stream.extend_from_slice(&tx_payload);

    let mut cursor = std::io::Cursor::new(&stream);
    let batch = sync::parse_next_blocks(&mut cursor, 10).unwrap();
    let blocks = batch.expect("should parse at least one block");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height, 300_000);
    assert_eq!(blocks[0].txs.len(), 1);
    assert_eq!(blocks[0].txs[0][0], 0x04);
}

#[test]
fn parse_shield_stream_handles_empty() {
    let stream: Vec<u8> = Vec::new();
    let mut cursor = std::io::Cursor::new(&stream);
    let result = sync::parse_next_blocks(&mut cursor, 10).unwrap();
    assert!(result.is_none());
}

#[test]
fn parse_shield_stream_rejects_oversize_packet() {
    let mut stream = Vec::new();
    // length > MAX_PACKET_SIZE
    stream.extend_from_slice(&(sync::MAX_PACKET_SIZE as u32 + 1).to_le_bytes());
    let mut cursor = std::io::Cursor::new(&stream);
    let result = sync::parse_next_blocks(&mut cursor, 10);
    assert!(result.is_err());
}

#[test]
fn parse_shield_stream_rejects_zero_length() {
    let mut stream = Vec::new();
    stream.extend_from_slice(&0u32.to_le_bytes());
    let mut cursor = std::io::Cursor::new(&stream);
    let result = sync::parse_next_blocks(&mut cursor, 10);
    assert!(result.is_err());
}

#[test]
fn parse_shield_stream_rejects_unknown_type() {
    let mut stream = Vec::new();
    let payload = [0xFFu8, 0, 0, 0];
    stream.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.extend_from_slice(&payload);
    let mut cursor = std::io::Cursor::new(&stream);
    let result = sync::parse_next_blocks(&mut cursor, 10);
    assert!(result.is_err());
}
