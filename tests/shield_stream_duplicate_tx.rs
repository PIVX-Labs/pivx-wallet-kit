//! A transaction the shield stream hands over twice must only enter the tree
//! once.
//!
//! A txid cannot legitimately appear in two blocks, so a repeat means the data
//! source is wrong. Trusting it is expensive in a way that hides itself: the
//! duplicate's commitments enter the commitment tree a second time, every
//! position after them shifts, and the root stops matching the chain. Notes
//! still decrypt, balances still read correctly, and nothing looks wrong until
//! a spend is built against the bad anchor and the network refuses it with
//! `bad-txns-shielded-requirements-not-met`. At that point the funds appear
//! stuck for no visible reason.
//!
//! This is a real failure, not a hypothetical one. PIVX's `getshielddata`
//! served transaction
//! `ba5528e825549230fe70e6baac0b13756c8dcfad3122d0ad3c60b03de56be805` twice,
//! attributed to blocks 5563567 and 5563568. The chain puts it only in
//! 5563568; block 5563567 carries no shielded transaction at all. A wallet
//! synced across that block computed a root matching nothing on the network,
//! and every shield spend afterwards was rejected. Discarding the repeat
//! restores an exact match with the node's `finalsaplingroot`.
//!
//! The bug was invisible to every existing test because they all build against
//! a tree this crate computed itself, and a tree checked only against itself
//! agrees with itself even when it is wrong. It also sat past the last embedded
//! checkpoint, which is the one region `checkpoint_audit` structurally cannot
//! cover, since it verifies consecutive checkpoint pairs and there is no
//! checkpoint after it.

use pivx_wallet_kit::sapling::sync::{ShieldBlock, apply_blocks_to_wallet};
use pivx_wallet_kit::wallet;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The actual transaction the stream duplicated, taken from the live
/// `getshielddata` response. A real one is needed rather than a stand-in
/// because the blocks are decrypted and their commitments appended for real,
/// so arbitrary bytes fail to deserialize long before the duplicate matters.
fn real_shield_tx() -> Vec<u8> {
    let hex = include_str!("fixtures/shield_tx_5563568.hex");
    pivx_wallet_kit::simd::hex::hex_string_to_bytes(hex.trim())
}

fn wallet_at(height: i32) -> wallet::WalletData {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_236_346).unwrap();
    w.last_block = height;
    w
}

#[test]
fn the_same_transaction_in_two_blocks_is_applied_once() {
    let dup = real_shield_tx();

    // What the stream did: the same transaction filed under two consecutive
    // blocks, the second of which is where it genuinely belongs.
    let duplicated = vec![
        ShieldBlock { height: 5_563_567, txs: vec![dup.clone()] },
        ShieldBlock { height: 5_563_568, txs: vec![dup.clone()] },
    ];
    // What the chain actually contains.
    let truthful = vec![
        ShieldBlock { height: 5_563_567, txs: vec![] },
        ShieldBlock { height: 5_563_568, txs: vec![dup.clone()] },
    ];

    let mut from_duplicated = wallet_at(5_563_000);
    let mut from_truthful = wallet_at(5_563_000);

    apply_blocks_to_wallet(&mut from_duplicated, duplicated).unwrap();
    apply_blocks_to_wallet(&mut from_truthful, truthful).unwrap();

    assert_eq!(
        from_duplicated.commitment_tree, from_truthful.commitment_tree,
        "a repeated transaction must not advance the tree twice: the resulting root would match \
         nothing on the network, and every spend anchored to it would be rejected"
    );
    assert_eq!(from_duplicated.last_block, from_truthful.last_block);
}

#[test]
fn distinct_transactions_are_all_applied() {
    // The guard against overcorrecting into dropping real data.
    // Two genuinely different shielded transactions, both from mainnet.
    let a = real_shield_tx();
    let b = pivx_wallet_kit::simd::hex::hex_string_to_bytes(
        include_str!("fixtures/tx_shield.hex").trim(),
    );
    assert_ne!(a, b, "the fixtures must differ for this test to mean anything");

    let one = vec![
        ShieldBlock { height: 5_563_567, txs: vec![a.clone()] },
        ShieldBlock { height: 5_563_568, txs: vec![b] },
    ];
    let only_first = vec![
        ShieldBlock { height: 5_563_567, txs: vec![a] },
        ShieldBlock { height: 5_563_568, txs: vec![] },
    ];

    let mut both = wallet_at(5_563_000);
    let mut single = wallet_at(5_563_000);
    apply_blocks_to_wallet(&mut both, one).unwrap();
    apply_blocks_to_wallet(&mut single, only_first).unwrap();

    assert_ne!(
        both.commitment_tree, single.commitment_tree,
        "two different transactions must both reach the tree"
    );
}

#[test]
fn a_duplicate_within_one_block_is_also_dropped() {
    // Same defect, different shape: nothing says the repeat has to straddle a
    // block boundary.
    let dup = real_shield_tx();
    let twice = vec![ShieldBlock {
        height: 5_563_567,
        txs: vec![dup.clone(), dup.clone()],
    }];
    let once = vec![ShieldBlock { height: 5_563_567, txs: vec![dup] }];

    let mut from_twice = wallet_at(5_563_000);
    let mut from_once = wallet_at(5_563_000);
    apply_blocks_to_wallet(&mut from_twice, twice).unwrap();
    apply_blocks_to_wallet(&mut from_once, once).unwrap();

    assert_eq!(from_twice.commitment_tree, from_once.commitment_tree);
}

#[test]
fn an_empty_block_still_advances_the_cursor() {
    // Blocks carrying no shielded transaction are normal in this stream, and
    // must not be mistaken for nothing having happened.
    let mut w = wallet_at(5_563_000);
    apply_blocks_to_wallet(
        &mut w,
        vec![ShieldBlock { height: 5_563_567, txs: vec![] }],
    )
    .unwrap();
    assert_eq!(w.last_block, 5_563_567);
}
