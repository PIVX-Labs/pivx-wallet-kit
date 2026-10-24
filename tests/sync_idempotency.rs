//! Applying shield blocks must be idempotent by block height.
//!
//! Applying a block twice advances the commitment tree twice and re-adds notes
//! the wallet already holds. The inflated balance is the visible symptom; the
//! damaging part is that every witness position shifts, so anchors derived from
//! them no longer match the chain and every spend built afterwards is rejected.
//!
//! This was reachable by following the kit's own documented sync pattern.
//! Applying blocks did not advance `last_block`: only `reset_to_checkpoint` set
//! it, so a caller syncing from `last_block + 1` re-fetched and re-applied the
//! whole range from the checkpoint on every sync after the first.

use pivx_wallet_kit::sapling::sync::{HandleBlocksResult, ShieldBlock, apply_blocks_to_wallet};
use pivx_wallet_kit::simd;
use pivx_wallet_kit::wallet::{self, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const TX_SHIELD_HEX: &str = include_str!("fixtures/tx_shield.hex");

/// The fixture carries two shielded outputs, so each application of it appends
/// exactly two leaves to the commitment tree.
const LEAVES_PER_BLOCK: usize = 2;

fn shield_tx() -> Vec<u8> {
    simd::hex::hex_string_to_bytes(TX_SHIELD_HEX.trim())
}

fn block(height: u32) -> ShieldBlock {
    ShieldBlock { height, txs: vec![shield_tx()] }
}

/// Tree leaf count: what a double-apply corrupts.
fn tree_size(hex: &str) -> usize {
    use ::sapling::Node;
    use incrementalmerkletree::frontier::CommitmentTree;
    use pivx_primitives::merkle_tree::read_commitment_tree;
    use std::io::Cursor;

    let bytes = simd::hex::hex_string_to_bytes(hex);
    let tree: CommitmentTree<Node, 32> = read_commitment_tree(Cursor::new(bytes)).unwrap();
    tree.size()
}

fn synced_wallet() -> WalletData {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    wallet::reset_to_checkpoint(&mut w).unwrap();
    w
}

fn apply(w: &mut WalletData, blocks: Vec<ShieldBlock>) -> HandleBlocksResult {
    apply_blocks_to_wallet(w, blocks).expect("applying blocks should not error")
}

/// The core guarantee: a second application of the same block changes nothing.
#[test]
fn applying_the_same_block_twice_is_a_no_op() {
    let mut w = synced_wallet();
    let height = w.last_block as u32 + 100;

    let first = apply(&mut w, vec![block(height)]);
    let size_after_first = tree_size(&first.commitment_tree);
    let notes_after_first = w.unspent_notes.len();

    assert_eq!(
        w.last_block, height as i32,
        "the cursor must advance, or a caller syncing from last_block + 1 replays \
         from the checkpoint forever"
    );

    let second = apply(&mut w, vec![block(height)]);

    assert_eq!(
        tree_size(&second.commitment_tree),
        size_after_first,
        "the commitment tree grew on re-apply: every witness position is now wrong"
    );
    assert_eq!(w.unspent_notes.len(), notes_after_first, "notes duplicated on re-apply");
    assert_eq!(w.last_block, height as i32, "cursor moved on a no-op apply");
    assert!(second.new_notes.is_empty(), "re-apply reported new notes");
    assert!(second.nullifiers.is_empty(), "re-apply reported nullifiers again");
}

/// Blocks at or below the cursor are dropped; only genuinely newer ones apply.
#[test]
fn only_blocks_above_the_cursor_are_applied() {
    let mut w = synced_wallet();
    let base = w.last_block as u32;
    let size_at_start = tree_size(&w.commitment_tree);

    for height in [base - 1, base] {
        let r = apply(&mut w, vec![block(height)]);
        assert!(
            r.new_notes.is_empty(),
            "block at height {height} (cursor {base}) should have been skipped"
        );
        assert_eq!(w.last_block, base as i32, "cursor moved for a stale block");
        assert_eq!(
            tree_size(&w.commitment_tree),
            size_at_start,
            "tree advanced for a stale block at height {height}"
        );
    }

    apply(&mut w, vec![block(base + 1)]);
    assert_eq!(w.last_block, base as i32 + 1);
    assert_eq!(
        tree_size(&w.commitment_tree),
        size_at_start + LEAVES_PER_BLOCK,
        "a genuinely new block should have advanced the tree"
    );
}

/// A batch mixing already-seen and new heights must apply only the new ones:
/// the realistic shape of a re-fetch with overlap.
#[test]
fn a_partially_overlapping_batch_applies_only_the_new_blocks() {
    let mut w = synced_wallet();
    let base = w.last_block as u32;

    apply(&mut w, vec![block(base + 1), block(base + 2)]);
    let size_two_blocks = tree_size(&w.commitment_tree);
    assert_eq!(w.last_block, base as i32 + 2);

    // Re-send both, plus one genuinely new block. Only the new one should land.
    apply(&mut w, vec![block(base + 1), block(base + 2), block(base + 3)]);

    assert_eq!(
        tree_size(&w.commitment_tree) - size_two_blocks,
        LEAVES_PER_BLOCK,
        "expected one block's worth of commitments; re-applying all three would add {}",
        3 * LEAVES_PER_BLOCK
    );
    assert_eq!(w.last_block, base as i32 + 3);
}

/// Out-of-order blocks within a batch must not rewind the cursor: it lands on
/// the highest height applied.
#[test]
fn cursor_tracks_the_highest_height_in_the_batch() {
    let mut w = synced_wallet();
    let base = w.last_block as u32;

    apply(&mut w, vec![block(base + 3), block(base + 1), block(base + 2)]);
    assert_eq!(w.last_block, base as i32 + 3, "cursor should be the maximum, not the last seen");
}

/// Non-contiguous heights must be accepted: the compact stream only carries
/// blocks containing shield data, so gaps are the normal case and cannot be
/// distinguished from missing data at this layer.
#[test]
fn gaps_in_block_heights_are_accepted() {
    let mut w = synced_wallet();
    let base = w.last_block as u32;

    apply(&mut w, vec![block(base + 1)]);
    apply(&mut w, vec![block(base + 5_000)]);

    assert_eq!(w.last_block, base as i32 + 5_000);
}

/// An empty batch is a no-op reporting current state rather than an error, so
/// re-syncing an already-current wallet is harmless.
#[test]
fn an_empty_batch_reports_current_state() {
    let mut w = synced_wallet();
    let before = w.last_block;
    let tree_before = w.commitment_tree.clone();

    let r = apply(&mut w, Vec::new());

    assert!(r.new_notes.is_empty());
    assert!(r.nullifiers.is_empty());
    assert_eq!(w.last_block, before);
    assert_eq!(r.commitment_tree, tree_before, "should echo the current tree");
}

/// A batch containing only stale blocks is equally a no-op: the path where the
/// filter removes everything must not be mistaken for "nothing supplied".
#[test]
fn a_wholly_stale_batch_is_a_no_op() {
    let mut w = synced_wallet();
    let base = w.last_block as u32;
    let tree_before = w.commitment_tree.clone();

    let r = apply(&mut w, vec![block(base - 10), block(base - 5), block(base)]);

    assert!(r.new_notes.is_empty());
    assert_eq!(w.last_block, base as i32);
    assert_eq!(w.commitment_tree, tree_before);
}
