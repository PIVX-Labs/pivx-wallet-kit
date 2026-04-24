//! Diagnostic: verify that non-empty checkpoint tree hex deserializes to the
//! correct size. If this test returns 0 for a non-empty checkpoint, the
//! checkpoint's leaf count isn't being preserved through serialization.

use incrementalmerkletree::frontier::CommitmentTree;
use pivx_primitives::merkle_tree::read_commitment_tree;
use pivx_wallet_kit::{checkpoints, simd};
use sapling::Node;
use std::io::Cursor;

#[test]
fn checkpoint_5236346_tree_reports_nonzero_size() {
    // This is the checkpoint the CLI (birthday_height=5236346) and the web
    // wallet demo both use. If the deserialized tree reports size=0, the
    // witness positions computed for freshly decrypted notes will be wrong
    // (they'd start from 0 instead of the real global position), causing
    // nullifier mismatches and broken spend filtering.
    let (h, tree_hex) = checkpoints::MAINNET_CHECKPOINTS
        .iter()
        .find(|(h, _)| *h == 5_236_346)
        .expect("checkpoint 5236346 present");

    let bytes = simd::hex::hex_string_to_bytes(tree_hex);
    let tree: CommitmentTree<Node, 32> =
        read_commitment_tree(Cursor::new(bytes)).expect("parse tree");
    let size = tree.size();

    println!("checkpoint height: {}", h);
    println!("tree size on native: {}", size);
    assert!(
        size > 0,
        "checkpoint tree should have non-zero size; got {}",
        size
    );
}

#[test]
fn every_nontrivial_checkpoint_reports_nonzero_size() {
    for (h, tree_hex) in checkpoints::MAINNET_CHECKPOINTS {
        if *tree_hex == "000000" {
            // first checkpoint is an empty tree, size 0 is correct
            continue;
        }
        let bytes = simd::hex::hex_string_to_bytes(tree_hex);
        let tree: CommitmentTree<Node, 32> =
            read_commitment_tree(Cursor::new(bytes)).expect("parse tree");
        assert!(
            tree.size() > 0,
            "checkpoint {} reports size 0 despite non-empty hex",
            h
        );
    }
}
