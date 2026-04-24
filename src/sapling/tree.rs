//! Sapling incremental commitment tree helpers.

use crate::sapling::sync::DEPTH;
use incrementalmerkletree::frontier::CommitmentTree;
use pivx_primitives::merkle_tree::read_commitment_tree;
use sapling::Node;
use std::error::Error;
use std::io::Cursor;

/// Compute the sapling root hash from a hex-encoded commitment tree, in the
/// byte-reversed form that matches the PIVX node's `finalsaplingroot` field.
pub fn get_sapling_root(tree_hex: &str) -> Result<String, Box<dyn Error>> {
    let tree: CommitmentTree<Node, { DEPTH }> =
        read_commitment_tree(Cursor::new(crate::simd::hex::hex_string_to_bytes(tree_hex)))?;
    let root_bytes = tree.root().to_bytes();
    let reversed: Vec<u8> = root_bytes.iter().rev().cloned().collect();
    Ok(crate::simd::hex::bytes_to_hex_string(&reversed))
}

/// Compare a wallet's local sapling root against a network-reported one.
///
/// Empty `network_root` is treated as "unknown" (no comparison performed).
pub fn roots_match(local_tree_hex: &str, network_root: &str) -> Result<bool, Box<dyn Error>> {
    if network_root.is_empty() {
        return Ok(true);
    }
    let our_root = get_sapling_root(local_tree_hex)?;
    Ok(our_root == network_root)
}
