//! Audit embedded checkpoints against independently computed trees.
//!
//! For every consecutive checkpoint pair `(a, b)` covered by a recorded stream,
//! starts from `a`'s stored tree, applies every shield block in `(a, b]`, and
//! compares the result to `b`'s stored tree.
//!
//! A mismatch means the stored tree does not correspond to the height it is
//! filed under. That is what the pre-fix stream parser would produce if a
//! generator sliced a parsed block list at a target height, since the block at
//! that height carried the *next* block's transactions. Recording the last
//! block of a fetched window instead was immune, because the final tree of a
//! whole window was always correct.
//!
//! Correctness propagates forward: if `a`'s tree is right, a matching `b` is
//! right too. So an audit chain is only as good as its earliest anchor.
//!
//! Run it before publishing new checkpoints:
//!
//! ```text
//! curl -o stream.bin 'https://<node>/mainnet/getshielddata?startBlock=<H>'
//! cargo run --release --example checkpoint_audit stream.bin <H>
//! ```
//!
//! `<H>` must be at or below `previous_checkpoint + 1` for the pair ending at
//! the new checkpoint to be auditable. The recording is large (fetching from
//! 2,700,001, the first checkpoint, returned 225 MB), which is why this is a
//! manual tool rather than a test.
//!
//! Every embedded checkpoint has been audited this way: all 63 pairs match,
//! from the empty tree at 2,700,000 through to 5,236,346. Because the chain
//! starts from an empty tree, that is absolute verification rather than mutual
//! consistency, so it needs no trusted anchor.

use pivx_wallet_kit::sapling::sync::{ShieldBlock, handle_blocks};
use pivx_wallet_kit::{checkpoints, sync, wallet};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn tree_size(hex: &str) -> usize {
    use ::sapling::Node;
    use incrementalmerkletree::frontier::CommitmentTree;
    use pivx_primitives::merkle_tree::read_commitment_tree;
    let bytes = pivx_wallet_kit::simd::hex::hex_string_to_bytes(hex);
    let tree: CommitmentTree<Node, 32> =
        read_commitment_tree(std::io::Cursor::new(bytes)).unwrap();
    tree.size()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: checkpoint_audit <stream> <startBlock>");
    // The `startBlock` the recording was fetched with. A pair is auditable when
    // the recording begins at or before the first block it needs, which is not
    // the same as the first block that happens to carry shield data.
    let fetch_start: i32 = args.next().expect("startBlock required").parse().unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let mut cursor = std::io::Cursor::new(&bytes);
    let all = sync::parse_next_blocks(&mut cursor, usize::MAX).unwrap().unwrap();

    let lowest = all.iter().map(|b| b.height).min().unwrap() as i32;
    let highest = all.iter().map(|b| b.height).max().unwrap() as i32;
    println!("recording: fetched from {fetch_start}, shield blocks {lowest}..={highest} ({})\n", all.len());

    let w = wallet::import_wallet(TEST_MNEMONIC, 100).unwrap();
    let cps = checkpoints::MAINNET_CHECKPOINTS;
    let (mut ok, mut bad, mut skipped) = (0, 0, 0);

    for pair in cps.windows(2) {
        let (from, from_tree) = pair[0];
        let (to, stored) = pair[1];
        // Need every block in (from, to] to be present in the recording.
        if from + 1 < fetch_start || to > highest {
            skipped += 1;
            continue;
        }

        // `ShieldBlock` is not `Clone`, so rebuild the ones in range.
        let in_range: Vec<ShieldBlock> = all
            .iter()
            .filter(|b| (b.height as i32) > from && (b.height as i32) <= to)
            .map(|b| ShieldBlock { height: b.height, txs: b.txs.clone() })
            .collect();
        let txs: usize = in_range.iter().map(|b| b.txs.len()).sum();
        let top = in_range.iter().map(|b| b.height).max().unwrap_or(0);

        let result = handle_blocks(from_tree, in_range, &w.extfvk, vec![]).unwrap();
        let matches = result.commitment_tree == stored;
        if matches {
            ok += 1;
        } else {
            bad += 1;
        }

        println!(
            "{from} -> {to}: {txs} txs, top block {top}, leaves {} -> {} (stored {}) {}",
            tree_size(from_tree),
            tree_size(&result.commitment_tree),
            tree_size(stored),
            if matches { "MATCH" } else { "MISMATCH" }
        );
        if !matches {
            println!("    computed {}", &result.commitment_tree[..64]);
            println!("    stored   {}", &stored[..64]);
        }
    }

    println!("\n{ok} match, {bad} mismatch, {skipped} not covered by this recording");
}
