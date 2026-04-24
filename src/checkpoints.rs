//! Embedded mainnet Sapling checkpoints.
//!
//! Each entry is `(block_height, commitment_tree_hex)`. New wallets start
//! at the latest checkpoint at or below their birthday height, skipping
//! the per-block witness advances that would otherwise be needed.

mod data;

pub use data::MAINNET_CHECKPOINTS;

/// Return the closest checkpoint at or before the given block height.
/// Returns `(height, commitment_tree_hex)`.
pub fn get_checkpoint(block_height: i32) -> (i32, &'static str) {
    MAINNET_CHECKPOINTS
        .iter()
        .rev()
        .find(|cp| cp.0 <= block_height)
        .copied()
        .unwrap_or(MAINNET_CHECKPOINTS[0])
}
