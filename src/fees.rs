//! Component-based fee estimation for PIVX transactions.

/// Estimate the fee (in satoshis) for a transaction by component count.
///
/// Flat rate of 1000 sat/byte applied to a conservative size model:
/// - 948 bytes per Sapling output
/// - 384 bytes per Sapling input
/// - 180 bytes per transparent input (signed P2PKH)
/// - 34 bytes per transparent output
/// - 100 bytes of transaction overhead
#[inline]
pub fn estimate_fee(
    transparent_input_count: u64,
    transparent_output_count: u64,
    sapling_input_count: u64,
    sapling_output_count: u64,
) -> u64 {
    const FEE_PER_BYTE: u64 = 1000;
    FEE_PER_BYTE
        * (sapling_output_count * 948
            + sapling_input_count * 384
            + transparent_input_count * 180
            + transparent_output_count * 34
            + 100)
}

/// Legacy v1 transparent-only fee estimator (10 sat/byte).
///
/// Used by the raw P2PKH builder that bypasses the librustpivx v3 transaction
/// format. Matches the pre-kit agent-kit behaviour: ~150 bytes/input, ~34
/// bytes/output, ~10 bytes overhead.
#[inline]
pub fn estimate_raw_transparent_fee(input_count: usize, output_count: usize) -> u64 {
    let est_size = input_count * 150 + output_count * 34 + 10;
    (est_size as u64) * 10
}
