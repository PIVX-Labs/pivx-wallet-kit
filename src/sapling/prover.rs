//! Sapling proving parameter verification and parsing.
//!
//! The kit does not touch the filesystem or network — consumers are
//! responsible for sourcing the raw bytes (from an on-disk cache, an HTTPS
//! download, or a bundled asset). Once bytes are in hand, pass them to
//! [`verify_and_load_params`] to validate their SHA256 against the pinned
//! mainnet hashes and parse them into the proving key types.

use crate::params::{OUTPUT_PARAMS_SHA256, SPEND_PARAMS_SHA256};
use sapling::circuit::{OutputParameters, SpendParameters};
use sha2::{Digest, Sha256};
use std::error::Error;

/// Loaded Groth16 proving parameter pair: `(output_params, spend_params)`.
pub type SaplingProver = (OutputParameters, SpendParameters);

fn sha256_hex(data: &[u8]) -> String {
    crate::simd::hex::bytes_to_hex_string(&Sha256::digest(data))
}

/// Verify `output_bytes` and `spend_bytes` against pinned SHA256 hashes,
/// then parse them into Sapling proving key types.
///
/// Consumers call this once per session after loading the parameter files,
/// then pass the resulting `SaplingProver` into transaction builders.
pub fn verify_and_load_params(
    output_bytes: &[u8],
    spend_bytes: &[u8],
) -> Result<SaplingProver, Box<dyn Error>> {
    if sha256_hex(output_bytes) != OUTPUT_PARAMS_SHA256 {
        return Err("SHA256 mismatch for sapling output parameters".into());
    }
    if sha256_hex(spend_bytes) != SPEND_PARAMS_SHA256 {
        return Err("SHA256 mismatch for sapling spend parameters".into());
    }

    let output_params = OutputParameters::read(output_bytes, false)?;
    let spend_params = SpendParameters::read(spend_bytes, false)?;

    Ok((output_params, spend_params))
}
