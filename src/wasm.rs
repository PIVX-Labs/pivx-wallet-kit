//! WASM bindings for browser and Node.js consumers.
//!
//! Only compiled for `wasm32-*` targets. Native consumers use the Rust API
//! directly — this module is a thin re-export layer that handles JsValue /
//! serde conversion and stores the (heavy) Sapling prover in a thread-local
//! cell so it can be loaded once and reused across build calls.

use crate::sapling::prover::SaplingProver;
use crate::wallet::WalletData;
use std::sync::OnceLock;
use wasm_bindgen::prelude::*;

/// Process-global prover cache.
///
/// Uses `OnceLock` rather than `thread_local!` so the prover survives across
/// rayon Web Workers under the `multicore` feature — each worker has its own
/// TLS, so a TLS-scoped cache would be invisible on non-main threads.
static PROVER: OnceLock<SaplingProver> = OnceLock::new();

#[cfg(feature = "multicore")]
pub use wasm_bindgen_rayon::init_thread_pool;

fn to_js_err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

// ---------------------------------------------------------------------------
// Mnemonic
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn generate_mnemonic() -> Result<String, JsError> {
    use rand_core::RngCore;
    let mut entropy = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut entropy);
    let m = bip39::Mnemonic::from_entropy(&entropy).map_err(to_js_err)?;
    Ok(m.to_string())
}

#[wasm_bindgen]
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    bip39::Mnemonic::parse_normalized(mnemonic).is_ok()
}

// ---------------------------------------------------------------------------
// Wallet lifecycle
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn create_wallet(current_height: u32) -> Result<JsValue, JsError> {
    let w = crate::wallet::create_new_wallet(current_height).map_err(to_js_err)?;
    serde_wasm_bindgen::to_value(&w).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn import_wallet(mnemonic: &str, current_height: u32) -> Result<JsValue, JsError> {
    let w = crate::wallet::import_wallet(mnemonic, current_height).map_err(to_js_err)?;
    serde_wasm_bindgen::to_value(&w).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn reset_to_checkpoint(wallet_js: JsValue) -> Result<JsValue, JsError> {
    let mut w: WalletData = serde_wasm_bindgen::from_value(wallet_js).map_err(to_js_err)?;
    crate::wallet::reset_to_checkpoint(&mut w).map_err(to_js_err)?;
    serde_wasm_bindgen::to_value(&w).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn encrypt_wallet(wallet_js: JsValue, key: &[u8]) -> Result<JsValue, JsError> {
    let mut w: WalletData = serde_wasm_bindgen::from_value(wallet_js).map_err(to_js_err)?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| JsError::new("key must be exactly 32 bytes"))?;
    crate::wallet::encrypt_secrets(&mut w, &key).map_err(to_js_err)?;
    serde_wasm_bindgen::to_value(&w).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn decrypt_wallet(wallet_js: JsValue, key: &[u8]) -> Result<JsValue, JsError> {
    let mut w: WalletData = serde_wasm_bindgen::from_value(wallet_js).map_err(to_js_err)?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| JsError::new("key must be exactly 32 bytes"))?;
    crate::wallet::decrypt_secrets(&mut w, &key).map_err(to_js_err)?;
    serde_wasm_bindgen::to_value(&w).map_err(to_js_err)
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn derive_transparent_address(mnemonic: &str) -> Result<String, JsError> {
    crate::keys::get_transparent_address(mnemonic).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn derive_shield_address(extfvk: &str) -> Result<String, JsError> {
    crate::keys::get_default_address(extfvk).map_err(to_js_err)
}

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn get_checkpoint(block_height: i32) -> Result<JsValue, JsError> {
    let (h, tree) = crate::checkpoints::get_checkpoint(block_height);
    serde_wasm_bindgen::to_value(&(h, tree)).map_err(to_js_err)
}

// ---------------------------------------------------------------------------
// Shield sync
// ---------------------------------------------------------------------------

/// Default per-call cap on blocks parsed from a shield stream (prevents a
/// malicious RPC from triggering multi-GB allocations in the browser).
pub const DEFAULT_MAX_SHIELD_BLOCKS: usize = 10_000;

#[wasm_bindgen]
pub fn parse_shield_stream(bytes: &[u8], max_blocks: Option<usize>) -> Result<JsValue, JsError> {
    use std::io::Cursor;
    let cap = max_blocks.unwrap_or(DEFAULT_MAX_SHIELD_BLOCKS);
    let mut cursor = Cursor::new(bytes);
    let mut all_blocks: Vec<crate::sapling::sync::ShieldBlock> = Vec::new();
    while all_blocks.len() < cap {
        let remaining = cap - all_blocks.len();
        match crate::sync::parse_next_blocks(&mut cursor, remaining.min(64)).map_err(to_js_err)? {
            Some(batch) => all_blocks.extend(batch),
            None => break,
        }
    }
    serde_wasm_bindgen::to_value(&all_blocks).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn handle_blocks(
    tree_hex: &str,
    blocks_js: JsValue,
    extfvk: &str,
    notes_js: JsValue,
) -> Result<JsValue, JsError> {
    let blocks: Vec<crate::sapling::sync::ShieldBlock> =
        serde_wasm_bindgen::from_value(blocks_js).map_err(to_js_err)?;
    let notes: Vec<crate::wallet::SerializedNote> =
        serde_wasm_bindgen::from_value(notes_js).map_err(to_js_err)?;

    let result = crate::sapling::sync::handle_blocks(tree_hex, blocks, extfvk, &notes)
        .map_err(to_js_err)?;
    serde_wasm_bindgen::to_value(&result).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn get_sapling_root(tree_hex: &str) -> Result<String, JsError> {
    crate::sapling::tree::get_sapling_root(tree_hex).map_err(to_js_err)
}

// ---------------------------------------------------------------------------
// Prover parameters
// ---------------------------------------------------------------------------

/// Verify and load Sapling proving parameters into the thread-local cell.
///
/// Call this once after downloading or fetching the parameter bytes from
/// cache. Subsequent `build_shield_tx` calls reuse the loaded prover.
#[wasm_bindgen]
pub fn load_sapling_params(output_bytes: &[u8], spend_bytes: &[u8]) -> Result<(), JsError> {
    if PROVER.get().is_some() {
        return Ok(());
    }
    let prover = crate::sapling::prover::verify_and_load_params(output_bytes, spend_bytes)
        .map_err(to_js_err)?;
    let _ = PROVER.set(prover);
    Ok(())
}

#[wasm_bindgen]
pub fn has_sapling_params() -> bool {
    PROVER.get().is_some()
}

// ---------------------------------------------------------------------------
// Transaction builders
// ---------------------------------------------------------------------------

/// Output shape of build_*_tx bindings: `{ result, wallet }` — a JS object with
/// two named fields, not a tuple.
#[derive(serde::Serialize)]
struct BuildTxResult<'a, T: serde::Serialize> {
    result: &'a T,
    wallet: &'a WalletData,
}

#[wasm_bindgen]
pub fn build_shield_tx(
    wallet_js: JsValue,
    to_address: &str,
    amount: u64,
    memo: &str,
    block_height: u32,
) -> Result<JsValue, JsError> {
    let mut w: WalletData = serde_wasm_bindgen::from_value(wallet_js).map_err(to_js_err)?;

    let prover = PROVER
        .get()
        .ok_or_else(|| JsError::new("Sapling prover not loaded — call load_sapling_params first"))?;
    let r = crate::sapling::builder::create_shield_transaction(
        &mut w,
        to_address,
        amount,
        memo,
        block_height,
        prover,
    )
    .map_err(to_js_err)?;

    serde_wasm_bindgen::to_value(&BuildTxResult {
        result: &r,
        wallet: &w,
    })
    .map_err(to_js_err)
}

/// Build a transparent-source transaction (either transparent- or shield-dest).
///
/// Pure transparent→transparent sends do not need the Sapling prover to be
/// loaded — callers can pass `block_height = 0` and skip `load_sapling_params`.
///
/// Shield destinations require `load_sapling_params` to have been called
/// (and `block_height` to be the current chain tip + 1).
#[wasm_bindgen]
pub fn build_transparent_tx(
    wallet_js: JsValue,
    bip39_seed: &[u8],
    to_address: &str,
    amount: u64,
    block_height: u32,
) -> Result<JsValue, JsError> {
    let mut w: WalletData = serde_wasm_bindgen::from_value(wallet_js).map_err(to_js_err)?;

    let r = crate::transparent::builder::create_raw_transparent_transaction(
        &mut w,
        bip39_seed,
        to_address,
        amount,
        block_height,
        PROVER.get(),
    )
    .map_err(to_js_err)?;

    serde_wasm_bindgen::to_value(&BuildTxResult {
        result: &r,
        wallet: &w,
    })
    .map_err(to_js_err)
}

// ---------------------------------------------------------------------------
// Fees
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn estimate_fee(
    transparent_input_count: u64,
    transparent_output_count: u64,
    sapling_input_count: u64,
    sapling_output_count: u64,
) -> u64 {
    crate::fees::estimate_fee(
        transparent_input_count,
        transparent_output_count,
        sapling_input_count,
        sapling_output_count,
    )
}
