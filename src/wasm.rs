//! WASM bindings — class-style API for JS/TS consumers.
//!
//! Surface:
//!
//!   - `Wallet` — owns the wallet state and secret material.
//!   - `SaplingParams` — holds the verified Groth16 proving keys.
//!   - `Mnemonic` — static namespace for BIP39 helpers.
//!   - `Fee` — static namespace for stateless fee math.
//!   - free `verify_message`, `parse_*`, `format_*`, `get_*` for
//!     pure stateless ops that don't fit any of the above.
//!
//! Native consumers use the underlying modules (`pivx_wallet_kit::wallet`,
//! `pivx_wallet_kit::keys`, etc.) directly — this module is a thin
//! adapter that handles JsValue / serde / wasm-bindgen wiring.

use crate::sapling::builder::TransactionResult;
use crate::sapling::prover;
use crate::sapling::sync::{HandleBlocksResult, ShieldBlock};
use crate::transparent::builder::{SpentOutpoint, TransparentTransactionResult};
use crate::wallet::{SerializedNote, SerializedUTXO, WalletData};
use wasm_bindgen::prelude::*;

#[cfg(feature = "multicore")]
pub use wasm_bindgen_rayon::init_thread_pool;

fn js_err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

// ---------------------------------------------------------------------------
// Mnemonic namespace
// ---------------------------------------------------------------------------

/// BIP39 mnemonic helpers. All methods are static; this struct is
/// `pub` only because wasm-bindgen needs a class to attach the
/// statics to in the generated `.d.ts`.
#[wasm_bindgen]
pub struct Mnemonic;

#[wasm_bindgen]
impl Mnemonic {
    /// Generate a fresh BIP39 mnemonic. `words` selects the length:
    /// one of 12, 15, 18, 21, or 24. Defaults to 12 (the PIVX Labs
    /// convention) when omitted or zero.
    #[wasm_bindgen(js_name = generate)]
    pub fn generate(words: Option<u32>) -> Result<String, JsError> {
        use rand_core::RngCore;
        let n = match words.unwrap_or(0) {
            0 | 12 => 12,
            15 => 15,
            18 => 18,
            21 => 21,
            24 => 24,
            other => {
                return Err(JsError::new(&format!(
                    "words must be one of 12, 15, 18, 21, 24; got {}",
                    other
                )));
            }
        };
        let entropy_bytes = match n {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => unreachable!(),
        };
        let mut entropy = vec![0u8; entropy_bytes];
        rand_core::OsRng.fill_bytes(&mut entropy);
        let m = bip39::Mnemonic::from_entropy(&entropy).map_err(js_err)?;
        Ok(m.to_string())
    }

    /// Check whether `phrase` is a syntactically valid BIP39 mnemonic.
    #[wasm_bindgen(js_name = validate)]
    pub fn validate(phrase: &str) -> bool {
        bip39::Mnemonic::parse_normalized(phrase).is_ok()
    }

    /// Derive the 64-byte BIP39 seed. Niche — most consumers should
    /// not need this; prefer constructing a `Wallet` from the
    /// mnemonic directly. Returned bytes are the caller's
    /// responsibility to wipe (no Zeroizing wrapper survives the
    /// JS↔WASM boundary).
    #[wasm_bindgen(js_name = toSeed)]
    pub fn to_seed(phrase: &str) -> Result<Vec<u8>, JsError> {
        let m = bip39::Mnemonic::parse_normalized(phrase).map_err(js_err)?;
        Ok(m.to_seed("").to_vec())
    }
}

// ---------------------------------------------------------------------------
// Fee namespace
// ---------------------------------------------------------------------------

/// Stateless fee math. Use these when you're not building through a
/// `Wallet` and want to size a hypothetical tx by component counts.
/// For "what would `wallet.send*` actually charge?" — see
/// `Wallet.estimateSend{Shield,Transparent}Fee` instead.
#[wasm_bindgen]
pub struct Fee;

#[wasm_bindgen]
impl Fee {
    /// PIVX v3 (Sapling-bundle) tx fee — for any tx that touches
    /// shield: shield→shield, shield→transparent, transparent→shield.
    #[wasm_bindgen(js_name = shieldTx)]
    pub fn shield_tx(
        transparent_inputs: u64,
        transparent_outputs: u64,
        sapling_inputs: u64,
        sapling_outputs: u64,
    ) -> u64 {
        crate::fees::estimate_fee(
            transparent_inputs,
            transparent_outputs,
            sapling_inputs,
            sapling_outputs,
        )
    }

    /// PIVX v1 (raw P2PKH) tx fee — for pure transparent → transparent.
    #[wasm_bindgen(js_name = transparentTx)]
    pub fn transparent_tx(inputs: u64, outputs: u64) -> u64 {
        crate::fees::estimate_raw_transparent_fee(inputs as usize, outputs as usize)
    }
}

// ---------------------------------------------------------------------------
// SaplingParams class
// ---------------------------------------------------------------------------

/// Loaded Groth16 proving parameters. Construct **once** per session
/// (after sourcing the bytes from cache or a CDN), then pass into
/// `Wallet.sendShield` / `Wallet.sendTransparent` as needed. Each
/// instance carries the full proving keys (~50MB) — do NOT load
/// multiple instances in parallel.
#[wasm_bindgen]
pub struct SaplingParams {
    inner: prover::SaplingProver,
}

#[wasm_bindgen]
impl SaplingParams {
    /// Verify SHA256 hashes against the kit's pinned mainnet values
    /// and parse into proving keys.
    #[wasm_bindgen(constructor)]
    pub fn new(output_bytes: &[u8], spend_bytes: &[u8]) -> Result<SaplingParams, JsError> {
        let inner =
            prover::verify_and_load_params(output_bytes, spend_bytes).map_err(js_err)?;
        Ok(SaplingParams { inner })
    }
}

// ---------------------------------------------------------------------------
// Wallet class
// ---------------------------------------------------------------------------

/// The kit's primary handle on a wallet. Owns the wallet state +
/// secret material; mutations are in place; serialization is
/// explicit (`toSerializedEncrypted` for production;
/// `toSerializedPlaintext` for debug only).
///
/// LOCKED state: a wallet loaded from `fromSerialized` of an
/// encrypted blob has its seed + mnemonic in ciphertext. Methods that
/// need them (`signMessage`, `sendShield`, `sendTransparent`,
/// address derivation) error until `unlock(key)` succeeds.
#[wasm_bindgen]
pub struct Wallet {
    inner: WalletData,
    locked: bool,
}

#[wasm_bindgen]
impl Wallet {
    // ─── Construction ───────────────────────────────────────────

    /// Create a brand-new wallet with a fresh BIP39 mnemonic.
    /// `current_height` is the chain tip at creation time, used to
    /// set the wallet's birthday for fast initial sync.
    #[wasm_bindgen(js_name = create)]
    pub fn create(current_height: u32) -> Result<Wallet, JsError> {
        let inner = crate::wallet::create_new_wallet(current_height).map_err(js_err)?;
        Ok(Wallet { inner, locked: false })
    }

    /// Import from an existing BIP39 mnemonic.
    #[wasm_bindgen(js_name = fromMnemonic)]
    pub fn from_mnemonic(mnemonic: &str, current_height: u32) -> Result<Wallet, JsError> {
        let inner = crate::wallet::import_wallet(mnemonic, current_height).map_err(js_err)?;
        Ok(Wallet { inner, locked: false })
    }

    /// Restore from JSON produced by `toSerializedPlaintext` /
    /// `toSerializedEncrypted`. Returns a wallet in the LOCKED state
    /// if the JSON was encrypted; call `unlock(key)` next.
    #[wasm_bindgen(js_name = fromSerialized)]
    pub fn from_serialized(json: &str) -> Result<Wallet, JsError> {
        let inner: WalletData = serde_json::from_str(json).map_err(js_err)?;
        // Detect lock state: the mnemonic field is plaintext if
        // BIP39-parseable; ciphertext otherwise. (The seed is
        // 32 bytes either way, so we can't distinguish on it alone.)
        let locked = bip39::Mnemonic::parse_normalized(&inner.mnemonic).is_err();
        Ok(Wallet { inner, locked })
    }

    // ─── Persistence ────────────────────────────────────────────

    /// **DANGER: PLAINTEXT.** Returns a JSON string containing the
    /// wallet's seed and mnemonic in cleartext. Only useful for
    /// testnet / debug / cross-implementation testing — NEVER persist
    /// the output of this method to disk or send it over the wire.
    /// Use [`Wallet::toSerializedEncrypted`] for production persistence.
    ///
    /// The intentionally-loud name is the footgun guard: any code
    /// review that sees `toSerializedPlaintext` should immediately
    /// trigger "wait, why?".
    #[wasm_bindgen(js_name = toSerializedPlaintext)]
    pub fn to_serialized_plaintext(&self) -> Result<String, JsError> {
        serde_json::to_string(&self.inner).map_err(js_err)
    }

    /// AES-CTR-encrypted JSON. The 32-byte `key` is the consumer's
    /// responsibility (typically derived from a passphrase via PBKDF2
    /// or similar).
    #[wasm_bindgen(js_name = toSerializedEncrypted)]
    pub fn to_serialized_encrypted(&self, key: &[u8]) -> Result<String, JsError> {
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| JsError::new("key must be exactly 32 bytes"))?;
        crate::wallet::serialize_encrypted(&self.inner, &key).map_err(js_err)
    }

    /// Decrypt a wallet that was loaded from `fromSerialized` of an
    /// encrypted blob. Errs cleanly on wrong key — the wallet stays
    /// LOCKED, no partial state. Idempotent if already unlocked.
    #[wasm_bindgen(js_name = unlock)]
    pub fn unlock(&mut self, key: &[u8]) -> Result<(), JsError> {
        if !self.locked {
            return Ok(());
        }
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| JsError::new("key must be exactly 32 bytes"))?;
        crate::wallet::decrypt_secrets(&mut self.inner, &key).map_err(js_err)?;
        self.locked = false;
        Ok(())
    }

    /// True if the wallet is currently usable. Methods that need
    /// the seed / mnemonic (signing, sending, address derivation)
    /// require `isUnlocked() == true`.
    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        !self.locked
    }

    // ─── Lifecycle ──────────────────────────────────────────────

    /// Drop cached notes / UTXOs / commitment-tree position back to
    /// the birthday checkpoint. Useful for re-syncing from scratch.
    /// Seed + viewing key untouched.
    #[wasm_bindgen(js_name = resetToCheckpoint)]
    pub fn reset_to_checkpoint(&mut self) -> Result<(), JsError> {
        crate::wallet::reset_to_checkpoint(&mut self.inner).map_err(js_err)
    }

    // ─── Read-only state ────────────────────────────────────────

    #[wasm_bindgen(js_name = shieldAddress)]
    pub fn shield_address(&self) -> Result<String, JsError> {
        crate::keys::get_default_address(&self.inner.extfvk).map_err(js_err)
    }

    #[wasm_bindgen(js_name = transparentAddress)]
    pub fn transparent_address(&self) -> Result<String, JsError> {
        self.ensure_unlocked()?;
        self.inner.get_transparent_address().map_err(js_err)
    }

    #[wasm_bindgen(js_name = shieldBalanceSat)]
    pub fn shield_balance_sat(&self) -> u64 {
        self.inner.get_balance()
    }

    #[wasm_bindgen(js_name = transparentBalanceSat)]
    pub fn transparent_balance_sat(&self) -> u64 {
        self.inner.get_transparent_balance()
    }

    #[wasm_bindgen(js_name = totalBalanceSat)]
    pub fn total_balance_sat(&self) -> u64 {
        self.inner.get_balance() + self.inner.get_transparent_balance()
    }

    #[wasm_bindgen(js_name = lastBlock)]
    pub fn last_block(&self) -> i32 {
        self.inner.last_block
    }

    #[wasm_bindgen(js_name = birthdayHeight)]
    pub fn birthday_height(&self) -> i32 {
        self.inner.birthday_height
    }

    /// Snapshot of unspent shield notes. Returned by value; callers
    /// who want a live read should re-call after sync.
    #[wasm_bindgen(js_name = notes)]
    pub fn notes(&self) -> NotesOut {
        NotesOut {
            notes: self.inner.unspent_notes.clone(),
        }
    }

    /// Snapshot of unspent transparent UTXOs.
    #[wasm_bindgen(js_name = utxos)]
    pub fn utxos(&self) -> UtxosOut {
        UtxosOut {
            utxos: self.inner.unspent_utxos.clone(),
        }
    }

    // ─── Sync ───────────────────────────────────────────────────

    /// Apply parsed shield blocks to the wallet — decrypts notes
    /// belonging to this wallet, advances the commitment tree,
    /// extracts nullifiers (potential spends of our notes), and
    /// removes any of our own notes that were spent in this batch.
    /// Returns the deltas; the wallet is mutated in place.
    ///
    /// On error the wallet's note set is left untouched — the caller
    /// can retry with the same or a different block batch without
    /// reloading from disk.
    #[wasm_bindgen(js_name = applyBlocks)]
    pub fn apply_blocks(
        &mut self,
        blocks: ShieldBlocksInput,
    ) -> Result<HandleBlocksResult, JsError> {
        // Clone instead of mem::take: if handle_blocks errors, we
        // do not want to strand the wallet with an empty note set.
        // The H6 zero-clone path is preserved for native consumers
        // that can hand handle_blocks an owned Vec directly; the
        // wasm wrapper accepts the per-note allocation cost in
        // exchange for state-corruption safety.
        let existing = self.inner.unspent_notes.clone();
        let result = crate::sapling::sync::handle_blocks(
            &self.inner.commitment_tree,
            blocks.blocks,
            &self.inner.extfvk,
            existing,
        )
        .map_err(js_err)?;
        // `updated_notes` is the post-batch state of existing notes
        // (witnesses advanced); `new_notes` is what was newly
        // discovered. handle_blocks does not filter out own notes
        // that were spent — the nullifier list contains every spend
        // in the batch, not just ours, so we let
        // finalize_transaction do the matching.
        self.inner.commitment_tree = result.commitment_tree.clone();
        self.inner.unspent_notes = result.updated_notes.clone();
        self.inner.unspent_notes.extend(result.new_notes.clone());
        self.inner.finalize_transaction(&result.nullifiers);
        Ok(result)
    }

    /// Replace the transparent UTXO set. Typical pattern: explorer →
    /// `parseBlockbookUtxos` → `setUtxos`.
    #[wasm_bindgen(js_name = setUtxos)]
    pub fn set_utxos(&mut self, utxos: UtxosInput) {
        self.inner.unspent_utxos = utxos.utxos;
    }

    /// Sign an arbitrary message with the wallet's transparent key.
    /// Returns a base64 signature compatible with PIVX Core's
    /// `verifymessage` RPC.
    #[wasm_bindgen(js_name = signMessage)]
    pub fn sign_message(&self, message: &str) -> Result<String, JsError> {
        self.ensure_unlocked()?;
        let bip39_seed = self.inner.get_bip39_seed().map_err(js_err)?;
        let (_addr, _pk, privkey) =
            crate::keys::transparent_key_from_bip39_seed(&bip39_seed, 0, 0).map_err(js_err)?;
        crate::messages::sign_message(&privkey, message).map_err(js_err)
    }

    // ─── Tx building ────────────────────────────────────────────

    /// Build a shield-source transaction (notes → anywhere). `params`
    /// is required since shield-source txs always emit a Sapling bundle.
    #[wasm_bindgen(js_name = sendShield)]
    pub fn send_shield(
        &mut self,
        opts: SendShieldOpts,
        params: &SaplingParams,
    ) -> Result<TransactionResult, JsError> {
        self.ensure_unlocked()?;
        crate::sapling::builder::create_shield_transaction(
            &mut self.inner,
            &opts.to_address,
            opts.amount_sat,
            &opts.memo,
            opts.block_height,
            &params.inner,
        )
        .map_err(js_err)
    }

    /// Build a transparent-to-transparent transaction (v1 P2PKH).
    /// No Sapling params needed.
    #[wasm_bindgen(js_name = sendTransparentToTransparent)]
    pub fn send_transparent_to_transparent(
        &mut self,
        to_address: &str,
        amount_sat: u64,
    ) -> Result<TransparentTransactionResult, JsError> {
        use pivx_primitives::consensus::{MAIN_NETWORK, NetworkConstants};
        self.ensure_unlocked()?;
        if to_address.starts_with(MAIN_NETWORK.hrp_sapling_payment_address()) {
            return Err(JsError::new(
                "to_address is a shield address — use sendTransparentToShield instead",
            ));
        }
        let bip39_seed = self.inner.get_bip39_seed().map_err(js_err)?;
        crate::transparent::builder::create_raw_transparent_transaction(
            &mut self.inner,
            &bip39_seed,
            to_address,
            amount_sat,
            0,
            None,
        )
        .map_err(js_err)
    }

    /// Build a transparent→shield transaction (v3 with Sapling output).
    /// Both `block_height` (chain tip + 1) and proving `params` are
    /// required.
    #[wasm_bindgen(js_name = sendTransparentToShield)]
    pub fn send_transparent_to_shield(
        &mut self,
        to_address: &str,
        amount_sat: u64,
        block_height: u32,
        params: &SaplingParams,
    ) -> Result<TransparentTransactionResult, JsError> {
        use pivx_primitives::consensus::{MAIN_NETWORK, NetworkConstants};
        self.ensure_unlocked()?;
        if !to_address.starts_with(MAIN_NETWORK.hrp_sapling_payment_address()) {
            return Err(JsError::new(
                "to_address is not a shield address — use sendTransparentToTransparent instead",
            ));
        }
        let bip39_seed = self.inner.get_bip39_seed().map_err(js_err)?;
        crate::transparent::builder::create_raw_transparent_transaction(
            &mut self.inner,
            &bip39_seed,
            to_address,
            amount_sat,
            block_height,
            Some(&params.inner),
        )
        .map_err(js_err)
    }

    // ─── Fee estimation ─────────────────────────────────────────

    /// Fee for `sendShield(to, amount)` against the current note set.
    /// Calls into the same selection routine the real send uses, so the
    /// returned fee is exactly what `sendShield` will charge against
    /// the same note set. Errs if shield balance is insufficient.
    ///
    /// `to_address` decides the destination shape: shield→shield uses
    /// `(0 t-out, 2 s-out)`; shield→transparent uses `(1 t-out, 2 s-out)`.
    #[wasm_bindgen(js_name = estimateSendShieldFee)]
    pub fn estimate_send_shield_fee(
        &self,
        to_address: &str,
        amount_sat: u64,
    ) -> Result<u64, JsError> {
        use pivx_primitives::consensus::{MAIN_NETWORK, NetworkConstants};
        let dest_is_shield =
            to_address.starts_with(MAIN_NETWORK.hrp_sapling_payment_address());
        let (t_outs, s_outs) = if dest_is_shield { (0u64, 2u64) } else { (1u64, 2u64) };
        let selection = crate::sapling::builder::select_shield_notes(
            &self.inner.unspent_notes,
            amount_sat,
            t_outs,
            s_outs,
        )
        .map_err(js_err)?;
        Ok(selection.fee)
    }

    /// Fee for `sendTransparent*` against the current UTXO set.
    /// Auto-routes by destination prefix (v1 P2PKH for D…, v3 for ps1…).
    /// Errs if transparent balance is insufficient.
    ///
    /// Uses the same fee shape the matching builder will charge:
    /// shield destination → `create_shielding_transaction` (which
    /// hardcodes `(n, 0, 0, 2)`); transparent destination →
    /// `create_raw_transparent_transaction` (`(n, 2)` v1 P2PKH).
    #[wasm_bindgen(js_name = estimateSendTransparentFee)]
    pub fn estimate_send_transparent_fee(
        &self,
        to_address: &str,
        amount_sat: u64,
    ) -> Result<u64, JsError> {
        use pivx_primitives::consensus::{MAIN_NETWORK, NetworkConstants};
        let dest_is_shield =
            to_address.starts_with(MAIN_NETWORK.hrp_sapling_payment_address());
        let mut utxos: Vec<u64> =
            self.inner.unspent_utxos.iter().map(|u| u.amount).collect();
        utxos.sort_unstable_by(|a, b| b.cmp(a));
        let mut total = 0u64;
        for (i, v) in utxos.iter().enumerate() {
            total = total.saturating_add(*v);
            let n = (i + 1) as u64;
            let fee = if dest_is_shield {
                // create_shielding_transaction hardcodes 2 sapling
                // outputs in its fee math (see transparent/builder.rs:
                // sapling_output_count = 2). Match exactly so a
                // follow-up `sendTransparentToShield(amount, …)` does
                // not fail with "Insufficient public balance" because
                // the estimator under-quoted.
                crate::fees::estimate_fee(n, 0, 0, 2)
            } else {
                // v1 P2PKH: N inputs, dest + change
                crate::fees::estimate_raw_transparent_fee(n as usize, 2)
            };
            if total >= amount_sat.saturating_add(fee) {
                return Ok(fee);
            }
        }
        Err(JsError::new(&format!(
            "insufficient transparent balance: have {} sat, need {} + fee",
            total, amount_sat
        )))
    }

    // ─── External-broadcast finalisers ──────────────────────────

    /// Mark notes spent after broadcasting a tx that this wallet
    /// built externally (i.e. without going through `sendShield`).
    #[wasm_bindgen(js_name = finalizeShieldSpend)]
    pub fn finalize_shield_spend(&mut self, nullifiers: Vec<String>) {
        self.inner.finalize_transaction(&nullifiers);
    }

    /// Mark UTXOs spent after broadcasting an externally-built
    /// transparent tx. Use the `spent` field returned by
    /// `sendTransparent` (or the equivalent off-wallet build).
    #[wasm_bindgen(js_name = finalizeTransparentSpend)]
    pub fn finalize_transparent_spend(&mut self, spent: SpentInput) {
        self.inner.finalize_transparent_send(&spent.spent);
    }

    // ─── Internal ───────────────────────────────────────────────

    fn ensure_unlocked(&self) -> Result<(), JsError> {
        if self.locked {
            return Err(JsError::new(
                "wallet is locked — call unlock(key) first",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Send-method input shapes
// ---------------------------------------------------------------------------

/// Inputs for `Wallet.sendShield`. The proving params are passed
/// as a separate `&SaplingParams` arg to the method (tsify-derived
/// structs can't reference wasm-bindgen classes through their fields).
#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(from_wasm_abi)]
pub struct SendShieldOpts {
    pub to_address: String,
    pub amount_sat: u64,
    pub memo: String,
    pub block_height: u32,
}

// ---------------------------------------------------------------------------
// Other tsify input/output containers (lift Vec<T> across boundary)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(from_wasm_abi)]
pub struct ShieldBlocksInput {
    pub blocks: Vec<ShieldBlock>,
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(from_wasm_abi)]
pub struct UtxosInput {
    pub utxos: Vec<SerializedUTXO>,
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(from_wasm_abi)]
pub struct SpentInput {
    pub spent: Vec<SpentOutpoint>,
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi)]
pub struct NotesOut {
    pub notes: Vec<SerializedNote>,
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi)]
pub struct UtxosOut {
    pub utxos: Vec<SerializedUTXO>,
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi)]
pub struct ShieldBlocksOut {
    pub blocks: Vec<ShieldBlock>,
}

#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi)]
pub struct BlockbookUtxosOut {
    pub utxos: Vec<SerializedUTXO>,
}

// ---------------------------------------------------------------------------
// Free utility functions
// ---------------------------------------------------------------------------

/// Verify a PIVX Core-format base64 signature against the claimed address.
#[wasm_bindgen(js_name = verifyMessage)]
pub fn verify_message(
    address: &str,
    message: &str,
    signature_b64: &str,
) -> Result<bool, JsError> {
    crate::messages::verify_message(address, message, signature_b64).map_err(js_err)
}

/// Parse a PIV amount string (e.g. `"1.23456789"`) into satoshis.
#[wasm_bindgen(js_name = parsePivToSat)]
pub fn parse_piv_to_sat(s: &str) -> Result<u64, JsError> {
    crate::amount::parse_piv_to_sat(s).map_err(|e| JsError::new(&e))
}

/// Format a satoshi amount as a PIV string with 8 decimal places.
#[wasm_bindgen(js_name = formatSatToPiv)]
pub fn format_sat_to_piv(sat: u64) -> String {
    crate::amount::format_sat_to_piv(sat)
}

/// Default per-call cap on blocks parsed from a shield stream.
pub const DEFAULT_MAX_SHIELD_BLOCKS: usize = 10_000;

/// Parse a binary shield stream (the kit's wire format) into
/// `ShieldBlock[]`.
#[wasm_bindgen(js_name = parseShieldStream)]
pub fn parse_shield_stream(
    bytes: &[u8],
    max_blocks: Option<usize>,
) -> Result<ShieldBlocksOut, JsError> {
    use std::io::Cursor;
    let cap = max_blocks.unwrap_or(DEFAULT_MAX_SHIELD_BLOCKS);
    let mut cursor = Cursor::new(bytes);
    let blocks = crate::sync::parse_next_blocks(&mut cursor, cap)
        .map_err(js_err)?
        .unwrap_or_default();
    Ok(ShieldBlocksOut { blocks })
}

/// Convert a Blockbook v2 `/api/v2/utxo/{address}` response into
/// `SerializedUTXO[]`. Input is the raw JSON array; the caller wires
/// Blockbook's schema directly so we accept `any` to be permissive
/// about minor shape drift on Blockbook's side.
#[wasm_bindgen(js_name = parseBlockbookUtxos)]
pub fn parse_blockbook_utxos(raw: JsValue) -> Result<BlockbookUtxosOut, JsError> {
    let raw: Vec<serde_json::Value> = serde_wasm_bindgen::from_value(raw).map_err(js_err)?;
    Ok(BlockbookUtxosOut {
        utxos: crate::wallet::parse_blockbook_utxos(&raw),
    })
}

/// `(height, commitment_tree_hex)` of the nearest mainnet checkpoint
/// at or below `block_height`.
#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi)]
pub struct Checkpoint {
    pub height: i32,
    pub commitment_tree_hex: String,
}

#[wasm_bindgen(js_name = getCheckpoint)]
pub fn get_checkpoint(block_height: i32) -> Checkpoint {
    let (height, tree) = crate::checkpoints::get_checkpoint(block_height);
    Checkpoint {
        height,
        commitment_tree_hex: tree.to_string(),
    }
}

/// Compute the byte-reversed Sapling root from a hex commitment tree.
/// Matches PIVX Core's `finalsaplingroot` field on a block header.
#[wasm_bindgen(js_name = getSaplingRoot)]
pub fn get_sapling_root(tree_hex: &str) -> Result<String, JsError> {
    crate::sapling::tree::get_sapling_root(tree_hex).map_err(js_err)
}
