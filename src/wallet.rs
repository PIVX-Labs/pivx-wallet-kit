//! In-memory wallet state and pure (de)serialization helpers.
//!
//! Persistence (disk, IndexedDB, etc.) is the consumer's responsibility.
//! This module owns the `WalletData` shape, note/UTXO tracking, checkpoint
//! reset, and a symmetric stream cipher for on-disk secret encryption —
//! but never touches the filesystem.

use crate::checkpoints;
use crate::keys;
use crate::params::PIVX_COIN_TYPE;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A serializable spendable Sapling note (mirrors pivx-shield-rust's JSSpendableNote).
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializedNote {
    /// Sapling `Note` serialized as JSON.
    pub note: serde_json::Value,
    /// Hex-encoded incremental witness.
    pub witness: String,
    /// Hex-encoded nullifier.
    pub nullifier: String,
    /// Optional memo text.
    pub memo: Option<String>,
    /// Block height when the note was received.
    #[serde(default)]
    pub height: u32,
}

/// A transparent unspent transaction output.
#[derive(Serialize, Deserialize, Clone)]
pub struct SerializedUTXO {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script: String,
    pub height: u32,
}

/// Persistent wallet state.
///
/// Sensitive fields (`seed`, `mnemonic`) are intended to be encrypted by the
/// consumer before being written to storage, via [`encrypt_secrets`] /
/// [`decrypt_secrets`]. In memory, they are zeroized on drop.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct WalletData {
    #[zeroize(skip)]
    pub version: u32,
    /// 32-byte seed. Encrypt before persisting (never output unencrypted).
    pub(crate) seed: [u8; 32],
    /// Encoded extended full viewing key (not secret).
    #[zeroize(skip)]
    pub extfvk: String,
    /// Block height when the wallet was created (never changes).
    #[serde(default)]
    #[zeroize(skip)]
    pub birthday_height: i32,
    /// Last synced block height.
    #[zeroize(skip)]
    pub last_block: i32,
    /// Hex-encoded Sapling commitment tree.
    #[zeroize(skip)]
    pub commitment_tree: String,
    /// Spendable shield notes.
    #[zeroize(skip)]
    pub unspent_notes: Vec<SerializedNote>,
    /// BIP39 mnemonic. Encrypt before persisting (never output unencrypted).
    pub(crate) mnemonic: String,
    /// Transparent UTXOs.
    #[serde(default)]
    #[zeroize(skip)]
    pub unspent_utxos: Vec<SerializedUTXO>,
}

impl WalletData {
    /// Sum of all unspent note values, in satoshis.
    #[inline]
    pub fn get_balance(&self) -> u64 {
        self.unspent_notes
            .iter()
            .map(|n| {
                n.note
                    .get("value")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            })
            .sum()
    }

    /// Derive the extended spending key on-the-fly from the stored seed.
    pub fn derive_extsk(&self) -> Result<String, Box<dyn Error>> {
        let extsk = keys::spending_key_from_seed(&self.seed, PIVX_COIN_TYPE, 0)?;
        Ok(keys::encode_extsk(&extsk))
    }

    /// Get the mnemonic (for export only).
    pub fn get_mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Sum of all transparent UTXO values, in satoshis.
    #[inline]
    pub fn get_transparent_balance(&self) -> u64 {
        self.unspent_utxos.iter().map(|u| u.amount).sum()
    }

    /// Get the default transparent address (derived from the mnemonic).
    pub fn get_transparent_address(&self) -> Result<String, Box<dyn Error>> {
        keys::get_transparent_address(&self.mnemonic)
    }

    /// Get the full 64-byte BIP39 seed (needed for transparent key derivation).
    pub fn get_bip39_seed(&self) -> Vec<u8> {
        let mnemonic = bip39::Mnemonic::parse_normalized(&self.mnemonic)
            .expect("Stored mnemonic should always be valid");
        mnemonic.to_seed("").to_vec()
    }

    /// Mark shield notes as spent by removing those whose nullifiers match.
    pub fn finalize_transaction(&mut self, spent_nullifiers: &[String]) {
        self.unspent_notes
            .retain(|n| !spent_nullifiers.contains(&n.nullifier));
    }

    /// Remove spent UTXOs after a transparent send.
    pub fn finalize_transparent_send(&mut self, spent: &[(String, u32)]) {
        self.unspent_utxos.retain(|u| {
            !spent.iter().any(|(txid, vout)| u.txid == *txid && u.vout == *vout)
        });
    }
}

// ---------------------------------------------------------------------------
// Wallet creation
// ---------------------------------------------------------------------------

/// Create a brand-new wallet with a freshly generated 24-word BIP39 mnemonic.
///
/// `current_height` is used to pick the closest embedded checkpoint as the
/// wallet birthday; callers fetch it from their chosen RPC source.
pub fn create_new_wallet(current_height: u32) -> Result<WalletData, Box<dyn Error>> {
    let mut entropy = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)?;
    entropy.zeroize();
    create_wallet_from_mnemonic(&mnemonic.to_string(), current_height)
}

/// Import a wallet from an existing BIP39 mnemonic phrase.
///
/// `current_height` is used to choose the birthday checkpoint; see
/// [`create_new_wallet`].
pub fn import_wallet(
    mnemonic_str: &str,
    current_height: u32,
) -> Result<WalletData, Box<dyn Error>> {
    let _ = bip39::Mnemonic::parse_normalized(mnemonic_str)
        .map_err(|e| format!("Invalid mnemonic: {}", e))?;
    create_wallet_from_mnemonic(mnemonic_str, current_height)
}

fn create_wallet_from_mnemonic(
    mnemonic_str: &str,
    current_height: u32,
) -> Result<WalletData, Box<dyn Error>> {
    let mnemonic = bip39::Mnemonic::parse_normalized(mnemonic_str)
        .map_err(|e| format!("Invalid mnemonic: {}", e))?;

    let mut bip39_seed = mnemonic.to_seed("");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bip39_seed[..32]);
    bip39_seed.zeroize();

    let extsk = keys::spending_key_from_seed(&seed, PIVX_COIN_TYPE, 0)?;
    let extfvk = keys::full_viewing_key(&extsk);

    let (checkpoint_height, commitment_tree) =
        checkpoints::get_checkpoint(current_height as i32);

    Ok(WalletData {
        version: 1,
        seed,
        extfvk: keys::encode_extfvk(&extfvk),
        birthday_height: checkpoint_height,
        last_block: checkpoint_height,
        commitment_tree: commitment_tree.to_string(),
        unspent_notes: vec![],
        mnemonic: mnemonic_str.to_string(),
        unspent_utxos: vec![],
    })
}

/// Reset the wallet to its birthday checkpoint, clearing all sync state.
///
/// Used to re-sync from scratch when the on-disk sapling root diverges
/// from the network, or when the user explicitly asks to resync.
pub fn reset_to_checkpoint(data: &mut WalletData) -> Result<(), Box<dyn Error>> {
    let birthday = if data.birthday_height > 0 {
        data.birthday_height
    } else {
        5_236_346
    };
    let (checkpoint_height, commitment_tree) = checkpoints::get_checkpoint(birthday);

    data.last_block = checkpoint_height;
    data.commitment_tree = commitment_tree.to_string();
    data.unspent_notes.clear();
    data.unspent_utxos.clear();
    Ok(())
}

// ---------------------------------------------------------------------------
// Device-agnostic secret encryption
// ---------------------------------------------------------------------------
//
// The kit provides a symmetric stream cipher for encrypting the `seed` and
// `mnemonic` fields before persistence. The encryption key itself is the
// consumer's responsibility (in native CLIs, typically derived from the
// machine ID; in browsers, from user-supplied passphrase material).

/// SHA256-CTR stream cipher — XORs `data` with a keystream derived from `key`.
///
/// Symmetric: the same function encrypts and decrypts.
#[inline]
pub fn crypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut offset = 0;
    let mut counter = 0u64;

    while offset < data.len() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(&counter.to_le_bytes());
        let block: [u8; 32] = hasher.finalize().into();

        let chunk_len = (data.len() - offset).min(32);
        for i in 0..chunk_len {
            result.push(data[offset + i] ^ block[i]);
        }
        offset += chunk_len;
        counter += 1;
    }
    result
}

/// Encrypt `seed` and `mnemonic` in place before serialization.
///
/// After this call, `seed` contains ciphertext and `mnemonic` contains a
/// hex-encoded ciphertext string. The wallet is safe to serialize to disk.
pub fn encrypt_secrets(data: &mut WalletData, key: &[u8; 32]) -> Result<(), Box<dyn Error>> {
    let encrypted_seed = crypt(&data.seed, key);
    data.seed.copy_from_slice(&encrypted_seed);

    let encrypted_mnemonic = crypt(data.mnemonic.as_bytes(), key);
    data.mnemonic.zeroize();
    data.mnemonic = crate::simd::hex::bytes_to_hex_string(&encrypted_mnemonic);

    Ok(())
}

/// Decrypt `seed` and `mnemonic` in place after deserialization.
///
/// Validates decryption by re-deriving the extfvk and comparing against the
/// stored value — a wrong key surfaces as an error rather than silently
/// producing garbage.
pub fn decrypt_secrets(data: &mut WalletData, key: &[u8; 32]) -> Result<(), Box<dyn Error>> {
    let decrypted_seed = crypt(&data.seed, key);
    data.seed.copy_from_slice(&decrypted_seed);

    let encrypted_bytes = crate::simd::hex::hex_string_to_bytes(&data.mnemonic);
    let decrypted_bytes = crypt(&encrypted_bytes, key);
    data.mnemonic = String::from_utf8(decrypted_bytes)
        .map_err(|_| "Failed to decrypt wallet — wrong key?")?;

    let extsk = keys::spending_key_from_seed(&data.seed, PIVX_COIN_TYPE, 0)?;
    let extfvk = keys::full_viewing_key(&extsk);
    let derived_extfvk = keys::encode_extfvk(&extfvk);
    if derived_extfvk != data.extfvk {
        return Err("Failed to decrypt wallet — wrong key or corrupted data.".into());
    }

    Ok(())
}
