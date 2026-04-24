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

/// Parse a list of UTXOs from a Blockbook API v2 `/api/v2/utxo/{address}` response.
///
/// Accepts amounts as either a string (`"12345"`) or a JSON number — both
/// forms appear in the wild depending on the Blockbook revision. UTXOs with
/// empty txids or zero amounts are skipped.
///
/// `script` is left empty because Blockbook doesn't always include scripts
/// and consumers that need them can reconstruct P2PKH from the spending
/// wallet's address.
pub fn parse_blockbook_utxos(raw: &[serde_json::Value]) -> Vec<SerializedUTXO> {
    let mut utxos = Vec::new();
    for u in raw {
        let txid = u["txid"].as_str().unwrap_or_default().to_string();
        let vout = u["vout"].as_u64().unwrap_or(0) as u32;
        let amount = u["value"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| u["value"].as_u64())
            .unwrap_or(0);
        let height = u["height"].as_u64().unwrap_or(0) as u32;

        if txid.is_empty() || amount == 0 {
            continue;
        }

        utxos.push(SerializedUTXO {
            txid,
            vout,
            amount,
            script: String::new(),
            height,
        });
    }
    utxos
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

    /// Deep-copy the wallet for on-disk encryption.
    ///
    /// The result can be safely mutated by [`encrypt_secrets`] without
    /// touching the original in-memory plaintext wallet. Field-by-field
    /// copy avoids an unzeroized JSON round-trip that would otherwise
    /// leak the seed bytes through `serde_json`'s internal buffers.
    pub fn clone_for_encryption(&self) -> Self {
        WalletData {
            version: self.version,
            seed: self.seed,
            extfvk: self.extfvk.clone(),
            birthday_height: self.birthday_height,
            last_block: self.last_block,
            commitment_tree: self.commitment_tree.clone(),
            unspent_notes: self.unspent_notes.clone(),
            mnemonic: self.mnemonic.clone(),
            unspent_utxos: self.unspent_utxos.clone(),
        }
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

/// Encrypt the wallet's secrets with `key` and serialize the result as a
/// pretty-printed JSON string, ready to be persisted.
///
/// Prefer this over calling [`encrypt_secrets`] + `serde_json::to_string_pretty`
/// by hand — it clones the wallet via [`WalletData::clone_for_encryption`] first,
/// so encryption never mutates the live in-memory plaintext wallet, and it
/// never passes an unencrypted `WalletData` through `serde_json`'s internal
/// buffers.
pub fn serialize_encrypted(data: &WalletData, key: &[u8; 32]) -> Result<String, Box<dyn Error>> {
    let mut disk_data = data.clone_for_encryption();
    encrypt_secrets(&mut disk_data, key)?;
    Ok(serde_json::to_string_pretty(&disk_data)?)
}

/// Deserialize an encrypted wallet JSON and decrypt its secrets with `key`.
///
/// Returns `Err` without mutating the input if the key is wrong (see
/// [`decrypt_secrets`] for the validation semantics).
pub fn deserialize_encrypted(json: &str, key: &[u8; 32]) -> Result<WalletData, Box<dyn Error>> {
    let mut data: WalletData = serde_json::from_str(json)?;
    decrypt_secrets(&mut data, key)?;
    Ok(data)
}

/// Decrypt `seed` and `mnemonic` in place after deserialization.
///
/// Validates the decryption by re-deriving the extfvk and comparing against
/// the stored value — a wrong key surfaces as an error rather than silently
/// producing garbage.
///
/// On any error the wallet's on-disk ciphertext is left untouched; only
/// after the extfvk check passes do the plaintext fields get committed.
/// This means a caller can retry with a different key without first
/// reloading the file from disk.
pub fn decrypt_secrets(data: &mut WalletData, key: &[u8; 32]) -> Result<(), Box<dyn Error>> {
    // Decrypt into scratch buffers first.
    let mut candidate_seed = [0u8; 32];
    candidate_seed.copy_from_slice(&crypt(&data.seed, key));

    let encrypted_bytes = crate::simd::hex::hex_string_to_bytes(&data.mnemonic);
    let decrypted_mnemonic_bytes = crypt(&encrypted_bytes, key);
    let candidate_mnemonic = match String::from_utf8(decrypted_mnemonic_bytes) {
        Ok(s) => s,
        Err(_) => {
            candidate_seed.zeroize();
            return Err("Failed to decrypt wallet — wrong key?".into());
        }
    };

    // Validate before mutating `data`.
    let extsk = match keys::spending_key_from_seed(&candidate_seed, PIVX_COIN_TYPE, 0) {
        Ok(k) => k,
        Err(e) => {
            candidate_seed.zeroize();
            return Err(e);
        }
    };
    let derived_extfvk = keys::encode_extfvk(&keys::full_viewing_key(&extsk));
    if derived_extfvk != data.extfvk {
        candidate_seed.zeroize();
        return Err("Failed to decrypt wallet — wrong key or corrupted data.".into());
    }

    // Commit.
    data.seed.copy_from_slice(&candidate_seed);
    data.mnemonic = candidate_mnemonic;
    candidate_seed.zeroize();
    Ok(())
}
