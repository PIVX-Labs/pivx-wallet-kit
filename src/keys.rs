//! Key derivation (BIP32/BIP44), address generation, WIF encoding.
//!
//! Pure logic. Consumers supply seeds; this module derives keys and addresses.

use crate::params::{PIVX_COIN_TYPE, PIVX_PUBKEY_PREFIX};
use pivx_client_backend::encoding::{decode_payment_address, decode_transparent_address};
use pivx_client_backend::keys::sapling as sapling_keys;
use pivx_primitives::consensus::{NetworkConstants, MAIN_NETWORK};
use pivx_primitives::legacy::TransparentAddress;
use pivx_primitives::zip32::AccountId;
use ::sapling::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use ::sapling::PaymentAddress;
use std::error::Error;
use zcash_keys::encoding;

use bip32::{DerivationPath, XPrv};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;

/// Shield or transparent address (decoded).
pub enum GenericAddress {
    Shield(PaymentAddress),
    Transparent(TransparentAddress),
}

/// Derive an extended Sapling spending key from a 32-byte seed.
pub fn spending_key_from_seed(
    seed: &[u8; 32],
    coin_type: u32,
    account_index: u32,
) -> Result<ExtendedSpendingKey, Box<dyn Error>> {
    let account_id =
        AccountId::try_from(account_index).map_err(|_| "Invalid account index")?;
    Ok(sapling_keys::spending_key(seed, coin_type, account_id))
}

/// Derive the extended full viewing key from an extended spending key.
#[allow(deprecated)]
pub fn full_viewing_key(extsk: &ExtendedSpendingKey) -> ExtendedFullViewingKey {
    extsk.to_extended_full_viewing_key()
}

/// Get the default Sapling payment address from an encoded extfvk.
pub fn get_default_address(enc_extfvk: &str) -> Result<String, Box<dyn Error>> {
    let extfvk = decode_extfvk(enc_extfvk)?;
    let (_index, address) = extfvk
        .to_diversifiable_full_viewing_key()
        .default_address();
    Ok(encode_payment_address(&address))
}

// ---------------------------------------------------------------------------
// Sapling key encoding / decoding
// ---------------------------------------------------------------------------

pub fn encode_extsk(extsk: &ExtendedSpendingKey) -> String {
    encoding::encode_extended_spending_key(
        MAIN_NETWORK.hrp_sapling_extended_spending_key(),
        extsk,
    )
}

pub fn decode_extsk(enc: &str) -> Result<ExtendedSpendingKey, Box<dyn Error>> {
    Ok(encoding::decode_extended_spending_key(
        MAIN_NETWORK.hrp_sapling_extended_spending_key(),
        enc,
    )?)
}

pub fn encode_extfvk(extfvk: &ExtendedFullViewingKey) -> String {
    encoding::encode_extended_full_viewing_key(
        MAIN_NETWORK.hrp_sapling_extended_full_viewing_key(),
        extfvk,
    )
}

pub fn decode_extfvk(enc: &str) -> Result<ExtendedFullViewingKey, Box<dyn Error>> {
    Ok(encoding::decode_extended_full_viewing_key(
        MAIN_NETWORK.hrp_sapling_extended_full_viewing_key(),
        enc,
    )?)
}

pub fn encode_payment_address(addr: &PaymentAddress) -> String {
    encoding::encode_payment_address(
        MAIN_NETWORK.hrp_sapling_payment_address(),
        addr,
    )
}

// ---------------------------------------------------------------------------
// Transparent key derivation (BIP32/BIP44)
// ---------------------------------------------------------------------------

/// Derive a transparent PIVX address from a BIP39 seed (64 bytes).
/// Path: `m/44'/PIVX_COIN_TYPE'/0'/change/index`.
/// Returns `(base58 address, compressed pubkey [33], private key [32])`.
pub fn transparent_key_from_bip39_seed(
    bip39_seed: &[u8],
    change: u32,
    index: u32,
) -> Result<(String, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let path: DerivationPath = format!("m/44'/{}'/0'/{}/{}", PIVX_COIN_TYPE, change, index)
        .parse()
        .map_err(|e| format!("Invalid derivation path: {e}"))?;

    let child = XPrv::derive_from_path(bip39_seed, &path)
        .map_err(|e| format!("BIP32 derivation failed: {e}"))?;

    let pubkey = child.public_key();
    let pubkey_bytes = pubkey.to_bytes();
    let privkey_bytes = child.to_bytes().to_vec();

    let address = pubkey_to_pivx_address(&pubkey_bytes);

    Ok((address, pubkey_bytes.to_vec(), privkey_bytes))
}

/// Get the default transparent address from a mnemonic string.
/// Derives at path `m/44'/119'/0'/0/0`.
pub fn get_transparent_address(mnemonic: &str) -> Result<String, Box<dyn Error>> {
    let mnemonic_parsed = bip39::Mnemonic::parse_normalized(mnemonic)
        .map_err(|e| format!("Invalid mnemonic: {e}"))?;
    let bip39_seed = mnemonic_parsed.to_seed("");
    let (address, _, _) = transparent_key_from_bip39_seed(&bip39_seed, 0, 0)?;
    Ok(address)
}

/// Convert a compressed public key to a PIVX transparent address (`D...`).
fn pubkey_to_pivx_address(pubkey: &[u8]) -> String {
    let sha_hash = Sha256::digest(pubkey);
    let pkh = Ripemd160::digest(sha_hash);

    let mut payload = Vec::with_capacity(25);
    payload.push(PIVX_PUBKEY_PREFIX);
    payload.extend_from_slice(&pkh);

    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);

    bs58::encode(&payload).into_string()
}

/// Decode any PIVX address into a `GenericAddress` (shield or transparent).
pub fn decode_generic_address(address: &str) -> Result<GenericAddress, Box<dyn Error>> {
    if address.starts_with(MAIN_NETWORK.hrp_sapling_payment_address()) {
        let addr =
            decode_payment_address(MAIN_NETWORK.hrp_sapling_payment_address(), address)
                .map_err(|_| "Failed to decode shield address")?;
        Ok(GenericAddress::Shield(addr))
    } else {
        let addr = decode_transparent_address(
            &MAIN_NETWORK.b58_pubkey_address_prefix(),
            &MAIN_NETWORK.b58_script_address_prefix(),
            address,
        )
        .map_err(|_| "Failed to decode transparent address")?
        .ok_or("Invalid transparent address")?;
        Ok(GenericAddress::Transparent(addr))
    }
}

/// Decode a base58 transparent PIVX address to its P2PKH scriptPubKey.
/// Returns the raw script bytes: `OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn address_to_p2pkh_script(address: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let decoded = bs58::decode(address).into_vec()
        .map_err(|e| format!("Invalid base58 address: {e}"))?;
    if decoded.len() != 25 {
        return Err("Invalid address length".into());
    }
    let pkh = &decoded[1..21];
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(pkh);
    script.push(0x88);
    script.push(0xac);
    Ok(script)
}
