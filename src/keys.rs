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
use zeroize::Zeroizing;

/// Shield or transparent address (decoded).
pub enum GenericAddress {
    Shield(PaymentAddress),
    Transparent(TransparentAddress),
}

/// Derive an extended Sapling spending key from a 32-byte seed,
/// at the BIP44 path `m/32'/PIVX_COIN_TYPE'/account_index'`.
///
/// `coin_type` was previously a parameter but everything else in the
/// kit hardwires PIVX, so it was a footgun (callers passing `0`
/// would derive a Bitcoin-shaped key that the kit then encodes with
/// PIVX HRPs). PIVX is now hardcoded; if/when other networks are
/// supported the function will accept a `Network` enum instead.
pub fn spending_key_from_seed(
    seed: &[u8; 32],
    account_index: u32,
) -> Result<ExtendedSpendingKey, Box<dyn Error>> {
    let account_id =
        AccountId::try_from(account_index).map_err(|_| "Invalid account index")?;
    Ok(sapling_keys::spending_key(seed, PIVX_COIN_TYPE, account_id))
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

/// Derive a shield payment address at the given diversifier index.
///
/// Sapling addresses are constructed from a `(diversifier, pk_d)` pair; the
/// diversifier is an 11-byte value derived from a diversifier *index*. All
/// addresses produced from the same extfvk decrypt to the same spending
/// key, so an unlimited number of distinct receive addresses can be issued
/// without the wallet needing to track multiple secrets: exactly what the
/// merchant flow wants (one address per invoice).
///
/// Not every index produces a valid diversifier (~50% are rejected by the
/// Sapling spec on hash failure), so this function scans forward from
/// `start_index` and returns the first valid index it finds along with the
/// encoded address. Callers track their own monotonic counter and pass
/// `last_used + 1` to advance; the returned index is what should be
/// persisted (skips already accounted for).
///
/// Returns `(used_index, encoded_address)`. `used_index >= start_index`.
pub fn shield_address_at(
    enc_extfvk: &str,
    start_index: u32,
) -> Result<(u32, String), Box<dyn Error>> {
    use zip32::DiversifierIndex;

    let extfvk = decode_extfvk(enc_extfvk)?;
    let dfvk = extfvk.to_diversifiable_full_viewing_key();
    let start: DiversifierIndex = DiversifierIndex::from(start_index);
    let (idx, address) = dfvk
        .find_address(start)
        .ok_or("no valid diversifier found beyond start_index: exhausted the diversifier space")?;
    // The diversifier index is an 11-byte value but for invoice-counter use
    // cases we always pass `u32` in, so a `u32` round-trip is guaranteed
    // unless a caller deliberately exceeded u32::MAX. Surface that as an
    // error rather than silently truncating.
    let used = u32::try_from(idx).map_err(|_| {
        "diversifier index overflowed u32: caller's start_index was too close to u32::MAX"
    })?;
    Ok((used, encode_payment_address(&address)))
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
#[allow(clippy::type_complexity)] // Tuple return is a documented stable shape; refactor tracked as an ergonomics concern
/// Derive a BIP44 transparent key triple at `m/44'/119'/0'/{change}/{index}`.
///
/// The privkey is returned wrapped in [`Zeroizing`]: it'll wipe its 32-byte
/// buffer when the caller drops it. Callers that need to copy the bytes into
/// another secret-bearing struct should do so via the deref (`&*privkey` or
/// `privkey.as_slice()`); copies into non-zeroizing containers re-introduce
/// the leak. Pubkey + address are public material and not wrapped.
pub fn transparent_key_from_bip39_seed(
    bip39_seed: &[u8],
    change: u32,
    index: u32,
) -> Result<(String, Vec<u8>, Zeroizing<Vec<u8>>), Box<dyn Error>> {
    check_child_number("change", change)?;
    check_child_number("index", index)?;

    let path: DerivationPath = format!("m/44'/{}'/0'/{}/{}", PIVX_COIN_TYPE, change, index)
        .parse()
        .map_err(|e| format!("Invalid derivation path: {e}"))?;

    let child = XPrv::derive_from_path(bip39_seed, &path)
        .map_err(|e| format!("BIP32 derivation failed: {e}"))?;

    let pubkey = child.public_key();
    let pubkey_bytes = pubkey.to_bytes();
    let privkey_bytes = Zeroizing::new(child.to_bytes().to_vec());

    let address = pubkey_to_pivx_address(&pubkey_bytes);

    Ok((address, pubkey_bytes.to_vec(), privkey_bytes))
}

/// Largest BIP32 child number that is not hardened.
///
/// The child number's high bit *is* the hardened flag, so the non-hardened half
/// of the space ends here. The last two levels of a BIP44 path are non-hardened
/// by definition (that is what lets a watch-only xpub derive them), so this is
/// the ceiling on both `change` and `index`.
const MAX_NON_HARDENED_CHILD: u32 = 0x7fff_ffff;

/// Reject a child number the high bit of which would silently mean "hardened".
///
/// The `bip32` crate rejects these too, but as `invalid child number` from
/// inside a path parse, which reads as a bug in the kit rather than as a
/// caller's counter having run off the end. A rotating consumer allocating one
/// slot per invoice is the only party who can reach it, so it says so.
fn check_child_number(what: &str, n: u32) -> Result<(), Box<dyn Error>> {
    if n > MAX_NON_HARDENED_CHILD {
        return Err(format!(
            "HD {what} {n} is out of range: BIP32 non-hardened child numbers stop at \
             {MAX_NON_HARDENED_CHILD}, because the high bit selects hardened derivation. \
             A consumer rotating addresses should move to the next `change` level rather \
             than push `index` past this."
        )
        .into());
    }
    Ok(())
}

/// Derive the transparent (`D...`) address at `m/44'/119'/0'/change/index`.
///
/// The counterpart to
/// [`crate::transparent::coldstake::owner_hash_from_seed`], which produced the
/// same key's `S...` form: a consumer could get the staking address for any
/// slot but only the `0/0` transparent one, which is the wrong way round for
/// address rotation (one address per invoice, per customer, per anything).
///
/// The private key is derived and dropped here, since only the address is
/// wanted. [`Zeroizing`] wipes it on the way out.
pub fn transparent_address_at(
    bip39_seed: &[u8],
    change: u32,
    index: u32,
) -> Result<String, Box<dyn Error>> {
    let (address, _pubkey, _privkey) =
        transparent_key_from_bip39_seed(bip39_seed, change, index)?;
    Ok(address)
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

/// Convert a compressed (or uncompressed) public key to a PIVX transparent
/// address (`D...`).
pub fn pubkey_to_pivx_address(pubkey: &[u8]) -> String {
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
///
/// Validates the Base58Check checksum and the version byte before building a
/// script. Both matter, and skipping either loses funds irrecoverably:
///
///  * **Checksum.** A single mistyped character changes the pubkey hash. The
///    resulting output pays a hash nobody holds the key for, and the coins are
///    gone. Catching exactly this is why Base58Check exists, so a plain
///    `bs58::decode` is not sufficient here.
///  * **Version byte.** Wrapping a non-P2PKH hash in a P2PKH script produces an
///    output that can never be satisfied. A PIVX P2SH address (prefix 13,
///    `7...`) carries a *script* hash; spending a P2PKH output requires a
///    *public key* whose hash matches, which no script hash will ever be.
///    Addresses from other networks are rejected for the same reason.
///
/// Callers that need P2SH support want a separate script builder: this one is
/// P2PKH by construction, so it refuses anything else rather than silently
/// mislabelling it.
pub fn address_to_p2pkh_script(address: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|e| format!("Invalid base58 address: {e}"))?;
    if decoded.len() != 25 {
        return Err(format!(
            "Invalid address length: {} bytes, expected 25 (1 version + 20 hash + 4 checksum)",
            decoded.len()
        )
        .into());
    }

    // Base58Check: the trailing 4 bytes are the first 4 of double-SHA256 over
    // the version-and-hash payload.
    let (payload, checksum) = decoded.split_at(21);
    let expected = Sha256::digest(Sha256::digest(payload));
    if expected[..4] != checksum[..] {
        return Err(format!(
            "Invalid address checksum for {address}: the address is mistyped or corrupted"
        )
        .into());
    }

    if payload[0] != PIVX_PUBKEY_PREFIX {
        return Err(format!(
            "Address {address} has version byte {}, not a PIVX transparent (P2PKH) address, \
             which uses {PIVX_PUBKEY_PREFIX}. Paying it as P2PKH would create an unspendable \
             output.",
            payload[0]
        )
        .into());
    }

    let pkh = &payload[1..21];
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(pkh);
    script.push(0x88);
    script.push(0xac);
    Ok(script)
}
