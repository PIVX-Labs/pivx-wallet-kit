//! PIVX Core-compatible message signing and verification.
//!
//! Wire format matches the `signmessage` / `verifymessage` RPC calls of a
//! PIVX Core node:
//!
//! 1. The message is hashed with the magic prefix `"DarkNet Signed Message:\n"`,
//!    each component preceded by a Bitcoin-style compact-size length.
//! 2. The hash is the digest used for a secp256k1 ECDSA recoverable signature.
//! 3. The signature is a 65-byte blob: 1 header byte encoding the recovery id
//!    (and whether the recovered pubkey is compressed) followed by the 64-byte
//!    compact (r||s) signature. PIVX Core always produces the compressed form.
//! 4. Final output is that 65-byte blob, standard-base64-encoded.
//!
//! With this format, signatures produced by [`sign_message`] verify against
//! `verifymessage` on a PIVX Core node, and signatures from `signmessage` on a
//! PIVX Core node verify via [`verify_message`].

use crate::keys;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1, SecretKey,
};
use sha2::{Digest, Sha256};
use std::error::Error;

/// Magic prefix used by PIVX Core for `signmessage` / `verifymessage`.
///
/// Inherited from Dash via DarkCoin; not the same as Bitcoin's
/// `"Bitcoin Signed Message:\n"`.
pub const PIVX_MSG_MAGIC: &str = "DarkNet Signed Message:\n";

fn write_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// Compute the 32-byte digest a PIVX Core signed-message signature is over.
fn message_hash(message: &str) -> [u8; 32] {
    let magic = PIVX_MSG_MAGIC.as_bytes();
    let mut buf = Vec::with_capacity(magic.len() + message.len() + 4);
    write_compact_size(&mut buf, magic.len() as u64);
    buf.extend_from_slice(magic);
    write_compact_size(&mut buf, message.len() as u64);
    buf.extend_from_slice(message.as_bytes());

    let h1 = Sha256::digest(&buf);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

/// Sign `message` with the given 32-byte private key.
///
/// Returns a base64 signature byte-compatible with PIVX Core's
/// `verifymessage` RPC. The recovered public key will be the compressed
/// form (matches PIVX Core's behaviour).
pub fn sign_message(privkey: &[u8; 32], message: &str) -> Result<String, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(privkey).map_err(|e| format!("Invalid privkey: {e}"))?;
    let hash = message_hash(message);
    let msg = Message::from_digest_slice(&hash)?;

    let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, &sk);
    let (recid, sig_bytes) = sig.serialize_compact();

    // Header byte: 27 + recid + 4 (compressed pubkey marker).
    let header = 27u8 + (recid.to_i32() as u8) + 4;

    let mut full = Vec::with_capacity(65);
    full.push(header);
    full.extend_from_slice(&sig_bytes);
    Ok(B64.encode(&full))
}

/// Verify that `signature_b64` is a valid PIVX Core-format signature of
/// `message` by the keypair that owns `address`.
///
/// Returns `Ok(true)` only if the recovered public key derives to exactly
/// `address`. `Ok(false)` for valid-shape but wrong-key signatures;
/// `Err(_)` for malformed input.
pub fn verify_message(
    address: &str,
    message: &str,
    signature_b64: &str,
) -> Result<bool, Box<dyn Error>> {
    let sig_bytes = B64
        .decode(signature_b64)
        .map_err(|e| format!("Bad base64: {e}"))?;
    if sig_bytes.len() != 65 {
        return Err(
            format!("Signature must be exactly 65 bytes; got {}", sig_bytes.len()).into(),
        );
    }
    let header = sig_bytes[0];
    if !(27..=34).contains(&header) {
        return Err(format!("Bad header byte: {}", header).into());
    }
    let compressed = header >= 31;
    let recid_byte = if compressed { header - 31 } else { header - 27 };
    let recid = RecoveryId::from_i32(recid_byte as i32)?;
    let sig = RecoverableSignature::from_compact(&sig_bytes[1..], recid)?;

    let hash = message_hash(message);
    let msg = Message::from_digest_slice(&hash)?;

    let secp = Secp256k1::new();
    let pubkey: PublicKey = secp.recover_ecdsa(&msg, &sig)?;

    let pubkey_bytes = if compressed {
        pubkey.serialize().to_vec()
    } else {
        pubkey.serialize_uncompressed().to_vec()
    };
    let recovered_addr = keys::pubkey_to_pivx_address(&pubkey_bytes);
    Ok(recovered_addr == address)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip — sign with a key, verify with the corresponding address.
    #[test]
    fn roundtrip_compressed() {
        // Deterministic mnemonic → known address + privkey
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let parsed = bip39::Mnemonic::parse_normalized(mnemonic).unwrap();
        let bip39_seed = parsed.to_seed("");
        let (address, _pubkey, privkey_vec) =
            keys::transparent_key_from_bip39_seed(&bip39_seed, 0, 0).unwrap();
        let mut privkey = [0u8; 32];
        privkey.copy_from_slice(&privkey_vec);

        let message = "Hello, PIVX!";
        let sig = sign_message(&privkey, message).unwrap();
        assert!(verify_message(&address, message, &sig).unwrap());

        // Wrong message must fail.
        assert!(!verify_message(&address, "Goodbye", &sig).unwrap());

        // Wrong address must fail.
        let other_addr = "DBnaqM7apSWDqRVU9Ppi3eR2bUzYGX6gxF";
        assert!(!verify_message(other_addr, message, &sig).unwrap());
    }

    /// Print a deterministic signature + WIF for cross-verification against
    /// PIVX Core's `verifymessage` and `signmessagewithprivkey` RPCs.
    #[test]
    fn print_signature_for_cross_verify() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let parsed = bip39::Mnemonic::parse_normalized(mnemonic).unwrap();
        let bip39_seed = parsed.to_seed("");
        let (address, _pk, privkey_vec) =
            keys::transparent_key_from_bip39_seed(&bip39_seed, 0, 0).unwrap();
        let mut privkey = [0u8; 32];
        privkey.copy_from_slice(&privkey_vec);

        // Encode privkey as PIVX mainnet WIF (compressed): 0xD4 + key + 0x01 + 4-byte SHA256d checksum, base58.
        let mut wif_payload = Vec::with_capacity(34);
        wif_payload.push(0xD4);
        wif_payload.extend_from_slice(&privkey);
        wif_payload.push(0x01);
        let checksum = Sha256::digest(Sha256::digest(&wif_payload));
        wif_payload.extend_from_slice(&checksum[..4]);
        let wif = bs58::encode(&wif_payload).into_string();

        let message = "PIVX-Wallet-Kit signing test 2026-04-25";
        let sig = sign_message(&privkey, message).unwrap();
        println!("ADDRESS:   {}", address);
        println!("WIF:       {}", wif);
        println!("MESSAGE:   {}", message);
        println!("SIGNATURE: {}", sig);
    }

    #[test]
    fn malformed_signatures_error() {
        let addr = "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ";
        // Empty
        assert!(verify_message(addr, "msg", "").is_err());
        // Wrong length (decoded to 32 bytes)
        let too_short = B64.encode([0u8; 32]);
        assert!(verify_message(addr, "msg", &too_short).is_err());
        // Bad header byte (decoded to 65 bytes but header out of range)
        let mut bad = [0u8; 65];
        bad[0] = 99;
        let bad_b64 = B64.encode(bad);
        assert!(verify_message(addr, "msg", &bad_b64).is_err());
    }
}
