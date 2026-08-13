//! Shared transaction decoding and signature verification for the integration
//! tests.
//!
//! Deliberately reimplements the transaction format rather than calling into the
//! crate: a verifier built on the code under test agrees with itself even when
//! both are wrong, which is exactly the failure these tests exist to catch. What
//! it must *not* be is three near-identical copies: they drift, and a bug in
//! one silently weakens every test that uses it.
//!
//! So this is one independent implementation, shared.
//!
//! Cargo compiles this module separately into each test binary, so any helper a
//! given binary does not call reads as dead there. The allow is for that, not
//! for genuinely unused code.

#![allow(dead_code)]

use sha2::{Digest, Sha256};

/// A parsed legacy transaction.
pub struct Decoded {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
    /// False when parsing did not land exactly on the end of the buffer, which
    /// means a length prefix disagreed with the bytes that followed.
    pub consumed_all: bool,
}

pub struct TxIn {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

fn varint(bytes: &[u8], p: &mut usize) -> u64 {
    let f = bytes[*p];
    match f {
        0xfd => {
            let v = u16::from_le_bytes(bytes[*p + 1..*p + 3].try_into().unwrap()) as u64;
            *p += 3;
            v
        }
        0xfe => {
            let v = u32::from_le_bytes(bytes[*p + 1..*p + 5].try_into().unwrap()) as u64;
            *p += 5;
            v
        }
        0xff => {
            let v = u64::from_le_bytes(bytes[*p + 1..*p + 9].try_into().unwrap());
            *p += 9;
            v
        }
        n => {
            *p += 1;
            n as u64
        }
    }
}

pub fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// Parse a raw v1 transaction.
pub fn decode(bytes: &[u8]) -> Decoded {
    let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let mut p = 4usize;

    let n_in = varint(bytes, &mut p);
    let mut inputs = Vec::with_capacity(n_in as usize);
    for _ in 0..n_in {
        let prev_txid: [u8; 32] = bytes[p..p + 32].try_into().unwrap();
        p += 32;
        let prev_vout = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
        p += 4;
        let sl = varint(bytes, &mut p) as usize;
        let script_sig = bytes[p..p + sl].to_vec();
        p += sl;
        let sequence = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
        p += 4;
        inputs.push(TxIn { prev_txid, prev_vout, script_sig, sequence });
    }

    let n_out = varint(bytes, &mut p);
    let mut outputs = Vec::with_capacity(n_out as usize);
    for _ in 0..n_out {
        let value = u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
        p += 8;
        let sl = varint(bytes, &mut p) as usize;
        outputs.push(TxOut { value, script_pubkey: bytes[p..p + sl].to_vec() });
        p += sl;
    }

    let locktime = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
    p += 4;

    Decoded { version, inputs, outputs, locktime, consumed_all: p == bytes.len() }
}

/// Rebuild the SIGHASH_ALL preimage for one input, per the legacy rules PIVX
/// inherits: the input being signed carries the prevout's `scriptPubKey`, every
/// other input carries an empty script.
pub fn sighash_all(tx: &Decoded, signing_index: usize, prevout_script: &[u8]) -> [u8; 32] {
    let mut pre = Vec::new();
    pre.extend_from_slice(&tx.version.to_le_bytes());

    write_varint(&mut pre, tx.inputs.len() as u64);
    for (i, input) in tx.inputs.iter().enumerate() {
        pre.extend_from_slice(&input.prev_txid);
        pre.extend_from_slice(&input.prev_vout.to_le_bytes());
        if i == signing_index {
            write_varint(&mut pre, prevout_script.len() as u64);
            pre.extend_from_slice(prevout_script);
        } else {
            pre.push(0x00);
        }
        pre.extend_from_slice(&input.sequence.to_le_bytes());
    }

    write_varint(&mut pre, tx.outputs.len() as u64);
    for out in &tx.outputs {
        pre.extend_from_slice(&out.value.to_le_bytes());
        write_varint(&mut pre, out.script_pubkey.len() as u64);
        pre.extend_from_slice(&out.script_pubkey);
    }

    pre.extend_from_slice(&tx.locktime.to_le_bytes());
    pre.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(Sha256::digest(&pre)));
    out
}

/// Split a `scriptSig` into its DER signature and pubkey.
///
/// Handles both layouts: `<sig> <pubkey>` for P2PKH, and `<sig> OP_FALSE
/// <pubkey>` for the cold-staking owner path. Returns whether the branch
/// selector was present, so a caller can assert on it.
pub fn split_script_sig(script_sig: &[u8]) -> (Vec<u8>, Vec<u8>, bool) {
    let sig_push = script_sig[0] as usize;
    assert!(sig_push > 0 && sig_push < 0x4c, "unexpected signature push opcode");
    let sig_with_type = &script_sig[1..1 + sig_push];
    let (sig_der, hash_type) = sig_with_type.split_at(sig_with_type.len() - 1);
    assert_eq!(hash_type[0], 0x01, "expected SIGHASH_ALL (0x01)");

    let mut off = 1 + sig_push;
    // A 0x00 here is OP_FALSE, not a push: a pubkey push is 33 or 65.
    let cold_stake_selector = script_sig[off] == 0x00;
    if cold_stake_selector {
        off += 1;
    }

    let key_push = script_sig[off] as usize;
    let pubkey = &script_sig[off + 1..off + 1 + key_push];
    assert_eq!(off + 1 + key_push, script_sig.len(), "trailing bytes after pubkey");

    (sig_der.to_vec(), pubkey.to_vec(), cold_stake_selector)
}

/// P2PKH `scriptPubKey` for a pubkey: what a node reconstructs to check a
/// P2PKH input.
pub fn p2pkh_script_from_pubkey(pubkey: &[u8]) -> Vec<u8> {
    use ripemd::Ripemd160;
    let pkh = Ripemd160::digest(Sha256::digest(pubkey));
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&pkh);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

/// Verify every input against an explicitly supplied prevout script.
///
/// Use this for cold-staking inputs, where the prevout is the P2CS script and
/// cannot be derived from the pubkey. Panics with a message naming the failure
/// mode, since a signature that does not commit to its prevout is the bug these
/// tests exist to find.
pub fn verify_with_prevouts(tx: &Decoded, prevout_scripts: &[Vec<u8>]) -> usize {
    assert_eq!(
        prevout_scripts.len(),
        tx.inputs.len(),
        "one prevout script per input is required"
    );
    let secp = secp256k1::Secp256k1::verification_only();

    for (i, input) in tx.inputs.iter().enumerate() {
        let (sig_der, pubkey_bytes, _) = split_script_sig(&input.script_sig);
        let sighash = sighash_all(tx, i, &prevout_scripts[i]);
        let msg = secp256k1::Message::from_digest(sighash);
        let sig = secp256k1::ecdsa::Signature::from_der(&sig_der)
            .unwrap_or_else(|e| panic!("input {i}: malformed DER signature: {e}"));
        let pk = secp256k1::PublicKey::from_slice(&pubkey_bytes)
            .unwrap_or_else(|e| panic!("input {i}: malformed pubkey: {e}"));

        secp.verify_ecdsa(&msg, &sig, &pk).unwrap_or_else(|e| {
            panic!(
                "input {i}: SIGNATURE DOES NOT COMMIT TO THIS TRANSACTION ({e}).\n\
                 The signed preimage and the serialized transaction disagree: the network \
                 would reject this, or a serialization bug is paying outputs the signature \
                 never authorised."
            )
        });
    }
    tx.inputs.len()
}

/// Verify every input, reconstructing each prevout script from the pubkey in its
/// own `scriptSig`: exactly the information a validating node has for P2PKH.
pub fn verify_all_signatures(tx: &Decoded) -> usize {
    let prevouts: Vec<Vec<u8>> = tx
        .inputs
        .iter()
        .map(|i| {
            let (_, pubkey, _) = split_script_sig(&i.script_sig);
            p2pkh_script_from_pubkey(&pubkey)
        })
        .collect();
    verify_with_prevouts(tx, &prevouts)
}
