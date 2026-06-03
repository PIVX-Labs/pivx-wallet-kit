//! Shield block processing — decrypt notes, track nullifiers, update witnesses.
//!
//! Pure transforms: feed in `(tree_hex, blocks, enc_extfvk, existing_notes)`,
//! get back `(new_tree_hex, new_notes, updated_notes, nullifiers)`. Consumers
//! handle network fetching and persistence.

use crate::keys;
use crate::wallet::SerializedNote;
use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use pivx_client_backend::decrypt_transaction;
use pivx_client_backend::keys::UnifiedFullViewingKey;
use pivx_primitives::consensus::{BlockHeight, MAIN_NETWORK};
use pivx_primitives::merkle_tree::{
    read_commitment_tree, read_incremental_witness, write_commitment_tree,
    write_incremental_witness,
};
use pivx_primitives::transaction::Transaction;
use pivx_primitives::zip32::{AccountId, Scope};
use pivx_protocol::memo::Memo;
use sapling::note::Note;
use sapling::{Node, Nullifier, NullifierDerivingKey};
use std::collections::HashMap;
use std::error::Error;
use std::io::Cursor;

/// Depth of the Sapling commitment tree.
pub const DEPTH: u8 = 32;

/// One block's worth of shield data — raw tx bytes, keyed to a block height.
#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct ShieldBlock {
    pub height: u32,
    pub txs: Vec<Vec<u8>>,
}

/// Output of [`handle_blocks`]: everything a caller needs to update their
/// persisted wallet state.
#[derive(serde::Serialize, serde::Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct HandleBlocksResult {
    /// Hex-encoded updated commitment tree.
    pub commitment_tree: String,
    /// Notes newly discovered in this batch.
    pub new_notes: Vec<SerializedNote>,
    /// Previously-known notes with updated witnesses.
    pub updated_notes: Vec<SerializedNote>,
    /// Nullifiers seen in this batch (potential spends of any of our notes).
    pub nullifiers: Vec<String>,
}

/// In-memory representation of a spendable note during block processing.
struct SpendableNote {
    note: Note,
    witness: IncrementalWitness<Node, DEPTH>,
    nullifier: String,
    memo: Option<String>,
    height: u32,
}

impl SpendableNote {
    /// Move-construct from a `SerializedNote`. Takes ownership so the
    /// JSON `Value` for the note can be moved into `serde_json::from_value`
    /// rather than cloned (the audit's H6 fix — saves one allocation per
    /// note per `handle_blocks` call).
    fn from_serialized(n: SerializedNote) -> Result<SpendableNote, Box<dyn Error>> {
        let SerializedNote {
            note,
            witness: witness_hex,
            nullifier,
            memo,
            height,
        } = n;
        let note: Note = serde_json::from_value(note)?;
        let wit_bytes = crate::simd::hex::hex_string_to_bytes(&witness_hex);
        let witness = read_incremental_witness(Cursor::new(wit_bytes))?;
        Ok(SpendableNote {
            note,
            witness,
            nullifier,
            memo,
            height,
        })
    }

    fn to_serialized(&self) -> Result<SerializedNote, Box<dyn Error>> {
        let mut buf = Vec::new();
        write_incremental_witness(&self.witness, &mut buf)?;
        Ok(SerializedNote {
            note: serde_json::to_value(&self.note)?,
            witness: crate::simd::hex::bytes_to_hex_string(&buf),
            nullifier: self.nullifier.clone(),
            memo: self.memo.clone(),
            height: self.height,
        })
    }
}

/// Process a batch of shield blocks, decrypting notes and updating the tree.
///
/// Takes `existing_notes` by value rather than by slice so each note's
/// JSON `Value` can be moved into `serde_json::from_value` instead of
/// cloned. Native consumers that have an owned `Vec<SerializedNote>`
/// (e.g. removed from a wallet's note set before re-adding the
/// updated set) save one allocation per note. Consumers that only
/// have a slice should clone before calling — the cost is the same
/// either way, just relocated to the call site.
pub fn handle_blocks(
    tree_hex: &str,
    blocks: Vec<ShieldBlock>,
    enc_extfvk: &str,
    existing_notes: Vec<SerializedNote>,
) -> Result<HandleBlocksResult, Box<dyn Error>> {
    let mut tree: CommitmentTree<Node, DEPTH> =
        read_commitment_tree(Cursor::new(crate::simd::hex::hex_string_to_bytes(tree_hex)))?;

    let extfvk = keys::decode_extfvk(enc_extfvk)?;
    let key = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk.clone())
        .map_err(|_| "Failed to create unified full viewing key")?;

    let mut comp_notes: Vec<SpendableNote> = existing_notes
        .into_iter()
        .map(SpendableNote::from_serialized)
        .collect::<Result<Vec<_>, _>>()?;

    let mut new_notes: Vec<SpendableNote> = vec![];
    let mut nullifiers: Vec<String> = vec![];

    let mut key_map = HashMap::new();
    key_map.insert(AccountId::default(), key.clone());
    let nullif_key = key
        .sapling()
        .ok_or("Cannot generate nullifier key")?
        .to_nk(Scope::External);

    for block in blocks {
        for tx_bytes in &block.txs {
            let tag = tx_bytes
                .first()
                .copied()
                .ok_or("empty tx bytes in shield block")?;
            let tx_nullifiers = if tag == 0x04 {
                handle_compact_transaction(
                    &mut tree,
                    tx_bytes,
                    &extfvk,
                    &nullif_key,
                    &mut comp_notes,
                    &mut new_notes,
                    block.height,
                )?
            } else {
                handle_transaction(
                    &mut tree,
                    tx_bytes,
                    &key_map,
                    &nullif_key,
                    &mut comp_notes,
                    &mut new_notes,
                    block.height,
                )?
            };
            let tx_nullifier_strs: Vec<String> = tx_nullifiers
                .iter()
                .map(|n| crate::simd::hex::bytes_to_hex_string(&n.0))
                .collect();
            nullifiers.extend(tx_nullifier_strs);
        }
    }

    let updated_notes: Vec<SerializedNote> = comp_notes
        .into_iter()
        .map(|n| n.to_serialized())
        .collect::<Result<Vec<_>, _>>()?;

    let new_serialized: Vec<SerializedNote> = new_notes
        .into_iter()
        .map(|n| n.to_serialized())
        .collect::<Result<Vec<_>, _>>()?;

    let mut tree_buf = Vec::new();
    write_commitment_tree(&tree, &mut tree_buf)?;

    Ok(HandleBlocksResult {
        commitment_tree: crate::simd::hex::bytes_to_hex_string(&tree_buf),
        new_notes: new_serialized,
        updated_notes,
        nullifiers,
    })
}

/// Process a single full-format transaction.
#[inline]
#[allow(clippy::ptr_arg)] // Witness vecs grow inside; slice would not allow `push`.
fn handle_transaction(
    tree: &mut CommitmentTree<Node, DEPTH>,
    tx_bytes: &[u8],
    key_map: &HashMap<AccountId, UnifiedFullViewingKey>,
    nullif_key: &NullifierDerivingKey,
    existing_witnesses: &mut Vec<SpendableNote>,
    new_witnesses: &mut Vec<SpendableNote>,
    block_height: u32,
) -> Result<Vec<Nullifier>, Box<dyn Error>> {
    let tx = Transaction::read(
        Cursor::new(tx_bytes),
        pivx_primitives::consensus::BranchId::Sapling,
    )?;

    let decrypted_tx = decrypt_transaction(
        &MAIN_NETWORK,
        BlockHeight::from_u32(block_height),
        &tx,
        key_map,
    );

    let mut nullifiers: Vec<Nullifier> = vec![];

    if let Some(sapling) = tx.sapling_bundle() {
        for spend in sapling.shielded_spends() {
            nullifiers.push(*spend.nullifier());
        }

        for (i, out) in sapling.shielded_outputs().iter().enumerate() {
            tree.append(Node::from_cmu(out.cmu()))
                .map_err(|_| "Failed to add cmu to tree")?;

            for witness in existing_witnesses.iter_mut().chain(new_witnesses.iter_mut()) {
                witness
                    .witness
                    .append(Node::from_cmu(out.cmu()))
                    .map_err(|_| "Failed to add cmu to witness")?;
            }

            for output in decrypted_tx.sapling_outputs() {
                if output.index() == i {
                    let witness = IncrementalWitness::<Node, DEPTH>::from_tree(tree.clone());
                    let nullifier =
                        get_nullifier_from_note(nullif_key, output.note(), &witness)?;
                    let memo = Memo::from_bytes(output.memo().as_slice())
                        .map(|m| match m {
                            Memo::Text(t) => t.to_string(),
                            _ => String::new(),
                        })
                        .ok();

                    new_witnesses.push(SpendableNote {
                        note: output.note().clone(),
                        witness,
                        nullifier,
                        memo,
                        height: block_height,
                    });
                    break;
                }
            }
        }
    }

    Ok(nullifiers)
}

/// Process a compact (0x04) transaction packet.
///
/// Packet layout:
/// ```text
/// [0x04][nSpends:1][nOutputs:1]
///   per spend:  nullifier(32)
///   per output: cv(32) + cmu(32) + epk(32) + enc_ciphertext(580) + out_ciphertext(80)
/// ```
/// Read a Bitcoin CompactSize varint at `pos`. Returns `(value, bytes_consumed)`.
/// `< 253` is a single byte; `253`/`254`/`255` prefix a 2/4/8-byte LE value.
/// Inverse of the bridge's encoder — the compact stream encodes the per-tx
/// spend/output counts this way so transactions with >255 spends/outputs (e.g.
/// the 821-spend tx in mainnet block 4,465,357) aren't truncated.
fn read_compact_size(data: &[u8], pos: usize) -> Result<(usize, usize), Box<dyn Error>> {
    let first = *data.get(pos).ok_or("compact size past end")?;
    match first {
        n if n < 253 => Ok((n as usize, 1)),
        253 => {
            let b = data.get(pos + 1..pos + 3).ok_or("truncated compact size")?;
            Ok((u16::from_le_bytes([b[0], b[1]]) as usize, 3))
        }
        254 => {
            let b = data.get(pos + 1..pos + 5).ok_or("truncated compact size")?;
            Ok((u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize, 5))
        }
        _ => {
            let b = data.get(pos + 1..pos + 9).ok_or("truncated compact size")?;
            Ok((u64::from_le_bytes(b.try_into().unwrap()) as usize, 9))
        }
    }
}

#[inline]
#[allow(clippy::ptr_arg)] // Witness vecs grow inside; slice would not allow `push`.
fn handle_compact_transaction(
    tree: &mut CommitmentTree<Node, DEPTH>,
    payload: &[u8],
    extfvk: &sapling::zip32::ExtendedFullViewingKey,
    nullif_key: &NullifierDerivingKey,
    existing_witnesses: &mut Vec<SpendableNote>,
    new_witnesses: &mut Vec<SpendableNote>,
    block_height: u32,
) -> Result<Vec<Nullifier>, Box<dyn Error>> {
    if payload.len() < 3 {
        return Err("compact tx too short".into());
    }

    // Spend/output counts are CompactSize varints (not single bytes): a tx can
    // have >255 spends/outputs, which a u8 count would silently truncate.
    let (num_spends, c1) = read_compact_size(payload, 1)?;
    let (num_outputs, c2) = read_compact_size(payload, 1 + c1)?;
    let mut pos = 1 + c1 + c2;

    let mut nullifiers = Vec::with_capacity(num_spends);
    for _ in 0..num_spends {
        if pos + 32 > payload.len() {
            return Err("truncated compact spend".into());
        }
        let mut nf = [0u8; 32];
        nf.copy_from_slice(&payload[pos..pos + 32]);
        nullifiers.push(Nullifier(nf));
        pos += 32;
    }

    let ivk = sapling::note_encryption::PreparedIncomingViewingKey::new(
        &extfvk.fvk.vk.ivk(),
    );

    const ENC_CT_SIZE: usize = 580;
    const OUT_CT_SIZE: usize = 80;
    const OUTPUT_SIZE: usize = 32 + 32 + 32 + ENC_CT_SIZE + OUT_CT_SIZE;

    for _ in 0..num_outputs {
        if pos + OUTPUT_SIZE > payload.len() {
            return Err("truncated compact output".into());
        }

        let cmu_bytes: [u8; 32] = payload[pos + 32..pos + 64].try_into()?;
        let epk_bytes: [u8; 32] = payload[pos + 64..pos + 96].try_into()?;
        let enc_ct: &[u8] = &payload[pos + 96..pos + 96 + ENC_CT_SIZE];

        let cmu = sapling::note::ExtractedNoteCommitment::from_bytes(&cmu_bytes)
            .into_option()
            .ok_or("invalid cmu")?;
        let cmu_node = Node::from_cmu(&cmu);
        tree.append(cmu_node)
            .map_err(|_| "failed to append cmu to tree")?;

        for w in existing_witnesses.iter_mut().chain(new_witnesses.iter_mut()) {
            w.witness
                .append(cmu_node)
                .map_err(|_| "failed to advance witness")?;
        }

        // ZIP-212 enforcement: PIVX mainnet has not yet activated a
        // ZIP-212-equivalent note-encryption upgrade, so `Off` is correct for
        // all current heights. If/when PIVX defines an activation height,
        // select the enforcement from the network consensus parameters here
        // (the full-tx path in `handle_transaction` already gets this right
        // via `decrypt_transaction`'s use of `MAIN_NETWORK`).
        let domain = sapling::note_encryption::SaplingDomain::new(
            sapling::note_encryption::Zip212Enforcement::Off,
        );

        let compact_output = CompactOutput {
            cmu: cmu_bytes,
            epk: epk_bytes,
            enc_ciphertext: enc_ct.try_into().map_err(|_| "enc_ct wrong size")?,
        };

        if let Some((note, _recipient, memo_bytes)) =
            zcash_note_encryption::try_note_decryption(&domain, &ivk, &compact_output)
        {
            let witness = IncrementalWitness::<Node, DEPTH>::from_tree(tree.clone());
            let nullifier = get_nullifier_from_note(nullif_key, &note, &witness)?;
            let memo = pivx_protocol::memo::Memo::from_bytes(memo_bytes.as_slice())
                .map(|m| match m {
                    pivx_protocol::memo::Memo::Text(t) => t.to_string(),
                    _ => String::new(),
                })
                .ok();

            new_witnesses.push(SpendableNote {
                note,
                witness,
                nullifier,
                memo,
                height: block_height,
            });
        }

        pos += OUTPUT_SIZE;
    }

    Ok(nullifiers)
}

struct CompactOutput {
    cmu: [u8; 32],
    epk: [u8; 32],
    enc_ciphertext: [u8; 580],
}

impl zcash_note_encryption::ShieldedOutput<sapling::note_encryption::SaplingDomain, 580>
    for CompactOutput
{
    fn ephemeral_key(&self) -> zcash_note_encryption::EphemeralKeyBytes {
        zcash_note_encryption::EphemeralKeyBytes(self.epk)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu
    }

    fn enc_ciphertext(&self) -> &[u8; 580] {
        &self.enc_ciphertext
    }
}

#[inline]
fn get_nullifier_from_note(
    nullif_key: &NullifierDerivingKey,
    note: &Note,
    witness: &IncrementalWitness<Node, DEPTH>,
) -> Result<String, Box<dyn Error>> {
    let path = witness.path().ok_or("Cannot find witness path")?;
    Ok(crate::simd::hex::bytes_to_hex_string(
        &note.nf(nullif_key, path.position().into()).0,
    ))
}

#[cfg(test)]
mod tests {
    use super::read_compact_size;

    #[test]
    fn read_compact_size_boundaries() {
        // <253: single byte.
        assert_eq!(read_compact_size(&[200], 0).unwrap(), (200, 1));
        assert_eq!(read_compact_size(&[0], 0).unwrap(), (0, 1));
        // 253 → 0xfd + u16 LE.
        assert_eq!(read_compact_size(&[0xfd, 0x35, 0x03], 0).unwrap(), (821, 3));
        assert_eq!(read_compact_size(&[0xfd, 0x00, 0x01], 0).unwrap(), (256, 3));
        // 254 → 0xfe + u32 LE.
        assert_eq!(
            read_compact_size(&[0xfe, 0x01, 0x00, 0x01, 0x00], 0).unwrap(),
            (65537, 5)
        );
        // Reads at an offset.
        assert_eq!(read_compact_size(&[0xff, 0xfd, 0x35, 0x03], 1).unwrap(), (821, 3));
    }

    #[test]
    fn read_compact_size_truncated_errors() {
        assert!(read_compact_size(&[], 0).is_err());
        assert!(read_compact_size(&[0xfd, 0x35], 0).is_err()); // needs 2 bytes, only 1
        assert!(read_compact_size(&[0xfe, 0x01, 0x00], 0).is_err()); // needs 4
    }
}
