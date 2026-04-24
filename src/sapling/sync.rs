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
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ShieldBlock {
    pub height: u32,
    pub txs: Vec<Vec<u8>>,
}

/// Output of [`handle_blocks`]: everything a caller needs to update their
/// persisted wallet state.
#[derive(serde::Serialize, serde::Deserialize)]
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
    fn from_serialized(n: &SerializedNote) -> Result<SpendableNote, Box<dyn Error>> {
        let note: Note = serde_json::from_value(n.note.clone())?;
        let wit_bytes = crate::simd::hex::hex_string_to_bytes(&n.witness);
        let witness = read_incremental_witness(Cursor::new(wit_bytes))?;
        Ok(SpendableNote {
            note,
            witness,
            nullifier: n.nullifier.clone(),
            memo: n.memo.clone(),
            height: n.height,
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
pub fn handle_blocks(
    tree_hex: &str,
    blocks: Vec<ShieldBlock>,
    enc_extfvk: &str,
    existing_notes: &[SerializedNote],
) -> Result<HandleBlocksResult, Box<dyn Error>> {
    let mut tree: CommitmentTree<Node, DEPTH> =
        read_commitment_tree(Cursor::new(crate::simd::hex::hex_string_to_bytes(tree_hex)))?;

    let extfvk = keys::decode_extfvk(enc_extfvk)?;
    let key = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk.clone())
        .map_err(|_| "Failed to create unified full viewing key")?;

    let mut comp_notes: Vec<SpendableNote> = existing_notes
        .iter()
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
            let tx_nullifiers = if tx_bytes[0] == 0x04 {
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

    let decrypted_tx =
        decrypt_transaction(&MAIN_NETWORK, BlockHeight::from_u32(320), &tx, key_map);

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
#[inline]
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

    let num_spends = payload[1] as usize;
    let num_outputs = payload[2] as usize;
    let mut pos = 3;

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
