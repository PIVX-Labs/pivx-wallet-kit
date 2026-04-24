//! Shielded transaction builder — spend notes, produce signed v3 tx hex.

use crate::fees;
use crate::keys::{self, GenericAddress};
use crate::sapling::prover::SaplingProver;
use crate::sapling::sync::DEPTH;
use crate::wallet::WalletData;
use incrementalmerkletree::frontier::CommitmentTree;
use pivx_primitives::consensus::{BlockHeight, Network, NetworkConstants};
use pivx_primitives::memo::MemoBytes;
use pivx_primitives::merkle_tree::read_incremental_witness;
use pivx_primitives::transaction::builder::{BuildConfig, Builder};
use pivx_primitives::transaction::components::transparent::builder::TransparentSigningSet;
use pivx_primitives::transaction::fees::fixed::FeeRule;
use pivx_primitives::zip32::Scope;
use pivx_protocol::memo::Memo;
use pivx_protocol::value::Zatoshis;
use rand_core::OsRng;
use sapling::note::Note;
use sapling::{Anchor, Node};
use std::error::Error;
use std::io::Cursor;
use std::str::FromStr;

/// Result of building a shield transaction.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TransactionResult {
    pub txhex: String,
    pub nullifiers: Vec<String>,
    pub amount: u64,
    pub fee: u64,
}

/// Build and sign a shield transaction spending from the wallet's notes.
///
/// `prover` must be supplied by the caller (see [`crate::sapling::prover::verify_and_load_params`]).
/// `block_height` should be set to the chain tip + 1, fetched by the consumer.
pub fn create_shield_transaction(
    wallet: &mut WalletData,
    to_address: &str,
    amount: u64,
    memo: &str,
    block_height: u32,
    prover: &SaplingProver,
) -> Result<TransactionResult, Box<dyn Error>> {
    let extsk = keys::decode_extsk(&wallet.derive_extsk()?)?;
    let network = Network::MainNetwork;

    let mut notes: Vec<(Note, String, bool)> = wallet
        .unspent_notes
        .iter()
        .map(|n| {
            let note: Note = serde_json::from_value(n.note.clone())?;
            let has_memo = n.memo.as_ref().is_some_and(|m| !m.is_empty());
            Ok((note, n.witness.clone(), has_memo))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    // Spend non-memo notes first, then by ascending value.
    notes.sort_by_key(|(note, _, has_memo)| (*has_memo, note.value().inner()));

    let anchor = match notes.first() {
        Some((_, witness_hex, _)) => {
            let witness = read_incremental_witness::<Node, _, { DEPTH }>(Cursor::new(
                crate::simd::hex::hex_string_to_bytes(witness_hex),
            ))?;
            Anchor::from_bytes(witness.root().to_bytes())
                .into_option()
                .unwrap_or(Anchor::empty_tree())
        }
        None => return Err("No spendable notes available".into()),
    };

    let mut builder = Builder::new(
        network,
        BlockHeight::from_u32(block_height),
        BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: None,
        },
    );
    let transparent_signing_set = TransparentSigningSet::new();

    let (transparent_output_count, sapling_output_count) =
        if to_address.starts_with(network.hrp_sapling_payment_address()) {
            (0u64, 2u64)
        } else {
            (1u64, 2u64)
        };

    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let fvk = dfvk.fvk().clone();
    let nk = dfvk.to_nk(Scope::External);

    let mut total = 0u64;
    let mut nullifiers = vec![];
    let mut sapling_input_count = 0u64;
    let mut fee = 0u64;

    for (note, witness_hex, _) in &notes {
        let witness = read_incremental_witness::<Node, _, { DEPTH }>(Cursor::new(
            crate::simd::hex::hex_string_to_bytes(witness_hex),
        ))?;
        builder
            .add_sapling_spend::<FeeRule>(
                fvk.clone(),
                note.clone(),
                witness.path().ok_or("Empty commitment tree")?,
            )
            .map_err(|_| "Failed to add sapling spend")?;

        let nullifier = note.nf(&nk, witness.witnessed_position().into());
        nullifiers.push(crate::simd::hex::bytes_to_hex_string(&nullifier.to_vec()));

        sapling_input_count += 1;
        fee = fees::estimate_fee(
            0,
            transparent_output_count,
            sapling_input_count,
            sapling_output_count,
        );
        total += note.value().inner();
        if total >= amount + fee {
            break;
        }
    }

    if total < amount + fee {
        return Err(format!(
            "Not enough balance. Have: {} sat, need: {} sat (amount) + {} sat (fee)",
            total, amount, fee
        )
        .into());
    }

    let send_amount = Zatoshis::from_u64(amount).map_err(|_| "Invalid amount")?;
    let change_amount =
        Zatoshis::from_u64(total - amount - fee).map_err(|_| "Invalid change")?;

    let to = keys::decode_generic_address(to_address)?;
    match to {
        GenericAddress::Transparent(addr) => {
            builder
                .add_transparent_output(&addr, send_amount)
                .map_err(|e| format!("Failed to add transparent output: {:?}", e))?;
        }
        GenericAddress::Shield(addr) => {
            let memo_bytes = if memo.is_empty() {
                MemoBytes::empty()
            } else {
                Memo::from_str(memo)
                    .map_err(|e| format!("Invalid memo: {}", e))?
                    .encode()
            };
            builder
                .add_sapling_output::<FeeRule>(None, addr, send_amount, memo_bytes)
                .map_err(|_| "Failed to add sapling output")?;
        }
    }

    if change_amount.is_positive() {
        let extfvk = keys::decode_extfvk(&wallet.extfvk)?;
        let (_idx, change_addr) = extfvk.to_diversifiable_full_viewing_key().default_address();
        builder
            .add_sapling_output::<FeeRule>(None, change_addr, change_amount, MemoBytes::empty())
            .map_err(|_| "Failed to add change output")?;
    }

    let result = builder.build(
        &transparent_signing_set,
        &[extsk],
        &[],
        OsRng,
        &prover.1,
        &prover.0,
        &FeeRule::non_standard(Zatoshis::from_u64(fee).map_err(|_| "Invalid fee")?),
    )?;

    let mut tx_hex = vec![];
    result.transaction().write(&mut tx_hex)?;

    Ok(TransactionResult {
        txhex: crate::simd::hex::bytes_to_hex_string(&tx_hex),
        nullifiers,
        amount,
        fee,
    })
}

// Re-export for convenience: callers often want the tree DEPTH constant when
// constructing/reading commitment trees alongside the builder.
pub use crate::sapling::sync::DEPTH as COMMITMENT_TREE_DEPTH;

/// Read a commitment tree from its hex-encoded form. Used by transparent
/// builders when the destination is a shield address (they need an anchor).
pub fn read_tree_hex(tree_hex: &str) -> Result<CommitmentTree<Node, { DEPTH }>, Box<dyn Error>> {
    let bytes = crate::simd::hex::hex_string_to_bytes(tree_hex);
    Ok(pivx_primitives::merkle_tree::read_commitment_tree(Cursor::new(bytes))?)
}
