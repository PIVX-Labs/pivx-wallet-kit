//! In-memory wallet state and pure (de)serialization helpers.
//!
//! Persistence (disk, IndexedDB, etc.) is the consumer's responsibility.
//! This module owns the `WalletData` shape, note/UTXO tracking, checkpoint
//! reset, and a symmetric stream cipher for on-disk secret encryption,
//! but never touches the filesystem.

use crate::checkpoints;
use crate::keys;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A serializable spendable Sapling note (mirrors pivx-shield-rust's JSSpendableNote).
#[derive(Clone, Serialize, Deserialize, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
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

/// The HD slot a transparent output was received at: the `change` and `index`
/// components of `m/44'/119'/0'/change/index`.
///
/// [`Default`] is `0/0`, the slot every non-rotating consumer uses and the one
/// [`WalletData::get_transparent_address`] returns.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct HdSlot {
    pub change: u32,
    pub index: u32,
}

/// A transparent unspent transaction output.
///
/// [`Default`] is derived so the maturity fields can be left off with
/// `..Default::default()`; the defaults (`coinstake: false`, `confirmations: 0`)
/// mean "an ordinary, immediately spendable output".
#[derive(Serialize, Deserialize, Clone, Default, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SerializedUTXO {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script: String,
    pub height: u32,
    /// Whether this output is subject to [`crate::params::COINBASE_MATURITY`].
    /// Defaults to `false`, so a consumer that never sets it sees exactly the
    /// pre-maturity behaviour. Note that [`parse_blockbook_utxos`] sets it from
    /// the explorer response when the key is present, so "never sets it" is a
    /// claim about your explorer as much as about your code.
    ///
    /// Named for the common case, but it covers **coinbase outputs too**: PIVX
    /// matures the two identically, and this carries both rather than splitting
    /// them across two fields that would always be read together. Set it on
    /// mining and masternode rewards as well as on staking ones.
    ///
    /// A staked cold-staking delegation lands here: staking consumes the
    /// delegation and recreates it inside a coinstake, so this is the *normal*
    /// state of a delegation that has been earning for any length of time.
    #[serde(default)]
    #[tsify(optional)]
    pub coinstake: bool,
    /// Depth in the main chain, as reported by the explorer this UTXO came
    /// from. Only consulted when `coinstake` is set; see
    /// [`SerializedUTXO::is_mature`].
    ///
    /// A stale value is safe in the direction that matters: confirmations only
    /// grow, so an old reading understates depth and holds an output back
    /// slightly longer than necessary rather than releasing it early.
    #[serde(default)]
    #[tsify(optional)]
    pub confirmations: u32,
    /// Which HD slot's key can sign this output, when the consumer knows.
    ///
    /// Only rotating consumers need it. A transparent output carries no hint of
    /// which of a wallet's addresses received it: the UTXO endpoint is queried
    /// per address, so the caller is the only party that ever knows, and the
    /// kit derives one key per build. Until now that key was always `0/0`, so a
    /// UTXO received at `0/5` and handed to an ordinary send got signed against
    /// the wrong script, producing a transaction the network rejects, with
    /// nothing in the kit positioned to notice.
    ///
    /// Tagging it closes that: the wallet-state builders skip anything not at
    /// `0/0`, and the `*_from_utxos` builders reject anything that disagrees
    /// with the slot they were asked to sign for.
    ///
    /// `None` means untagged, which is what every existing consumer produces
    /// and what [`parse_blockbook_utxos`] returns. An untagged output matches
    /// every slot ([`SerializedUTXO::matches_slot`]), so behaviour is exactly
    /// as it was before this field existed: the caller keeps whatever
    /// bookkeeping they already had.
    #[serde(default, rename = "hdSlot")]
    #[tsify(optional)]
    pub hd_slot: Option<HdSlot>,
}

impl SerializedUTXO {
    /// Whether the key at `m/44'/119'/0'/change/index` may sign this output.
    ///
    /// An untagged UTXO (`hd_slot: None`) matches every slot. The tag is opt-in,
    /// and its absence means "unknown", never "not this one": treating unknown
    /// as a mismatch would break every consumer that predates the field, and
    /// the pre-existing contract is that the caller vouches for the set they
    /// hand in.
    pub fn matches_slot(&self, change: u32, index: u32) -> bool {
        match self.hd_slot {
            Some(slot) => slot.change == change && slot.index == index,
            None => true,
        }
    }

    /// Whether `txid` is a well-formed transaction id: exactly 32 bytes of hex.
    ///
    /// Worth checking explicitly because nothing downstream will. A txid is
    /// decoded with [`crate::simd::hex::hex_string_to_bytes`], which is an
    /// unchecked SIMD decoder: a non-hex byte decodes to garbage and an
    /// odd-length string drops its trailing nibble, neither loudly. The result
    /// is written straight into the transaction's prevout, so a malformed txid
    /// does not fail, it produces a transaction whose bytes are wrong, and the
    /// signature is computed over the same wrong bytes, so nothing disagrees
    /// with anything.
    ///
    /// The parse boundary would catch this, but two documented paths go around
    /// it: `setUtxos` takes a caller-built set directly, and the
    /// `*_from_utxos` builders never touch `WalletData` at all. Both are the
    /// paths a payment processor uses.
    pub fn has_valid_txid(&self) -> bool {
        self.txid.len() == 64 && self.txid.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /// Whether the network will accept a spend of this output right now.
    ///
    /// Only coinstake and coinbase outputs are ever immature; everything else
    /// is spendable as soon as it exists. An immature output is not lost, it is
    /// waiting: the count rises one per block.
    pub fn is_mature(&self) -> bool {
        !self.coinstake || self.confirmations > crate::params::COINBASE_MATURITY
    }

    /// Blocks remaining until [`SerializedUTXO::is_mature`] turns true.
    pub fn blocks_until_mature(&self) -> u32 {
        if self.is_mature() {
            0
        } else {
            (crate::params::COINBASE_MATURITY + 1).saturating_sub(self.confirmations)
        }
    }
}

/// Whether a UTXO is a cold-staking delegation rather than an ordinary output.
///
/// Requires the `script` field: a P2CS output is recognisable only from its
/// script, and nothing else about the UTXO distinguishes it. An empty script
/// means "unknown", and unknown is treated as ordinary, which is the direction
/// that preserves existing behaviour, at the cost of the hazard documented on
/// [`WalletData::get_transparent_balance`].
pub fn is_delegated_utxo(utxo: &SerializedUTXO) -> bool {
    if utxo.script.is_empty() {
        return false;
    }
    crate::transparent::coldstake::is_p2cs(&crate::simd::hex::hex_string_to_bytes(&utxo.script))
}

/// The hex `scriptPubKey` carried on a UTXO entry, or empty if absent or
/// malformed.
///
/// No explorer serves this on its UTXO endpoint, so it is only ever present
/// because the caller joined it on themselves; see [`parse_blockbook_utxos`]
/// for where it comes from. `hex` is accepted because that is the name the
/// field has on the tx endpoint it gets copied from, and `scriptPubKey` may
/// arrive either flat or as Core's verbose-RPC object.
fn utxo_script_hex(u: &serde_json::Value) -> String {
    let raw = u["script"]
        .as_str()
        .or_else(|| u["scriptPubKey"].as_str())
        .or_else(|| u["scriptPubKey"]["hex"].as_str())
        .or_else(|| u["hex"].as_str())
        .unwrap_or_default();

    // `hex_string_to_bytes` is an unchecked SIMD decoder: an odd length drops a
    // trailing nibble and a non-hex byte decodes to garbage, neither loudly. A
    // malformed script that reached `is_delegated_utxo` would be classified on
    // that garbage, so it is dropped to empty here instead, which reads as
    // "unknown" and is the direction that stays safe.
    if raw.is_empty() || !raw.len().is_multiple_of(2) || !raw.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return String::new();
    }
    raw.to_ascii_lowercase()
}

/// Read a JSON field that may be a number or a decimal string.
///
/// Blockbook returns `value` as a string on some revisions and a number on
/// others, and there is no reason to assume the other integer fields are
/// exempt, so every one of them goes through this rather than `as_u64` alone.
/// Returns `None` when the field is absent, null, or not an unsigned integer in
/// either form; callers decide whether that is a default or a reason to skip
/// the entry.
fn json_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
}

/// Parse a list of UTXOs from a Blockbook API v2 `/api/v2/utxo/{address}` response.
///
/// Accepts amounts as either a string (`"12345"`) or a JSON number, both of
/// which appear in the wild depending on the Blockbook revision. UTXOs with
/// empty txids or zero amounts are skipped.
///
/// # Scripts
///
/// The UTXO endpoint carries no `scriptPubKey`, on Blockbook or on its
/// work-alikes (rusty-blox included), so `script` is normally empty and
/// consumers that only build ordinary sends reconstruct P2PKH from their own
/// address.
///
/// Cold staking cannot do that. A P2CS output is recognisable only from its
/// script, and the sighash commits to the exact bytes, so those consumers must
/// join a second call onto each entry before calling this:
/// `/api/v2/tx/{txid}` returns `vout[n].hex`, the scriptPubKey of outpoint
/// `(txid, n)`. Entries are read for `script`, `scriptPubKey` or `hex`, so the
/// field can be copied across under whichever name is handiest. Anything that
/// is not valid even-length hex is treated as absent.
///
/// # Maturity
///
/// `coinstake` and `confirmations` are read from the entry when present.
/// Unlike `script`, this needs no cooperation from the caller: an explorer that
/// returns those keys (rusty-blox does, Blockbook proper does not) turns on
/// maturity enforcement for every builder on its own. The effect reaches
/// ordinary sends, not only cold staking, so a caller that derives a spendable
/// total by summing the returned slice will disagree with
/// [`WalletData::get_transparent_balance`] and with what the builders will
/// actually select.
///
/// A `coinbase` key, where an explorer supplies one, folds into the same flag:
/// PIVX matures coinbase and coinstake outputs by the identical rule, so mining
/// and masternode rewards are held back alongside staking ones. A `spendable`
/// key is ignored; the verdict comes from the other two.
pub fn parse_blockbook_utxos(raw: &[serde_json::Value]) -> Vec<SerializedUTXO> {
    parse_blockbook_utxos_at(raw, None)
}

/// [`parse_blockbook_utxos`], tagging every parsed output with the HD slot it
/// was received at.
///
/// The UTXO endpoint is queried per address, so a rotating consumer already
/// knows which slot a response belongs to at the moment it arrives. Passing it
/// here is the cheapest place to record it: the alternative is re-walking the
/// returned slice to set `hdSlot` by hand, and a consumer who forgets loses the
/// protection the tag exists to provide.
///
/// `None` leaves every output untagged, which is what [`parse_blockbook_utxos`]
/// does and what every consumer written before the field got.
pub fn parse_blockbook_utxos_at(
    raw: &[serde_json::Value],
    hd_slot: Option<HdSlot>,
) -> Vec<SerializedUTXO> {
    let mut utxos: Vec<SerializedUTXO> = Vec::new();
    for u in raw {
        let txid = u["txid"].as_str().unwrap_or_default().to_string();
        // Present-but-unparseable is not the same as absent, and for `vout` the
        // difference decides which output gets spent. `value` is already read as
        // either a string or a number because Blockbook revisions differ on
        // that, and nothing says `vout` is exempt from the same drift: a
        // revision returning `"1"` would have silently become vout 0 here, and
        // vout 0 is usually a real output, so the wallet would sign for the
        // wrong outpoint of the right transaction rather than fail. Absent
        // still defaults to 0, which is the pre-existing behaviour.
        let vout = match u.get("vout") {
            Some(v) => match json_u64(v) {
                Some(n) => n as u32,
                None => continue,
            },
            None => 0,
        };
        let amount = json_u64(&u["value"]).unwrap_or(0);
        let height = json_u64(&u["height"]).unwrap_or(0) as u32;
        let script = utxo_script_hex(u);
        // Explorers differ on whether they flag coinstake outputs at all
        // (Blockbook's UTXO entries carry no such field), so this is normally
        // set by the caller from the same tx responses that supplied `script`.
        // Absent means "not a coinstake", which preserves prior behaviour.
        //
        // `coinbase` folds into the same flag. PIVX matures the two identically
        // (`IsCoinBase() || IsCoinStake()` in `CheckInputs`), and a wallet
        // holding mining or masternode rewards would otherwise have them
        // treated as spendable as soon as they arrive. Folding rather than
        // adding a field keeps `SerializedUTXO` the shape it already is.
        let coinstake = u["coinstake"].as_bool().unwrap_or(false)
            || u["coinbase"].as_bool().unwrap_or(false);
        let confirmations = json_u64(&u["confirmations"]).unwrap_or(0) as u32;

        // A txid that is not 32 bytes of hex cannot be turned into a prevout,
        // and the unchecked hex decoder downstream will not say so: it drops a
        // trailing nibble or decodes garbage and the builder writes the result
        // into the transaction. Dropped here alongside the other two, so the
        // entry never reaches a balance or a signature.
        if txid.is_empty() || amount == 0 || txid.len() != 64
            || !txid.bytes().all(|b| b.is_ascii_hexdigit())
        {
            continue;
        }

        // Deduplicate by outpoint. Blockbook can list the same UTXO twice
        // while a transaction is confirming, once from its mempool view
        // (confirmations 0, height 0) and once as confirmed, and observed
        // responses do exactly that. Ingesting both doubles the apparent
        // balance and makes the builder select the same outpoint twice,
        // producing a transaction that spends one output twice. That is a
        // guaranteed network rejection, and it looks like a wallet bug from
        // the outside, so the guard belongs here at the parse boundary rather
        // than in each builder.
        //
        // Linear scan: UTXO sets are small, and it keeps input order
        // deterministic (first sighting wins its position) without pulling in
        // a hash map.
        if let Some(existing) = utxos
            .iter_mut()
            .find(|e| e.vout == vout && e.txid == txid)
        {
            // Prefer the confirmed sighting's height: the mempool copy
            // reports 0, which would misrepresent the UTXO's age.
            existing.height = existing.height.max(height);
            // A caller joining scripts on may have covered only one of the two
            // sightings. An empty script is "unknown", never a correction, so
            // it must not overwrite one we already have.
            if existing.script.is_empty() {
                existing.script = script;
            }
            // Same reasoning for maturity: the mempool sighting reports 0
            // confirmations, and taking the lower of the two would hold a
            // mature output back. `coinstake` is a property of the funding
            // transaction, so either sighting asserting it settles it.
            existing.confirmations = existing.confirmations.max(confirmations);
            existing.coinstake |= coinstake;
            continue;
        }

        utxos.push(SerializedUTXO {
            txid,
            vout,
            amount,
            script,
            height,
            coinstake,
            confirmations,
            hd_slot,
        });
    }
    utxos
}

/// Persistent wallet state.
///
/// Sensitive fields (`seed`, `mnemonic`) are intended to be encrypted by the
/// consumer before being written to storage, via [`encrypt_secrets`] /
/// [`decrypt_secrets`]. In memory, they are zeroized on drop.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, tsify::Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
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
    /// Hex nonce the persisted `seed` and `mnemonic` were encrypted under.
    ///
    /// Public by nature: a nonce is stored in the clear beside its ciphertext.
    /// `None` means either a live in-memory wallet (nothing is encrypted) or a
    /// file written before the nonce existed, which [`decrypt_secrets`] reads
    /// with the legacy keystream. Re-saving such a wallet writes a nonce.
    #[serde(default, rename = "cipherNonce", skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    #[zeroize(skip)]
    pub cipher_nonce: Option<String>,
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

    /// Derive the extended Sapling spending key on-the-fly from the
    /// stored seed.
    ///
    /// Returns the typed key directly: callers that need to feed it
    /// into the builder no longer pay an encode/decode round-trip on
    /// every shield send. For consumers that need the bech32 string
    /// form (persistence, RPC, display), use [`derive_extsk_encoded`].
    pub fn derive_extsk(&self) -> Result<::sapling::zip32::ExtendedSpendingKey, Box<dyn Error>> {
        keys::spending_key_from_seed(&self.seed, 0)
    }

    /// Like [`derive_extsk`] but returns the bech32-encoded string form.
    /// Convenient for persistence and RPC integration; for in-process
    /// signing prefer the typed [`derive_extsk`] above to avoid the
    /// encode/decode round-trip.
    pub fn derive_extsk_encoded(&self) -> Result<String, Box<dyn Error>> {
        Ok(keys::encode_extsk(&self.derive_extsk()?))
    }

    /// Get the mnemonic (for export only).
    pub fn get_mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Sum of all transparent UTXO values, in satoshis.
    #[inline]
    /// Spendable transparent balance, excluding anything delegated for cold
    /// staking.
    ///
    /// A delegated output still belongs to this wallet: the owner key can
    /// redeem it, but it cannot be spent by an ordinary P2PKH transaction, so
    /// counting it here would report funds that no plain send can reach. Use
    /// [`WalletData::get_delegated_balance`] for the other half, and
    /// `withdrawColdStake` to move it.
    ///
    /// Detection needs each UTXO's `script`, which no explorer supplies on its
    /// UTXO endpoint. When it is absent a delegated output is indistinguishable
    /// from an ordinary one and is counted here, so consumers that use cold
    /// staking must join it on from `/api/v2/tx/{txid}` before parsing; see
    /// [`parse_blockbook_utxos`].
    ///
    /// Immature coinstake outputs are excluded for the same reason: no send can
    /// reach them yet. See [`WalletData::get_immature_balance`]. A UTXO that
    /// never had `coinstake` set counts as mature, so this is unchanged for
    /// consumers that do not populate the field.
    ///
    /// Outputs tagged to an HD slot other than `0/0` are excluded for the same
    /// reason as the two above: an ordinary send derives the key at `0/0` and
    /// cannot sign them. See [`WalletData::get_rotated_balance`]. Untagged
    /// outputs count here, so this is also unchanged for consumers that do not
    /// populate `hd_slot`.
    pub fn get_transparent_balance(&self) -> u64 {
        self.unspent_utxos
            .iter()
            .filter(|u| !is_delegated_utxo(u) && u.is_mature() && u.matches_slot(0, 0))
            .map(|u| u.amount)
            .sum()
    }

    /// Value held at HD slots other than `0/0`, which the wallet-state builders
    /// cannot reach.
    ///
    /// Spend it with `sendTransparentFromUtxos*`, passing the slot's
    /// `fromChange` / `fromIndex` and only that slot's outputs. Always 0 unless
    /// UTXOs carry `hd_slot`, so a consumer that never rotates never sees it.
    ///
    /// A *balance*, not a spendable amount, and it overlaps the other two by
    /// design: a delegation or an immature coinstake received at `0/5` is
    /// counted here as well as in
    /// [`WalletData::get_delegated_balance`] / [`WalletData::get_immature_balance`].
    /// One answers "where does this live", the others "what state is it in".
    pub fn get_rotated_balance(&self) -> u64 {
        self.unspent_utxos
            .iter()
            .filter(|u| !u.matches_slot(0, 0))
            .map(|u| u.amount)
            .sum()
    }

    /// Value held in outputs that exist but cannot be spent yet, because they
    /// come from a coinstake or coinbase that has not reached
    /// [`crate::params::COINBASE_MATURITY`].
    ///
    /// Reported separately rather than folded into either balance so a UI can
    /// say "arriving in N blocks" instead of showing coins that vanish and
    /// reappear. Includes immature delegations, which are also counted in
    /// [`WalletData::get_delegated_balance`]: the two overlap by design, since
    /// one answers "what do I hold" and this one answers "what is still
    /// landing".
    pub fn get_immature_balance(&self) -> u64 {
        self.unspent_utxos.iter().filter(|u| !u.is_mature()).map(|u| u.amount).sum()
    }

    /// Balance held in cold-staking delegations, redeemable via
    /// `withdrawColdStake` rather than an ordinary send.
    ///
    /// Only counts UTXOs whose `script` is populated and parses as P2CS; see
    /// the note on [`WalletData::get_transparent_balance`].
    ///
    /// This is a *balance*, not a spendable amount. Staking a delegation
    /// replaces it with a coinstake output that PIVX will not let anyone spend
    /// until it is 101 confirmations deep, and that immature output is counted
    /// here because the coins are genuinely held. The withdrawal builder refuses
    /// it until it matures; see [`WalletData::get_immature_balance`] for how
    /// much is in that state.
    pub fn get_delegated_balance(&self) -> u64 {
        self.unspent_utxos
            .iter()
            .filter(|u| is_delegated_utxo(u))
            .map(|u| u.amount)
            .sum()
    }

    /// Get the default transparent address (derived from the mnemonic).
    pub fn get_transparent_address(&self) -> Result<String, Box<dyn Error>> {
        keys::get_transparent_address(&self.mnemonic)
    }

    /// Get the full 64-byte BIP39 seed (needed for transparent key derivation).
    ///
    /// Returns `Err` if `self.mnemonic` is not a valid BIP39 phrase. The
    /// stored mnemonic is *expected* to be valid post-`decrypt_secrets`,
    /// but this method is safe to call before decryption (it'll just
    /// fail): useful for early lifecycle paths where the wallet may
    /// still be sealed.
    ///
    /// The returned bytes are wrapped in [`Zeroizing`] so they wipe
    /// when the caller drops them.
    pub fn get_bip39_seed(&self) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
        let mnemonic = bip39::Mnemonic::parse_normalized(&self.mnemonic)
            .map_err(|e| format!("Invalid stored mnemonic: {e}"))?;
        Ok(Zeroizing::new(mnemonic.to_seed("").to_vec()))
    }

    /// Mark shield notes as spent by removing those whose nullifiers match.
    pub fn finalize_transaction(&mut self, spent_nullifiers: &[String]) {
        self.unspent_notes
            .retain(|n| !spent_nullifiers.contains(&n.nullifier));
    }

    /// Remove spent UTXOs after a transparent send.
    pub fn finalize_transparent_send(&mut self, spent: &[crate::transparent::builder::SpentOutpoint]) {
        self.unspent_utxos.retain(|u| {
            !spent.iter().any(|s| u.txid == s.txid && u.vout == s.vout)
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
            // Deliberately not carried across: `encrypt_secrets` draws a fresh
            // nonce, and copying the source wallet's would be meaningless here.
            cipher_nonce: None,
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

    let extsk = keys::spending_key_from_seed(&seed, 0)?;
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
        // A fresh wallet holds plaintext; a nonce appears only once
        // `encrypt_secrets` has run.
        cipher_nonce: None,
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

/// Length of the per-encryption nonce, in bytes.
pub const CIPHER_NONCE_LEN: usize = 16;

/// Domain tag for the seed's keystream. See [`crypt_v2`].
const DOMAIN_SEED: u8 = 0x01;

/// Domain tag for the mnemonic's keystream. See [`crypt_v2`].
const DOMAIN_MNEMONIC: u8 = 0x02;

/// SHA256-CTR with a nonce and a domain tag: the keystream is
/// `SHA256(key || nonce || domain || counter)`.
///
/// Replaces [`crypt`], which derived its keystream from the key and a counter
/// alone. That had two consequences, and the first is not theoretical:
///
///  * **The seed and the mnemonic shared a keystream.** `encrypt_secrets`
///    called `crypt` twice under one key, and each call restarted the counter
///    at zero, so both fields were XORed against the *same* first 32 bytes.
///    XORing the two stored ciphertexts therefore cancels the keystream and
///    yields `seed XOR mnemonic[0..32]` to anyone holding the file, no key
///    required. That is a two-time pad, and `extfvk` sits in the same file in
///    plaintext, giving an oracle to confirm a guess: recover a candidate seed
///    from a guessed mnemonic prefix, derive its extfvk, compare.
///  * **Every wallet under one key shared a keystream.** The intended native
///    key is machine-derived, so two wallets on a machine XORed to leak
///    `seedA XOR seedB`, and re-encrypting a wallet was byte-identical each
///    time.
///
/// The nonce is fresh per `encrypt_secrets` call and stored in the clear
/// beside the ciphertext, which is what a nonce is for. The domain tag
/// separates the two fields within one encryption, so a shared nonce still
/// yields independent keystreams.
fn crypt_v2(data: &[u8], key: &[u8; 32], nonce: &[u8], domain: u8) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut offset = 0;
    let mut counter = 0u64;

    while offset < data.len() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(nonce);
        hasher.update([domain]);
        hasher.update(counter.to_le_bytes());
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

/// SHA256-CTR stream cipher: XORs `data` with a keystream derived from `key`.
///
/// Symmetric: the same function encrypts and decrypts.
///
/// **Legacy.** Retained only so wallets encrypted before the nonce existed can
/// still be read; [`decrypt_secrets`] falls back to it. Do not encrypt with
/// this: two calls under one key produce the same keystream, so encrypting two
/// secrets with it lets an observer XOR the ciphertexts together and recover
/// one plaintext from the other. [`encrypt_secrets`] uses a nonced,
/// domain-separated keystream instead.
#[inline]
pub fn crypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut offset = 0;
    let mut counter = 0u64;

    while offset < data.len() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(counter.to_le_bytes());
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
    // Fresh per call, so re-encrypting the same wallet is not byte-identical
    // and two wallets sharing a key (the native path derives it from the
    // machine id) do not share a keystream.
    let mut nonce = [0u8; CIPHER_NONCE_LEN];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| format!("Failed to draw an encryption nonce: {e}"))?;

    let encrypted_seed = crypt_v2(&data.seed, key, &nonce, DOMAIN_SEED);
    data.seed.copy_from_slice(&encrypted_seed);

    let encrypted_mnemonic = crypt_v2(data.mnemonic.as_bytes(), key, &nonce, DOMAIN_MNEMONIC);
    data.mnemonic.zeroize();
    data.mnemonic = crate::simd::hex::bytes_to_hex_string(&encrypted_mnemonic);

    data.cipher_nonce = Some(crate::simd::hex::bytes_to_hex_string(&nonce));

    Ok(())
}

/// Encrypt the wallet's secrets with `key` and serialize the result as a
/// pretty-printed JSON string, ready to be persisted.
///
/// Prefer this over calling [`encrypt_secrets`] + `serde_json::to_string_pretty`
/// by hand: it clones the wallet via [`WalletData::clone_for_encryption`] first,
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
/// the stored value: a wrong key surfaces as an error rather than silently
/// producing garbage.
///
/// On any error the wallet's on-disk ciphertext is left untouched; only
/// after the extfvk check passes do the plaintext fields get committed.
/// This means a caller can retry with a different key without first
/// reloading the file from disk.
pub fn decrypt_secrets(data: &mut WalletData, key: &[u8; 32]) -> Result<(), Box<dyn Error>> {
    // Which keystream produced this file is recorded by the presence of a
    // nonce, so there is no guessing and no trial decryption: a file written
    // before the nonce existed reads with the legacy scheme, and re-saving it
    // writes a nonce. The extfvk check below is what actually decides whether
    // the key was right, and it is applied identically either way.
    let encrypted_bytes = crate::simd::hex::hex_string_to_bytes(&data.mnemonic);
    let (decrypted_seed, decrypted_mnemonic_bytes) = match &data.cipher_nonce {
        Some(nonce_hex) => {
            let nonce = crate::simd::hex::hex_string_to_bytes(nonce_hex);
            if nonce.len() != CIPHER_NONCE_LEN {
                return Err(format!(
                    "Wallet has a {}-byte cipher nonce, expected {CIPHER_NONCE_LEN}: the file \
                     is corrupted",
                    nonce.len()
                )
                .into());
            }
            (
                crypt_v2(&data.seed, key, &nonce, DOMAIN_SEED),
                crypt_v2(&encrypted_bytes, key, &nonce, DOMAIN_MNEMONIC),
            )
        }
        None => (crypt(&data.seed, key), crypt(&encrypted_bytes, key)),
    };

    // Decrypt into scratch buffers first.
    let mut candidate_seed = [0u8; 32];
    candidate_seed.copy_from_slice(&decrypted_seed);

    let candidate_mnemonic = match String::from_utf8(decrypted_mnemonic_bytes) {
        Ok(s) => s,
        Err(_) => {
            candidate_seed.zeroize();
            return Err("Failed to decrypt wallet: wrong key?".into());
        }
    };

    // Validate before mutating `data`.
    let extsk = match keys::spending_key_from_seed(&candidate_seed, 0) {
        Ok(k) => k,
        Err(e) => {
            candidate_seed.zeroize();
            return Err(e);
        }
    };
    let derived_extfvk = keys::encode_extfvk(&keys::full_viewing_key(&extsk));
    if derived_extfvk != data.extfvk {
        candidate_seed.zeroize();
        return Err("Failed to decrypt wallet: wrong key or corrupted data.".into());
    }

    // Commit. The nonce is dropped along with the ciphertext it belonged to,
    // keeping the invariant that a nonce is present exactly when the secret
    // fields hold ciphertext. `encrypt_secrets` draws a fresh one anyway, so
    // carrying this one forward could only mislead.
    data.seed.copy_from_slice(&candidate_seed);
    data.mnemonic = candidate_mnemonic;
    data.cipher_nonce = None;
    candidate_seed.zeroize();
    Ok(())
}
