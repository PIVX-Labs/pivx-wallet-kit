//! Pay-to-cold-staking (P2CS) script construction and parsing.
//!
//! Cold staking splits authority over an output in two: a *staking* key that
//! may stake the coins but never move them, and an *owner* key that may spend
//! them. The output script encodes both hashes and selects between them with a
//! branch the spender chooses at redeem time.
//!
//! # Provenance
//!
//! Every constant and offset below was verified byte-for-byte against two
//! independent sources rather than reconstructed from memory, because a wrong
//! script here does not fail loudly: it produces an output that is either
//! unspendable or spendable by the wrong party.
//!
//! * **PIVX Core**: `src/script/standard.cpp`
//!   (`GetScriptForStakeDelegation`, `GetScriptForStakeDelegationLOF`,
//!   `MatchPayToColdStaking`), `src/script/script.cpp`
//!   (`CScript::IsPayToColdStaking`), `src/script/script.h` (opcode values),
//!   `src/chainparams.cpp` (address prefixes, upgrade heights).
//! * **MyPIVXWallet**: `scripts/script.js` (`isP2CS`, `getAddressFromHash`),
//!   `scripts/transaction_builder.js` (`addColdStakeOutput`),
//!   `scripts/transaction.js` (`signInput`).
//!
//! Note that MyPIVXWallet's `OWNER_START_INDEX` / `COLD_START_INDEX` constants
//! are named the opposite way round to what they hold: index 6 is rendered as
//! a `coldaddress` (staking, `S...`) and index 28 as a `pubkeyhash` (owner,
//! `D...`). The offsets here follow Core's `MatchPayToColdStaking`, which is
//! unambiguous.

use crate::fees;
use crate::keys;
use crate::params::{PIVX_PUBKEY_PREFIX, PIVX_STAKING_PREFIX};
use crate::transparent::builder::{
    SigningInput, SpentOutpoint, TransparentTransactionResult, TxOutput,
    validate_outpoints, sign_and_serialize,
};
use crate::wallet::{SerializedUTXO, WalletData};
use std::error::Error;

/// Smallest delegation the reference wallets will create: 1 PIV.
///
/// Defined as `MIN_COLDSTAKING_AMOUNT` in PIVX Core's `consensus/consensus.h`,
/// but note that despite living in that header it is **not** enforced by
/// `validation.cpp` or `policy.cpp`: it is a wallet-level rule. Core's
/// `delegatestake` RPC rejects smaller amounts, and MyPIVXWallet refuses them
/// too. This crate follows both rather than emitting delegations the reference
/// implementations would not.
pub const MIN_COLDSTAKING_AMOUNT: u64 = 100_000_000;

/// Preferred size of a single delegated output: 500 PIV.
///
/// `stakeSplitTarget` in MyPIVXWallet's `chain_params.json`. Staking works per
/// output, so one large delegation is a single staking unit while several
/// right-sized ones compete independently. MyPIVXWallet splits on this boundary
/// when delegating, and [`split_delegation_amounts`] reproduces its arithmetic.
pub const STAKE_SPLIT_TARGET: u64 = 50_000_000_000;

/// Divide a delegation into output-sized pieces, matching MyPIVXWallet's
/// `createAndSendTransaction` split.
///
/// Below the target the whole amount is one output. At or above it, the amount
/// is cut into `floor(amount / target)` pieces, with the remainder folded into
/// the *first* one, so every piece is at least the target and none is a stray
/// fragment. Returns amounts summing exactly to `amount`.
///
/// ```text
///  400 PIV -> [400]                  (below target)
/// 1000 PIV -> [500, 500]
/// 1200 PIV -> [700, 500]             (remainder joins the first)
/// ```
pub fn split_delegation_amounts(amount: u64, target: u64) -> Vec<u64> {
    if target == 0 || amount < target {
        return vec![amount];
    }
    let pieces = amount / target;
    let remainder = amount % target;
    (0..pieces)
        .map(|i| if i == 0 { target + remainder } else { target })
        .collect()
}

// Opcodes, from PIVX Core `src/script/script.h`.
const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_ROT: u8 = 0x7b;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSIG: u8 = 0xac;
const OP_FALSE: u8 = 0x00;
const PUSH_20: u8 = 0x14;

/// `OP_CHECKCOLDSTAKEVERIFY_LOF`: "last output free", permitting the final
/// output of a coinstake to pay elsewhere (masternode and budget payments).
const OP_CHECKCOLDSTAKEVERIFY_LOF: u8 = 0xd1;

/// `OP_CHECKCOLDSTAKEVERIFY`: the post-v6.0 form, which drops the last-output
/// exemption.
const OP_CHECKCOLDSTAKEVERIFY: u8 = 0xd2;

/// Exact serialized length of a P2CS script. Core's `IsPayToColdStaking`
/// requires equality, not a minimum.
pub const P2CS_SCRIPT_LEN: usize = 51;

/// Offsets of the two embedded hashes, per Core's `MatchPayToColdStaking`:
/// `stakerPubKeyHash = script[6..26]`, `ownerPubKeyHash = script[28..48]`.
const STAKER_HASH_OFFSET: usize = 6;
const OWNER_HASH_OFFSET: usize = 28;

/// The two P2CS variants. Both are accepted by `IsPayToColdStaking`, so an
/// output of either kind is spendable by the same owner path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdStakeVariant {
    /// `OP_CHECKCOLDSTAKEVERIFY_LOF` (`0xd1`). **The current network form.**
    ///
    /// Core selects between the two on `UPGRADE_V6_0` activation, and V6 is set
    /// to `NO_ACTIVATION_HEIGHT` on mainnet, testnet and regtest alike, so
    /// `fV6Enforced` is false everywhere today and Core itself emits LOF.
    /// MyPIVXWallet emits LOF unconditionally, which agrees.
    Lof,
    /// `OP_CHECKCOLDSTAKEVERIFY` (`0xd2`), for after v6.0 activates.
    ///
    /// Provided so the switch is a one-line change rather than a re-derivation,
    /// but do not emit it until V6 is actually active: pre-activation nodes
    /// treat the delegation differently.
    V6,
}

impl ColdStakeVariant {
    fn opcode(self) -> u8 {
        match self {
            ColdStakeVariant::Lof => OP_CHECKCOLDSTAKEVERIFY_LOF,
            ColdStakeVariant::V6 => OP_CHECKCOLDSTAKEVERIFY,
        }
    }
}

/// The two key hashes a P2CS output commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdStakeHashes {
    /// May stake the output, never spend it.
    pub staker: [u8; 20],
    /// May spend the output.
    pub owner: [u8; 20],
}

/// Decode a Base58Check address, returning `(version, hash160)`.
///
/// Shares the checksum discipline of the P2PKH path: an unverified address is
/// how funds reach a hash nobody holds a key for, and a delegation locks the
/// coins behind *two* hashes, so a typo in either is equally unrecoverable.
fn decode_checked(address: &str) -> Result<(u8, [u8; 20]), Box<dyn Error>> {
    use sha2::{Digest, Sha256};

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

    let (payload, checksum) = decoded.split_at(21);
    let expected = Sha256::digest(Sha256::digest(payload));
    if expected[..4] != checksum[..] {
        return Err(format!(
            "Invalid address checksum for {address}: the address is mistyped or corrupted"
        )
        .into());
    }

    let mut hash = [0u8; 20];
    hash.copy_from_slice(&payload[1..21]);
    Ok((payload[0], hash))
}

/// Base58Check-encode `hash160` under `version`.
pub(crate) fn encode_checked(version: u8, hash: &[u8; 20]) -> String {
    use sha2::{Digest, Sha256};

    let mut payload = Vec::with_capacity(25);
    payload.push(version);
    payload.extend_from_slice(hash);
    let checksum = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum[..4]);
    bs58::encode(payload).into_string()
}

/// Encode a staking (`S...`) address from a key hash.
pub fn encode_staking_address(hash: &[u8; 20]) -> String {
    encode_checked(PIVX_STAKING_PREFIX, hash)
}

/// Decode a staking (`S...`) address to its key hash.
///
/// Rejects owner (`D...`) addresses: swapping the two arguments of a delegation
/// would hand spending authority to the intended staker, so the version byte is
/// enforced rather than ignored.
pub fn decode_staking_address(address: &str) -> Result<[u8; 20], Box<dyn Error>> {
    let (version, hash) = decode_checked(address)?;
    if version != PIVX_STAKING_PREFIX {
        return Err(format!(
            "Address {address} has version byte {version}, not a PIVX staking address, which \
             uses {PIVX_STAKING_PREFIX} and renders as `S...`"
        )
        .into());
    }
    Ok(hash)
}

/// Decode an owner (`D...`) transparent address to its key hash.
pub fn decode_owner_address(address: &str) -> Result<[u8; 20], Box<dyn Error>> {
    let (version, hash) = decode_checked(address)?;
    if version != PIVX_PUBKEY_PREFIX {
        return Err(format!(
            "Address {address} has version byte {version}, not a PIVX transparent address, \
             which uses {PIVX_PUBKEY_PREFIX} and renders as `D...`"
        )
        .into());
    }
    Ok(hash)
}

/// Build a P2CS `scriptPubKey` delegating to `staker`, spendable by `owner`.
///
/// Layout, matching Core's `GetScriptForStakeDelegationLOF` exactly:
///
/// ```text
/// OP_DUP OP_HASH160 OP_ROT OP_IF <verify-op> 0x14 <staker:20>
///                          OP_ELSE          0x14 <owner:20>
///                          OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG
/// ```
///
/// The `OP_IF` branch carries the staking hash and the `OP_ELSE` branch the
/// owner hash: the redeeming script pushes a boolean to pick one. Getting that
/// order backwards would let the staker spend and leave the owner unable to.
pub fn build_p2cs_script(
    staker: &[u8; 20],
    owner: &[u8; 20],
    variant: ColdStakeVariant,
) -> Vec<u8> {
    let mut script = Vec::with_capacity(P2CS_SCRIPT_LEN);
    script.push(OP_DUP);
    script.push(OP_HASH160);
    script.push(OP_ROT);
    script.push(OP_IF);
    script.push(variant.opcode());
    script.push(PUSH_20);
    script.extend_from_slice(staker);
    script.push(OP_ELSE);
    script.push(PUSH_20);
    script.extend_from_slice(owner);
    script.push(OP_ENDIF);
    script.push(OP_EQUALVERIFY);
    script.push(OP_CHECKSIG);
    debug_assert_eq!(script.len(), P2CS_SCRIPT_LEN);
    script
}

/// Build a P2CS `scriptPubKey` from a staking address and an owner address.
pub fn p2cs_script_from_addresses(
    staking_address: &str,
    owner_address: &str,
    variant: ColdStakeVariant,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let staker = decode_staking_address(staking_address)?;
    let owner = decode_owner_address(owner_address)?;
    Ok(build_p2cs_script(&staker, &owner, variant))
}

/// Whether `script` is a well-formed P2CS output.
///
/// Mirrors Core's `CScript::IsPayToColdStaking`, including the exact-length
/// requirement: a 52-byte script with the right prefix is not P2CS.
pub fn is_p2cs(script: &[u8]) -> bool {
    script.len() == P2CS_SCRIPT_LEN
        && script[0] == OP_DUP
        && script[1] == OP_HASH160
        && script[2] == OP_ROT
        && script[3] == OP_IF
        && (script[4] == OP_CHECKCOLDSTAKEVERIFY || script[4] == OP_CHECKCOLDSTAKEVERIFY_LOF)
        && script[5] == PUSH_20
        && script[26] == OP_ELSE
        && script[27] == PUSH_20
        && script[48] == OP_ENDIF
        && script[49] == OP_EQUALVERIFY
        && script[50] == OP_CHECKSIG
}

/// Whether `script` is the LOF variant. Assumes [`is_p2cs`] already passed.
pub fn is_p2cs_lof(script: &[u8]) -> bool {
    is_p2cs(script) && script[4] == OP_CHECKCOLDSTAKEVERIFY_LOF
}

/// Extract both key hashes from a P2CS script.
pub fn parse_p2cs_script(script: &[u8]) -> Result<ColdStakeHashes, Box<dyn Error>> {
    if !is_p2cs(script) {
        return Err("Not a pay-to-cold-staking script".into());
    }
    let mut staker = [0u8; 20];
    let mut owner = [0u8; 20];
    staker.copy_from_slice(&script[STAKER_HASH_OFFSET..STAKER_HASH_OFFSET + 20]);
    owner.copy_from_slice(&script[OWNER_HASH_OFFSET..OWNER_HASH_OFFSET + 20]);
    Ok(ColdStakeHashes { staker, owner })
}

/// The staking and owner addresses a P2CS script pays, rendered in their
/// respective formats (`S...` and `D...`).
pub fn addresses_from_p2cs_script(script: &[u8]) -> Result<(String, String), Box<dyn Error>> {
    let h = parse_p2cs_script(script)?;
    Ok((
        encode_staking_address(&h.staker),
        encode_checked(PIVX_PUBKEY_PREFIX, &h.owner),
    ))
}

/// Build the `scriptSig` that redeems a P2CS output back to its owner.
///
/// Identical to a P2PKH `scriptSig` except for a single `OP_FALSE` between the
/// signature and the pubkey. That byte is the branch selector: `OP_ROT` lifts it
/// to the top of the stack and `OP_IF` pops it, so false takes `OP_ELSE`: the
/// owner hash, which `OP_EQUALVERIFY` then matches against `hash160(pubkey)`.
/// Pushing true instead selects the staking branch, which is the staker's path
/// and is not what a spend wants.
///
/// Matches MyPIVXWallet's `signInput({ isColdStake: true })`.
pub fn build_p2cs_owner_script_sig(sig_with_hashtype: &[u8], pubkey: &[u8]) -> Vec<u8> {
    let mut script_sig = Vec::with_capacity(sig_with_hashtype.len() + pubkey.len() + 3);
    script_sig.push(sig_with_hashtype.len() as u8);
    script_sig.extend_from_slice(sig_with_hashtype);
    script_sig.push(OP_FALSE);
    script_sig.push(pubkey.len() as u8);
    script_sig.extend_from_slice(pubkey);
    script_sig
}

/// Build an ordinary P2PKH `scriptSig`: `<sig> <pubkey>`.
///
/// Sits beside [`build_p2cs_owner_script_sig`] so the signing loop has one
/// definition of each redeem-script layout to choose between, rather than
/// open-coding either.
pub fn build_p2pkh_script_sig(sig_with_hashtype: &[u8], pubkey: &[u8]) -> Vec<u8> {
    let mut script_sig = Vec::with_capacity(sig_with_hashtype.len() + pubkey.len() + 2);
    script_sig.push(sig_with_hashtype.len() as u8);
    script_sig.extend_from_slice(sig_with_hashtype);
    script_sig.push(pubkey.len() as u8);
    script_sig.extend_from_slice(pubkey);
    script_sig
}

/// P2PKH `scriptPubKey` for a key hash: the form a P2CS output is redeemed
/// *into* when an owner withdraws a delegation.
pub fn p2pkh_script_from_hash(hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(OP_DUP);
    script.push(OP_HASH160);
    script.push(PUSH_20);
    script.extend_from_slice(hash);
    script.push(OP_EQUALVERIFY);
    script.push(OP_CHECKSIG);
    script
}

/// Derive the owner key hash the kit signs with, from a BIP39 seed and HD slot.
///
/// Convenience wrapper so callers building a delegation do not have to
/// re-derive and re-decode their own address.
pub fn owner_hash_from_seed(
    bip39_seed: &[u8],
    change: u32,
    index: u32,
) -> Result<[u8; 20], Box<dyn Error>> {
    let (address, _pubkey, _priv) =
        keys::transparent_key_from_bip39_seed(bip39_seed, change, index)?;
    decode_owner_address(&address)
}

/// Build and sign a delegation: transparent inputs → one P2CS output.
///
/// Delegates `amount` to `staking_address`, retaining spending authority at the
/// wallet's own transparent address (HD `0/0`) so the delegation can be
/// withdrawn later. Any remainder returns there as a plain P2PKH change output.
///
/// **`0/0` on both sides, and not by omission.** Funding comes from `0/0`, and
/// the owner hash written into the P2CS script is `0/0`'s. The withdrawal
/// builders take the owner slot as an argument, so the two halves of cold
/// staking are deliberately asymmetric: anything this function builds is
/// withdrawn with `from_change = 0, from_index = 0`, while
/// [`create_coldstake_withdrawal`] can also redeem delegations owned elsewhere
/// (created by another wallet, or by a future version of this one).
///
/// The asymmetry only becomes reachable once a consumer rotates transparent
/// addresses, and it does not do what the shape of the call suggests:
/// delegating to *this wallet's own* rotated staking address (`stakingAddressAt(0,
/// 5)`) produces a delegation staked by `0/5` and owned by `0/0`. That is a
/// valid delegation and the coins stay under this wallet's control, but a
/// caller expecting "self-stake at slot 5" to mean "owner at slot 5" would go
/// looking for the funds under the wrong key. Pinned in
/// `tests/transparent_address_rotation.rs`.
///
/// The output is a normal transaction output with an unusual script, so this
/// goes through the same [`sign_and_serialize`] path as every other transparent
/// send: the signed preimage and the emitted body are produced from one
/// `TxOutput` slice by one function, exactly as for a P2PKH send.
///
/// `TransparentTransactionResult::amount` is the delegated amount, excluding
/// change and fee.
pub fn create_delegation_transaction(
    wallet: &mut WalletData,
    bip39_seed: &[u8],
    staking_address: &str,
    amount: u64,
    variant: ColdStakeVariant,
) -> Result<TransparentTransactionResult, Box<dyn Error>> {
    let selection = select_for_delegation(wallet, staking_address, amount)?;

    let (own_address, pubkey_bytes, privkey_bytes) =
        keys::transparent_key_from_bip39_seed(bip39_seed, 0, 0)?;
    let owner = decode_owner_address(&own_address)?;
    let staker = decode_staking_address(staking_address)?;
    let own_script = p2pkh_script_from_hash(&owner);

    // Split into staking-sized pieces. Staking works per output, so one large
    // delegation is a single staking unit where several compete independently.
    let p2cs_script = build_p2cs_script(&staker, &owner, variant);
    let mut outputs: Vec<TxOutput> = split_delegation_amounts(amount, STAKE_SPLIT_TARGET)
        .into_iter()
        .map(|value| TxOutput { value, script: p2cs_script.clone() })
        .collect();

    let change = selection.total - amount - selection.fee;
    // Dust change would make the transaction non-standard; drop it to the miner
    // instead, exactly as the transparent builders do.
    if change > 0 && !fees::is_dust(change, own_script.len()) {
        outputs.push(TxOutput { value: change, script: own_script.clone() });
    }

    let signing_inputs: Vec<SigningInput> = selection
        .selected
        .iter()
        .map(|u| SigningInput::p2pkh(u.clone(), &own_script))
        .collect();
    // Dropped dust change raises the fee actually paid.
    let fee = selection.total - outputs.iter().map(|o| o.value).sum::<u64>();
    let txhex = sign_and_serialize(&signing_inputs, &outputs, &pubkey_bytes, &privkey_bytes)?;

    let spent: Vec<SpentOutpoint> = selection
        .selected
        .iter()
        .map(|u| SpentOutpoint { txid: u.txid.clone(), vout: u.vout })
        .collect();

    Ok(TransparentTransactionResult { txhex, spent, amount, fee })
}

/// Fee [`create_delegation_transaction`] will charge for the same inputs.
///
/// Runs the identical selection, so a successful quote means the delegation
/// itself will get as far as signing.
///
/// A lower bound where dust is concerned: change below the dust threshold is
/// dropped to the miner rather than emitted, raising the fee actually paid.
/// `TransparentTransactionResult::fee` reports the true figure.
pub fn estimate_delegation_fee(
    wallet: &WalletData,
    staking_address: &str,
    amount: u64,
) -> Result<u64, Box<dyn Error>> {
    Ok(select_for_delegation(wallet, staking_address, amount)?.fee)
}

/// Withdraw delegated coins: P2CS inputs → an ordinary P2PKH output.
///
/// Spends `delegated` back to `to_address`, ending the delegation. Every
/// supplied UTXO is spent; any remainder after fee returns to the owner address
/// as change.
///
/// # A delegated outpoint can be consumed by the staker
///
/// Unlike an ordinary output, which only its owner can spend, a delegated
/// output can be consumed at any moment by the staking node: that is what
/// staking *is*. Core's `CheckColdStake` constrains what the staker may do with
/// it: the spend must be a coinstake with a single input, every output must
/// carry the identical `scriptPubKey` it is spending (bar the last one under the
/// LOF variant, reserved for masternode and budget payments), and the value
/// returned must be at least the value taken. So the staker cannot move the
/// coins, cannot redirect them, and cannot reduce them. **The delegation
/// survives with the same owner and at least the same value.**
///
/// What does change is the outpoint. The old `(txid, vout)` is spent and the
/// delegation reappears at a new one. A withdrawal built against the old
/// reference is then rejected by the network for spending an output that no
/// longer exists.
///
/// Nothing is lost when that happens, and no funds are at risk, but consumers
/// should refresh their UTXO set immediately before building a withdrawal, and
/// treat a missing-inputs rejection as "re-fetch and rebuild" rather than an
/// error in the transaction. This crate performs no I/O, so it cannot detect
/// staleness on the caller's behalf.
///
/// The replacement is also *immature*. It lives in a coinstake transaction, and
/// PIVX applies [`crate::params::COINBASE_MATURITY`] to those, so it cannot be
/// spent until it is 101 confirmations deep. Explorers list it long before that, in the
/// same shape as any other UTXO, so a freshly staked delegation looks perfectly
/// spendable and is not.
///
/// This is rejected here rather than by the network, but only when the caller
/// populates `coinstake` and `confirmations` on the UTXO, since this crate performs
/// no I/O and cannot determine either for itself. The same tx responses that
/// supply `script` identify a coinstake, by its empty zero-value first output.
///
/// Each UTXO's `script` field must carry the hex `scriptPubKey` of the P2CS
/// output being spent. That is not optional bookkeeping: the sighash commits to
/// the exact script, so it cannot be inferred. No explorer returns it from the
/// UTXO endpoint, so callers fetch it separately, from `/api/v2/tx/{txid}` as
/// `vout[n].hex`, and hand it to `parse_blockbook_utxos` alongside the outpoint.
///
/// The owner hash in every script must match the key at `from_change/from_index`,
/// or the wallet cannot produce a signature that satisfies the output. That is
/// checked up front rather than discovered as a rejected broadcast.
/// Where the remainder of a partial withdrawal goes.
///
/// This is the difference between "withdraw some and keep earning" and
/// "withdraw some and silently stop staking the rest". A withdrawal spends its
/// inputs whole, so any part not being withdrawn comes back as change, and
/// plain change is an ordinary output, no longer delegated.
#[derive(Debug, Clone, Copy)]
pub enum WithdrawalChange<'a> {
    /// Return change as an ordinary transparent output. The remainder stops
    /// staking.
    Plain,
    /// Re-delegate change to this staking address, keeping it staked.
    ///
    /// Falls back to [`WithdrawalChange::Plain`] when the change is below
    /// [`MIN_COLDSTAKING_AMOUNT`], since a smaller delegation is one the
    /// reference wallets will not create. MyPIVXWallet applies the same rule via
    /// its `delegateChange` option, which its staking UI enables by default.
    Delegate(&'a str),
}

pub fn create_coldstake_withdrawal(
    bip39_seed: &[u8],
    from_change: u32,
    from_index: u32,
    delegated: &[SerializedUTXO],
    to_address: &str,
    amount: u64,
) -> Result<TransparentTransactionResult, Box<dyn Error>> {
    create_coldstake_withdrawal_with_change(
        bip39_seed,
        from_change,
        from_index,
        delegated,
        to_address,
        amount,
        WithdrawalChange::Plain,
    )
}

/// As [`create_coldstake_withdrawal`], choosing what happens to the remainder.
///
/// Use [`WithdrawalChange::Delegate`] to keep the unwithdrawn portion staking.
/// Without it a partial withdrawal quietly un-stakes everything the spent inputs
/// held beyond the amount taken, which is rarely what a user pressing
/// "withdraw 4,000 of my 10,000" expects.
///
/// Note that inputs *not* supplied are untouched and keep staking either way:
/// this only governs the change from the inputs actually spent.
pub fn create_coldstake_withdrawal_with_change(
    bip39_seed: &[u8],
    from_change: u32,
    from_index: u32,
    delegated: &[SerializedUTXO],
    to_address: &str,
    amount: u64,
    change_policy: WithdrawalChange<'_>,
) -> Result<TransparentTransactionResult, Box<dyn Error>> {
    if delegated.is_empty() {
        return Err("No delegated UTXOs provided".into());
    }
    if amount == 0 {
        return Err("Withdrawal amount is zero".into());
    }
    validate_outpoints(delegated)?;

    let (own_address, pubkey_bytes, privkey_bytes) =
        keys::transparent_key_from_bip39_seed(bip39_seed, from_change, from_index)?;
    let owner = decode_owner_address(&own_address)?;
    let own_script = p2pkh_script_from_hash(&owner);

    // Resolve each input's P2CS script and confirm this wallet owns it.
    let mut inputs = Vec::with_capacity(delegated.len());
    let mut total: u64 = 0;
    for (i, utxo) in delegated.iter().enumerate() {
        if utxo.script.is_empty() {
            return Err(format!(
                "UTXO {}:{} has no script: withdrawing a delegation needs the P2CS \
                 scriptPubKey, which the sighash commits to and cannot be inferred",
                utxo.txid, utxo.vout
            )
            .into());
        }
        // A staked delegation lives in a coinstake, so this is the routine case
        // rather than an exotic one: withdraw too soon after a stake and the
        // network rejects the spend. Erroring names the wait instead, since
        // every one of these clears on its own.
        if !utxo.is_mature() {
            return Err(format!(
                "UTXO {}:{} was created by a coinstake {} block(s) ago and needs {}. It was \
                 staked recently, so it becomes withdrawable in {} block(s)",
                utxo.txid,
                utxo.vout,
                utxo.confirmations,
                crate::params::COINBASE_MATURITY + 1,
                utxo.blocks_until_mature(),
            )
            .into());
        }
        let script = crate::simd::hex::hex_string_to_bytes(&utxo.script);
        let hashes = parse_p2cs_script(&script).map_err(|e| {
            format!("UTXO {}:{} (input {i}) is not a delegated output: {e}", utxo.txid, utxo.vout)
        })?;
        if hashes.owner != owner {
            return Err(format!(
                "UTXO {}:{} is owned by {}: this wallet's key at {from_change}/{from_index} is \
                 {own_address}, so it cannot sign for it",
                utxo.txid,
                utxo.vout,
                encode_checked(PIVX_PUBKEY_PREFIX, &hashes.owner),
            )
            .into());
        }
        total = total
            .checked_add(utxo.amount)
            .ok_or("UTXO total overflow: caller passed malformed amounts")?;
        inputs.push(SigningInput {
            utxo: utxo.clone(),
            prevout_script: script,
            cold_stake_owner: true,
        });
    }

    // Two surcharges over the flat model, both learned the hard way:
    //
    //  - each P2CS redeem script is one byte longer than a P2PKH one (the
    //    OP_FALSE branch selector), so one extra byte per input;
    //  - re-delegated change is a 51-byte P2CS script rather than a 25-byte
    //    P2PKH one, which the flat 34-bytes-per-output figure does not cover.
    //
    // Missing the second one produced a transaction a node rejected outright
    // with `insufficient fee: 2290 < 2520`: the fee model has to track the
    // real serialized size, because that is what the relay minimum is charged
    // against. Budgeting for P2CS change even when the change turns out to be
    // plain (below the delegation minimum) merely over-pays slightly, which is
    // the safe direction.
    let change_surcharge = match change_policy {
        WithdrawalChange::Delegate(_) => fees::P2CS_OUTPUT_EXTRA_BYTES,
        WithdrawalChange::Plain => 0,
    };
    let fee = fees::estimate_raw_transparent_fee_with_extra(
        delegated.len(),
        2,
        delegated.len() + change_surcharge,
    );
    let needed = amount.checked_add(fee).ok_or("Amount plus fee overflows u64")?;
    if total < needed {
        return Err(format!(
            "Insufficient delegated balance. Have: {total} sat, need: {amount} sat + {fee} sat fee"
        )
        .into());
    }

    let destination = keys::address_to_p2pkh_script(to_address)?;
    if fees::is_dust(amount, destination.len()) {
        return Err(format!(
            "Withdrawal of {amount} sat is below the dust threshold of {} sat: a transaction \
             containing a dust output is non-standard and will not relay",
            fees::dust_threshold(destination.len())
        )
        .into());
    }
    let mut outputs = vec![TxOutput { value: amount, script: destination }];

    let change = total - needed;
    if change > 0 {
        // Re-delegating keeps the remainder staked, but only above the minimum
        // a delegation is allowed to be; below that it has to come back plain.
        let change_script = match change_policy {
            WithdrawalChange::Delegate(staking_address) if change >= MIN_COLDSTAKING_AMOUNT => {
                let staker = decode_staking_address(staking_address)?;
                build_p2cs_script(&staker, &owner, ColdStakeVariant::Lof)
            }
            _ => own_script,
        };
        if !fees::is_dust(change, change_script.len()) {
            outputs.push(TxOutput { value: change, script: change_script });
        }
    }

    // Dropped dust change raises the fee actually paid.
    let fee = total - outputs.iter().map(|o| o.value).sum::<u64>();

    let txhex = sign_and_serialize(&inputs, &outputs, &pubkey_bytes, &privkey_bytes)?;

    let spent: Vec<SpentOutpoint> = delegated
        .iter()
        .map(|u| SpentOutpoint { txid: u.txid.clone(), vout: u.vout })
        .collect();

    Ok(TransparentTransactionResult { txhex, spent, amount, fee })
}

/// Fee [`create_coldstake_withdrawal`] will charge for `input_count` delegated
/// inputs.
///
/// This is a **lower bound**, not always the exact figure. If the withdrawal
/// leaves change below the dust threshold, that change is dropped to the miner
/// rather than emitted as an unrelayable output, and the fee actually paid rises
/// by the dropped amount. The estimator cannot see that from the input count
/// alone. `TransparentTransactionResult::fee` always reports the true figure.
pub fn estimate_coldstake_withdrawal_fee(input_count: usize) -> u64 {
    fees::estimate_raw_transparent_fee_with_extra(input_count, 2, input_count)
}

struct DelegationSelection {
    selected: Vec<SerializedUTXO>,
    total: u64,
    fee: u64,
}

/// Validate the delegation and select UTXOs to cover it.
///
/// Shared by the builder and the estimator so the two cannot quote different
/// fees: the fee depends on how many inputs selection reaches for.
fn select_for_delegation(
    wallet: &WalletData,
    staking_address: &str,
    amount: u64,
) -> Result<DelegationSelection, Box<dyn Error>> {
    // Validate the staking address before any selection work, so a typo fails
    // for the reason it actually is rather than as "insufficient funds".
    decode_staking_address(staking_address)?;

    if amount < MIN_COLDSTAKING_AMOUNT {
        return Err(format!(
            "Delegation of {amount} sat is below the {MIN_COLDSTAKING_AMOUNT} sat minimum \
             (1 PIV) that PIVX Core and MyPIVXWallet both enforce"
        )
        .into());
    }

    validate_outpoints(&wallet.unspent_utxos)?;
    // A delegation is funded from ordinary outputs. Already-delegated ones are
    // P2CS and cannot be re-delegated without first being withdrawn, immature
    // coinstake outputs cannot be spent at all yet, and outputs at another HD
    // slot cannot be signed by the `0/0` key this builder uses. Shared with the
    // transparent builders so all three exclusions stay in one place: this
    // path signs with the same key and has the same reach.
    let utxos = crate::transparent::builder::spendable_utxos(wallet);
    if utxos.is_empty() {
        let immature = wallet.get_immature_balance();
        if immature > 0 {
            return Err(format!(
                "No spendable transparent UTXOs available to fund a delegation: {immature} sat \
                 is in coinstake outputs that have not reached maturity yet"
            )
            .into());
        }
        let rotated = wallet.get_rotated_balance();
        if rotated > 0 {
            // Unlike an ordinary send there is no per-slot escape hatch here:
            // a delegation records its owner in the script, and this builder
            // writes the 0/0 key into it, so funding it from elsewhere is not
            // a thing that could be made to work by naming a slot. The only
            // route is to move the coins first, so say that rather than
            // leaving the caller looking for an argument that does not exist.
            return Err(format!(
                "No spendable transparent UTXOs available to fund a delegation: {rotated} sat \
                 sits at HD slots other than 0/0. A delegation is always funded from, and \
                 owned by, the key at 0/0, so move the coins there first with \
                 sendTransparentFromUtxos before delegating"
            )
            .into());
        }
        return Err("No spendable transparent UTXOs available to fund a delegation".into());
    }

    // The delegation is split into staking-sized pieces, so the fee covers that
    // many P2CS outputs plus a possible change output. Each P2CS script is 51
    // bytes against the fee model's flat 25-byte assumption, so the surcharge is
    // declared per piece rather than silently under-paid.
    let piece_count = split_delegation_amounts(amount, STAKE_SPLIT_TARGET).len();
    let fee_for = |input_count: usize| {
        fees::estimate_raw_transparent_fee_with_extra(
            input_count,
            piece_count + 1,
            piece_count * fees::P2CS_OUTPUT_EXTRA_BYTES,
        )
    };

    let mut selected: Vec<SerializedUTXO> = Vec::new();
    let mut total: u64 = 0;
    for utxo in &utxos {
        selected.push(utxo.clone());
        total = total
            .checked_add(utxo.amount)
            .ok_or("UTXO total overflow: explorer returned malformed amounts")?;
        if total >= amount.saturating_add(fee_for(selected.len())) {
            break;
        }
    }

    let fee = fee_for(selected.len());
    let needed = amount.checked_add(fee).ok_or("Amount plus fee overflows u64")?;
    if total < needed {
        return Err(format!(
            "Insufficient public balance for delegation. Have: {total} sat, need: {amount} sat \
             + {fee} sat fee"
        )
        .into());
    }

    Ok(DelegationSelection { selected, total, fee })
}
