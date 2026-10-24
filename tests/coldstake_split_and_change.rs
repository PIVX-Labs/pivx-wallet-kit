//! Stake splitting, and keeping the remainder staked on a partial withdrawal.
//!
//! Both close gaps against MyPIVXWallet that only show up in use rather than in
//! a unit test:
//!
//! * Staking works per output, so delegating 10,000 PIV as one output creates a
//!   single staking unit where twenty compete independently. MyPIVXWallet splits
//!   on a 500 PIV boundary; this reproduces its arithmetic.
//! * A withdrawal spends its inputs whole, so the part not withdrawn comes back
//!   as change. Plain change is an ordinary output: it stops staking. Someone
//!   withdrawing 4,000 of their 10,000 does not expect the other 6,000 to go
//!   idle.

use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::coldstake::{
    ColdStakeVariant, MIN_COLDSTAKING_AMOUNT, STAKE_SPLIT_TARGET, WithdrawalChange,
    build_p2cs_script, create_coldstake_withdrawal, create_coldstake_withdrawal_with_change,
    create_delegation_transaction, encode_staking_address, is_p2cs, owner_hash_from_seed,
    parse_p2cs_script, split_delegation_amounts,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const STAKER: [u8; 20] = [0xAA; 20];
const COIN: u64 = 100_000_000;

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn owner() -> [u8; 20] {
    owner_hash_from_seed(&seed(), 0, 0).unwrap()
}

fn staking_addr() -> String {
    encode_staking_address(&STAKER)
}

fn utxo(letter: &str, vout: u32, amount: u64) -> SerializedUTXO {
    SerializedUTXO { txid: letter.repeat(64), vout, amount, script: String::new(), height: 5_000_000, ..Default::default() }
}

fn delegated_utxo(letter: &str, vout: u32, amount: u64) -> SerializedUTXO {
    let script = build_p2cs_script(&STAKER, &owner(), ColdStakeVariant::Lof);
    SerializedUTXO {
        txid: letter.repeat(64),
        vout,
        amount,
        script: simd::hex::bytes_to_hex_string(&script),
        height: 5_000_000,
        ..Default::default()
    }
}

fn wallet_with(utxos: Vec<SerializedUTXO>) -> WalletData {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = utxos;
    w
}

fn to_address() -> String {
    pivx_wallet_kit::keys::get_transparent_address(TEST_MNEMONIC).unwrap()
}

/// Decode outputs as `(value, script)`.
fn outputs_of(txhex: &str) -> Vec<(u64, Vec<u8>)> {
    let b = simd::hex::hex_string_to_bytes(txhex);
    let mut p = 4usize;
    let varint = |b: &[u8], p: &mut usize| -> u64 {
        let f = b[*p];
        match f {
            0xfd => { let v = u16::from_le_bytes(b[*p+1..*p+3].try_into().unwrap()) as u64; *p += 3; v }
            0xfe => { let v = u32::from_le_bytes(b[*p+1..*p+5].try_into().unwrap()) as u64; *p += 5; v }
            0xff => { let v = u64::from_le_bytes(b[*p+1..*p+9].try_into().unwrap()); *p += 9; v }
            n => { *p += 1; n as u64 }
        }
    };
    let n_in = varint(&b, &mut p);
    for _ in 0..n_in {
        p += 36;
        let sl = varint(&b, &mut p) as usize;
        p += sl + 4;
    }
    let n_out = varint(&b, &mut p);
    let mut outs = Vec::new();
    for _ in 0..n_out {
        let value = u64::from_le_bytes(b[p..p+8].try_into().unwrap()); p += 8;
        let sl = varint(&b, &mut p) as usize;
        outs.push((value, b[p..p+sl].to_vec())); p += sl;
    }
    outs
}

// --- splitting arithmetic ---------------------------------------------------

/// Matches MyPIVXWallet: below the target it is one piece; at or above, the
/// remainder joins the first piece so none is a stray fragment.
#[test]
fn split_matches_mypivxwallet_arithmetic() {
    let t = STAKE_SPLIT_TARGET; // 500 PIV
    assert_eq!(split_delegation_amounts(400 * COIN, t), vec![400 * COIN]);
    assert_eq!(split_delegation_amounts(t, t), vec![t]);
    assert_eq!(split_delegation_amounts(1_000 * COIN, t), vec![500 * COIN, 500 * COIN]);
    assert_eq!(split_delegation_amounts(1_200 * COIN, t), vec![700 * COIN, 500 * COIN]);

    // 10,000 PIV becomes twenty pieces, not one.
    let pieces = split_delegation_amounts(10_000 * COIN, t);
    assert_eq!(pieces.len(), 20);
    assert!(pieces.iter().all(|&p| p >= t), "no piece may fall below the target");
}

/// Whatever the amount, the pieces must sum back to it exactly: a split that
/// loses or invents satoshis would silently change what the user delegated.
#[test]
fn split_always_conserves_the_total() {
    let t = STAKE_SPLIT_TARGET;
    for amount in [
        1, COIN, 499 * COIN, 500 * COIN, 501 * COIN, 999 * COIN,
        1_000 * COIN, 12_345 * COIN, 99_999 * COIN,
    ] {
        let pieces = split_delegation_amounts(amount, t);
        assert_eq!(pieces.iter().sum::<u64>(), amount, "amount {amount}");
        assert!(!pieces.is_empty());
    }
}

// --- splitting in a real delegation -----------------------------------------

#[test]
fn a_large_delegation_is_split_into_staking_sized_outputs() {
    let mut w = wallet_with(vec![utxo("a", 0, 2_000 * COIN)]);
    let amount = 1_200 * COIN;

    let result =
        create_delegation_transaction(&mut w, &seed(), &staking_addr(), amount, ColdStakeVariant::Lof)
            .expect("delegation should build");

    let outs = outputs_of(&result.txhex);
    let p2cs: Vec<&(u64, Vec<u8>)> = outs.iter().filter(|(_, s)| is_p2cs(s)).collect();

    assert_eq!(p2cs.len(), 2, "1200 PIV should split into two pieces");
    assert_eq!(p2cs[0].0, 700 * COIN);
    assert_eq!(p2cs[1].0, 500 * COIN);
    assert_eq!(p2cs.iter().map(|(v, _)| v).sum::<u64>(), amount);
    assert_eq!(result.amount, amount, "reported amount is the delegated total");

    // Every piece names the same staker and owner.
    for (_, script) in &p2cs {
        let h = parse_p2cs_script(script).unwrap();
        assert_eq!(h.staker, STAKER);
        assert_eq!(h.owner, owner());
    }
}

#[test]
fn a_small_delegation_stays_a_single_output() {
    let mut w = wallet_with(vec![utxo("a", 0, 1_000 * COIN)]);
    let amount = 400 * COIN;

    let result =
        create_delegation_transaction(&mut w, &seed(), &staking_addr(), amount, ColdStakeVariant::Lof)
            .unwrap();

    let p2cs: Vec<(u64, Vec<u8>)> =
        outputs_of(&result.txhex).into_iter().filter(|(_, s)| is_p2cs(s)).collect();
    assert_eq!(p2cs.len(), 1);
    assert_eq!(p2cs[0].0, amount);
}

/// The fee has to cover every piece, or a split delegation under-pays and does
/// not relay.
#[test]
fn the_fee_grows_with_the_number_of_pieces() {
    let small = {
        let mut w = wallet_with(vec![utxo("a", 0, 5_000 * COIN)]);
        create_delegation_transaction(&mut w, &seed(), &staking_addr(), 400 * COIN, ColdStakeVariant::Lof)
            .unwrap()
            .fee
    };
    let large = {
        let mut w = wallet_with(vec![utxo("a", 0, 5_000 * COIN)]);
        create_delegation_transaction(&mut w, &seed(), &staking_addr(), 2_000 * COIN, ColdStakeVariant::Lof)
            .unwrap()
            .fee
    };
    assert!(large > small, "4 pieces ({large}) should cost more than 1 ({small})");
}

// --- delegated change on withdrawal ----------------------------------------

/// The default keeps the old behaviour: change comes back plain, and the
/// remainder stops staking.
#[test]
fn plain_change_stops_staking_the_remainder() {
    let delegated = vec![delegated_utxo("d", 0, 10_000 * COIN)];

    let result = create_coldstake_withdrawal(
        &seed(), 0, 0, &delegated, &to_address(), 4_000 * COIN,
    )
    .unwrap();

    let outs = outputs_of(&result.txhex);
    assert_eq!(outs.len(), 2, "withdrawal + change");
    assert!(!is_p2cs(&outs[0].1), "the withdrawn amount is an ordinary output");
    assert!(
        !is_p2cs(&outs[1].1),
        "plain change must not be a delegation: this is the behaviour Delegate() exists to change"
    );
    assert!(outs[1].0 > 5_999 * COIN, "roughly 6,000 PIV of change");
}

/// The point of the whole exercise: withdraw part, keep the rest staked.
#[test]
fn delegated_change_keeps_the_remainder_staked() {
    let delegated = vec![delegated_utxo("d", 0, 10_000 * COIN)];
    let staking = staking_addr();

    let result = create_coldstake_withdrawal_with_change(
        &seed(), 0, 0, &delegated, &to_address(), 4_000 * COIN,
        WithdrawalChange::Delegate(&staking),
    )
    .unwrap();

    let outs = outputs_of(&result.txhex);
    assert_eq!(outs.len(), 2);
    assert!(!is_p2cs(&outs[0].1), "the withdrawn amount is ordinary");
    assert_eq!(outs[0].0, 4_000 * COIN);

    assert!(is_p2cs(&outs[1].1), "change should be re-delegated");
    let h = parse_p2cs_script(&outs[1].1).unwrap();
    assert_eq!(h.staker, STAKER, "change should keep staking with the same staker");
    assert_eq!(h.owner, owner(), "and stay owned by this wallet");
    assert!(outs[1].0 > 5_999 * COIN);

    // Value conservation across the whole thing.
    assert_eq!(10_000 * COIN - outs.iter().map(|(v, _)| v).sum::<u64>(), result.fee);
}

/// Change below the delegation minimum cannot be re-delegated: the reference
/// wallets will not create a sub-1-PIV delegation, so it falls back to plain
/// rather than erroring.
#[test]
fn change_below_the_minimum_falls_back_to_plain() {
    // Withdraw nearly everything, leaving under 1 PIV of change.
    let total = 10 * COIN;
    let delegated = vec![delegated_utxo("d", 0, total)];
    let staking = staking_addr();

    let fee = pivx_wallet_kit::transparent::coldstake::estimate_coldstake_withdrawal_fee(1);
    let amount = total - fee - (MIN_COLDSTAKING_AMOUNT / 2); // ~0.5 PIV change

    let result = create_coldstake_withdrawal_with_change(
        &seed(), 0, 0, &delegated, &to_address(), amount,
        WithdrawalChange::Delegate(&staking),
    )
    .unwrap();

    let outs = outputs_of(&result.txhex);
    assert_eq!(outs.len(), 2);
    assert!(
        !is_p2cs(&outs[1].1),
        "change under the 1 PIV minimum must come back plain, not as an invalid delegation"
    );
    assert!(outs[1].0 < MIN_COLDSTAKING_AMOUNT);
}

/// Inputs that were never supplied are untouched and keep staking: the part of
/// the answer that depends on UTXO structure rather than change policy.
#[test]
fn unspent_delegations_are_untouched() {
    // Ten 1,000 PIV delegations; withdraw 4,000 using only four of them.
    let delegated: Vec<SerializedUTXO> = (0..4)
        .map(|i| delegated_utxo("d", i, 1_000 * COIN))
        .collect();

    let result = create_coldstake_withdrawal_with_change(
        &seed(), 0, 0, &delegated, &to_address(), 3_990 * COIN,
        WithdrawalChange::Delegate(&staking_addr()),
    )
    .unwrap();

    // Only the four supplied outpoints are spent; the other six are not
    // referenced at all and remain delegated on chain.
    assert_eq!(result.spent.len(), 4);
}

/// A re-delegation of change must name a valid staking address.
#[test]
fn delegated_change_validates_the_staking_address() {
    let delegated = vec![delegated_utxo("d", 0, 10_000 * COIN)];
    let owner_addr = to_address();

    // An owner address in the staking slot.
    assert!(
        create_coldstake_withdrawal_with_change(
            &seed(), 0, 0, &delegated, &to_address(), 4_000 * COIN,
            WithdrawalChange::Delegate(&owner_addr),
        )
        .is_err(),
        "a D-address must not be accepted as the change staker"
    );

    // A corrupted staking address.
    let staking = staking_addr();
    let typo = {
        let mut raw = bs58::decode(&staking).into_vec().unwrap();
        raw[5] ^= 0x01;
        bs58::encode(raw).into_string()
    };
    assert!(
        create_coldstake_withdrawal_with_change(
            &seed(), 0, 0, &delegated, &to_address(), 4_000 * COIN,
            WithdrawalChange::Delegate(&typo),
        )
        .is_err()
    );
}

/// Change may be re-delegated to a *different* staker than the one being
/// withdrawn from: moving a delegation between nodes in one transaction.
#[test]
fn change_can_be_delegated_to_a_different_staker() {
    let delegated = vec![delegated_utxo("d", 0, 10_000 * COIN)];
    let new_staker = [0xCC; 20];
    let new_staking_addr = encode_staking_address(&new_staker);

    let result = create_coldstake_withdrawal_with_change(
        &seed(), 0, 0, &delegated, &to_address(), 4_000 * COIN,
        WithdrawalChange::Delegate(&new_staking_addr),
    )
    .unwrap();

    let outs = outputs_of(&result.txhex);
    let h = parse_p2cs_script(&outs[1].1).unwrap();
    assert_eq!(h.staker, new_staker, "change should follow the new staker");
    assert_ne!(h.staker, STAKER);
    assert_eq!(h.owner, owner());
}
