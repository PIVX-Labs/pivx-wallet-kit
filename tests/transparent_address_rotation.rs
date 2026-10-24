//! Rotating transparent receive addresses across HD slots.
//!
//! Shield rotation is free: every diversified address decrypts to one spending
//! key, so a wallet holding a thousand of them still has one balance and one
//! signer. Transparent rotation is not. Each slot under
//! `m/44'/119'/0'/change/index` is a distinct key with a distinct address, and
//! a P2PKH UTXO carries no record of which of them received it, so a wallet
//! holding outputs at several slots cannot tell them apart by inspection.
//!
//! That matters because every wallet-state builder signs with the key at `0/0`.
//! Feed it an output received at `0/5` and it produces a syntactically valid
//! transaction whose signature satisfies no input: a broadcast failure with
//! nothing to point at. These tests pin the two halves of the fix, the `hdSlot`
//! tag that lets the kit tell the outputs apart, and the address accessor that
//! makes rotating possible in the first place.
//!
//! The last section covers cold staking, where the slot handling is
//! deliberately asymmetric (delegate at `0/0` only, withdraw from anywhere) and
//! rotation is what first makes that reachable.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_from_utxos,
    create_raw_transparent_transaction_from_utxos_to_many,
    create_raw_transparent_transaction_to_many, estimate_raw_transparent_fee_to_many,
    max_sendable_transparent,
};
use pivx_wallet_kit::transparent::coldstake::{
    ColdStakeVariant, build_p2cs_script, create_delegation_transaction, encode_staking_address,
};
use pivx_wallet_kit::wallet::{self, HdSlot, SerializedUTXO, WalletData};

mod common;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn address_at(change: u32, index: u32) -> String {
    keys::transparent_address_at(&seed(), change, index).unwrap()
}

/// An output with no slot tag: what every consumer written before the field
/// produces, and what `parseBlockbookUtxos` returns without one.
fn untagged(letter: &str, vout: u32, amount: u64) -> SerializedUTXO {
    SerializedUTXO {
        txid: letter.repeat(64),
        vout,
        amount,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    }
}

fn at_slot(letter: &str, vout: u32, amount: u64, change: u32, index: u32) -> SerializedUTXO {
    SerializedUTXO {
        hd_slot: Some(HdSlot { change, index }),
        ..untagged(letter, vout, amount)
    }
}

/// The same, carrying the scriptPubKey the slot's address actually pays to.
fn at_slot_with_script(
    letter: &str,
    vout: u32,
    amount: u64,
    change: u32,
    index: u32,
) -> SerializedUTXO {
    let script = keys::address_to_p2pkh_script(&address_at(change, index)).unwrap();
    SerializedUTXO {
        script: simd::hex::bytes_to_hex_string(&script),
        ..at_slot(letter, vout, amount, change, index)
    }
}

fn wallet_with(utxos: Vec<SerializedUTXO>) -> WalletData {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_utxos = utxos;
    w
}

fn to_address() -> String {
    keys::pubkey_to_pivx_address(&[0x02; 33])
}

fn one(address: &str, amount: u64) -> Vec<Recipient> {
    vec![Recipient { address: address.to_string(), amount }]
}

// ---------------------------------------------------------------------------
// Deriving rotated addresses
// ---------------------------------------------------------------------------

#[test]
fn slot_zero_matches_the_default_transparent_address() {
    let w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    assert_eq!(
        address_at(0, 0),
        w.get_transparent_address().unwrap(),
        "transparent_address_at(0, 0) must be the address the wallet already reports, \
         or rotation starts by disagreeing with itself"
    );
}

#[test]
fn every_slot_yields_a_distinct_address() {
    let mut seen = std::collections::HashSet::new();
    for change in 0..2 {
        for index in 0..8 {
            assert!(
                seen.insert(address_at(change, index)),
                "slot {change}/{index} repeated an address: rotation would hand two \
                 invoices the same one"
            );
        }
    }
}

#[test]
fn rotated_addresses_are_valid_p2pkh_and_derivation_is_stable() {
    for index in [0u32, 1, 7, 100, 65_535, 0x7fff_ffff] {
        let addr = address_at(0, index);
        assert!(addr.starts_with('D'), "slot 0/{index} produced {addr}, not a D... address");
        // Round-trips through the same validation an outgoing payment gets.
        keys::address_to_p2pkh_script(&addr)
            .unwrap_or_else(|e| panic!("slot 0/{index} produced an unpayable address: {e}"));
        assert_eq!(addr, address_at(0, index), "derivation is not deterministic");
    }
}

#[test]
fn a_child_number_past_the_non_hardened_ceiling_says_so() {
    // The high bit is the hardened flag, so BIP32 has no non-hardened child
    // above 2^31-1. A monotonic invoice counter is the only thing that reaches
    // it, and the underlying crate's "invalid child number" reads as a kit bug.
    for (change, index) in [(0u32, 0x8000_0000u32), (0x8000_0000, 0), (0, u32::MAX)] {
        let err = keys::transparent_address_at(&seed(), change, index)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("non-hardened") && err.contains("2147483647"),
            "slot {change}/{index} gave an unhelpful error: {err}"
        );
    }
}

#[test]
fn the_staking_address_for_a_slot_is_the_same_key() {
    // Both forms wrap one hash160 under different version bytes. If they ever
    // disagree, a consumer delegating from a rotated address would hand
    // spending authority to a key it does not hold.
    for index in [0u32, 3, 42] {
        let owner = pivx_wallet_kit::transparent::coldstake::owner_hash_from_seed(&seed(), 0, index)
            .unwrap();
        let from_address =
            pivx_wallet_kit::transparent::coldstake::decode_owner_address(&address_at(0, index))
                .unwrap();
        assert_eq!(
            owner, from_address,
            "slot 0/{index}: the staking address and the transparent address are not the \
             same key"
        );
        // Sanity: the S... form is derived from that same hash.
        assert!(encode_staking_address(&owner).starts_with('S'));
    }
}

// ---------------------------------------------------------------------------
// Untagged UTXOs behave exactly as before
// ---------------------------------------------------------------------------

#[test]
fn untagged_utxos_are_still_selectable_and_spendable() {
    let mut w = wallet_with(vec![untagged("a", 0, 500_000), untagged("b", 0, 400_000)]);
    assert_eq!(w.get_transparent_balance(), 900_000);
    assert_eq!(w.get_rotated_balance(), 0, "nothing is tagged, so nothing is rotated");

    let result =
        create_raw_transparent_transaction_to_many(&mut w, &seed(), &one(&to_address(), 100_000))
            .unwrap();
    let tx = common::decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    common::verify_all_signatures(&tx);
}

#[test]
fn an_untagged_utxo_can_be_spent_from_any_slot() {
    // The tag is opt-in. Its absence means "unknown", never "not this slot":
    // rejecting untagged inputs would break every consumer that rotates today
    // by tracking slots outside the kit.
    for (change, index) in [(0u32, 0u32), (0, 5), (1, 9)] {
        let result = create_raw_transparent_transaction_from_utxos(
            &seed(),
            change,
            index,
            &[untagged("a", 0, 500_000)],
            &to_address(),
            100_000,
        )
        .unwrap_or_else(|e| panic!("untagged input refused at slot {change}/{index}: {e}"));
        let tx = common::decode(&simd::hex::hex_string_to_bytes(&result.txhex));
        common::verify_all_signatures(&tx);
    }
}

// ---------------------------------------------------------------------------
// Tagged UTXOs are kept away from the 0/0 builders
// ---------------------------------------------------------------------------

#[test]
fn rotated_utxos_are_excluded_from_the_wallet_state_balance() {
    let w = wallet_with(vec![
        untagged("a", 0, 500_000),
        at_slot("b", 0, 700_000, 0, 5),
        at_slot("c", 0, 300_000, 1, 2),
    ]);
    assert_eq!(
        w.get_transparent_balance(),
        500_000,
        "only the 0/0-reachable output belongs in the spendable balance"
    );
    assert_eq!(w.get_rotated_balance(), 1_000_000, "the other two are reported separately");
}

#[test]
fn a_utxo_tagged_zero_zero_is_treated_as_the_default_slot() {
    let w = wallet_with(vec![at_slot("a", 0, 500_000, 0, 0)]);
    assert_eq!(
        w.get_transparent_balance(),
        500_000,
        "an explicit 0/0 tag names the default slot, so it stays spendable"
    );
    assert_eq!(w.get_rotated_balance(), 0);
}

#[test]
fn the_wallet_state_builder_never_selects_a_rotated_utxo() {
    // The whole point: the 700_000 output would be picked first by
    // largest-first selection, and signed with the 0/0 key it does not belong
    // to. It must not be reachable at all.
    let mut w = wallet_with(vec![at_slot("b", 0, 700_000, 0, 5), untagged("a", 0, 500_000)]);

    let result =
        create_raw_transparent_transaction_to_many(&mut w, &seed(), &one(&to_address(), 100_000))
            .unwrap();
    assert_eq!(result.spent.len(), 1, "selection reached past the untagged output");
    assert_eq!(
        result.spent[0].txid,
        "a".repeat(64),
        "selection picked the rotated output, which the 0/0 key cannot sign for"
    );

    let tx = common::decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    common::verify_all_signatures(&tx);
}

#[test]
fn a_send_larger_than_the_default_slot_holds_fails_and_says_where_the_rest_is() {
    let mut w = wallet_with(vec![untagged("a", 0, 200_000), at_slot("b", 0, 900_000, 0, 5)]);
    let err = create_raw_transparent_transaction_to_many(
        &mut w,
        &seed(),
        &one(&to_address(), 800_000),
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("Insufficient"), "unexpected error: {err}");
    assert!(
        err.contains("900000") && err.contains("sendTransparentFromUtxos"),
        "the error must account for the rotated coins and name the way to spend them, \
         or the funds look lost. Got: {err}"
    );
}

#[test]
fn a_wallet_holding_only_rotated_coins_reports_why_it_cannot_send() {
    let mut w = wallet_with(vec![at_slot("b", 0, 900_000, 0, 5)]);
    let err = create_raw_transparent_transaction_to_many(
        &mut w,
        &seed(),
        &one(&to_address(), 100_000),
    )
    .unwrap_err()
    .to_string();

    assert!(
        err.contains("HD slot") && err.contains("900000"),
        "expected an explanation naming the slots, got: {err}"
    );
}

#[test]
fn the_estimator_and_max_sendable_agree_with_the_builder() {
    // The invariant the exclusions already carry: a figure a UI shows must be
    // one the builder will honour. A rotated output that inflated either would
    // offer coins the send then refuses.
    let w = wallet_with(vec![untagged("a", 0, 500_000), at_slot("b", 0, 9_000_000, 0, 5)]);
    let max = max_sendable_transparent(&w, 1);
    assert!(max > 0 && max < 500_000, "max sendable {max} was computed over rotated coins");

    let mut w2 = wallet_with(w.unspent_utxos.clone());
    let fee = estimate_raw_transparent_fee_to_many(&w, &one(&to_address(), max)).unwrap();
    let result =
        create_raw_transparent_transaction_to_many(&mut w2, &seed(), &one(&to_address(), max))
            .unwrap();
    assert_eq!(result.fee, fee, "estimator and builder disagree once rotated coins exist");
    assert_eq!(result.spent.len(), 1);
}

#[test]
fn delegation_cannot_be_funded_from_a_rotated_utxo() {
    // `create_delegation_transaction` signs with 0/0 and records it as the
    // owner, so a rotated input would be both unsignable and, if it somehow
    // confirmed, redeemable only by the wrong key.
    let mut w = wallet_with(vec![at_slot("b", 0, 900_000_000, 0, 5)]);
    let err = create_delegation_transaction(
        &mut w,
        &seed(),
        &encode_staking_address(&[0xAA; 20]),
        500_000_000,
        ColdStakeVariant::Lof,
    )
    .unwrap_err()
    .to_string();

    assert!(
        err.contains("HD slot") || err.contains("Insufficient"),
        "expected the rotated funds to be out of reach, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// The explicit-UTXO builders refuse inputs from another slot
// ---------------------------------------------------------------------------

#[test]
fn spending_from_the_matching_slot_produces_a_valid_transaction() {
    let result = create_raw_transparent_transaction_from_utxos(
        &seed(),
        0,
        5,
        &[at_slot_with_script("b", 0, 500_000, 0, 5)],
        &to_address(),
        100_000,
    )
    .unwrap();

    let tx = common::decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    common::verify_all_signatures(&tx);

    // Change returns to the source address, keeping the slot's funds at the
    // slot rather than quietly consolidating them onto 0/0.
    let change_script = keys::address_to_p2pkh_script(&address_at(0, 5)).unwrap();
    assert!(
        tx.outputs.iter().any(|o| o.script_pubkey == change_script),
        "change did not return to the slot it came from"
    );
}

#[test]
fn a_tagged_utxo_from_another_slot_is_rejected() {
    let err = create_raw_transparent_transaction_from_utxos(
        &seed(),
        0,
        5,
        &[at_slot("b", 0, 500_000, 0, 9)],
        &to_address(),
        100_000,
    )
    .unwrap_err()
    .to_string();

    assert!(
        err.contains("0/9") && err.contains("0/5"),
        "the error must name both slots so the caller can see the mix-up: {err}"
    );
}

#[test]
fn a_mixed_slot_input_set_is_rejected_rather_than_signed() {
    // One key signs every input, so a set spanning two slots can only ever
    // produce a transaction the network rejects.
    let err = create_raw_transparent_transaction_from_utxos_to_many(
        &seed(),
        0,
        5,
        &[at_slot("b", 0, 500_000, 0, 5), at_slot("c", 0, 400_000, 0, 6)],
        &one(&to_address(), 100_000),
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("0/6"), "expected the foreign input to be named, got: {err}");
}

#[test]
fn a_mistagged_utxo_is_caught_by_its_script() {
    // The tag says 0/5 and the script says otherwise. The script wins: it is
    // the thing the signature has to satisfy, and it is independent of any
    // bookkeeping the caller may have got wrong.
    let mut utxo = at_slot_with_script("b", 0, 500_000, 0, 9);
    utxo.hd_slot = Some(HdSlot { change: 0, index: 5 });

    let err = create_raw_transparent_transaction_from_utxos(
        &seed(),
        0,
        5,
        &[utxo],
        &to_address(),
        100_000,
    )
    .unwrap_err()
    .to_string();

    assert!(
        err.contains(&address_at(0, 9)),
        "the error must name the address that actually owns the output: {err}"
    );
}

#[test]
fn an_untagged_utxo_with_a_foreign_script_is_still_caught() {
    // No tag at all, so only the script can catch this. A consumer who joins
    // scripts on for cold staking gets the check for free on ordinary sends.
    let script = keys::address_to_p2pkh_script(&address_at(0, 9)).unwrap();
    let utxo = SerializedUTXO {
        script: simd::hex::bytes_to_hex_string(&script),
        ..untagged("b", 0, 500_000)
    };

    let err = create_raw_transparent_transaction_from_utxos(
        &seed(),
        0,
        5,
        &[utxo],
        &to_address(),
        100_000,
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("cannot sign for"), "expected a script mismatch, got: {err}");
}

#[test]
fn a_matching_script_passes_untouched() {
    // The mirror of the above: the same check must not fire on the correct
    // script, or cold-staking consumers (who always populate it) lose ordinary
    // sends entirely.
    let result = create_raw_transparent_transaction_from_utxos(
        &seed(),
        1,
        3,
        &[at_slot_with_script("b", 0, 500_000, 1, 3)],
        &to_address(),
        100_000,
    )
    .unwrap();
    let tx = common::decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    common::verify_all_signatures(&tx);
}

#[test]
fn a_p2cs_script_is_still_reported_as_delegated_not_as_a_slot_mismatch() {
    // Ordering: the delegated-output guard runs first, so a delegation gets the
    // error that tells the caller to withdraw it, not a confusing one about
    // scripts.
    let owner =
        pivx_wallet_kit::transparent::coldstake::owner_hash_from_seed(&seed(), 0, 5).unwrap();
    let script = build_p2cs_script(&[0xAA; 20], &owner, ColdStakeVariant::Lof);
    let utxo = SerializedUTXO {
        script: simd::hex::bytes_to_hex_string(&script),
        ..at_slot("b", 0, 500_000, 0, 5)
    };

    let err = create_raw_transparent_transaction_from_utxos(
        &seed(),
        0,
        5,
        &[utxo],
        &to_address(),
        100_000,
    )
    .unwrap_err()
    .to_string();

    assert!(
        err.contains("cold staking"),
        "a delegation must be reported as one: {err}"
    );
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

#[test]
fn the_parser_tags_what_it_is_told_and_nothing_otherwise() {
    let raw = vec![serde_json::json!({
        "txid": "a".repeat(64),
        "vout": 0,
        "value": "500000",
        "height": 5_000_000,
    })];

    let untagged = wallet::parse_blockbook_utxos(&raw);
    assert_eq!(untagged[0].hd_slot, None, "the default parse must stay untagged");

    let slot = HdSlot { change: 0, index: 7 };
    let tagged = wallet::parse_blockbook_utxos_at(&raw, Some(slot));
    assert_eq!(tagged[0].hd_slot, Some(slot));
    assert!(!tagged[0].matches_slot(0, 0), "a 0/7 output must not pass as 0/0");
    assert!(tagged[0].matches_slot(0, 7));
}

#[test]
fn a_tag_survives_the_parsers_duplicate_merge() {
    // Blockbook lists a confirming UTXO twice. Both sightings come from the
    // same per-address query, so the surviving entry must keep the slot.
    let entry = serde_json::json!({
        "txid": "a".repeat(64),
        "vout": 0,
        "value": "500000",
        "height": 0,
        "confirmations": 0,
    });
    let mut confirmed = entry.clone();
    confirmed["height"] = serde_json::json!(5_000_000);
    confirmed["confirmations"] = serde_json::json!(12);

    let slot = HdSlot { change: 1, index: 4 };
    let utxos = wallet::parse_blockbook_utxos_at(&[entry, confirmed], Some(slot));
    assert_eq!(utxos.len(), 1, "duplicate outpoint was not collapsed");
    assert_eq!(utxos[0].hd_slot, Some(slot));
}


// ---------------------------------------------------------------------------
// Cold staking against rotated slots
// ---------------------------------------------------------------------------
//
// The two halves of cold staking are not symmetric about the HD slot, and the
// asymmetry predates rotation: `create_delegation_transaction` hardcodes the
// owner to `0/0`, while the withdrawal builders take the slot as an argument.
// Rotation is what makes the difference reachable, so these pin it.

/// The `S...` form of the key at a given slot.
fn staking_address_at(change: u32, index: u32) -> String {
    encode_staking_address(
        &pivx_wallet_kit::transparent::coldstake::owner_hash_from_seed(&seed(), change, index)
            .unwrap(),
    )
}

/// The `(staker, owner)` addresses of every P2CS output in a built transaction.
fn p2cs_parties(txhex: &str) -> Vec<(String, String)> {
    let tx = common::decode(&simd::hex::hex_string_to_bytes(txhex));
    tx.outputs
        .iter()
        .filter(|o| pivx_wallet_kit::transparent::coldstake::is_p2cs(&o.script_pubkey))
        .map(|o| {
            pivx_wallet_kit::transparent::coldstake::addresses_from_p2cs_script(&o.script_pubkey)
                .unwrap()
        })
        .collect()
}

#[test]
fn a_delegation_is_always_owned_by_slot_zero_even_when_the_staker_is_rotated() {
    // Delegating to this wallet's *own* rotated staking address does not move
    // ownership there: the builder derives the owner at 0/0 unconditionally.
    // The delegation is still fully under this wallet's control and still
    // withdrawable, but only via `withdrawColdStake(0, 0, ...)`, so a consumer
    // that assumes "self-stake at slot 5 means owner 5" would look for the
    // funds under the wrong key.
    let mut w = wallet_with(vec![untagged("a", 0, 900_000_000)]);
    let result = create_delegation_transaction(
        &mut w,
        &seed(),
        &staking_address_at(0, 5),
        500_000_000,
        ColdStakeVariant::Lof,
    )
    .unwrap();

    let parties = p2cs_parties(&result.txhex);
    assert!(!parties.is_empty(), "no P2CS output was built");
    for (staker, owner) in &parties {
        assert_eq!(
            *staker,
            staking_address_at(0, 5),
            "the staking address should be the one that was asked for"
        );
        assert_eq!(
            *owner,
            address_at(0, 0),
            "the owner must be slot 0/0: `create_delegation_transaction` derives it there \
             and nothing about the staking address changes that"
        );
    }
}

#[test]
fn a_delegation_cannot_be_owned_by_a_rotated_slot() {
    // The corollary, stated as a fact rather than an accident: there is no
    // argument that would move ownership. If one is ever added, this test is
    // the thing that should fail and be rewritten.
    let mut w = wallet_with(vec![untagged("a", 0, 900_000_000)]);
    let result = create_delegation_transaction(
        &mut w,
        &seed(),
        &staking_address_at(0, 0),
        500_000_000,
        ColdStakeVariant::Lof,
    )
    .unwrap();
    for (_, owner) in p2cs_parties(&result.txhex) {
        assert_ne!(owner, address_at(0, 5));
        assert_eq!(owner, address_at(0, 0));
    }
}

#[test]
fn a_delegation_funded_only_by_rotated_coins_says_to_consolidate() {
    // Before the slot tag this built a transaction signing 0/5's output with
    // 0/0's key, which the network rejects. Now it is refused up front, and the
    // error has to name the way out: there is no `delegateColdStakeFromUtxos`,
    // so the answer is to move the coins to 0/0 first.
    let mut w = wallet_with(vec![at_slot("b", 0, 900_000_000, 0, 5)]);
    let err = create_delegation_transaction(
        &mut w,
        &seed(),
        &staking_address_at(0, 0),
        500_000_000,
        ColdStakeVariant::Lof,
    )
    .unwrap_err()
    .to_string();

    assert!(
        err.contains("0/0") && err.contains("sendTransparentFromUtxos"),
        "the error must explain that delegation funds from 0/0 and how to get coins \
         there: {err}"
    );
}

#[test]
fn withdrawing_from_a_rotated_owner_returns_change_to_that_slot() {
    // The withdrawal builders *are* slot-aware, so a delegation owned by 0/5
    // (created elsewhere, since this kit only ever owns at 0/0) withdraws
    // correctly and leaves its remainder at 0/5 rather than consolidating onto
    // 0/0 behind the caller's back.
    let owner =
        pivx_wallet_kit::transparent::coldstake::owner_hash_from_seed(&seed(), 0, 5).unwrap();
    let script = build_p2cs_script(&[0xAA; 20], &owner, ColdStakeVariant::Lof);
    let delegated = SerializedUTXO {
        script: simd::hex::bytes_to_hex_string(&script),
        ..at_slot("b", 0, 900_000_000, 0, 5)
    };

    let result = pivx_wallet_kit::transparent::coldstake::create_coldstake_withdrawal(
        &seed(),
        0,
        5,
        &[delegated],
        &to_address(),
        400_000_000,
    )
    .unwrap();

    let tx = common::decode(&simd::hex::hex_string_to_bytes(&result.txhex));
    let change_script = keys::address_to_p2pkh_script(&address_at(0, 5)).unwrap();
    assert!(
        tx.outputs.iter().any(|o| o.script_pubkey == change_script),
        "change did not return to the owner slot it was withdrawn from"
    );
    assert!(
        !tx.outputs
            .iter()
            .any(|o| o.script_pubkey == keys::address_to_p2pkh_script(&address_at(0, 0)).unwrap()),
        "change leaked to slot 0/0, which is not where this delegation lived"
    );
}

#[test]
fn re_delegated_change_keeps_the_owner_slot_it_came_from() {
    // `withdrawColdStakeKeepingRest` rebuilds a P2CS for the remainder. That
    // script has to carry the *same* owner, or the kept-back portion becomes
    // withdrawable only by a different key.
    use pivx_wallet_kit::transparent::coldstake::WithdrawalChange;

    let owner =
        pivx_wallet_kit::transparent::coldstake::owner_hash_from_seed(&seed(), 0, 5).unwrap();
    let script = build_p2cs_script(&[0xAA; 20], &owner, ColdStakeVariant::Lof);
    let delegated = SerializedUTXO {
        script: simd::hex::bytes_to_hex_string(&script),
        ..at_slot("b", 0, 1_000_000_000, 0, 5)
    };
    let staking = encode_staking_address(&[0xAA; 20]);

    let result =
        pivx_wallet_kit::transparent::coldstake::create_coldstake_withdrawal_with_change(
            &seed(),
            0,
            5,
            &[delegated],
            &to_address(),
            400_000_000,
            WithdrawalChange::Delegate(&staking),
        )
        .unwrap();

    let parties = p2cs_parties(&result.txhex);
    assert_eq!(parties.len(), 1, "expected exactly one re-delegated change output");
    assert_eq!(
        parties[0].1,
        address_at(0, 5),
        "re-delegated change changed owner: the kept-back portion would be withdrawable \
         only by a key the delegation never had"
    );
}

#[test]
fn a_delegation_owned_by_another_slot_is_refused_with_the_owner_named() {
    // The withdrawal path validates against the P2CS script's own owner hash,
    // which is stronger than the hdSlot tag and independent of it. A caller who
    // guesses the slot wrong gets told which address actually owns the output.
    let owner =
        pivx_wallet_kit::transparent::coldstake::owner_hash_from_seed(&seed(), 0, 5).unwrap();
    let script = build_p2cs_script(&[0xAA; 20], &owner, ColdStakeVariant::Lof);
    let delegated = SerializedUTXO {
        script: simd::hex::bytes_to_hex_string(&script),
        ..untagged("b", 0, 900_000_000)
    };

    let err = pivx_wallet_kit::transparent::coldstake::create_coldstake_withdrawal(
        &seed(),
        0,
        0,
        &[delegated],
        &to_address(),
        400_000_000,
    )
    .unwrap_err()
    .to_string();

    assert!(
        err.contains(&address_at(0, 5)),
        "the error must name the address that actually owns the delegation: {err}"
    );
}

#[test]
fn a_delegation_this_kit_built_stays_reachable_by_the_default_withdrawal() {
    // The round trip that matters for an existing consumer: delegate (owner
    // 0/0), then withdraw at 0/0. The P2CS output is indexed under its owner's
    // address, so a rotating consumer querying the 0/0 address tags it 0/0, and
    // the tag agrees with the slot the withdrawal needs.
    let mut w = wallet_with(vec![untagged("a", 0, 900_000_000)]);
    let delegation = create_delegation_transaction(
        &mut w,
        &seed(),
        &staking_address_at(0, 0),
        500_000_000,
        ColdStakeVariant::Lof,
    )
    .unwrap();

    let tx = common::decode(&simd::hex::hex_string_to_bytes(&delegation.txhex));
    let p2cs = tx
        .outputs
        .iter()
        .find(|o| pivx_wallet_kit::transparent::coldstake::is_p2cs(&o.script_pubkey))
        .expect("no P2CS output");

    let delegated = SerializedUTXO {
        script: simd::hex::bytes_to_hex_string(&p2cs.script_pubkey),
        ..at_slot("c", 0, p2cs.value, 0, 0)
    };
    let mut w2 = wallet_with(vec![delegated.clone()]);
    assert_eq!(
        w2.get_delegated_balance(),
        p2cs.value,
        "a 0/0-tagged delegation must still count as delegated"
    );
    assert_eq!(w2.get_rotated_balance(), 0, "0/0 is not a rotated slot");
    w2.unspent_utxos.clear();

    pivx_wallet_kit::transparent::coldstake::create_coldstake_withdrawal(
        &seed(),
        0,
        0,
        &[delegated],
        &to_address(),
        p2cs.value - 100_000,
    )
    .expect("a delegation this kit built must be withdrawable at 0/0");
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

#[test]
fn slot_tags_survive_a_serialization_round_trip() {
    // The tag is only useful if it outlives a page reload: a wallet that
    // forgets its slots on restore silently re-exposes rotated coins to the
    // `0/0` builders, which is the exact failure the tag exists to prevent.
    let w = wallet_with(vec![
        untagged("a", 0, 500_000),
        at_slot("b", 0, 700_000, 0, 5),
        at_slot("c", 1, 300_000, 1, 2),
    ]);

    let json = serde_json::to_string(&w).unwrap();
    let restored: WalletData = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.get_transparent_balance(), 500_000);
    assert_eq!(restored.get_rotated_balance(), 1_000_000);
    assert_eq!(restored.unspent_utxos[0].hd_slot, None);
    assert_eq!(restored.unspent_utxos[1].hd_slot, Some(HdSlot { change: 0, index: 5 }));
    assert_eq!(restored.unspent_utxos[2].hd_slot, Some(HdSlot { change: 1, index: 2 }));
}

#[test]
fn a_wallet_persisted_before_the_field_existed_restores_untagged() {
    // Older JSON has no `hdSlot` key at all. It must read as untagged, not fail
    // to deserialize and not read as some default slot that changes behaviour.
    let w = wallet_with(vec![untagged("a", 0, 500_000)]);
    let mut json: serde_json::Value = serde_json::to_value(&w).unwrap();
    json["unspent_utxos"][0].as_object_mut().unwrap().remove("hdSlot");
    assert!(json["unspent_utxos"][0].get("hdSlot").is_none());

    let restored: WalletData = serde_json::from_value(json).unwrap();
    assert_eq!(restored.unspent_utxos[0].hd_slot, None);
    assert_eq!(restored.get_transparent_balance(), 500_000, "old coins became unspendable");
    assert_eq!(restored.get_rotated_balance(), 0);
}
