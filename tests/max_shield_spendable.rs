//! "Empty my shield balance" has to return an amount the builder accepts.
//!
//! `maxSendableSat` computes from transparent UTXOs in both of its branches: a
//! `ps1…` destination there prices a *shielding* send (transparent in, shield
//! out), not a spend of notes. So there was no accessor for the shield-spend
//! direction, and callers had to solve `shieldBalanceSat -
//! estimateSendShieldFee` themselves. The two are mutually dependent, because
//! the fee grows with the number of notes selection reaches for, which is the
//! arithmetic the README warns against doing by hand on the transparent side.
//!
//! The invariant under test is the same one `max_sendable_transparent` carries:
//! whatever this returns, handing it straight to the builder must work. Erring
//! high is the failure that matters, since it offers an amount that is then
//! refused. Erring low only leaves dust behind.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::sapling::builder::{
    ShieldRecipient, max_shield_spendable, max_shield_spendable_to_many, select_shield_notes,
    shield_recipient_fee_shape,
};
use pivx_wallet_kit::wallet::{self, SerializedNote, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn note(value: u64) -> SerializedNote {
    SerializedNote {
        note: serde_json::json!({ "value": value }),
        witness: String::new(),
        nullifier: format!("{value:064x}"),
        memo: None,
        height: 5_000_000,
    }
}

fn wallet_with(notes: Vec<SerializedNote>) -> WalletData {
    let mut w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    w.unspent_notes = notes;
    w
}

fn t_address() -> String {
    keys::pubkey_to_pivx_address(&[0x02; 33])
}

fn shield_address() -> String {
    let w = wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
    keys::get_default_address(&w.extfvk).unwrap()
}

/// Run the builder's own selection against `amount`, the way a real send would.
fn is_buildable(w: &WalletData, address: &str, amount: u64) -> bool {
    let recipients = vec![ShieldRecipient {
        address: address.to_string(),
        amount,
        memo: String::new(),
    }];
    let Ok((t_outs, s_outs, total)) = shield_recipient_fee_shape(&recipients) else {
        return false;
    };
    select_shield_notes(&w.unspent_notes, total, t_outs, s_outs).is_ok()
}

#[test]
fn the_figure_is_buildable_for_a_transparent_destination() {
    let w = wallet_with(vec![note(50_000_000), note(30_000_000), note(20_000_000)]);
    let max = max_shield_spendable(&w, &t_address());
    assert!(max > 0, "a funded wallet reported nothing sendable");
    assert!(
        is_buildable(&w, &t_address(), max),
        "the builder refused the amount that was offered as the maximum"
    );
}

#[test]
fn the_figure_is_buildable_for_a_shield_destination() {
    let w = wallet_with(vec![note(50_000_000), note(30_000_000)]);
    let max = max_shield_spendable(&w, &shield_address());
    assert!(max > 0);
    assert!(
        is_buildable(&w, &shield_address(), max),
        "the builder refused the offered maximum for a shield destination"
    );
}

#[test]
fn one_satoshi_more_than_the_maximum_is_refused() {
    // Pins that the figure is the *maximum*, not merely a safe under-estimate:
    // if max + 1 also built, the accessor would be leaving money behind.
    // Slack of one Sapling output is expected and allowed for, since the shape
    // charges for a change output a max send does not emit.
    let w = wallet_with(vec![note(50_000_000), note(30_000_000)]);
    let max = max_shield_spendable(&w, &t_address());
    let slack = 948 * 1000; // one Sapling output at the modelled rate

    assert!(
        !is_buildable(&w, &t_address(), max + slack + 1),
        "the reported maximum understates by more than one Sapling output"
    );
}

#[test]
fn it_accounts_for_the_fee_growing_with_note_count() {
    // Each note adds 384 bytes to the model, so the same balance split across
    // more notes must yield a strictly smaller maximum. Getting this wrong is
    // exactly what hand-rolled arithmetic gets wrong.
    let few = wallet_with(vec![note(60_000_000), note(60_000_000)]);
    let many = wallet_with((0..12).map(|_| note(10_000_000)).collect());
    assert_eq!(
        few.get_balance(),
        many.get_balance(),
        "the two wallets must hold the same total for the comparison to mean anything"
    );

    let max_few = max_shield_spendable(&few, &t_address());
    let max_many = max_shield_spendable(&many, &t_address());
    assert!(
        max_many < max_few,
        "more notes must cost more fee: {max_many} was not below {max_few}"
    );
    assert!(is_buildable(&many, &t_address(), max_many));
}

#[test]
fn a_transparent_destination_costs_more_than_a_shield_one() {
    // A transparent recipient adds a transparent output on top of the Sapling
    // outputs the bundle carries regardless, so it must leave less spendable.
    let w = wallet_with(vec![note(50_000_000)]);
    assert!(
        max_shield_spendable(&w, &t_address()) < max_shield_spendable(&w, &shield_address()),
        "the transparent output was not charged for"
    );
}

#[test]
fn nothing_sendable_reports_zero_rather_than_a_wrong_number() {
    // Empty wallet.
    assert_eq!(max_shield_spendable(&wallet_with(vec![]), &t_address()), 0);

    // Balance below the fee: saturates to 0 instead of wrapping.
    let broke = wallet_with(vec![note(1_000)]);
    assert_eq!(max_shield_spendable(&broke, &t_address()), 0);

    // A remainder that would be dust at a transparent destination is refused by
    // the builder, so offering it would offer an unbuildable amount.
    let fee = 1000 * (2 * 948 + 384 + 34 + 100);
    let dusty = wallet_with(vec![note(fee + 1_000)]);
    let max = max_shield_spendable(&dusty, &t_address());
    assert_eq!(max, 0, "a dust remainder was offered as sendable, got {max}");
    // The same balance to a shield destination has no dust rule to trip.
    assert!(max_shield_spendable(&dusty, &shield_address()) > 0);

    // Unparseable destination.
    assert_eq!(max_shield_spendable(&wallet_with(vec![note(50_000_000)]), "not-an-address"), 0);

    // A note whose value cannot be read makes the whole wallet unbuildable, so
    // 0 is the honest answer rather than a total that skips it.
    let mut bad = wallet_with(vec![note(50_000_000)]);
    bad.unspent_notes.push(SerializedNote {
        note: serde_json::json!({ "not_value": 1 }),
        ..note(0)
    });
    assert_eq!(
        max_shield_spendable(&bad, &t_address()),
        0,
        "an unreadable note was skipped instead of disabling the figure"
    );
}

#[test]
fn the_multi_recipient_form_charges_per_output() {
    let w = wallet_with(vec![note(500_000_000)]);
    let one = max_shield_spendable_to_many(&w, 1, 0);
    let three = max_shield_spendable_to_many(&w, 3, 0);
    assert!(three < one, "extra transparent recipients were not charged for");

    let one_shield = max_shield_spendable_to_many(&w, 0, 1);
    let three_shield = max_shield_spendable_to_many(&w, 0, 3);
    assert!(three_shield < one_shield, "extra shield recipients were not charged for");

    // No recipients is not a question with an answer.
    assert_eq!(max_shield_spendable_to_many(&w, 0, 0), 0);
}
