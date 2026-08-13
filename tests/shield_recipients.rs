//! Recipient validation and fee-shape tests for multi-recipient shield sends.
//!
//! Building an actual shield transaction needs the ~50MB Groth16 proving
//! parameters, which are the consumer's responsibility and deliberately absent
//! from this repo. Everything *around* the proof is testable without them:
//! which recipients are accepted, how the output shape is derived, and whether
//! the fee estimator still agrees with the builder.
//!
//! The proving path itself is exercised against real params in the WASM
//! harness. What matters here is that the fee shape a recipient list implies
//! is correct, because an under-estimate strands a transaction unconfirmed
//! with no error anyone can trace back to this code.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::sapling::builder::{ShieldRecipient, shield_recipient_fee_shape};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn shield_address() -> String {
    let mnemonic = bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap();
    let bip39_seed = mnemonic.to_seed("");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bip39_seed[..32]);
    let extsk = keys::spending_key_from_seed(&seed, 0).unwrap();
    let extfvk = keys::full_viewing_key(&extsk);
    keys::get_default_address(&keys::encode_extfvk(&extfvk)).unwrap()
}

fn transparent_address() -> String {
    keys::get_transparent_address(TEST_MNEMONIC).unwrap()
}

fn shield_recipient(address: &str, amount: u64) -> ShieldRecipient {
    ShieldRecipient { address: address.to_string(), amount, memo: String::new() }
}

/// The two single-recipient shapes must be exactly what the previous
/// hardcoded logic produced: `(0, 2)` for a shield destination and `(1, 2)`
/// for a transparent one. Any drift here silently changes the fee every
/// existing consumer pays.
#[test]
fn single_recipient_shape_matches_the_previous_hardcoded_values() {
    let (t, s, total) = shield_recipient_fee_shape(&[shield_recipient(&shield_address(), 100_000)])
        .expect("shield recipient should resolve");
    assert_eq!((t, s), (0, 2), "shield destination shape changed");
    assert_eq!(total, 100_000);

    let (t, s, total) =
        shield_recipient_fee_shape(&[shield_recipient(&transparent_address(), 100_000)])
            .expect("transparent recipient should resolve");
    assert_eq!((t, s), (1, 2), "transparent destination shape changed");
    assert_eq!(total, 100_000);
}

/// Sapling output count is `shield recipients + 1` for change. The floor of 2
/// only binds for a single shield recipient: beyond that the real count takes
/// over.
#[test]
fn sapling_output_count_grows_with_shield_recipients() {
    let s_addr = shield_address();

    for n in 1..=5u64 {
        let recipients: Vec<ShieldRecipient> = (0..n)
            .map(|_| shield_recipient(&s_addr, 10_000))
            .collect();
        let (t, s, total) = shield_recipient_fee_shape(&recipients).unwrap();

        assert_eq!(t, 0, "no transparent outputs expected");
        assert_eq!(
            s,
            (n + 1).max(2),
            "{n} shield recipients should imply {} sapling outputs",
            (n + 1).max(2)
        );
        assert_eq!(total, n * 10_000);
    }
}

/// Transparent recipients paid from shield notes count against the transparent
/// output total, while change stays in the shield pool.
#[test]
fn transparent_recipients_count_separately() {
    let t_addr = transparent_address();
    let recipients: Vec<ShieldRecipient> =
        (0..3).map(|_| shield_recipient(&t_addr, 10_000)).collect();

    let (t, s, total) = shield_recipient_fee_shape(&recipients).unwrap();
    assert_eq!(t, 3, "three transparent outputs expected");
    // No shield recipients, so only the change note: floored at 2.
    assert_eq!(s, 2);
    assert_eq!(total, 30_000);
}

/// A single shield transaction can pay both pools at once. This is the case
/// the transparent builders cannot serve, and the reason shield multi-recipient
/// is more capable rather than merely equivalent.
#[test]
fn mixed_pools_in_one_transaction() {
    let recipients = vec![
        shield_recipient(&shield_address(), 50_000),
        shield_recipient(&transparent_address(), 30_000),
        shield_recipient(&shield_address(), 20_000),
    ];

    let (t, s, total) = shield_recipient_fee_shape(&recipients).unwrap();
    assert_eq!(t, 1, "one transparent recipient");
    assert_eq!(s, 3, "two shield recipients + change");
    assert_eq!(total, 100_000);
}

/// A fee quoted for a bigger send must never come out below a smaller one:
/// the property that actually protects against stranded transactions.
#[test]
fn fee_is_monotonic_in_recipient_count() {
    let s_addr = shield_address();
    let mut previous = 0u64;

    for n in 1..=6u64 {
        let recipients: Vec<ShieldRecipient> =
            (0..n).map(|_| shield_recipient(&s_addr, 10_000)).collect();
        let (t, s, _) = shield_recipient_fee_shape(&recipients).unwrap();

        // One spend note, whatever output shape this recipient list implies.
        let fee = pivx_wallet_kit::fees::estimate_fee(0, t, 1, s);
        assert!(
            fee >= previous,
            "fee dropped going from {} to {n} recipients ({previous} -> {fee})",
            n - 1
        );
        previous = fee;
    }
}

#[test]
fn rejects_empty_recipient_list() {
    assert!(shield_recipient_fee_shape(&[]).is_err());
}

#[test]
fn rejects_zero_amount() {
    assert!(shield_recipient_fee_shape(&[shield_recipient(&shield_address(), 0)]).is_err());
}

/// A memo on a transparent output has nowhere to go. Erroring is the honest
/// behaviour: silently dropping it would let a caller believe a payment
/// carried a reference it does not.
#[test]
fn rejects_memo_on_a_transparent_recipient() {
    let with_memo = ShieldRecipient {
        address: transparent_address(),
        amount: 10_000,
        memo: "invoice 41".to_string(),
    };
    let err = shield_recipient_fee_shape(&[with_memo]).unwrap_err().to_string();
    assert!(
        err.contains("memo"),
        "error should name the memo as the problem, got: {err}"
    );

    // The same memo on a shield recipient is fine.
    let ok = ShieldRecipient {
        address: shield_address(),
        amount: 10_000,
        memo: "invoice 41".to_string(),
    };
    assert!(shield_recipient_fee_shape(&[ok]).is_ok());
}

/// A Sapling memo field is 512 bytes. Over-long memos must be rejected during
/// recipient resolution, not deep inside the builder: otherwise the fee
/// estimator quotes a fee for a send that cannot be built, breaking the
/// estimator/builder agreement the rest of this module maintains.
#[test]
fn rejects_over_long_memo() {
    let s_addr = shield_address();

    let ok = ShieldRecipient {
        address: s_addr.clone(),
        amount: 10_000,
        memo: "x".repeat(512),
    };
    assert!(
        shield_recipient_fee_shape(&[ok]).is_ok(),
        "512 bytes is exactly the limit and must be accepted"
    );

    let too_long = ShieldRecipient {
        address: s_addr,
        amount: 10_000,
        memo: "x".repeat(513),
    };
    let err = shield_recipient_fee_shape(&[too_long])
        .expect_err("513 bytes must be rejected")
        .to_string();
    assert!(
        err.to_lowercase().contains("memo"),
        "error should name the memo, got: {err}"
    );
}

/// The 512-byte limit is on encoded bytes, so a short string of multi-byte
/// characters can still overflow it. Counting characters instead of bytes would
/// let this through.
#[test]
fn memo_limit_is_measured_in_bytes_not_characters() {
    let s_addr = shield_address();

    // 200 snowmen = 200 chars but 600 bytes.
    let multibyte = ShieldRecipient {
        address: s_addr.clone(),
        amount: 10_000,
        memo: "☃".repeat(200),
    };
    assert!(
        shield_recipient_fee_shape(&[multibyte]).is_err(),
        "600 bytes of multi-byte characters must be rejected despite being 200 chars"
    );

    // 170 snowmen = 510 bytes, inside the limit.
    let fits = ShieldRecipient {
        address: s_addr,
        amount: 10_000,
        memo: "☃".repeat(170),
    };
    assert!(
        shield_recipient_fee_shape(&[fits]).is_ok(),
        "510 bytes of multi-byte characters should fit"
    );
}

/// Validation must reach every element, not stop at the first. A long list with
/// one bad entry at the end is the realistic shape of a caller bug.
#[test]
fn validates_every_recipient_in_a_long_list() {
    let s_addr = shield_address();
    let mut recipients: Vec<ShieldRecipient> =
        (0..40).map(|_| shield_recipient(&s_addr, 10_000)).collect();

    recipients.push(ShieldRecipient {
        address: s_addr,
        amount: 10_000,
        memo: "x".repeat(1000),
    });

    let err = shield_recipient_fee_shape(&recipients)
        .expect_err("a bad memo at position 40 must be caught")
        .to_string();
    assert!(err.to_lowercase().contains("memo"), "got: {err}");
}

#[test]
fn rejects_amounts_that_overflow_when_summed() {
    let s_addr = shield_address();
    let overflow = vec![
        shield_recipient(&s_addr, u64::MAX),
        shield_recipient(&s_addr, 1),
    ];
    assert!(
        shield_recipient_fee_shape(&overflow).is_err(),
        "overflowing amounts should be rejected, not wrapped"
    );
}

#[test]
fn rejects_a_malformed_address() {
    let bad = shield_recipient("not-an-address", 10_000);
    assert!(shield_recipient_fee_shape(&[bad]).is_err());
}
