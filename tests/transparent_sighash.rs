//! Signature-level verification for the raw v1 transparent builders.
//!
//! The existing integration tests assert on transaction *shape*: hex is
//! non-empty, version bytes are right, a script appears somewhere in the body.
//! None of them check that the ECDSA signatures actually commit to the
//! transaction that was built. That gap matters because the transparent path
//! hand-rolls both its serialization and its SIGHASH_ALL preimage, in two
//! places (`compute_sighash` and the transaction writer) that must stay
//! byte-identical to each other.
//!
//! The failure this guards against is not a build error. A sighash that
//! disagrees with the serialized outputs produces a transaction the network
//! silently rejects; worse, a serialization bug that still hashes consistently
//! produces a *valid* transaction paying the wrong outputs. Neither is visible
//! from the outside without doing what a validating node does.
//!
//! So these tests re-derive everything from the finished transaction bytes and
//! never call the builder's own hashing code. The prevout script is
//! reconstructed from the pubkey inside each `scriptSig`: exactly the
//! information a node has, which means a bug in `compute_sighash` cannot hide
//! by being reused on both sides of the comparison.

mod common;
use common::{decode as parse_tx, verify_all_signatures};

use pivx_wallet_kit::keys;
use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_from_utxos,
    create_raw_transparent_transaction_from_utxos_to_many,
};
use pivx_wallet_kit::wallet::SerializedUTXO;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC)
        .unwrap()
        .to_seed("")
        .to_vec()
}

fn utxo(txid_byte: &str, vout: u32, amount: u64) -> SerializedUTXO {
    SerializedUTXO {
        txid: txid_byte.repeat(64),
        vout,
        amount,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Baseline: two outputs (recipient + change). The signature must commit to
/// both, in the order they were serialized.
#[test]
fn signature_commits_to_transaction_with_change() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    let utxos = vec![utxo("b", 1, 100_000_000)];

    let result =
        create_raw_transparent_transaction_from_utxos(&bip39_seed, 0, 5, &utxos, &to, 50_000_000)
            .expect("builder should produce a signed tx");

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));

    assert_eq!(tx.version, 1);
    assert_eq!(tx.locktime, 0);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 2, "expected recipient + change");

    let verified = verify_all_signatures(&tx);
    assert_eq!(verified, 1);

    // The recipient output must carry the exact requested amount.
    let to_script = keys::address_to_p2pkh_script(&to).unwrap();
    let recipient = tx
        .outputs
        .iter()
        .find(|o| o.script_pubkey == to_script)
        .expect("no output pays the requested address");
    assert_eq!(recipient.value, 50_000_000);

    // Value must be conserved: inputs - outputs == fee.
    let out_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
    assert_eq!(100_000_000 - out_total, result.fee);
}

/// No-change path: the whole UTXO minus fee goes to one output. Exercises the
/// `output_count == 1` branch, which is serialized separately.
#[test]
fn signature_commits_to_transaction_without_change() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    let utxos = vec![utxo("c", 0, 100_000_000)];

    // amount = total - fee leaves nothing over.
    let fee = pivx_wallet_kit::fees::estimate_raw_transparent_fee(1, 2);
    let amount = 100_000_000 - fee;

    let result =
        create_raw_transparent_transaction_from_utxos(&bip39_seed, 0, 5, &utxos, &to, amount)
            .expect("builder should produce a signed tx");

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));

    assert_eq!(tx.outputs.len(), 1, "expected no change output");
    assert_eq!(tx.outputs[0].value, amount);
    assert_eq!(verify_all_signatures(&tx), 1);
}

/// Multi-input: every input signs the same set of outputs but a different
/// preimage (each commits its own prevout script at its own position). A
/// builder that reused one input's sighash for all of them would pass shape
/// assertions and fail here.
#[test]
fn every_input_signature_is_independently_valid() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    let utxos = vec![
        utxo("a", 0, 100_000_000),
        utxo("b", 1, 200_000_000),
        utxo("c", 2, 300_000_000),
    ];

    let result =
        create_raw_transparent_transaction_from_utxos(&bip39_seed, 0, 3, &utxos, &to, 250_000_000)
            .expect("builder should produce a signed tx");

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));

    assert_eq!(tx.inputs.len(), 3);
    assert_eq!(verify_all_signatures(&tx), 3);

    // Each input must reference its own distinct outpoint, byte-reversed.
    for (i, letter) in ["a", "b", "c"].iter().enumerate() {
        let mut expected = simd::hex::hex_string_to_bytes(&letter.repeat(64));
        expected.reverse();
        assert_eq!(
            tx.inputs[i].prev_txid.to_vec(),
            expected,
            "input {i} references the wrong outpoint"
        );
        assert_eq!(tx.inputs[i].prev_vout, i as u32);
    }
}

/// Negative control. The verifier must actually reject a transaction whose
/// outputs were altered after signing: otherwise the tests above prove
/// nothing. Flipping one satoshi in an output value invalidates the preimage
/// without touching the signature.
#[test]
fn verifier_rejects_a_tampered_output_value() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    let utxos = vec![utxo("d", 0, 100_000_000)];

    let result =
        create_raw_transparent_transaction_from_utxos(&bip39_seed, 0, 5, &utxos, &to, 50_000_000)
            .expect("builder should produce a signed tx");

    let mut tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));

    // Untampered: verifies.
    assert_eq!(verify_all_signatures(&tx), 1);

    // Tampered: must not.
    tx.outputs[0].value += 1;
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_all_signatures(&tx);
    }))
    .is_err();

    assert!(
        panicked,
        "verifier accepted a transaction whose output value was changed after signing: the \
         harness is not actually checking the signature"
    );
}

/// Negative control for recipient substitution: the failure mode that costs
/// money. Redirecting an output to a different address must invalidate the
/// signature.
#[test]
fn verifier_rejects_a_redirected_output() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    let utxos = vec![utxo("e", 0, 100_000_000)];

    let result =
        create_raw_transparent_transaction_from_utxos(&bip39_seed, 0, 5, &utxos, &to, 50_000_000)
            .expect("builder should produce a signed tx");

    let mut tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(verify_all_signatures(&tx), 1);

    // Repoint an output at an unrelated address.
    let attacker = keys::transparent_key_from_bip39_seed(&bip39_seed, 0, 99).unwrap().0;
    tx.outputs[0].script_pubkey = keys::address_to_p2pkh_script(&attacker).unwrap();

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_all_signatures(&tx);
    }))
    .is_err();

    assert!(
        panicked,
        "verifier accepted a transaction whose recipient was swapped after signing"
    );
}

// ---------------------------------------------------------------------------
// Multi-recipient
// ---------------------------------------------------------------------------

/// Derive `n` distinct transparent addresses to pay.
fn distinct_addresses(bip39_seed: &[u8], n: u32) -> Vec<String> {
    (0..n)
        .map(|i| {
            keys::transparent_key_from_bip39_seed(bip39_seed, 0, 100 + i)
                .unwrap()
                .0
        })
        .collect()
}

/// The core multi-recipient assertion: with three recipients plus change, the
/// signature must commit to all four outputs, and each must carry exactly the
/// requested amount to exactly the requested address, in the requested order.
///
/// This is the case Erik's commission split needs: paying a seller and a
/// referrer from one transaction, and paying the wrong split is the failure
/// that costs money.
#[test]
fn multi_recipient_signature_commits_to_every_output() {
    let bip39_seed = seed();
    let addrs = distinct_addresses(&bip39_seed, 3);
    let recipients = vec![
        Recipient { address: addrs[0].clone(), amount: 30_000_000 },
        Recipient { address: addrs[1].clone(), amount: 20_000_000 },
        Recipient { address: addrs[2].clone(), amount: 10_000_000 },
    ];
    let utxos = vec![utxo("a", 0, 100_000_000)];

    let result = create_raw_transparent_transaction_from_utxos_to_many(
        &bip39_seed, 0, 5, &utxos, &recipients,
    )
    .expect("multi-recipient build should succeed");

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));

    assert_eq!(tx.version, 1);
    assert_eq!(tx.outputs.len(), 4, "3 recipients + change");

    // The signature must be valid over all four outputs.
    assert_eq!(verify_all_signatures(&tx), 1);

    // Recipient order must be preserved, with the right amount at each slot.
    for (i, r) in recipients.iter().enumerate() {
        let expected_script = keys::address_to_p2pkh_script(&r.address).unwrap();
        assert_eq!(
            tx.outputs[i].script_pubkey, expected_script,
            "output {i} pays the wrong address: recipient order was not preserved"
        );
        assert_eq!(
            tx.outputs[i].value, r.amount,
            "output {i} pays the wrong amount"
        );
    }

    // Change is last and returns to the source address.
    let source = keys::transparent_key_from_bip39_seed(&bip39_seed, 0, 5).unwrap().0;
    assert_eq!(
        tx.outputs[3].script_pubkey,
        keys::address_to_p2pkh_script(&source).unwrap(),
        "change must return to the source address"
    );

    // Reported total is the recipient sum, excluding change and fee.
    assert_eq!(result.amount, 60_000_000);

    // Value conservation across the whole transaction.
    let out_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
    assert_eq!(100_000_000 - out_total, result.fee);
}

/// Multi-recipient with no change output: exercises a different output count
/// in both the preimage and the body.
#[test]
fn multi_recipient_without_change() {
    let bip39_seed = seed();
    let addrs = distinct_addresses(&bip39_seed, 2);
    let utxos = vec![utxo("b", 0, 100_000_000)];

    // 2 recipients + assumed change = 3 outputs in the fee model.
    let fee = pivx_wallet_kit::fees::estimate_raw_transparent_fee(1, 3);
    let half = (100_000_000 - fee) / 2;
    let recipients = vec![
        Recipient { address: addrs[0].clone(), amount: half },
        // Absorb the rounding remainder so nothing is left for change.
        Recipient { address: addrs[1].clone(), amount: 100_000_000 - fee - half },
    ];

    let result = create_raw_transparent_transaction_from_utxos_to_many(
        &bip39_seed, 0, 5, &utxos, &recipients,
    )
    .expect("build should succeed");

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(tx.outputs.len(), 2, "no change output expected");
    assert_eq!(verify_all_signatures(&tx), 1);
    assert_eq!(result.amount, 100_000_000 - fee);
}

/// Many recipients across many inputs: the combination most likely to expose
/// a varint or offset error, since both counts cross out of single-byte range
/// behaviour in the same transaction.
#[test]
fn multi_recipient_multi_input() {
    let bip39_seed = seed();
    let addrs = distinct_addresses(&bip39_seed, 6);
    let recipients: Vec<Recipient> = addrs
        .iter()
        .enumerate()
        .map(|(i, a)| Recipient {
            address: a.clone(),
            amount: 10_000_000 + (i as u64 * 1_000_000),
        })
        .collect();

    let utxos = vec![
        utxo("a", 0, 50_000_000),
        utxo("b", 1, 50_000_000),
        utxo("c", 2, 50_000_000),
        utxo("d", 3, 50_000_000),
    ];

    let result = create_raw_transparent_transaction_from_utxos_to_many(
        &bip39_seed, 0, 5, &utxos, &recipients,
    )
    .expect("build should succeed");

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));

    assert_eq!(tx.inputs.len(), 4);
    assert_eq!(tx.outputs.len(), 7, "6 recipients + change");
    assert_eq!(verify_all_signatures(&tx), 4);

    for (i, r) in recipients.iter().enumerate() {
        assert_eq!(tx.outputs[i].value, r.amount, "output {i} amount");
    }
    assert_eq!(result.amount, recipients.iter().map(|r| r.amount).sum::<u64>());
}

/// Tampering with a *middle* output must invalidate the signature. A sighash
/// that only committed to the first and last outputs: an easy off-by-one when
/// generalising from the old fixed two-output shape: would pass every
/// positive test above and fail here.
#[test]
fn multi_recipient_verifier_rejects_tampering_with_a_middle_output() {
    let bip39_seed = seed();
    let addrs = distinct_addresses(&bip39_seed, 3);
    let recipients = vec![
        Recipient { address: addrs[0].clone(), amount: 30_000_000 },
        Recipient { address: addrs[1].clone(), amount: 20_000_000 },
        Recipient { address: addrs[2].clone(), amount: 10_000_000 },
    ];
    let utxos = vec![utxo("c", 0, 100_000_000)];

    let result = create_raw_transparent_transaction_from_utxos_to_many(
        &bip39_seed, 0, 5, &utxos, &recipients,
    )
    .unwrap();

    let mut tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(verify_all_signatures(&tx), 1);

    // Redirect the middle recipient's payment.
    let attacker = keys::transparent_key_from_bip39_seed(&bip39_seed, 0, 99).unwrap().0;
    tx.outputs[1].script_pubkey = keys::address_to_p2pkh_script(&attacker).unwrap();

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_all_signatures(&tx);
    }))
    .is_err();

    assert!(
        panicked,
        "signature did not commit to the middle output: a recipient could be swapped without \
         invalidating the transaction"
    );
}

/// Reordering outputs without changing any value must also invalidate. Guards
/// against a sighash that commits to the output *set* rather than the output
/// *sequence*.
#[test]
fn multi_recipient_verifier_rejects_reordered_outputs() {
    let bip39_seed = seed();
    let addrs = distinct_addresses(&bip39_seed, 2);
    let recipients = vec![
        Recipient { address: addrs[0].clone(), amount: 30_000_000 },
        Recipient { address: addrs[1].clone(), amount: 20_000_000 },
    ];
    let utxos = vec![utxo("d", 0, 100_000_000)];

    let result = create_raw_transparent_transaction_from_utxos_to_many(
        &bip39_seed, 0, 5, &utxos, &recipients,
    )
    .unwrap();

    let mut tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(verify_all_signatures(&tx), 1);

    tx.outputs.swap(0, 1);

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_all_signatures(&tx);
    }))
    .is_err();

    assert!(panicked, "signature did not commit to output ordering");
}

/// Single-recipient calls routed through the multi-recipient path must produce
/// byte-identical transactions to the legacy single-recipient entry point.
/// This is the backwards-compatibility guarantee for existing consumers.
#[test]
fn single_recipient_is_byte_identical_through_both_entry_points() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    let utxos = vec![utxo("e", 0, 100_000_000), utxo("f", 1, 50_000_000)];

    let legacy = create_raw_transparent_transaction_from_utxos(
        &bip39_seed, 0, 5, &utxos, &to, 50_000_000,
    )
    .unwrap();

    let via_many = create_raw_transparent_transaction_from_utxos_to_many(
        &bip39_seed,
        0,
        5,
        &utxos,
        &[Recipient { address: to.clone(), amount: 50_000_000 }],
    )
    .unwrap();

    assert_eq!(
        legacy.txhex, via_many.txhex,
        "the multi-recipient path changed single-recipient output: existing callers would see \
         different transactions"
    );
    assert_eq!(legacy.fee, via_many.fee);
    assert_eq!(legacy.amount, via_many.amount);
}

/// Input validation. Each of these would otherwise produce a transaction the
/// network rejects, for reasons hard to trace back to the call site.
#[test]
fn multi_recipient_rejects_invalid_input() {
    let bip39_seed = seed();
    let addrs = distinct_addresses(&bip39_seed, 1);
    let utxos = vec![utxo("a", 0, 100_000_000)];

    // Empty recipient list.
    assert!(
        create_raw_transparent_transaction_from_utxos_to_many(&bip39_seed, 0, 5, &utxos, &[])
            .is_err(),
        "empty recipient list should be rejected"
    );

    // Zero-value payment.
    let zero = vec![Recipient { address: addrs[0].clone(), amount: 0 }];
    assert!(
        create_raw_transparent_transaction_from_utxos_to_many(&bip39_seed, 0, 5, &utxos, &zero)
            .is_err(),
        "zero-amount recipient should be rejected"
    );

    // Amounts that overflow u64 when summed.
    let overflow = vec![
        Recipient { address: addrs[0].clone(), amount: u64::MAX },
        Recipient { address: addrs[0].clone(), amount: 1 },
    ];
    assert!(
        create_raw_transparent_transaction_from_utxos_to_many(
            &bip39_seed, 0, 5, &utxos, &overflow
        )
        .is_err(),
        "overflowing recipient amounts should be rejected, not wrapped"
    );

    // Shield destination in a raw transparent send.
    let shield = vec![Recipient {
        address: "ps1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            .to_string(),
        amount: 10_000_000,
    }];
    assert!(
        create_raw_transparent_transaction_from_utxos_to_many(&bip39_seed, 0, 5, &utxos, &shield)
            .is_err(),
        "shield recipient should be rejected from the raw transparent path"
    );

    // Insufficient funds across the recipient set.
    let too_much = vec![
        Recipient { address: addrs[0].clone(), amount: 60_000_000 },
        Recipient { address: addrs[0].clone(), amount: 60_000_000 },
    ];
    assert!(
        create_raw_transparent_transaction_from_utxos_to_many(
            &bip39_seed, 0, 5, &utxos, &too_much
        )
        .is_err(),
        "recipient total exceeding available funds should be rejected"
    );
}

/// The output count crosses from a 1-byte varint to the 3-byte `0xfd` form at
/// 253. That transition happens independently in the sighash preimage and in
/// the transaction body, so it is the single most likely place for the two to
/// disagree, and a disagreement is invisible to any check that does not verify
/// the signature.
#[test]
fn signature_holds_across_the_output_count_varint_boundary() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();

    // 251/252 recipients => 252/253 outputs with change: either side of the
    // boundary. Plus a couple beyond it.
    for n in [251usize, 252, 253, 300] {
        let utxos = vec![utxo("a", 0, 100_000_000_000)];
        let recipients: Vec<Recipient> = (0..n)
            .map(|_| Recipient { address: to.clone(), amount: 1_000_000 })
            .collect();

        let result = create_raw_transparent_transaction_from_utxos_to_many(
            &bip39_seed, 0, 5, &utxos, &recipients,
        )
        .unwrap_or_else(|e| panic!("{n} recipients failed to build: {e}"));

        let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
        assert_eq!(tx.outputs.len(), n + 1, "{n} recipients + change");

        // The assertion that matters: the signature must still commit to the
        // whole transaction once the count is length-prefixed differently.
        assert_eq!(
            verify_all_signatures(&tx),
            1,
            "{n} recipients: signature does not commit to the transaction"
        );

        assert_eq!(result.amount, n as u64 * 1_000_000);
        let out_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
        assert_eq!(100_000_000_000 - out_total, result.fee, "{n}: value not conserved");
    }
}

/// Same boundary on the input side: 253 inputs crosses into the 3-byte varint,
/// and every one of them must still verify against its own preimage position.
#[test]
fn signature_holds_across_the_input_count_varint_boundary() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();

    for n in [252usize, 253, 260] {
        let utxos: Vec<SerializedUTXO> = (0..n)
            .map(|i| utxo("b", i as u32, 1_000_000))
            .collect();

        let result = create_raw_transparent_transaction_from_utxos_to_many(
            &bip39_seed,
            0,
            5,
            &utxos,
            &[Recipient { address: to.clone(), amount: 500_000 }],
        )
        .unwrap_or_else(|e| panic!("{n} inputs failed to build: {e}"));

        let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
        assert_eq!(tx.inputs.len(), n);
        assert_eq!(
            verify_all_signatures(&tx),
            n,
            "{n} inputs: at least one signature does not commit to the transaction"
        );
    }
}

/// Dust recipients are refused. A transaction carrying an output worth less than
/// it costs to spend is non-standard: `IsStandardTx` rejects it with
/// `reason = "dust"`, so building one hands the caller bytes no node will
/// relay. Confirmed against a live node, which answered `-26: dust:`.
#[test]
fn dust_recipients_are_rejected() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    let utxos = vec![utxo("c", 0, 100_000_000)];

    // 5460 sat for a 25-byte P2PKH script.
    let threshold = pivx_wallet_kit::fees::dust_threshold(25);
    assert_eq!(threshold, 5_460, "P2PKH dust threshold changed");

    for amount in [1u64, 100, threshold - 1] {
        let err = create_raw_transparent_transaction_from_utxos_to_many(
            &bip39_seed,
            0,
            5,
            &utxos,
            &[Recipient { address: to.clone(), amount }],
        )
        .expect_err("a dust recipient must be rejected")
        .to_string();
        assert!(err.contains("dust"), "amount {amount}: got {err}");
    }

    // Exactly at the threshold is fine, and still signs correctly.
    let result = create_raw_transparent_transaction_from_utxos_to_many(
        &bip39_seed,
        0,
        5,
        &utxos,
        &[Recipient { address: to, amount: threshold }],
    )
    .expect("the threshold itself is not dust");

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(tx.outputs[0].value, threshold);
    assert_eq!(verify_all_signatures(&tx), 1);
}

/// Dust *change* is dropped rather than emitted, since keeping it would make the
/// transaction unrelayable. The dropped value goes to the miner, so the fee the
/// result reports must be the fee actually paid, not the estimate.
#[test]
fn dust_change_is_absorbed_into_the_fee() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    let total = 100_000_000u64;
    let utxos = vec![utxo("d", 0, total)];

    // Aim to leave 1000 sat of change: well under the 5460 threshold.
    let fee = pivx_wallet_kit::fees::estimate_raw_transparent_fee(1, 2);
    let amount = total - fee - 1_000;

    let result = create_raw_transparent_transaction_from_utxos_to_many(
        &bip39_seed,
        0,
        5,
        &utxos,
        &[Recipient { address: to, amount }],
    )
    .expect("dust change should be dropped, not rejected");

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(tx.outputs.len(), 1, "the dust change output must not be emitted");
    assert_eq!(tx.outputs[0].value, amount);

    // The reported fee absorbs the dropped change.
    assert_eq!(result.fee, fee + 1_000, "reported fee should include the absorbed dust");
    assert_eq!(total - amount, result.fee, "value must still be conserved");
    assert_eq!(verify_all_signatures(&tx), 1);
}

/// Non-dust change is still emitted normally.
#[test]
fn non_dust_change_is_emitted() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    let total = 100_000_000u64;
    let utxos = vec![utxo("e", 0, total)];

    let fee = pivx_wallet_kit::fees::estimate_raw_transparent_fee(1, 2);
    let change = 10_000u64; // comfortably above 5460
    let amount = total - fee - change;

    let result = create_raw_transparent_transaction_from_utxos_to_many(
        &bip39_seed,
        0,
        5,
        &utxos,
        &[Recipient { address: to, amount }],
    )
    .unwrap();

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(tx.outputs.len(), 2);
    assert_eq!(tx.outputs[1].value, change);
    assert_eq!(result.fee, fee);
    assert_eq!(verify_all_signatures(&tx), 1);
}

/// A repeated outpoint must be refused. `parse_blockbook_utxos` collapses
/// duplicates, but the from-UTXOs builders bypass the parser entirely: the
/// caller hands in an exact set and every one of them is spent. Pre-fix this
/// built a transaction spending one output twice while claiming double its
/// value.
#[test]
fn rejects_duplicate_outpoints_in_a_caller_supplied_set() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();

    let duplicated = vec![utxo("a", 0, 100_000_000), utxo("a", 0, 100_000_000)];
    let err = create_raw_transparent_transaction_from_utxos_to_many(
        &bip39_seed,
        0,
        5,
        &duplicated,
        &[Recipient { address: to.clone(), amount: 150_000_000 }],
    )
    .expect_err("a repeated outpoint must be rejected")
    .to_string();
    assert!(
        err.contains("Duplicate UTXO"),
        "error should name the duplicate, got: {err}"
    );

    // Same txid but different vouts are distinct outpoints and must be allowed.
    let distinct = vec![utxo("a", 0, 100_000_000), utxo("a", 1, 100_000_000)];
    let result = create_raw_transparent_transaction_from_utxos_to_many(
        &bip39_seed,
        0,
        5,
        &distinct,
        &[Recipient { address: to, amount: 150_000_000 }],
    )
    .expect("distinct vouts of one txid must be spendable together");

    let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
    assert_eq!(tx.inputs.len(), 2);
    assert_eq!(verify_all_signatures(&tx), 2);

    // And no outpoint appears twice in what was actually built.
    let mut seen = std::collections::HashSet::new();
    for i in &tx.inputs {
        assert!(
            seen.insert((i.prev_txid, i.prev_vout)),
            "the same outpoint was serialized twice"
        );
    }
}

/// The parser must consume exactly the bytes the builder emitted. Catches
/// length-prefix drift: a varint written for the wrong count, or a script
/// length that disagrees with the script that follows.
#[test]
fn serialized_transaction_has_no_trailing_or_missing_bytes() {
    let bip39_seed = seed();
    let to = keys::get_transparent_address(TEST_MNEMONIC).unwrap();

    for input_count in 1..=4usize {
        let utxos: Vec<SerializedUTXO> = (0..input_count)
            .map(|i| utxo("f", i as u32, 100_000_000))
            .collect();

        let result = create_raw_transparent_transaction_from_utxos(
            &bip39_seed,
            0,
            5,
            &utxos,
            &to,
            50_000_000,
        )
        .expect("builder should produce a signed tx");

        // parse_tx asserts full consumption internally.
        let tx = parse_tx(&simd::hex::hex_string_to_bytes(&result.txhex));
        assert_eq!(tx.inputs.len(), input_count);
        assert_eq!(verify_all_signatures(&tx), input_count);
    }
}
