//! The shielded fee model must cover the transaction it prices, and at the
//! shielded rate every missed byte costs a hundred times what it does on the
//! transparent path.
//!
//! PIVX charges a shielded transaction the ordinary relay fee for its total
//! size, multiplied by `K = DEFAULT_SHIELDEDTXFEE_K = 100`, in
//! `GetShieldedTxMinFee` (`src/validation.cpp`, `src/validation.h`). With
//! `minRelayTxFee = CFeeRate(10000)`, which is 10 sat/byte, that comes to
//! **1000 sat per byte**, measured against the transaction's *actual* total
//! size.
//!
//! `estimate_fee` approximates that size from component counts. The
//! transparent path has `fee_covers_relay_minimum.rs` proving its model covers
//! real serialized bytes, written after a live node answered `insufficient
//! fee: 2290 < 2520`. The shielded path had no equivalent, and a shortfall
//! there is charged at 1000 sat/byte rather than 10.
//!
//! There is an opposite edge too: Core refuses a shielded transaction paying
//! more than `GetShieldedTxMinFee(tx) * 100`. The acceptable fee is a window,
//! not a floor.
//!
//! These tests are arithmetic over the model rather than built transactions,
//! because building one needs the ~50 MB Groth16 proving parameters, which CI
//! does not have. The figures they are pinned against come from a real mainnet
//! shielding transaction, recorded below, so the model is anchored to something
//! a node actually accepted rather than to itself.

use pivx_wallet_kit::fees;

/// `DEFAULT_SHIELDEDTXFEE_K` in PIVX Core's `src/validation.h`.
const SHIELDED_FEE_K: u64 = 100;

/// `minRelayTxFee = CFeeRate(10000)` in `src/validation.cpp`, per kilobyte,
/// so 10 per byte.
const MIN_RELAY_SAT_PER_BYTE: u64 = 10;

/// What a node demands per byte of a shielded transaction.
const SHIELDED_SAT_PER_BYTE: u64 = MIN_RELAY_SAT_PER_BYTE * SHIELDED_FEE_K;

/// Ceiling Core applies: `nMaxFee = GetShieldedTxMinFee(tx) * 100`.
const SHIELDED_FEE_CEILING_MULTIPLE: u64 = 100;

// --- Measured from mainnet, transaction 4cd0838d ------------------------------
//
// 1.0 PIV shielded from a single P2PKH input, change returned transparently.
// Accepted and confirmed at block 5602605.
const LIVE_TX_BYTES: u64 = 2162;
const LIVE_TX_INPUTS: u64 = 1;

#[test]
fn the_shielded_rate_is_the_product_core_computes() {
    assert_eq!(SHIELDED_SAT_PER_BYTE, 1000);
}

#[test]
fn the_model_covers_the_transaction_mainnet_accepted() {
    // The shape of 4cd0838d: one transparent input, one transparent change
    // output, two sapling outputs.
    let modelled = fees::estimate_fee(LIVE_TX_INPUTS, 1, 0, 2);
    let required = SHIELDED_SAT_PER_BYTE * LIVE_TX_BYTES;

    assert!(
        modelled >= required,
        "model quotes {modelled} sat for a transaction the network prices at {required} sat \
         ({LIVE_TX_BYTES} bytes at {SHIELDED_SAT_PER_BYTE} sat/B): a shielded send would be \
         rejected for insufficient fee"
    );

    // And not absurdly over, which Core also refuses.
    assert!(
        modelled <= required * SHIELDED_FEE_CEILING_MULTIPLE,
        "model quotes {modelled} sat, past Core's ceiling of {} sat",
        required * SHIELDED_FEE_CEILING_MULTIPLE
    );
}

#[test]
fn counting_the_change_output_widened_a_margin_that_was_14_bytes() {
    // Before the fix the model passed `transparent_outputs = 0` while the
    // builder emitted a 34-byte change output. It covered the live transaction
    // by 14 bytes, entirely because the 180-byte input allowance over-estimates
    // a real ~147-byte input.
    let old = fees::estimate_fee(LIVE_TX_INPUTS, 0, 0, 2);
    let new = fees::estimate_fee(LIVE_TX_INPUTS, 1, 0, 2);
    let required = SHIELDED_SAT_PER_BYTE * LIVE_TX_BYTES;

    assert_eq!(
        new - old,
        34 * SHIELDED_SAT_PER_BYTE,
        "counting one transparent output should add exactly one output's worth"
    );
    assert_eq!(old - required, 14 * SHIELDED_SAT_PER_BYTE, "the old margin was 14 bytes");
    assert_eq!(new - required, 48 * SHIELDED_SAT_PER_BYTE, "the new margin is 48 bytes");
}

#[test]
fn the_model_covers_every_shape_the_builder_can_produce() {
    // A shielding transaction is inputs -> 2 sapling outputs + 1 transparent
    // change. The only thing that varies is how many inputs selection reaches
    // for, and each real input is at most 148 bytes against a 180-byte
    // allowance, so coverage must widen rather than narrow.
    for inputs in 1..=25u64 {
        let modelled = fees::estimate_fee(inputs, 1, 0, 2);

        // Reconstruct the largest transaction that shape can serialize to,
        // from the live measurement: the non-input remainder held constant,
        // plus the worst-case 148 bytes per input.
        let non_input_bytes = LIVE_TX_BYTES - 147 * LIVE_TX_INPUTS;
        let worst_case_bytes = non_input_bytes + 148 * inputs;
        let required = SHIELDED_SAT_PER_BYTE * worst_case_bytes;

        assert!(
            modelled >= required,
            "{inputs} inputs: model {modelled} sat against a worst case of {required} sat \
             ({worst_case_bytes} bytes)"
        );
    }
}

#[test]
fn the_model_grows_with_every_component_it_prices() {
    // A component that does not move the fee is a component the model is
    // blind to, which is how the transparent change output went unpriced.
    let base = fees::estimate_fee(1, 1, 0, 2);
    assert!(fees::estimate_fee(2, 1, 0, 2) > base, "transparent inputs must be priced");
    assert!(fees::estimate_fee(1, 2, 0, 2) > base, "transparent outputs must be priced");
    assert!(fees::estimate_fee(1, 1, 1, 2) > base, "sapling spends must be priced");
    assert!(fees::estimate_fee(1, 1, 0, 3) > base, "sapling outputs must be priced");
}

#[test]
fn the_component_sizes_are_the_ones_the_protocol_defines() {
    // 948 and 384 are not estimates: they are the serialized sizes of a
    // Sapling output description and a spend description. If either drifts,
    // the model stops tracking the format it claims to price.
    let one_output = fees::estimate_fee(0, 0, 0, 1) - fees::estimate_fee(0, 0, 0, 0);
    let one_spend = fees::estimate_fee(0, 0, 1, 0) - fees::estimate_fee(0, 0, 0, 0);
    assert_eq!(one_output, 948 * SHIELDED_SAT_PER_BYTE, "Sapling output description is 948 bytes");
    assert_eq!(one_spend, 384 * SHIELDED_SAT_PER_BYTE, "Sapling spend description is 384 bytes");
}

#[test]
fn the_shieldable_maximum_prices_the_change_output_too() {
    // `max_shieldable_transparent` exists to mirror the builder's model. If it
    // priced the shielding transaction without the transparent change output
    // the builder budgets for, it would quote a maximum the builder then
    // refuses to build. Building one here needs the Groth16 parameters, so this
    // pins the accessor to the model instead.
    use pivx_wallet_kit::transparent::builder::max_shieldable_transparent;
    use pivx_wallet_kit::wallet::{self, SerializedUTXO};

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon about";
    let mut w = wallet::import_wallet(mnemonic, 5_000_000).unwrap();
    let total = 10 * 100_000_000;
    w.unspent_utxos = vec![SerializedUTXO {
        txid: "a".repeat(64),
        vout: 0,
        amount: total,
        script: String::new(),
        height: 5_000_000,
        ..Default::default()
    }];

    assert_eq!(
        total - max_shieldable_transparent(&w),
        fees::estimate_fee(1, 1, 0, 2),
        "the shieldable maximum must reserve the fee for 1 transparent change output and \
         2 sapling outputs, exactly as the builder does"
    );
}
