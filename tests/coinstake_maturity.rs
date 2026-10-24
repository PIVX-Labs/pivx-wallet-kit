//! Immature coinstake outputs must never be selected for spending.
//!
//! Staking a cold-staking delegation *consumes and recreates it*: the staker's
//! coinstake spends the P2CS outpoint and pays an identical script back, so a
//! delegation that has been earning for any length of time is a coinstake
//! output, not the original delegation. PIVX applies `COINBASE_MATURITY` to
//! coinstake outputs, so the replacement cannot be spent until it is 101
//! confirmations deep.
//!
//! Explorers publish it long before then, in the same shape as any other UTXO:
//! verified on mainnet, where a live delegation appeared in `/api/v2/utxo` with
//! 19 confirmations and nothing in the response marking it immature. So the
//! wallet cannot rely on the feed to hide these, and a withdrawal built against
//! a freshly staked delegation would be rejected by the network.
//!
//! `coinstake` defaults to false, so a consumer that never populates it sees
//! exactly the pre-maturity behaviour. It is not opt-in at the parse boundary
//! though: `parse_blockbook_utxos` reads the flag from the explorer response
//! when it is there, and rusty-blox supplies it.

use pivx_wallet_kit::params::COINBASE_MATURITY;
use pivx_wallet_kit::simd;
use pivx_wallet_kit::transparent::builder::{
    Recipient, create_raw_transparent_transaction_from_utxos_to_many,
    create_raw_transparent_transaction_to_many,
};
use pivx_wallet_kit::transparent::coldstake::{
    ColdStakeVariant, build_p2cs_script, create_coldstake_withdrawal, create_delegation_transaction,
};
use pivx_wallet_kit::wallet::{self, SerializedUTXO, WalletData};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const STAKER: [u8; 20] = [0xAA; 20];

fn seed() -> Vec<u8> {
    bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap().to_seed("").to_vec()
}

fn owner_hash() -> [u8; 20] {
    pivx_wallet_kit::transparent::coldstake::owner_hash_from_seed(&seed(), 0, 0).unwrap()
}

/// An ordinary output from a coinstake, `confirmations` deep.
fn coinstake_utxo(letter: &str, amount: u64, confirmations: u32) -> SerializedUTXO {
    SerializedUTXO {
        txid: letter.repeat(64),
        vout: 1,
        amount,
        script: String::new(),
        height: 5_000_000,
        coinstake: true,
        confirmations,
        ..Default::default()
    }
}

/// A delegation recreated by a stake, `confirmations` deep. This is what a live
/// delegation looks like almost all of the time.
fn staked_delegation(letter: &str, amount: u64, confirmations: u32) -> SerializedUTXO {
    let script = build_p2cs_script(&STAKER, &owner_hash(), ColdStakeVariant::Lof);
    SerializedUTXO {
        txid: letter.repeat(64),
        vout: 1,
        amount,
        script: simd::hex::bytes_to_hex_string(&script),
        height: 5_000_000,
        coinstake: true,
        confirmations,
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

// ---------------------------------------------------------------------------
// The rule itself
// ---------------------------------------------------------------------------

/// Maturity turns over at depth 101, not 100: PIVX Core's `GetBlocksToMaturity`
/// is `(COINBASE_MATURITY + 1) - depth`, so an output is spendable once its
/// depth *exceeds* the constant. An off-by-one here either strands funds for a
/// block or builds a transaction the network rejects.
#[test]
fn maturity_boundary_is_one_past_the_constant() {
    let cases = [
        (COINBASE_MATURITY - 1, false, 2),
        (COINBASE_MATURITY, false, 1),
        (COINBASE_MATURITY + 1, true, 0),
        (COINBASE_MATURITY + 2, true, 0),
    ];
    for (confirmations, mature, remaining) in cases {
        let u = coinstake_utxo("a", 1_000_000, confirmations);
        assert_eq!(u.is_mature(), mature, "depth {confirmations}");
        assert_eq!(u.blocks_until_mature(), remaining, "depth {confirmations}");
    }
}

/// PIVX Core, transcribed. Two separate rules govern this, and conflating them
/// is the mistake that costs either a rejected broadcast or stranded funds.
mod core_rules {
    /// `consensus.nCoinbaseMaturity`, mainnet (`chainparams.cpp`, `CMainParams`).
    /// Testnet is 15 and regtest 100, which is why this is worth pinning.
    pub const N_COINBASE_MATURITY: i64 = 100;

    /// The **consensus** rule (`validation.cpp`, `CheckInputs`). Applies to
    /// `IsCoinBase() || IsCoinStake()` alike:
    ///
    /// ```cpp
    /// if ((signed long)nSpendHeight - coin.nHeight < (signed long)consensus.nCoinbaseMaturity)
    ///     return state.Invalid(..., "bad-txns-premature-spend-of-coinbase-coinstake");
    /// ```
    ///
    /// A transaction mined at `spend_height` spending an output created at
    /// `coin_height` is valid when the difference reaches the constant.
    pub fn consensus_accepts(spend_height: i64, coin_height: i64) -> bool {
        spend_height - coin_height >= N_COINBASE_MATURITY
    }

    /// The **wallet** rule (`wallet.cpp`), deliberately one block stricter:
    ///
    /// ```cpp
    /// int CWalletTx::GetBlocksToMaturity() const {
    ///     if (!(IsCoinBase() || IsCoinStake())) return 0;
    ///     return std::max(0, (Params().GetConsensus().nCoinbaseMaturity + 1) - GetDepthInMainChain());
    /// }
    /// bool CWalletTx::IsInMainChainImmature() const {
    ///     ...
    ///     return (depth > 0 && depth <= Params().GetConsensus().nCoinbaseMaturity);
    /// }
    /// ```
    pub fn blocks_to_maturity(depth: i64) -> i64 {
        std::cmp::max(0, (N_COINBASE_MATURITY + 1) - depth)
    }

    pub fn wallet_says_immature(depth: i64) -> bool {
        depth > 0 && depth <= N_COINBASE_MATURITY
    }
}

/// Cross-check this crate against Core's own arithmetic across the whole
/// interesting range, rather than at a few hand-picked points.
///
/// A wallet must follow the *wallet* rule, not the consensus one. The two differ
/// at exactly one depth (100), where consensus would accept a spend but Core's
/// wallet still refuses to build it. Matching the stricter rule means this crate
/// can never emit a transaction rejected as a premature spend.
#[test]
fn matches_pivx_core_maturity_arithmetic() {
    assert_eq!(COINBASE_MATURITY as i64, core_rules::N_COINBASE_MATURITY);

    for depth in 1..=250u32 {
        let u = coinstake_utxo("a", 1_000_000, depth);
        let d = depth as i64;

        assert_eq!(
            u.is_mature(),
            !core_rules::wallet_says_immature(d),
            "depth {depth}: disagrees with Core's IsInMainChainImmature"
        );
        assert_eq!(
            u.blocks_until_mature() as i64,
            core_rules::blocks_to_maturity(d),
            "depth {depth}: disagrees with Core's GetBlocksToMaturity"
        );

        // Never looser than consensus. A transaction built now would land at
        // `spend_height = tip + 1`, and for an output `depth` deep that makes
        // `spend_height - coin_height == depth`.
        if u.is_mature() {
            assert!(
                core_rules::consensus_accepts(d, 0),
                "depth {depth}: would build a spend that consensus rejects"
            );
        }
    }
}

/// The single depth where the two rules disagree, called out on its own so the
/// deliberate one-block conservatism cannot be "fixed" by accident.
#[test]
fn is_one_block_stricter_than_consensus_at_the_boundary() {
    let at_100 = coinstake_utxo("a", 1_000_000, 100);
    assert!(core_rules::consensus_accepts(100, 0), "consensus would accept a spend at depth 100");
    assert!(!at_100.is_mature(), "but Core's wallet waits, and so do we");
    assert_eq!(at_100.blocks_until_mature(), 1);
}

/// Nothing but coinstake and coinbase outputs is ever held back, and the flag
/// defaults to off, so existing consumers are untouched.
#[test]
fn ordinary_outputs_are_never_immature() {
    let u = SerializedUTXO {
        txid: "a".repeat(64),
        vout: 0,
        amount: 1_000_000,
        script: String::new(),
        height: 5_000_000,
        // Deliberately zero confirmations: brand new, but not a coinstake.
        ..Default::default()
    };
    assert!(u.is_mature());
    assert_eq!(u.blocks_until_mature(), 0);
}

// ---------------------------------------------------------------------------
// Balances
// ---------------------------------------------------------------------------

/// An immature output is real but unspendable, so it belongs in neither the
/// spendable balance nor nowhere at all. It gets its own accessor.
#[test]
fn immature_value_is_reported_separately_from_spendable() {
    let w = wallet_with(vec![
        coinstake_utxo("a", 5_000_000, 5),                        // immature
        coinstake_utxo("b", 3_000_000, COINBASE_MATURITY + 1),    // mature
    ]);

    assert_eq!(w.get_transparent_balance(), 3_000_000, "immature must not read as spendable");
    assert_eq!(w.get_immature_balance(), 5_000_000);
}

/// A staked delegation is both delegated *and* immature. It is counted as
/// delegated (the coins are held) and as immature (they cannot move yet), and
/// in neither case as ordinary spendable balance.
#[test]
fn a_freshly_staked_delegation_counts_as_delegated_and_immature() {
    let w = wallet_with(vec![staked_delegation("a", 51_600_000_000, 19)]);

    assert_eq!(w.get_delegated_balance(), 51_600_000_000);
    assert_eq!(w.get_immature_balance(), 51_600_000_000);
    assert_eq!(w.get_transparent_balance(), 0);
}

// ---------------------------------------------------------------------------
// Builders: wallet-set paths filter, explicit-set paths error
// ---------------------------------------------------------------------------

/// Selecting from the wallet's own set skips immature outputs the way it skips
/// delegated ones, and says why when that leaves nothing.
#[test]
fn an_ordinary_send_will_not_select_an_immature_coinstake() {
    let mut w = wallet_with(vec![coinstake_utxo("a", 100_000_000, 5)]);
    let err = create_raw_transparent_transaction_to_many(
        &mut w,
        &seed(),
        &[Recipient { address: to_address(), amount: 1_000_000 }],
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("maturity"), "error should name the reason, got: {err}");
    assert!(err.contains("100000000"), "error should name the held amount, got: {err}");
}

/// Funding a delegation is a spend like any other, so the same rule applies.
/// Otherwise a user who just received a stake could build a delegation against
/// it and have the broadcast rejected.
#[test]
fn a_delegation_cannot_be_funded_from_an_immature_coinstake() {
    let mut w = wallet_with(vec![coinstake_utxo("a", 60_000_000_000, 5)]);
    let err = create_delegation_transaction(
        &mut w,
        &seed(),
        &pivx_wallet_kit::transparent::coldstake::encode_staking_address(&STAKER),
        50_000_000_000,
        ColdStakeVariant::Lof,
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("maturity"), "got: {err}");
}

/// When the caller names the exact inputs, an immature one is an error rather
/// than a silent drop, because the resulting transaction would not be what they asked
/// for. The message says how long the wait is, because unlike the delegated
/// case this one clears on its own.
#[test]
fn spending_a_named_immature_utxo_errors_with_the_wait() {
    let err = create_raw_transparent_transaction_from_utxos_to_many(
        &seed(),
        0,
        0,
        &[coinstake_utxo("a", 100_000_000, 90)],
        &[Recipient { address: to_address(), amount: 1_000_000 }],
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("not mature"), "got: {err}");
    assert!(err.contains("11 block(s)"), "should say 101 - 90 = 11 blocks left, got: {err}");
}

/// The case this whole guardrail exists for: withdrawing a delegation that was
/// staked moments ago. Without the check this builds a perfectly well-formed
/// transaction that the network then refuses.
#[test]
fn withdrawing_a_freshly_staked_delegation_errors_instead_of_building() {
    let err = create_coldstake_withdrawal(
        &seed(),
        0,
        0,
        &[staked_delegation("a", 51_600_000_000, 19)],
        &to_address(),
        1_000_000_000,
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("staked recently"), "got: {err}");
    assert!(err.contains("82 block(s)"), "should say 101 - 19 = 82 blocks left, got: {err}");
}

/// The same delegation, once matured, withdraws normally. Without this the test
/// above would pass just as well against a builder that rejected everything.
#[test]
fn the_same_delegation_withdraws_once_mature() {
    let tx = create_coldstake_withdrawal(
        &seed(),
        0,
        0,
        &[staked_delegation("a", 51_600_000_000, COINBASE_MATURITY + 1)],
        &to_address(),
        1_000_000_000,
    )
    .expect("a matured delegation must withdraw");

    assert!(!tx.txhex.is_empty());
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// The flags survive the explorer boundary, and their absence means "ordinary".
#[test]
fn parser_reads_maturity_fields_and_defaults_them_off() {
    let raw = vec![
        serde_json::json!({
            "txid": "a".repeat(64), "vout": 1, "value": "100", "height": 5_000_000,
            "coinstake": true, "confirmations": 19,
        }),
        // No flags at all: the shape every non-cold-staking consumer sends.
        serde_json::json!({
            "txid": "b".repeat(64), "vout": 0, "value": "100", "height": 5_000_000,
        }),
    ];

    let parsed = wallet::parse_blockbook_utxos(&raw);
    assert!(parsed[0].coinstake && !parsed[0].is_mature());
    assert_eq!(parsed[0].confirmations, 19);
    assert!(!parsed[1].coinstake && parsed[1].is_mature());
}

/// PIVX matures coinbase and coinstake outputs by the same rule
/// (`IsCoinBase() || IsCoinStake()` in `CheckInputs`), so a `coinbase` flag from
/// the explorer has to hold the output back too. Without this, a wallet
/// receiving mining or masternode rewards would treat them as spendable as soon
/// as they arrive, and build transactions the network rejects.
#[test]
fn parser_treats_a_coinbase_flag_as_maturity_bearing() {
    let raw = vec![
        // rusty-blox reports both keys; only one of them is ever set.
        serde_json::json!({
            "txid": "a".repeat(64), "vout": 0, "value": "100", "height": 5_000_000,
            "coinbase": true, "coinstake": false, "confirmations": 19,
        }),
        serde_json::json!({
            "txid": "b".repeat(64), "vout": 0, "value": "100", "height": 5_000_000,
            "coinbase": false, "coinstake": true, "confirmations": 19,
        }),
        serde_json::json!({
            "txid": "c".repeat(64), "vout": 0, "value": "100", "height": 5_000_000,
            "coinbase": false, "coinstake": false, "confirmations": 19,
        }),
    ];

    let parsed = wallet::parse_blockbook_utxos(&raw);
    assert!(!parsed[0].is_mature(), "a 19-confirmation coinbase is not spendable");
    assert!(!parsed[1].is_mature(), "a 19-confirmation coinstake is not spendable");
    assert!(parsed[2].is_mature(), "an ordinary output is spendable immediately");

    // Both fold into the one flag, which is why `SerializedUTXO` did not need a
    // second field for this.
    assert!(parsed[0].coinstake);

    // And it releases on the same boundary as a coinstake.
    let mature = wallet::parse_blockbook_utxos(&[serde_json::json!({
        "txid": "d".repeat(64), "vout": 0, "value": "100", "height": 5_000_000,
        "coinbase": true, "confirmations": 101,
    })]);
    assert!(mature[0].is_mature());
}

/// Wallets already sitting in someone's `localStorage` were serialized before
/// these fields existed. They must still load, and load as spendable, or an
/// upgrade would strand every existing user's balance behind a maturity wait
/// that never ends.
#[test]
fn a_wallet_serialized_before_maturity_existed_still_loads() {
    let mut w = wallet_with(vec![]);
    let json = serde_json::to_value(&w).unwrap();

    // Strip the fields back out, reproducing the old on-disk shape exactly.
    let mut old = json.clone();
    old["unspent_utxos"] = serde_json::json!([{
        "txid": "a".repeat(64),
        "vout": 0,
        "amount": 100_000_000u64,
        "script": "",
        "height": 5_000_000,
    }]);
    assert!(
        !old["unspent_utxos"][0].as_object().unwrap().contains_key("coinstake"),
        "the fixture must not carry the new fields"
    );

    w = serde_json::from_value(old).expect("an older wallet must still deserialize");
    assert_eq!(w.unspent_utxos.len(), 1);
    assert!(w.unspent_utxos[0].is_mature(), "an output with no flags must read as spendable");
    assert_eq!(w.get_transparent_balance(), 100_000_000);
    assert_eq!(w.get_immature_balance(), 0);
}

/// The explorer double-lists a confirming UTXO, once from its mempool view at 0
/// confirmations. Taking the lower reading would hold a matured output back for
/// another 100 blocks, so the deeper sighting has to win.
#[test]
fn dedupe_keeps_the_deeper_confirmation_count() {
    let txid = "a".repeat(64);
    for order in [[0u32, 150], [150, 0]] {
        let raw: Vec<serde_json::Value> = order
            .iter()
            .map(|c| {
                serde_json::json!({
                    "txid": txid, "vout": 1, "value": "100", "height": 5_000_000,
                    "coinstake": true, "confirmations": c,
                })
            })
            .collect();

        let parsed = wallet::parse_blockbook_utxos(&raw);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].confirmations, 150, "order {order:?}");
        assert!(parsed[0].is_mature(), "order {order:?}");
    }
}
