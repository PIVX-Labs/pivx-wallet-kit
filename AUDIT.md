# pivx-wallet-kit audit

## Executive summary

The extraction is broadly faithful — keys, fee math, shield parsing, and the raw P2PKH sighash logic all match the original almost line-for-line, and the integration test fixtures demonstrate the end-to-end parse path works on real mainnet txs. But there are three structural bugs that need fixing before this gets stamped as "v1": **(1) a zeroize regression in the agent-kit `clone_wallet_for_disk` shim that leaks raw seed bytes through an un-zeroized JSON round-trip**, **(2) `thread_local!` prover storage in `wasm.rs` is per-Web-Worker, so the `multicore` feature path will silently fail to find the prover on non-main workers**, and **(3) `handle_blocks` panics on any empty `tx_bytes` via `tx_bytes[0]`, and hardcodes `BlockHeight::from_u32(320)` for decryption regardless of the actual block height**. The kit also accidentally made `SaplingProver` mandatory for transparent-only v3 txs — a breaking API relative to the pre-extraction `Box::leak`-dummy-prover trick — which the shim papers over by always loading the prover and always fetching block height, regressing pure transparent sends from zero-RTT to two-RTT.

## Critical (fix before any real use)

### [B1] Seed bytes leak through an unzeroized JSON round-trip in `clone_wallet_for_disk`
File: `/Users/jskitty/Documents/Projects/pivx-agent-kit/src/wallet.rs:97-102`
```rust
fn clone_wallet_for_disk(data: &WalletData) -> WalletData {
    let json = serde_json::to_string(data).expect("WalletData serializes");
    serde_json::from_str(&json).expect("WalletData round-trips through JSON")
}
```
The original `save_wallet` built the disk clone field-by-field. The refactor replaces this with a `serde_json` round-trip. `serde_json::to_string(data)` produces a `String` containing the 32-byte seed serialized as `[102, 233, ...]` and the full mnemonic. That `String` is then copied into a second `WalletData` by `from_str`. Neither intermediate is wrapped in any zeroize guard, and `serde_json`'s internal allocations are not tagged for zeroize either. A process-memory dump taken any time between `save_wallet` entering and returning will contain the seed in plaintext. This is the precise failure mode `WalletData`'s `ZeroizeOnDrop` derive was supposed to prevent.

Fix: restore the original field-by-field clone approach. Because `WalletData` has `ZeroizeOnDrop` and shouldn't derive `Clone`, a private helper is fine:
```rust
fn clone_wallet_for_disk(data: &WalletData) -> WalletData {
    WalletData {
        version: data.version,
        seed: data.seed,                       // [u8; 32] is Copy
        extfvk: data.extfvk.clone(),
        birthday_height: data.birthday_height,
        last_block: data.last_block,
        commitment_tree: data.commitment_tree.clone(),
        unspent_notes: data.unspent_notes.clone(),
        mnemonic: data.mnemonic.clone(),
        unspent_utxos: data.unspent_utxos.clone(),
    }
}
```
This also avoids an O(tree-size) serialize/parse on every save. Since the fields are `pub(crate)` and the shim lives outside the kit, either expose a constructor (`pub fn clone_for_encryption(&self) -> Self`) on `WalletData` or make the sensitive fields `pub` to the kit's consumers. The former is better.

### [B2] `thread_local!` prover storage is per-Web-Worker under the `multicore` feature
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/wasm.rs:13-15, 157-161, 183-199`
```rust
thread_local! {
    static PROVER: RefCell<Option<SaplingProver>> = const { RefCell::new(None) };
}
```
With `wasm-bindgen-rayon` (gated behind `multicore`), rayon spawns Web Workers for the thread pool, each of which is an independent OS thread and therefore has its own `thread_local` storage. `load_sapling_params` runs on whichever thread the JS caller invokes it from (usually the main thread). When `build_shield_tx` is later scheduled onto a worker by rayon (e.g., because proof generation is the expensive part being parallelized), the worker's `PROVER` is `None`, and the build will fail with "Sapling prover not loaded". Single-threaded WASM is fine because there's only one JS thread.

Fix: swap `thread_local!` for `OnceLock` (or `Lazy` / a `static Mutex<Option<SaplingProver>>`). `SaplingProver` is `(OutputParameters, SpendParameters)` — both are `Send + Sync` in this codebase — so a process-global static is correct:
```rust
use std::sync::OnceLock;
static PROVER: OnceLock<SaplingProver> = OnceLock::new();

pub fn load_sapling_params(output_bytes: &[u8], spend_bytes: &[u8]) -> Result<(), JsError> {
    let prover = crate::sapling::prover::verify_and_load_params(output_bytes, spend_bytes)
        .map_err(to_js_err)?;
    PROVER.set(prover).map_err(|_| JsError::new("params already loaded"))?;
    Ok(())
}
```
The native agent-kit already uses exactly this pattern (`src/prover.rs:12`), so aligning the WASM side actually *reduces* divergence.

### [B3] `handle_blocks` panics on empty `tx_bytes` and hardcodes `BlockHeight::from_u32(320)`
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/sapling/sync.rs:118, 184-185`
```rust
let tx_nullifiers = if tx_bytes[0] == 0x04 {
```
`tx_bytes[0]` panics on any zero-length `txs` entry. `parse_next_blocks` can't produce one today (it rejects zero-length packets), but *consumers supplying their own blocks* can — and the kit's purity claim ("consumers supply block bytes") means this boundary is untrusted. One line lower, `handle_transaction` calls:
```rust
let decrypted_tx = decrypt_transaction(&MAIN_NETWORK, BlockHeight::from_u32(320), &tx, key_map);
```
The 320 appears to be a holdover from a placeholder. It's used by `zcash_client_backend::decrypt_transaction` to decide what ZIP-212 enforcement applies. For PIVX mainnet, Sapling activated well before block 320, so it happens to work today, but the correct value is `BlockHeight::from_u32(block_height)` (the parameter already being threaded through the function). This is a silent-correctness hazard that will surface when/if PIVX ever introduces a note-encryption upgrade tied to height.

Fix:
```rust
for tx_bytes in &block.txs {
    let tag = tx_bytes.first().copied().ok_or("empty tx bytes")?;
    let tx_nullifiers = if tag == 0x04 {
        handle_compact_transaction(..)
    } else {
        handle_transaction(.., block.height, ..)?    // add height param
    };
    ...
}

// in handle_transaction:
let decrypted_tx = decrypt_transaction(
    &MAIN_NETWORK, BlockHeight::from_u32(block_height), &tx, key_map,
);
```

### [B4] `Zip212Enforcement::Off` is always used for compact-tx decryption
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/sapling/sync.rs:300-302`
```rust
let domain = sapling::note_encryption::SaplingDomain::new(
    sapling::note_encryption::Zip212Enforcement::Off,
);
```
Compact-tx decryption hard-codes `Off`, whereas the full-tx path delegates to `decrypt_transaction` which picks the enforcement from the network+height. If the PIVX chain enables ZIP-212 in a future activation, this path will silently decrypt notes with incorrect enforcement (either missing notes we *should* receive because receivers were rejected, or, worse, accepting malformed notes). Flag as **critical** because it's a trust boundary: the kit silently chooses a security-relevant parameter.

Fix: select the enforcement from `MAIN_NETWORK` the same way the full-tx path does. Until PIVX has a defined activation, hardcoding `Off` must be documented with a comment pointing to the PIVX spec.

### [B5] Compact-tx output loop panics on slice misalignment from a crafted stream (latent)
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/sapling/sync.rs:251, 283-285`

Every individual access in `handle_compact_transaction` is bounds-checked, so no current panic. But combined with B3 (missing `first()` check in `handle_blocks`), the boundary hasn't been fully hardened against untrusted inputs. Add a Miri/fuzz test for `handle_compact_transaction` with random payloads as hardening, and consider fuzzing `handle_blocks` via `cargo-fuzz`.

## High (should fix soon)

### [H1] `create_transparent_transaction` now requires a Sapling prover even for transparent-only txs
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/transparent/builder.rs:172-181`
```rust
let prover_ref = if is_shield_dest {
    prover.ok_or("Shield destination requires a Sapling prover ...")?
} else {
    prover.ok_or("Sapling prover is required by the v3 builder even for transparent-only txs")?
};
```
This is a breaking behavioural change relative to the pre-extraction code, which used `Box::leak(Box::new(dummy_prover))` inside the `else` branch to satisfy librustpivx's builder lifetime requirements without asking the caller for a prover. The extraction removed the trick and shifted the burden to the caller. The agent-kit shim now papers over this by always calling `prover::ensure_prover_loaded()` on the transparent path (`src/shield.rs:59`), which means a transparent-only send from a fresh CLI now blocks on a 50+MB prover download instead of returning in sub-second as it used to.

Fix: reinstate the dummy-prover behavior inside the kit, gated on `is_shield_dest`. A cleaner option: leak a `OnceLock<SaplingProver>` populated from the Groth16 test vectors (128 bytes) so builds don't allocate per call:
```rust
static DUMMY_PROVER: OnceLock<SaplingProver> = OnceLock::new();
fn dummy_prover() -> &'static SaplingProver {
    DUMMY_PROVER.get_or_init(|| {
        let (o, s) = sapling::circuit::tiny_test_vectors(); // or equivalent
        (o, s)
    })
}
let prover_ref = if is_shield_dest {
    prover.ok_or("Shield destination requires a Sapling prover")?
} else {
    dummy_prover()
};
```
If no such cheap construction exists, at minimum document this as a breaking change in the kit's README and remove the misleading comment ("won't actually be invoked").

### [H2] `create_raw_transparent_transaction` shim always fetches block count, regressing zero-RTT transparent sends
File: `/Users/jskitty/Documents/Projects/pivx-agent-kit/src/shield.rs:78-97`
```rust
pub fn create_raw_transparent_transaction(..) -> Result<..> {
    let net = crate::network::PivxNetwork::new();
    let block_height = net.get_block_count().unwrap_or(0) + 1;
    let prover = if to_address.starts_with("ps") { ... } else { None };
    transparent_builder::create_raw_transparent_transaction(
        wallet, bip39_seed, to_address, amount, block_height, prover,
    )
}
```
The original `create_raw_transparent_transaction` only fetched `block_count` on the shield-destination branch — pure transparent→transparent sends never hit the network for a height. The refactored shim unconditionally fetches it, adding an RTT to every transparent send. Then it passes the height through `create_raw_transparent_transaction`, which only uses it on the shield-fallback path. Net effect: ~100-300ms regression per transparent send.

Fix: push the height fetch inside the shield branch:
```rust
let (block_height, prover) = if to_address.starts_with("ps") {
    let net = crate::network::PivxNetwork::new();
    let bh = net.get_block_count()? + 1;
    prover::ensure_prover_loaded()?;
    (bh, Some(prover::get_prover()?))
} else {
    (0, None)   // kit fn ignores these on the transparent branch
};
```
And document in the kit's `create_raw_transparent_transaction` that `block_height_for_shield` and `prover_for_shield` are only consumed when the destination is shield.

### [H3] Returning `JsValue` as tuple produces a JS array, not a named object
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/wasm.rs:201, 229, 256`
```rust
let encoded = serde_wasm_bindgen::to_value(&(&result_out, &w)).map_err(to_js_err)?;
```
`serde_wasm_bindgen::to_value` serializes a 2-tuple as a 2-element JS array. Consumers have to write `const [result, wallet] = await build_shield_tx(...)` — undocumented in the Rust doc comments. If a consumer writes `result.txhex`, they get `undefined` silently (JS arrays accept arbitrary property access).

Fix: define a proper return struct and export it:
```rust
#[derive(serde::Serialize)]
struct BuildTxResult<'a> {
    result: &'a TransactionResult,
    wallet: &'a WalletData,
}
...
let out = BuildTxResult { result: &result_out, wallet: &w };
serde_wasm_bindgen::to_value(&out).map_err(to_js_err)
```

### [H4] `spending_key_from_seed` accepts any `coin_type` but the kit is PIVX-only
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/keys.rs:27-35`
```rust
pub fn spending_key_from_seed(
    seed: &[u8; 32],
    coin_type: u32,
    account_index: u32,
) -> Result<ExtendedSpendingKey, Box<dyn Error>> { ... }
```
Everything else in the kit hardwires `PIVX_COIN_TYPE` and `MAIN_NETWORK`. A consumer who passes `coin_type = 0` (Bitcoin) or `coin_type = 1` (testnet-generic) will derive a spending key that's *valid* but semantically wrong — the kit then encodes it with PIVX's bech32 HRPs, producing a "ps…" address that is silently derived off the wrong path.

Fix: either drop the parameter (make it private and always `PIVX_COIN_TYPE`), or validate it against a small whitelist. If it's kept for future testnet support, accept a `Network` enum instead.

### [H5] `wallet.commitment_tree == "00"` check misses the real empty-tree marker `"000000"`
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/transparent/builder.rs:106`
```rust
if !wallet.commitment_tree.is_empty() && wallet.commitment_tree != "00" {
```
`checkpoints::MAINNET_CHECKPOINTS[0].1` is `"000000"`, not `"00"`. The check `!= "00"` never matches the genesis checkpoint. It works (returns the empty-tree root), but it's a misleading check that will definitely confuse future maintainers.

Fix: centralize an `is_empty_tree_hex(s: &str) -> bool { s.is_empty() || s == "00" || s == "000000" }` helper.

### [H6] `handle_blocks` clones every `SerializedNote.note` JSON value once per block batch
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/sapling/sync.rs:101-104, 62`

`from_serialized` does `serde_json::from_value(n.note.clone())`. Per-batch this is O(notes) allocations. Accept `Vec<SerializedNote>` instead of `&[SerializedNote]` and move the values.

### [H7] `handle_blocks` inner loop is O(n²) in witnesses (inherited)
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/sapling/sync.rs:194-203, 291-298`

For each output, every witness advances. O(outputs × witnesses). Inherited from pre-extraction code. At minimum, add a comment. Real solution: use `pivx_client_backend::scanning::scan_block` batched advancement.

### [H8] `parse_shield_stream` passes `usize::MAX` as `max_blocks`, enabling unbounded allocation
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/wasm.rs:113-124`

Multi-GB stream from malicious RPC → browser DoS.

Fix: take a `max_blocks` parameter (or cap internally).

### [H9] `Cargo.lock` is committed to the library crate
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/Cargo.lock`

Committed due to yanked `core2 = 0.3.3`. Either document why, or patch `core2` to a non-yanked source so the lock can be dropped.

## Medium (cleanup / hardening)

### [M1] `incrementalmerkletree = "0.7"` direct dep risks version skew with pivx_primitives
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/Cargo.toml:25`

Kit mixes `pivx_primitives::merkle_tree::read_commitment_tree` with direct `incrementalmerkletree` imports. Use `pivx_primitives::merkle_tree::{CommitmentTree, IncrementalWitness}` re-exports instead and drop the direct dep.

### [M2] `[patch.crates-io]` includes `orchard` but PIVX doesn't use it
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/Cargo.toml:56-60`

Patch is load-bearing for librustpivx's transitive orchard dep. Document this.

### [M3] `agent-kit/Cargo.toml` retains `sapling` as a direct dep that is no longer used
File: `/Users/jskitty/Documents/Projects/pivx-agent-kit/Cargo.toml:18`

Grep confirms no `use sapling` in agent-kit src/. Drop it.

### [M4] `get_bip39_seed()` panics on invalid mnemonic via `.expect(...)`
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/wallet.rs:116-120`

The invariant "stored mnemonic is valid" only holds post-`decrypt_secrets`. Change to `Result<Vec<u8>, Box<dyn Error>>` or document the precondition. Also wrap in `Zeroizing`.

### [M5] `TransparentTransactionResult.spent` is `Vec<(String, u32)>` — unnamed tuple
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/transparent/builder.rs:33-37`

Make it `Vec<SpentOutpoint>` with `{ txid, vout }` fields.

### [M6] `WalletData::derive_extsk` returns an encoded `String`, round-tripping on every send
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/wallet.rs:94-97`

Every shield send calls `decode_extsk(&wallet.derive_extsk()?)?`. Return `ExtendedSpendingKey` directly; add `derive_extsk_encoded()` separately.

### [M7] `SaplingProver = (OutputParameters, SpendParameters)` is an unnamed tuple type alias
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/sapling/prover.rs:15`

Make it a named struct with `.output` and `.spend` fields.

### [M8] Inner fee-estimation loop recomputes fee + parses all witnesses
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/sapling/builder.rs:100-126`

Parses witness for every note even when only 3 are needed. Restructure: select first, parse second.

### [M9] `transparent_key_from_bip39_seed` exposes 32-byte private key as unzeroized `Vec<u8>`
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/keys.rs:102-117`

Return `Zeroizing<Vec<u8>>` or `secp256k1::SecretKey` directly.

### [M10] `decrypt_secrets` decrypts-in-place before validation, leaving corrupted `WalletData` on wrong-key error
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/wallet.rs:269-286`

Decrypt into a scratch buffer, validate, then commit.

## Low (polish / style)

### [N1] `src/lib.rs` module-doc table omits sub-modules
Add `sapling::sync`, `sapling::builder` etc. to the doc table, or mark `simd` as `#[doc(hidden)]`.

### [N2] `sapling/notes.rs`, `sapling/keys.rs`, `sapling/tx.rs` are empty scaffolds
Fill them or remove from `mod.rs`. Speculative generality.

### [N3] `get_sapling_root` uses `.iter().rev().cloned().collect::<Vec<u8>>()` — allocation for a reverse
Simpler: `let mut reversed = root_bytes; reversed.reverse();`

### [N4] No disk round-trip test
Add encrypt → serialize → deserialize → decrypt path; would catch B1-style regressions.

### [N5] `hex_string_to_bytes` silently tolerates odd-length input and non-hex chars
Add `hex_string_to_bytes_checked` returning `Result`; add property tests.

### [N6] Inconsistent `Box<dyn Error>` vs a domain `KitError` type
For v0.2.0, consider `thiserror` + domain enum so consumers can match specific errors.

### [N7] `handle_blocks_processes_real_shield_tx_without_key` is a misleading test
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/tests/integration.rs:282-311`

Rename or tighten: assert `size_after - size_before == 2` (number of appended commitments).

### [N8] Stale/irrelevant helper `_use_incremental_witness`
File: `/Users/jskitty/Documents/Projects/pivx-wallet-kit/src/sapling/builder.rs:202-206`

Remove the dead stub.

### [N9] `let _ = PROVER.set(loaded);` in agent-kit silently ignores "already set"
File: `/Users/jskitty/Documents/Projects/pivx-agent-kit/src/prover.rs:46`

Convert to `.expect("prover should not be set twice")`.

## Non-issues (considered and cleared)

- **`u64` across the WASM boundary**: `wasm-bindgen =0.2.100` maps `u64` to JS `BigInt` automatically. Safe on Node ≥10.4 + all modern browsers.
- **`getrandom` with `js` feature**: Enabled correctly. `OsRng` flows through all WASM paths.
- **`secp256k1::Secp256k1::new()` per call**: Allocates fresh context. Not great (~1MB) but not a bug; `global-context` feature is enabled, use `SECP256K1` global as a future optimization.
- **`key_map.insert(AccountId::default(), key.clone())`**: Once per batch, not per tx. Acceptable.
- **SHA256-CTR `crypt` not AEAD**: `decrypt_secrets` validates via extfvk re-derivation. Attacker can't produce ciphertext decrypting to the correct seed without SHA256 pre-image. Acceptable at the designed trust boundary; document it.
- **`seed: pub(crate)`**: Kit is the boundary. Better than `pub` (invites misuse) and better than fully private with no getter.
- **`zeroize(skip)` on `extfvk`, `commitment_tree`, `unspent_notes`**: These are public-by-definition. Correct to skip.
- **`SpendableNote` not zeroize**: Intermediate sync state; only nullifier is secret-adjacent and flows back into `WalletData` which is zeroized.

## Dimension checklist

- Correctness: **ISSUES FOUND** — [B3] empty-slice panic, hardcoded 320; [B4] Zip212Enforcement::Off hazard; [H5] tree-empty check misses "000000"
- Testing: **ISSUES FOUND** — no disk-roundtrip test; no `get_sapling_root` known-value test; no fuzz/property tests for hex decode; [N7] misleading test assertions
- Style: **ISSUES FOUND** — [M5], [M7] unnamed tuples; [N2] empty scaffold modules; [N8] dead helper
- Documentation: **ISSUES FOUND** — [N1] module table incomplete; doc on `crypt` doesn't state trust model; [M4] invariant documented but not enforced
- Performance: **ISSUES FOUND** — [H2] agent-kit RTT regression; [H6] per-block clone; [H7] O(n²) witness advancement inherited; [M8] unnecessary witness parsing
- Safety: **ISSUES FOUND** — [B1] seed leak through JSON roundtrip; [B2] thread_local prover breaks under multicore; [H8] unbounded parse_shield_stream; [M9] privkey bytes not zeroized; [M10] decrypt_secrets leaves corrupted state on wrong-key error
