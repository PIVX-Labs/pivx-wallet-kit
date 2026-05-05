# pivx-wallet-kit v0.2 — class-style API design

## Scope

This document specifies the v0.2.0 wasm-facing API. Phase 4 of the
NPM-publish-readiness plan (see `AUDIT.md`'s 2026-05-05 status header)
implements this design. The native Rust `pub use` surface is largely
untouched — this is exclusively about how the kit looks from JS/TS
consumers.

## Summary

Replace the current ~28 free functions with:
1. A single `Wallet` class that owns the wallet state + secret material.
2. A `SaplingParams` class that owns the proving parameters.
3. A `Mnemonic` static namespace for BIP39 helpers.
4. A `Fee` static namespace for stateless fee math.
5. A handful of free utility functions for pure stateless ops that
   don't fit the namespaces above (parsers, formatters, address
   derivation from raw extfvk).

## Goals

- Eliminate the "forgot to overwrite `wallet`" footgun that today's
  `build_*_tx` returns force on every consumer.
- Stop shipping the mnemonic across the JS↔WASM boundary on every
  call. Mnemonic enters once via the constructor and lives in Rust.
- Stop the per-call `WalletData` JSON round-trip. With an opaque
  `Wallet` handle, mutations happen in place; serialization happens
  only when explicitly persisting.
- Make the consensus-format split (v1 P2PKH vs v3 Sapling) obvious in
  fee-estimation API names.
- Replace the global `OnceLock<SaplingProver>` with explicit
  per-instance `SaplingParams` so testnet / mainnet swaps are
  trivial.
- Make required-load-order compile-time enforced where possible
  (params must exist before `send_shield` can be called).

## Non-goals

- Native Rust API redesign. The native consumers (pivx-agent-kit,
  PIVX Tasks) still call `pivx_wallet_kit::wallet::*`,
  `pivx_wallet_kit::keys::*`, etc. directly. A few signatures shift
  in Phase 1 + 2 (M4, M5, M6, M7, M9, H4) — this phase doesn't
  introduce any further native breakages.
- Multi-address support. The hardcoded `(change=0, index=0)` stays;
  exposed via a single `wallet.transparent_address()` getter. Future
  v0.3 may add `wallet.transparent_address_at(change, index)`.
- Network selection. PIVX-only is hardcoded after H4 dropped the
  `coin_type` parameter.

## API surface

### `Wallet` class

```ts
class Wallet {
    // ─── Construction ────────────────────────────────────

    /// Create a brand-new wallet with a fresh BIP39 mnemonic.
    /// `current_height` is the chain tip at creation time, used to set
    /// the wallet's birthday so the kit can skip pre-birthday blocks
    /// during initial sync.
    static create(current_height: number): Wallet;

    /// Import from an existing BIP39 mnemonic. Validates the phrase.
    static fromMnemonic(mnemonic: string, current_height: number): Wallet;

    /// Restore from JSON produced by `toSerialized()`.
    /// If the JSON came from `toSerializedEncrypted()`, the returned
    /// wallet is in the LOCKED state — call `unlock(key)` before any
    /// send / sign operation.
    static fromSerialized(json: string): Wallet;

    // ─── Persistence ─────────────────────────────────────

    /// Plain JSON — for unencrypted persistence (testnet, throwaway).
    /// Production callers should use `toSerializedEncrypted` instead.
    toSerialized(): string;

    /// AES-CTR-encrypted JSON. The 32-byte `key` is the consumer's
    /// responsibility (typically derived from a passphrase via PBKDF2
    /// or KDF-of-choice).
    toSerializedEncrypted(key: Uint8Array): string;

    /// Decrypt a wallet that was loaded from `fromSerialized` of an
    /// encrypted blob. Errs cleanly on wrong key — wallet stays
    /// LOCKED, no partial state. Idempotent if already unlocked.
    unlock(key: Uint8Array): void;

    /// True if the wallet is currently usable (seed in plaintext).
    /// False after `fromSerialized` of an encrypted blob, before
    /// `unlock()`. Send / sign / address operations require unlocked.
    isUnlocked(): boolean;

    // ─── Lifecycle ───────────────────────────────────────

    /// Drop cached notes / UTXOs / commitment tree position back to
    /// the birthday checkpoint. Useful when re-scanning from scratch.
    /// The seed and viewing key are unchanged.
    resetToCheckpoint(): void;

    // ─── Read-only state ─────────────────────────────────

    shieldAddress(): string;            // ps1...
    transparentAddress(): string;       // D...

    shieldBalanceSat(): bigint;
    transparentBalanceSat(): bigint;
    totalBalanceSat(): bigint;          // shield + transparent

    lastBlock(): number;                // last block applied
    birthdayHeight(): number;           // checkpoint birthday

    notes(): SerializedNote[];          // unspent shield notes
    utxos(): SerializedUTXO[];          // unspent transparent UTXOs

    // ─── Sync ────────────────────────────────────────────

    /// Apply parsed shield blocks to the wallet — decrypts notes
    /// belonging to this wallet, advances the commitment tree,
    /// extracts nullifiers (potential spends of our notes).
    /// Returns the deltas; the wallet itself is also mutated in place.
    applyBlocks(blocks: ShieldBlock[]): HandleBlocksResult;

    /// Replace the wallet's transparent UTXO set in one shot
    /// (typical pattern: fetch from explorer, parse via
    /// `parseBlockbookUtxos`, replace).
    setUtxos(utxos: SerializedUTXO[]): void;

    /// Sign an arbitrary message with the wallet's transparent key
    /// at m/44'/119'/0'/0/0. Returns a base64 signature compatible
    /// with PIVX Core's `verifymessage` RPC.
    signMessage(message: string): string;

    // ─── Tx building ─────────────────────────────────────

    /// Build a shield-source transaction (notes → anywhere). Sapling
    /// proving params are required.
    sendShield(opts: SendShieldOpts): TransactionResult;

    /// Build a transparent-source transaction. Auto-detects the
    /// destination format: D... uses v1 P2PKH (no params needed),
    /// ps1... uses v3 (params required, set via `opts.saplingParams`).
    sendTransparent(opts: SendTransparentOpts): TransparentTransactionResult;

    // ─── Fee estimation ──────────────────────────────────

    /// Fee for `sendShield(amount)` against the current note set.
    /// Performs the same selection the real send would; errs if
    /// shield balance is insufficient.
    estimateSendShieldFee(amount_sat: bigint): bigint;

    /// Fee for `sendTransparent({to, amount})`. Auto-routes by
    /// destination prefix (v1 vs v3). Errs if transparent balance
    /// is insufficient.
    estimateSendTransparentFee(to_address: string, amount_sat: bigint): bigint;

    /// Mark spent notes / UTXOs after broadcasting a tx that this
    /// wallet built. (`send*` methods do this automatically; this
    /// helper exists for callers that broadcast externally.)
    finalizeShieldSpend(nullifiers: string[]): void;
    finalizeTransparentSpend(spent: SpentOutpoint[]): void;
}
```

### Send-method input shape

```ts
interface SendShieldOpts {
    to_address: string;
    amount_sat: bigint;
    memo: string;                  // shield-only; empty string for none
    block_height: number;          // chain tip + 1
    sapling_params: SaplingParams;
}

interface SendTransparentOpts {
    to_address: string;
    amount_sat: bigint;
    /// Required iff to_address is a shield address (ps1...).
    /// Optional otherwise.
    sapling_params?: SaplingParams;
    /// Required iff to_address is a shield address. Optional
    /// otherwise (v1 P2PKH path doesn't read it).
    block_height?: number;
}
```

The `?` markers are the tsify-generated shape. Rust internally validates
that `to_address` and the optional fields agree at the start of
`sendTransparent()`; misuse returns a clear error rather than a
mysterious failure deeper in the build path.

### `SaplingParams` class

```ts
class SaplingParams {
    /// Verify SHA256 hashes against the kit's pinned mainnet values
    /// and parse into proving keys. Pass the raw bytes from however
    /// you sourced them (CDN, IndexedDB cache, bundled asset).
    constructor(output_bytes: Uint8Array, spend_bytes: Uint8Array);
}
```

That's the entire public surface. `SaplingParams` is a black-box
handle; the consumer holds it and passes it where required.

### `Mnemonic` static namespace

```ts
class Mnemonic {
    /// Generate a fresh BIP39 phrase. `words` ∈ {12, 15, 18, 21, 24};
    /// defaults to 12 (PIVX Labs convention).
    static generate(words?: number): string;
    static validate(phrase: string): boolean;

    /// Get the 64-byte BIP39 seed. Niche — most consumers should
    /// not need this. Returned as `Uint8Array` and is the caller's
    /// responsibility to wipe.
    static toSeed(phrase: string): Uint8Array;
}
```

### `Fee` static namespace

```ts
class Fee {
    /// PIVX v3 (Sapling-bundle) tx fee. Use for any tx that touches
    /// shield: shield→shield, shield→transparent, transparent→shield.
    static shieldTx(
        transparent_inputs: bigint,
        transparent_outputs: bigint,
        sapling_inputs: bigint,
        sapling_outputs: bigint,
    ): bigint;

    /// PIVX v1 (raw P2PKH) tx fee. Use for pure transparent → transparent.
    static transparentTx(inputs: bigint, outputs: bigint): bigint;
}
```

### Free utility functions

```ts
/// Verify a PIVX Core-format base64 signature against an address.
function verifyMessage(address: string, message: string, signature_b64: string): boolean;

/// PIV-decimal ↔ satoshi.
function parsePivToSat(s: string): bigint;
function formatSatToPiv(sat: bigint): string;

/// Parse a binary shield stream (kit's wire format) into ShieldBlock[].
function parseShieldStream(bytes: Uint8Array, max_blocks?: number): ShieldBlock[];

/// Convert a Blockbook /api/v2/utxo response into SerializedUTXO[].
function parseBlockbookUtxos(raw: any): SerializedUTXO[];

/// Get the nearest mainnet checkpoint at or below `block_height`.
function getCheckpoint(block_height: number): Checkpoint;

/// Compute the byte-reversed Sapling root from a hex commitment tree.
function getSaplingRoot(tree_hex: string): string;
```

## Lifecycle: the encrypted-wallet round trip

```ts
// 1. New wallet. Lives in memory, plaintext.
const w = Wallet.fromMnemonic("word1 word2 ... word24", 5_000_000);

// 2. Persist encrypted.
const blob = w.toSerializedEncrypted(my_32_byte_key);
await idbStore.put("wallet", blob);

// 3. Some time later, restore. The wallet starts LOCKED — `unlock`
//    is the only operation the kit will accept until then.
const w2 = Wallet.fromSerialized(await idbStore.get("wallet"));
console.log(w2.isUnlocked());  // false
w2.unlock(my_32_byte_key);     // throws on wrong key, wallet stays LOCKED
console.log(w2.isUnlocked());  // true

// 4. Use it.
const tx = w2.sendTransparent({
    to_address: "Dxxxxx",
    amount_sat: 1_000_000_000n,
});
```

## Migration impact for our internal consumers

Both internal consumers stay on the **native Rust API**, not the wasm
class API. So Phase 4 doesn't directly break them, **but** they'll
benefit from:

- **agent-kit**: cleaner CLI internals if `core::send` etc. mirror
  the wasm class shape. Optional refactor; not in v0.2 critical path.
- **PIVX Tasks**: the message-signing path uses
  `kit_keys::transparent_key_from_bip39_seed` directly. No change.

Any future JS-based wallet (a web wallet, a browser-extension wallet,
a desktop Electron wallet) gets the new API straight off NPM with no
adjustment.

## Backwards compatibility

**There is none.** This is the v0.2.0 *first NPM release*. There are
no published consumers to break. Internal Rust consumers were updated
in Phase 1 + 2.

## Open design points (decide during implementation)

These came up during writing; pinning them now to revisit at code time:

1. **`Wallet.applyBlocks`** — should it return the new state delta
   only, or both delta + a list of caught nullifiers separately? The
   current `HandleBlocksResult` covers it; keep as-is.
2. **`Wallet.notes()` / `utxos()`** — return cloned `Vec<…>` or
   borrowed slices? Cloned is necessary for tsify; cost is the
   shape-passes-through-JsValue boundary. Acceptable for the
   "show me my unspents" UI use case which is read-only and
   infrequent.
3. **`isUnlocked()` mechanic** — internally, "locked" means the
   `seed`/`mnemonic` fields are still ciphertext. Methods that need
   them (`signMessage`, `sendShield`, `transparentAddress`, …) check
   and error early. Methods that DON'T (balances, last_block) work
   even on a locked wallet.
4. **`SaplingParams` lifetime** — held by JS, passed into `sendShield`
   on every call. JS is responsible for keeping a single instance
   alive across operations (rather than allocating per call). The
   class doesn't know how to hold itself, but a typical consumer
   keeps it on a top-level singleton.
5. **`block_height` for shield destinations** — the kit currently
   accepts any `u32`; passing a stale height is a footgun. Worth
   documenting that the caller MUST pass `chain_tip + 1`. Future
   versions could expose a `chainTipPlusOne()` helper that wraps a
   consumer-provided height-fetcher.

## Testing plan

- Add a wasm-bindgen-test integration test exercising the full happy
  path: `fromMnemonic` → `toSerializedEncrypted` → `fromSerialized` →
  `unlock` → `sendTransparent` → `applyBlocks` → balance.
- Lock-state tests: verify operations on a locked wallet error
  cleanly.
- Wrong-key test on `unlock`: wallet stays in the locked state, can
  retry.
- `Fee.shieldTx` and `Fee.transparentTx` numerical regression — pin
  the values for known input/output counts.
- `estimateSend*Fee` returns the same fee the corresponding `send*`
  method consumes.

## Appendix — what's NOT in v0.2

To keep the design tight, the following are explicitly deferred:

- **Multi-account / multi-address**. Wallet exposes one shield + one
  transparent address each, both at the index-0 derivation path.
- **Native Rust class wrapper**. The `Wallet` class is wasm-only;
  native callers continue to use `WalletData` + free functions
  directly.
- **Async block fetcher**. The kit stays I/O-free; consumers wire
  their own RPC.
- **Batch sends / multi-output sends**. The current builders
  build a single (destination + change) output pair. Multi-output
  is a v0.3+ addition.
- **Ledger / hardware-wallet support**. Out of scope; consumers
  who need it can take the kit's `WalletData` shape and substitute
  the signer.
