# PIVX Wallet Kit

[![CI](https://github.com/PIVX-Labs/pivx-wallet-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/PIVX-Labs/pivx-wallet-kit/actions/workflows/ci.yml)

Pure-Rust wallet primitives for [PIVX](https://pivx.org), with first-class Sapling shield support.

Designed as the shared core that powers PIVX wallet clients — native CLIs, MCP servers, desktop apps, and embeddable web wallets — from a single audited codebase.

## Why

Every PIVX wallet reinvents the same primitives: BIP39 seeds, BIP44 derivation, address encoding, transparent tx construction, Sapling note management, shielded tx building. Each reimplementation is a new surface for subtle bugs and divergent behaviour between clients.

PIVX Wallet Kit consolidates that core into one library:

- **No I/O, no network, no filesystem.** The kit is pure logic. Consumers provide block data, current heights, proving-parameter bytes, and their own encryption keys.
- **Native + WASM.** Compiles to x86_64, aarch64, and `wasm32-unknown-unknown`, so the same code runs in [`pivx-agent-kit`](https://github.com/PIVX-Labs/pivx-agent-kit) on a server and in a browser wallet with zero logic drift.
- **Sapling-native.** Built on the [`librustpivx`](https://github.com/Duddino/librustpivx) fork of the Zcash Sapling crates, with PIVX's v3 type 0 transaction format.

## Architecture

```
pivx-wallet-kit (pure Rust, cdylib + rlib)
        │
        ├── native → pivx-agent-kit (CLI + MCP server, HTTP, disk)
        │
        └── WASM   → embeddable web wallets
```

## Modules

| Module                          | Purpose                                                                    |
|---------------------------------|----------------------------------------------------------------------------|
| `params`                        | PIVX chain constants: coin type, prefixes, Sapling param SHA256 hashes     |
| `amount`                        | PIV amount parsing / formatting (exact integer, no float)                  |
| `checkpoints`                   | Embedded mainnet checkpoint data for fast initial sync                     |
| `keys`                          | BIP32/BIP44 derivation, Sapling ZIP32 keys, transparent address encoding   |
| `fees`                          | Component-based fee estimation for v3 and raw v1 transactions              |
| `wallet`                        | In-memory `WalletData`, (de)serialization, symmetric secret encryption, Blockbook UTXO parser |
| `sync`                          | Pure shield stream parser — bytes → block batches                          |
| `sapling::sync`                 | `handle_blocks`: decrypt notes, advance tree, extract nullifiers           |
| `sapling::tree`                 | Commitment tree root extraction and empty-tree helpers                     |
| `sapling::prover`               | SHA256-verified proving parameter loader (consumer supplies bytes)         |
| `sapling::builder`              | Shield → anything transaction builder                                      |
| `transparent::builder`          | `create_shielding_transaction` (t → shield) + `create_raw_transparent_transaction` (canonical entry — no prover needed for transparent dests) |
| `transparent::tx`               | Low-level varint helpers                                                   |
| `transparent::utxo`             | `Utxo` alias                                                               |
| `simd::hex`                     | SIMD-accelerated hex encoding (NEON/AVX2/SSE2/scalar)                      |
| `wasm` *(wasm32 only)*          | `#[wasm_bindgen]` exports + process-global Sapling prover cell             |

## Building

```bash
# Native (release)
cargo build --release

# WASM (wasm-pack)
wasm-pack build --release --target web

# Tests (includes real mainnet tx fixtures in tests/fixtures/)
cargo test
```

The native `rlib` is what downstream Rust consumers (e.g. `pivx-agent-kit`) depend on. The `wasm32-unknown-unknown` `cdylib` is the target for web wallets.

## How to use

### Native (Rust)

Add the kit to your `Cargo.toml`:

```toml
[dependencies]
pivx-wallet-kit = { git = "https://github.com/PIVX-Labs/pivx-wallet-kit" }
```

Then:

```rust
use pivx_wallet_kit::{wallet, sapling::builder, sapling::prover};

// Import from mnemonic — consumer fetches current height from its RPC source.
let current_height = fetch_from_rpc();
let mut w = wallet::import_wallet(&mnemonic, current_height)?;

// Derive addresses (no prover needed):
let shield      = pivx_wallet_kit::keys::get_default_address(&w.extfvk)?;
let transparent = pivx_wallet_kit::keys::get_transparent_address(&w.get_mnemonic().to_string())?;

// Build a pure transparent send (still no prover needed):
let tx = pivx_wallet_kit::transparent::builder::create_raw_transparent_transaction(
    &mut w, &w.get_bip39_seed(), &to_t_addr, amount_sat,
    0, None, // block_height / prover only used when destination is shield
)?;

// For anything touching Sapling, load the proving parameters once:
let prover = prover::verify_and_load_params(&output_bytes, &spend_bytes)?;

// Build a shield transaction — pure function, no I/O.
let tx = builder::create_shield_transaction(
    &mut w, to_address, amount, memo, block_height, &prover,
)?;

// Consumer broadcasts `tx.txhex` via whatever transport it chooses.
```

### Browser (WASM)

```bash
wasm-pack build --release --target web
```

produces a complete ES-module NPM package at `pkg/`. Import it like any other module:

```js
import init, {
  generate_mnemonic, import_wallet,
  derive_shield_address, derive_transparent_address,
  encrypt_wallet, decrypt_wallet,
  parse_blockbook_utxos, format_sat_to_piv,
} from './pkg/pivx_wallet_kit.js';

await init();

const mnemonic = generate_mnemonic();
const wallet   = import_wallet(mnemonic, 0);
const shield   = derive_shield_address(wallet.extfvk);
const transparent = derive_transparent_address(mnemonic);

// Before persisting the wallet, encrypt it with a key the consumer supplies:
const encrypted = encrypt_wallet(wallet, someKey32Bytes);
```

**See [`examples/web-wallet/`](examples/web-wallet/) for a full runnable demo** — one HTML file + ~100 lines of JS, hits a real PIVX explorer for transparent balance, and demonstrates the encrypt/decrypt round-trip a web wallet would run before writing to `localStorage`.

## Status

v0.1.0 — extraction from `pivx-agent-kit` complete. 36 integration tests passing against real PIVX mainnet transactions; all four tx directions (T↔T, T↔S, S↔T, S↔S) verified end-to-end on mainnet.

## License

MIT © JSKitty
