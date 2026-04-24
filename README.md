# PIVX Wallet Kit

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
| `checkpoints`                   | Embedded mainnet checkpoint data for fast initial sync                     |
| `keys`                          | BIP32/BIP44 derivation, Sapling ZIP32 keys, transparent address encoding   |
| `fees`                          | Component-based fee estimation for v3 and raw v1 transactions              |
| `wallet`                        | In-memory `WalletData`, (de)serialization, symmetric secret encryption    |
| `sync`                          | Pure shield stream parser — bytes → block batches                          |
| `sapling::sync`                 | `handle_blocks`: decrypt notes, advance tree, extract nullifiers           |
| `sapling::tree`                 | Commitment tree root extraction and comparison                             |
| `sapling::prover`               | SHA256-verified proving parameter loader (consumer supplies bytes)         |
| `sapling::builder`              | Shield → anything transaction builder                                      |
| `transparent::builder`          | v3 transparent builder (supports t → shield) + raw v1 P2PKH builder        |
| `transparent::tx`               | Low-level varint helpers                                                   |
| `transparent::utxo`             | `Utxo` alias                                                               |
| `simd::hex`                     | SIMD-accelerated hex encoding (NEON/AVX2/SSE2/scalar)                      |
| `wasm` *(wasm32 only)*          | `#[wasm_bindgen]` exports + thread-local Sapling prover cell              |

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

## Consumer example (native)

```rust
use pivx_wallet_kit::{wallet, sapling::builder, sapling::prover};

// Import from mnemonic — consumer fetches current height from its RPC source
let current_height = fetch_from_rpc();
let mut w = wallet::import_wallet(&mnemonic, current_height)?;

// Load Sapling proving parameters from disk / cache / embedded bytes
let prover = prover::verify_and_load_params(&output_bytes, &spend_bytes)?;

// Build a shield tx — pure function, no I/O
let tx = builder::create_shield_transaction(
    &mut w, to_address, amount, memo, block_height, &prover,
)?;
// Consumer broadcasts tx.txhex via whatever transport it chooses.
```

## Status

v0.1.0 — extraction from `pivx-agent-kit` complete. 24 integration tests passing against real PIVX mainnet transactions.

## License

MIT © JSKitty
