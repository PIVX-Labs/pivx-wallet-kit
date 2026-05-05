# PIVX Wallet Kit

[![CI](https://github.com/PIVX-Labs/pivx-wallet-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/PIVX-Labs/pivx-wallet-kit/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@pivx-labs/pivx-wallet-kit?color=cb3837&logo=npm)](https://www.npmjs.com/package/@pivx-labs/pivx-wallet-kit)

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
        └── WASM   → embeddable web wallets (npm @pivx-labs/pivx-wallet-kit)
```

## Modules

| Module                          | Purpose                                                                    |
|---------------------------------|----------------------------------------------------------------------------|
| `params`                        | PIVX chain constants: coin type, prefixes, Sapling param SHA256 hashes     |
| `amount`                        | PIV amount parsing / formatting (exact integer, no float)                  |
| `checkpoints`                   | Embedded mainnet checkpoint data for fast initial sync                     |
| `keys`                          | BIP32/BIP44 derivation, Sapling ZIP32 keys, transparent address encoding   |
| `messages`                      | PIVX Core-compatible message signing / verification                        |
| `fees`                          | Component-based fee estimation for v3 and raw v1 transactions              |
| `wallet`                        | In-memory `WalletData`, (de)serialization, symmetric secret encryption, Blockbook UTXO parser |
| `sync`                          | Pure shield stream parser — bytes → block batches                          |
| `sapling::sync`                 | `handle_blocks`: decrypt notes, advance tree, extract nullifiers           |
| `sapling::tree`                 | Commitment tree root extraction and empty-tree helpers                     |
| `sapling::prover`               | SHA256-verified proving parameter loader (consumer supplies bytes)         |
| `sapling::builder`              | Shield → anything transaction builder (`select_shield_notes` + `create_shield_transaction`) |
| `transparent::builder`          | `create_shielding_transaction` (t → shield) + `create_raw_transparent_transaction` (canonical entry — no prover needed for transparent dests) |
| `wasm` *(wasm32 only)*          | Class-style `Wallet` / `SaplingParams` / `Mnemonic` / `Fee` API for JS consumers |

## Building

```bash
# Native (release)
cargo build --release

# WASM (wasm-pack), bundler target for npm
wasm-pack build --release --target bundler --scope pivx-labs

# Tests (55 total: 14 unit + 2 messages + 39 integration with real
# mainnet tx fixtures)
cargo test
```

The native `rlib` is what downstream Rust consumers (e.g. `pivx-agent-kit`) depend on. The `wasm32-unknown-unknown` `cdylib` is the target for web wallets, distributed via npm as [`@pivx-labs/pivx-wallet-kit`](https://www.npmjs.com/package/@pivx-labs/pivx-wallet-kit).

## How to use

### Native (Rust)

Add the kit to your `Cargo.toml`:

```toml
[dependencies]
pivx-wallet-kit = { git = "https://github.com/PIVX-Labs/pivx-wallet-kit" }
```

```rust
use pivx_wallet_kit::{wallet, sapling, transparent, keys};

// Import from mnemonic — consumer fetches current height from its RPC source.
let current_height = fetch_from_rpc();
let mut w = wallet::import_wallet(&mnemonic, current_height)?;

// Derive addresses (no prover needed):
let shield      = keys::get_default_address(&w.extfvk)?;
let transparent = w.get_transparent_address()?;

// Sign an arbitrary message with the transparent key (PIVX Core-compatible).
let bip39_seed = w.get_bip39_seed()?;
let (_, _, privkey) = keys::transparent_key_from_bip39_seed(&bip39_seed, 0, 0)?;
let signature = pivx_wallet_kit::messages::sign_message(&privkey, "hello")?;

// Build a pure transparent send (still no prover needed):
let tx = transparent::builder::create_raw_transparent_transaction(
    &mut w, &bip39_seed, &to_t_addr, amount_sat,
    0, None, // block_height / prover only used when destination is shield
)?;

// For anything touching Sapling, load the proving parameters once:
let prover = sapling::prover::verify_and_load_params(&output_bytes, &spend_bytes)?;

// Build a shield transaction — pure function, no I/O.
let tx = sapling::builder::create_shield_transaction(
    &mut w, &to_address, amount, &memo, block_height, &prover,
)?;

// Consumer broadcasts `tx.txhex` via whatever transport it chooses.
```

### Browser (npm)

```bash
npm install @pivx-labs/pivx-wallet-kit
```

The package exports a class-style API. The seed and mnemonic stay on the WASM heap — JS only ever sees handles and serialized JSON.

```js
import init, {
  Wallet,
  SaplingParams,
  Mnemonic,
  Fee,
  parseBlockbookUtxos,
  parseShieldStream,
  formatSatToPiv,
} from '@pivx-labs/pivx-wallet-kit';

await init();

// Create or import a wallet. `currentHeight` picks the latest embedded
// checkpoint for fast initial sync.
const phrase = Mnemonic.generate(12);
const wallet = Wallet.fromMnemonic(phrase, currentHeight);

const shield      = wallet.shieldAddress();
const transparent = wallet.transparentAddress();

// Sync transparent UTXOs from any Blockbook explorer.
const raw = await fetch(`/api/v2/utxo/${transparent}`).then(r => r.json());
wallet.setUtxos(parseBlockbookUtxos(raw));
const transparentSat = wallet.transparentBalanceSat();

// Sync shield blocks from a PIVX Core compact-stream RPC.
const bytes = new Uint8Array(await (await fetch(streamURL)).arrayBuffer());
const blocks = parseShieldStream(bytes);
wallet.applyBlocks(blocks);
const shieldSat = wallet.shieldBalanceSat();

// Build a transparent → transparent tx (no prover required).
// Direct `u64` wasm-bindgen args take BigInt:
const tx = wallet.sendTransparentToTransparent(toAddress, 100_000n);

// Build a shield-source tx (load proving params once per session).
// `SendShieldOpts` is a tsify struct — its `u64` fields cross via
// serde_wasm_bindgen and take a regular number, NOT BigInt.
const params = new SaplingParams(outputParamsBytes, spendParamsBytes);
const shieldTx = wallet.sendShield({
  to_address: shieldAddress,
  amount_sat: 50000,
  memo: '',
  block_height: chainTip,
}, params);

// Consumer broadcasts `shieldTx.txhex` via whatever transport it chooses.

// Encrypt before persisting to localStorage / IndexedDB:
const encrypted = wallet.toSerializedEncrypted(passphraseDerivedKey32Bytes);
localStorage.setItem('wallet', encrypted);
```

**See [`examples/web-wallet/`](examples/web-wallet/) for a full runnable demo** — one HTML file + ~200 lines of JS, hits a real PIVX explorer for transparent balance, runs a real shield sync from mainnet, and demonstrates the encrypt → reload → unlock cycle a web wallet would run before writing to `localStorage`.

## Status

**v0.2.0** — class-style WASM API, full audit pass (3 rounds), end-to-end mainnet verification across all four send paths (T↔T, T↔S, S↔T, S↔S). Used in production by [`pivx-agent-kit`](https://github.com/PIVX-Labs/pivx-agent-kit) and [`pivx-tasks`](https://github.com/PIVX-Labs/pivx-tasks).

## License

MIT © JSKitty
