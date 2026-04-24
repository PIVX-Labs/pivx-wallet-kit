# PIVX Wallet Kit

Pure-Rust wallet primitives for [PIVX](https://pivx.org), with first-class Sapling shield support.

Designed as the shared core that powers PIVX wallet clients — native CLIs, MCP servers, desktop apps, and embeddable web wallets — from a single audited codebase.

## Why

Every PIVX wallet reinvents the same primitives: BIP39 seeds, BIP44 derivation, address encoding, transparent tx construction, Sapling note management, shielded tx building. Each reimplementation is a new surface for subtle bugs and divergent behaviour between clients.

PIVX Wallet Kit consolidates that core into one library:

- **No I/O, no network, no filesystem.** The kit is pure logic. Consumers provide block data and handle persistence.
- **Native + WASM.** Compiles to x86_64, aarch64, and `wasm32-unknown-unknown`, so the same code runs in `pivx-agent-kit` on a server and in a browser wallet with no divergence.
- **Sapling-native.** Built on the [`librustpivx`](https://github.com/Duddino/librustpivx) fork of the Zcash Sapling crates, with PIVX's v3 type 0 transaction format.

## Status

Early scaffold. Extraction of wallet primitives from [`pivx-agent-kit`](https://github.com/PIVX-Labs/pivx-agent-kit) is in progress.

## Architecture

```
pivx-wallet-kit (pure Rust, cdylib + rlib)
        │
        ├── native → pivx-agent-kit (CLI + MCP server, HTTP, disk)
        │
        └── WASM   → embeddable web wallets
```

Modules:

| Module        | Purpose                                                   |
|---------------|-----------------------------------------------------------|
| `params`      | PIVX chain constants (coin type, prefixes, magic)        |
| `checkpoints` | Embedded mainnet checkpoint data for fast sync            |
| `keys`        | BIP32/BIP44 derivation, address generation, WIF           |
| `fees`        | Component-based fee estimation                            |
| `wallet`      | In-memory wallet state and serialization                  |
| `sync`        | Pure block → state delta transforms                       |
| `sapling`     | Sapling shield keys, notes, tree, tx building             |
| `transparent` | Transparent tx building and UTXO management               |
| `wasm`        | WASM bindings (browser / Node)                            |

## Building

```bash
# Native
cargo build --release

# WASM (wasm-pack)
wasm-pack build --release --target web
```

## License

MIT © JSKitty
