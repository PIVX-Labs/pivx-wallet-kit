# PIVX Wallet Kit — Web Wallet Demo

A tiny one-page demo showing how a browser wallet can use `pivx-wallet-kit` via WebAssembly:

- Generate / import a BIP39 mnemonic
- Derive shield and transparent addresses
- Fetch a transparent balance from an explorer (uses the kit's Blockbook parser)
- Encrypt and decrypt the wallet in-memory — same round-trip a real wallet would do before writing to `localStorage` or IndexedDB

No framework, no bundler, no server-side component. ~100 lines of JS, ~100 lines of HTML/CSS.

## Run it

From the repo root (**not** from inside `examples/web-wallet/` — the demo imports the WASM package from `../../pkg/`, so the server needs to see that path):

```bash
# 1. Build the WASM package (one-time, or after kit changes)
wasm-pack build --release --target web

# 2. Serve the repo root with any static HTTP server
python3 -m http.server 8080
# (or: npx serve .  /  php -S localhost:8080  /  any other)

# 3. Open http://localhost:8080/examples/web-wallet/ in a browser
```

If you prefer to host the demo standalone (e.g. on a static site), copy or symlink the repo-root `pkg/` directory into `examples/web-wallet/` and change the import paths in `app.js` from `../../pkg/…` to `./pkg/…`.

## What the code does

```js
import init, {
  generate_mnemonic, validate_mnemonic, import_wallet,
  derive_shield_address, derive_transparent_address,
  encrypt_wallet, decrypt_wallet,
  parse_blockbook_utxos, format_sat_to_piv,
} from '../../pkg/pivx_wallet_kit.js';

await init();                             // instantiate WebAssembly module

const mnemonic = generate_mnemonic();     // 24 words, OsRng via getrandom/js
const wallet   = import_wallet(mnemonic, 0); // 0 = use earliest checkpoint

const shield      = derive_shield_address(wallet.extfvk);        // ps1...
const transparent = derive_transparent_address(mnemonic);        // D...

// Parse explorer response:
const utxos = parse_blockbook_utxos(await fetchBlockbook(transparent));
const total = utxos.reduce((sum, u) => sum + BigInt(u.amount), 0n);

// Encrypt before persisting (wrong-key decrypt errors cleanly):
const key32 = new Uint8Array(await crypto.subtle.digest('SHA-256', passphrase));
const encrypted = encrypt_wallet(wallet, key32);
const restored  = decrypt_wallet(encrypted, key32);
```

## Not shown in this demo

- **Shield sync** — requires streaming compact blocks from a bridge and calling `handle_blocks` per batch; worth its own example.
- **Transaction building** — needs Sapling proving parameters loaded via `load_sapling_params(output_bytes, spend_bytes)` first. Add a "Send" button in your own fork, or see how the native [pivx-agent-kit](https://github.com/PIVX-Labs/pivx-agent-kit) drives the same API.
