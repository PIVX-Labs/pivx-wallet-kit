# PIVX Wallet Kit: Web Wallet Demo

A tiny one-page demo showing how a browser wallet can use `pivx-wallet-kit` via WebAssembly:

- Generate / import a BIP39 mnemonic
- Derive shield and transparent addresses
- Fetch a transparent balance from an explorer, joining each UTXO's scriptPubKey on so cold-staking delegations are visible
- Run a real shield sync from mainnet and report the shield balance
- Encrypt and decrypt the wallet in-memory: same round-trip a real wallet would do before writing to `localStorage` or IndexedDB

No framework, no bundler, no server-side component. ~300 lines of JS, ~150 lines of HTML/CSS.

## Run it

From the repo root (**not** from inside `examples/web-wallet/`: the demo imports the WASM package from `../../pkg/`, so the server needs to see that path):

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
  Wallet, Mnemonic, parseBlockbookUtxos, parseShieldStream, formatSatToPiv,
} from '../../pkg/pivx_wallet_kit.js';

await init();                             // instantiate WebAssembly module

const phrase = Mnemonic.generate();       // OsRng via getrandom/js
const wallet = Wallet.fromMnemonic(phrase, currentHeight); // picks the nearest checkpoint

const shield      = wallet.shieldAddress();        // ps1...
const transparent = wallet.transparentAddress();   // D...

// Transparent balance. `fetchUtxos` in app.js joins each UTXO's scriptPubKey on
// from /api/v2/tx/{txid}, which the UTXO endpoint does not return and cold
// staking cannot work without.
wallet.setUtxos(parseBlockbookUtxos(await fetchUtxos(transparent)));
const piv = formatSatToPiv(wallet.transparentBalanceSat());

// Shield balance, from a compact block stream.
wallet.applyBlocks(parseShieldStream(bytes));
const shieldPiv = formatSatToPiv(wallet.shieldBalanceSat());

// Encrypt before persisting (wrong-key decrypt errors cleanly):
const key32 = new Uint8Array(await crypto.subtle.digest('SHA-256', passphrase));
const encrypted = wallet.toSerializedEncrypted(key32);
const restored  = Wallet.fromSerialized(encrypted);   // LOCKED until unlock(key32)
```

The seed and mnemonic stay on the WASM heap throughout; JS only ever holds a handle.

## Not shown in this demo

- **Transaction building**: transparent sends need no prover (`sendTransparentToTransparent`), but anything touching Sapling needs proving parameters loaded via `SaplingParams` first. Add a "Send" button in your own fork, or see how the native [pivx-agent-kit](https://github.com/PIVX-Labs/pivx-agent-kit) drives the same API.
- **Cold staking**: `delegateColdStake` / `withdrawColdStake` and friends. The UTXO fetching this demo does is the part those need most, since delegations are invisible without each output's script.
