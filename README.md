# PIVX Wallet Kit

[![CI](https://github.com/PIVX-Labs/pivx-wallet-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/PIVX-Labs/pivx-wallet-kit/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@pivx-labs/pivx-wallet-kit?color=cb3837&logo=npm)](https://www.npmjs.com/package/@pivx-labs/pivx-wallet-kit)

Pure-Rust wallet primitives for [PIVX](https://pivx.org), with first-class Sapling shield support.

Designed as the shared core that powers PIVX wallet clients (native CLIs, MCP servers, desktop apps, and embeddable web wallets) from a single audited codebase.

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
| `params`                        | PIVX chain constants: coin type, prefixes, coinbase maturity, Sapling param SHA256 hashes |
| `amount`                        | PIV amount parsing / formatting (exact integer, no float)                  |
| `checkpoints`                   | Embedded mainnet checkpoint data for fast initial sync                     |
| `keys`                          | BIP32/BIP44 derivation, Sapling ZIP32 keys, transparent address encoding   |
| `messages`                      | PIVX Core-compatible message signing / verification                        |
| `fees`                          | Component-based fee estimation for v3 and raw v1 transactions              |
| `wallet`                        | In-memory `WalletData`, (de)serialization, symmetric secret encryption, Blockbook UTXO parser |
| `sync`                          | Pure shield stream parser: bytes → block batches                          |
| `sapling::sync`                 | `handle_blocks`: decrypt notes, advance tree, extract nullifiers           |
| `sapling::tree`                 | Commitment tree root extraction and empty-tree helpers                     |
| `sapling::prover`               | SHA256-verified proving parameter loader (consumer supplies bytes)         |
| `sapling::builder`              | Shield → anything transaction builder (`select_shield_notes` + `create_shield_transaction`) |
| `transparent::builder`          | `create_shielding_transaction` (t → shield) + `create_raw_transparent_transaction` (canonical entry: no prover needed for transparent dests) |
| `transparent::coldstake`        | Pay-to-cold-staking: P2CS script build/parse, `S...` addresses, delegation and withdrawal builders |
| `wasm` *(wasm32 only)*          | Class-style `Wallet` / `SaplingParams` / `Mnemonic` / `Fee` API for JS consumers |

## Building

```bash
# Native (release)
cargo build --release

# WASM (wasm-pack), bundler target for npm
wasm-pack build --release --target bundler --scope pivx-labs

# Tests (281 total: 16 unit + 265 integration, many against real
# mainnet tx fixtures)
cargo test
```

The native `rlib` is what downstream Rust consumers (e.g. `pivx-agent-kit`) depend on. The `wasm32-unknown-unknown` `cdylib` is the target for web wallets, distributed via npm as [`@pivx-labs/pivx-wallet-kit`](https://www.npmjs.com/package/@pivx-labs/pivx-wallet-kit).

### Parallel proving (`multicore`)

Groth16 proving is single-threaded by default on every target. The `multicore` feature turns on
rayon-parallel proving in `bellman` and `sapling`:

```bash
# Native: parallelises the Groth16 FFT/multiexp across cores.
# Recommended for servers, CLIs, and anything else not running in a browser.
cargo build --release --features multicore
```

There is no downside to enabling it natively; it is off by default only so that the same default
build is safe on every target. Downstream Rust consumers that care about proving latency should
turn it on.

On `wasm32` the feature additionally pulls in `wasm-bindgen-rayon`, and needs real setup: a
nightly toolchain with `-Z build-std`, the `atomics` and `bulk-memory` target features, COOP/COEP
headers on the serving origin, and a call to `initThreadPool` before any proving. **Without all
of that, leave it off**: rayon in a threadless WASM build blocks forever waiting for worker
threads that can never be spawned. The default single-threaded build proves in ~6s in-browser,
which is slower than native but always returns.

## How to use

### Native (Rust)

Add the kit to your `Cargo.toml`:

```toml
[dependencies]
pivx-wallet-kit = { git = "https://github.com/PIVX-Labs/pivx-wallet-kit" }
```

```rust
use pivx_wallet_kit::{wallet, sapling, transparent, keys};

// Import from mnemonic: consumer fetches current height from its RPC source.
let current_height = fetch_from_rpc();
let mut w = wallet::import_wallet(&mnemonic, current_height)?;

// Derive addresses (no prover needed):
let shield      = keys::get_default_address(&w.extfvk)?;
let transparent = w.get_transparent_address()?;

// Rotate receive addresses. Shield diversifiers all share one spending key;
// transparent slots are separate keys, so see "Rotating transparent addresses".
let (used_index, invoice_shield) = keys::shield_address_at(&w.extfvk, next_index)?;
let invoice_transparent = keys::transparent_address_at(&w.get_bip39_seed()?, 0, next_index)?;

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

// Build a shield transaction: pure function, no I/O.
let tx = sapling::builder::create_shield_transaction(
    &mut w, &to_address, amount, &memo, block_height, &prover,
)?;

// Consumer broadcasts `tx.txhex` via whatever transport it chooses.
```

### Browser (npm)

```bash
npm install @pivx-labs/pivx-wallet-kit
```

The package exports a class-style API. The seed and mnemonic stay on the WASM heap: JS only ever sees handles and serialized JSON.

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

// A fresh receive address per invoice. Shield rotation is free; transparent
// rotation needs per-slot ingest and spending, see "Rotating transparent
// addresses" below.
// `usedIndex` may be past `nextIndex`: invalid diversifiers are skipped.
const { index: usedIndex, address: invoiceShield } = wallet.shieldAddressAt(nextIndex);
const invoiceTransparent = wallet.transparentAddressAt(0, nextIndex);

// Sync transparent UTXOs from any Blockbook explorer. Cold staking needs one
// more call per funding tx; see "Cold staking needs scripts" below.
const raw = await fetch(`/api/v2/utxo/${transparent}`).then(r => r.json());
wallet.setUtxos(parseBlockbookUtxos(raw));
const transparentSat = wallet.transparentBalanceSat();

// Sync shield blocks from a PIVX Core `getshielddata` RPC. Fetch the whole
// range in one request: parsing a partial stream is fine, but splitting the
// *fetch* cuts blocks in half. There is no `format` parameter worth passing,
// the node serves one framing regardless.
const bytes = new Uint8Array(await (await fetch(streamURL)).arrayBuffer());
const blocks = parseShieldStream(bytes);
wallet.applyBlocks(blocks);
const shieldSat = wallet.shieldBalanceSat();

// Build a transparent → transparent tx (no prover required).
const tx = wallet.sendTransparentToTransparent(toAddress, 100_000n);

// Pay several transparent recipients from one transaction. Recipients are
// paid in order; any remainder returns to the wallet as change. `amount`
// is the recipient total, excluding change and fee.
const split = wallet.sendTransparentToMany({ recipients: [
  { address: sellerAddress,   amount: 95_000_000n },
  { address: referrerAddress, amount:  5_000_000n },
]});

// Build a shield-source tx (load proving params once per session).
const params = new SaplingParams(outputParamsBytes, spendParamsBytes);
const shieldTx = wallet.sendShield({
  to_address: shieldAddress,
  amount_sat: 50000,
  memo: '',
  block_height: chainTip,
}, params);

// Pay several recipients from shield notes. Unlike the transparent
// multi-send, shield and transparent destinations can be mixed in one
// transaction, and each shield recipient can carry its own memo.
const shieldSplit = wallet.sendShieldToMany({ recipients: [
  { address: shieldAddress,      amount: 95_000_000n, memo: 'invoice 41' },
  { address: transparentAddress, amount:  5_000_000n },
]}, chainTip + 1, params);

// Cold staking. The staking address may stake the coins but never move them;
// this wallet keeps spending authority, so the delegation can be withdrawn.
// Amounts at or above 500 PIV are split into staking-sized outputs.
const delegation = wallet.delegateColdStake(stakingAddress, 200_000_000n);

// Withdraw part of a delegation and keep the remainder staked. Without the
// staking address, change comes back as an ordinary output and stops staking.
const partial = wallet.withdrawColdStakeKeepingRest(
  0, 0, { utxos: delegatedUtxos }, myAddress, 400_000_000n, stakingAddress);

// Identify delegated outputs. Needs the script, which the UTXO endpoint does
// not return; see "Cold staking needs scripts" below.
const info = Wallet.inspectColdStakeScript(scriptHex);
// { isColdStake, isLof, stakingAddress, ownerAddress }

// Consumer broadcasts `shieldTx.txhex` via whatever transport it chooses.

// Encrypt before persisting to localStorage / IndexedDB:
const encrypted = wallet.toSerializedEncrypted(passphraseDerivedKey32Bytes);
localStorage.setItem('wallet', encrypted);
```

**See [`examples/web-wallet/`](examples/web-wallet/) for a full runnable demo**: one HTML file + ~200 lines of JS, hits a real PIVX explorer for transparent balance, runs a real shield sync from mainnet, and demonstrates the encrypt → reload → unlock cycle a web wallet would run before writing to `localStorage`.

### Cold staking needs scripts

A delegation is recognisable *only* from its `scriptPubKey`, and no explorer returns one from its UTXO endpoint: not Blockbook, not its work-alikes such as [rusty-blox](https://github.com/Liquid369/rusty-blox). Nothing else about a delegated output distinguishes it from an ordinary one, and the sighash commits to the exact script, so it cannot be inferred either.

Skip this and there is no error, just wrong answers: `delegatedBalanceSat()` reads 0, delegated outputs are counted as spendable and can be picked for an ordinary send that the network then rejects, and `withdrawColdStake` has nothing to sign against. Wallets that never delegate are unaffected.

The script comes from a second call. `/api/v2/tx/{txid}` returns `vout[n].hex`, the scriptPubKey of outpoint `(txid, n)`. Join it on before parsing:

```js
const utxos = await fetch(`/api/v2/utxo/${transparent}`).then(r => r.json());

// One fetch per distinct funding tx, not per UTXO, and bound the concurrency.
// A delegation that has been staking a while has one output per stake, so this
// list reaches the hundreds; see `mapWithLimit` in examples/web-wallet.
const txids = [...new Set(utxos.map(u => u.txid))];
const txs = await mapWithLimit(txids, 6, id =>
  fetch(`/api/v2/tx/${id}`).then(r => r.json()));

const scripts = new Map();
for (const tx of txs) for (const o of tx.vout) scripts.set(`${tx.txid}:${o.n}`, o.hex);

wallet.setUtxos(parseBlockbookUtxos(
  utxos.map(u => ({ ...u, script: scripts.get(`${u.txid}:${u.vout}`) ?? '' })),
));

wallet.delegatedBalanceSat(); // now non-zero if anything is delegated
```

`parseBlockbookUtxos` reads the script from `script`, `scriptPubKey` (flat or Core's nested verbose-RPC object) or `hex`, so copy it across under whichever name is handiest. Anything that is not valid even-length hex is treated as absent.

`/api/v2/address/{addr}?details=txs` is the bulk alternative: it returns the same `vout[].hex` for every transaction touching the address, in one paged call.

#### Staked delegations are coinstake outputs

Staking a delegation **consumes and recreates it**. The script is preserved byte-for-byte (consensus requires it, so the delegation keeps working and `is_p2cs` keeps matching), but the outpoint changes on every stake and the replacement lives in a *coinstake* transaction. Two consequences:

- **The outpoint churns.** Refresh the UTXO set immediately before building a withdrawal and treat a missing-inputs rejection as "re-fetch and rebuild". A set cached for an hour may already be stale.
- **The new output is immature.** PIVX applies `COINBASE_MATURITY` to coinstake outputs, so it takes 101 confirmations to become spendable. Explorers list it as an ordinary UTXO well before then: on mainnet a live delegation showed up in `/api/v2/utxo` with 19 confirmations, indistinguishable in that response from a spendable one.

The kit enforces this, but it can only do so with information you supply: it performs no I/O, so it cannot see confirmations or transaction types for itself. Set `coinstake` and `confirmations` on each UTXO and every builder respects them. Both default to "ordinary, spendable", so a consumer that leaves them unset sees exactly the pre-0.4.0 behaviour.

> **You may already be populating them without meaning to.** `parseBlockbookUtxos` reads `coinstake` and `confirmations` straight off each entry, so any explorer whose UTXO endpoint returns those keys switches maturity enforcement on with no code change on your side. Blockbook proper returns neither. [rusty-blox](https://github.com/Liquid369/rusty-blox) returns both, and a live `/utxo` entry looks like this:
>
> ```json
> {"txid":"7ee7ab26…","vout":1,"value":"81127555556","confirmations":364,
>  "height":5531321,"coinbase":false,"coinstake":true,"spendable":true}
> ```
>
> That is the correct outcome, not a surprise to work around: those coins genuinely cannot be spent yet. But it lands on the *ordinary send* path, not just the cold-staking one, so check the "send max" note below before shipping.
>
> `coinbase` is read as well, and folds into the same flag: PIVX matures coinbase and coinstake outputs by the identical rule, so mining and masternode rewards are held back too. A `spendable` field is ignored, because the kit reaches its own verdict from the other two.

Detect a coinstake from the same tx responses the script join already fetched. Do this when your explorer does not report `coinstake` itself:

```js
// PIVX marks a coinstake with an empty zero-value first output, and unlike a
// coinbase it always spends a real input.
const isCoinstakeTx = tx =>
  tx.vout.length >= 2 && tx.vout[0].value === '0' && !!tx.vin?.[0]?.txid;

// `txs` is from the join above, so this costs no extra requests.
const coinstakeTxids = new Set(txs.filter(isCoinstakeTx).map(tx => tx.txid));

wallet.setUtxos(parseBlockbookUtxos(utxos.map(u => ({
  ...u,
  script: scripts.get(`${u.txid}:${u.vout}`) ?? '',
  coinstake: coinstakeTxids.has(u.txid),
  confirmations: u.confirmations,   // explorers return this already
}))));

wallet.transparentBalanceSat();  // spendable now
wallet.immatureBalanceSat();     // exists, but not yet spendable
wallet.delegatedBalanceSat();    // delegated, mature or not
```

With that in place a builder will not select an immature output, and naming one explicitly is an error that says how long the wait is:

```
UTXO abc…:1 was created by a coinstake 19 block(s) ago and needs 101.
It was staked recently, so it becomes withdrawable in 82 block(s)
```

101 confirmations, not 100, throughout: `COINBASE_MATURITY` is 100, and the kit follows Core's *wallet* rule (`depth > nCoinbaseMaturity`) rather than the looser consensus one, so an output is spendable once its depth **exceeds** the constant. Both rules are transcribed in `params.rs` and checked against Core's arithmetic in `tests/coinstake_maturity.rs`.

> **Testing on testnet:** `COINBASE_MATURITY` is a mainnet constant, like everything else in `params`. Testnet's own `nCoinbaseMaturity` is 15, so between 16 and 101 confirmations the kit will hold back outputs that testnet itself would let you spend. That is over-strict rather than unsafe, and it is the right behaviour for the mainnet target, but do not read it as a bug when a testnet reward stays immature far longer than the chain says it should. It does make the "send max" interaction easy to reproduce there, since nearly every recent staking reward will read as immature.

Balance semantics are worth stating precisely, because the three overlap:

| accessor | includes |
|---|---|
| `transparentBalanceSat` | ordinary outputs at HD slot `0/0` (or untagged), mature only: what a plain send can spend right now |
| `delegatedBalanceSat` | every P2CS output, mature or not: what is committed to staking |
| `immatureBalanceSat` | every coinstake/coinbase output below maturity, delegated or not |
| `rotatedBalanceSat` | every output tagged to an HD slot other than `0/0`: see [Rotating transparent addresses](#rotating-transparent-addresses) |

A freshly staked delegation appears in both `delegatedBalanceSat` and `immatureBalanceSat`, and in neither `transparentBalanceSat`. That is deliberate: one answers "what do I hold", the other "what is still landing". `rotatedBalanceSat` is 0 unless you rotate transparent addresses.

### Rotating transparent addresses

`transparentAddressAt(change, index)` derives the address at `m/44'/119'/0'/change/index`; `transparentAddress()` is the `(0, 0)` case. Use it for one address per invoice, per customer, or per anything else you want to keep unlinked on-chain.

The two rotation stories look alike and are not:

```js
const { address } = wallet.shieldAddressAt(nextIndex);  // one key behind all of them
const t = wallet.transparentAddressAt(0, nextIndex);    // a separate key each
```

Every Sapling address a wallet issues decrypts to the same spending key, so `shieldAddressAt` costs nothing: sync, balance and spending are unchanged no matter how many you hand out. Transparent slots are independent keys, which puts three things on you:

**Discovery is yours.** Nothing in the kit scans for transparent outputs. Query the explorer once per address and keep your own cursor and gap limit.

**Tag what you ingest.** A P2PKH UTXO carries no record of which address received it, so the kit cannot tell one slot's outputs from another's unless you say. Pass the slot to `parseBlockbookUtxos`:

```js
const addr = wallet.transparentAddressAt(0, invoice.slot);
const raw  = await fetch(`/api/v2/utxo/${addr}`).then(r => r.json());
const { utxos } = parseBlockbookUtxos(raw, { change: 0, index: invoice.slot });
```

**Spend one slot at a time.** `sendTransparentFromUtxos(fromChange, fromIndex, …)` derives one key and signs every input with it, paying change back to that same address. A set spanning two slots cannot become one valid transaction, so build one per slot.

The tag is what makes the mistake loud instead of silent. Every wallet-state builder (`sendTransparentToTransparent`, `sendTransparentToMany`, `sendTransparentToShield`, `delegateColdStake`) signs with the `0/0` key, so a rotated output handed to one of them would be signed against the wrong script: a well-formed transaction whose signature satisfies no input, rejected at broadcast with nothing to point at. Tagged outputs are excluded from those builders' selection and surface in `rotatedBalanceSat` instead, and `sendTransparentFromUtxos*` rejects any input that disagrees with the slot it was asked to sign for:

```
UTXO abc…:0 was received at HD slot 0/9, but this send signs with the key at
0/5 (D…). Build one transaction per slot, or drop the hdSlot tag if the
outputs are not actually slot-specific
```

If you joined scripts on for cold staking, the same check runs against the `scriptPubKey` too, which catches a mis-tagged input as readily as an untagged one.

Untagged UTXOs are unaffected: no tag means "unknown", never "not this slot", so everything written before `hdSlot` existed behaves exactly as it did, including consumers already rotating by tracking slots outside the kit.

#### Cold staking is `0/0`-only on the delegating side

The two halves of cold staking are not symmetric about the slot, and rotation is what makes the difference reachable:

| | slot |
|---|---|
| `delegateColdStake` | funds from `0/0`, and writes `0/0` into the script as the owner |
| `withdrawColdStake` / `withdrawColdStakeKeepingRest` | take `fromChange` / `fromIndex`, and can redeem a delegation owned by any slot |

So anything the kit delegates is withdrawn with `(0, 0)`, and the withdrawal builders are the more general half because they also have to handle delegations this kit did not create. A P2CS output is indexed under its *owner's* address, so a rotating consumer querying the `0/0` address is the one who sees it, tags it `0/0`, and hands it back to a `(0, 0)` withdrawal. That round trip is consistent.

Two things to know before rotating:

**Delegating to your own rotated staking address does not move ownership.** `delegateColdStake(wallet.stakingAddressAt(0, 5), …)` builds a delegation staked by `0/5` and owned by `0/0`. It is a valid delegation and the coins stay under your control, but if you read that call as "self-stake at slot 5" you will look for the funds under `0/5` and not find them. Withdraw it at `(0, 0)`.

**Rotated coins cannot fund a delegation.** There is no `delegateColdStakeFromUtxos`. Adding one would mean parameterising the owner slot as well as the funding slot, since the owner hash is baked into the P2CS script, and that is a larger change than this one. For now, move the coins to `0/0` first. Before the slot tag existed this case silently built a transaction signing `0/5`'s output with `0/0`'s key; now it is refused up front and says so:

```
No spendable transparent UTXOs available to fund a delegation: 900000000 sat sits at
HD slots other than 0/0. A delegation is always funded from, and owned by, the key at
0/0, so move the coins there first with sendTransparentFromUtxos before delegating
```

Withdrawals are unaffected in both directions. Change from a withdrawal at `0/5` returns to `0/5` rather than consolidating onto `0/0`, and re-delegated change (`withdrawColdStakeKeepingRest`) keeps the owner it came from. Those paths validate against the P2CS script's own owner hash rather than the `hdSlot` tag, which is stronger and independent of your bookkeeping: name the wrong slot and the error tells you which address actually owns the output.

`change` and `index` are BIP32 non-hardened child numbers and stop at `2147483647`; past that, move to the next `change` level. Unlike `shieldAddressAt` there are no invalid indices to skip, so a slot's address is always exactly the one you asked for.

#### Drive "send max" from `transparentBalanceSat`, not your own sum

`transparentBalanceSat` is filtered by exactly the rule the builders select on, so it is the ceiling a send can reach. Deriving that ceiling any other way puts your UI and the kit into disagreement, and the disagreement runs the wrong way:

```js
// Wrong: counts delegated and immature outputs no builder will select.
const max = utxos.reduce((a, u) => a + Number(u.value), 0) - fee;
```

That overshoots by whatever is delegated or still maturing, so the UI offers an amount and the kit then refuses it with `No spendable transparent UTXOs: … sat is in coinstake outputs that have not reached maturity yet`. A wallet with no delegations and no staking history sees the two agree, which is why this survives testing and then fires on the first staker who presses **Max**. Any balance shown next to a send field should come from the same accessor, for the same reason.

Do not subtract a fee from `transparentBalanceSat` yourself either. The fee depends on how many inputs selection reaches for, so the amount and the fee are mutually dependent, and solving that by hand is a reliable source of off-by-one errors. Ask for the figure instead:

```js
const max = wallet.maxSendableSat(destination);
if (max === 0n) {
  // Nothing sendable: no spendable UTXOs, or what survives the fee is dust.
  // Disable the control rather than offering an amount that will be refused.
} else {
  amountField.value = formatSatToPiv(max);
}
```

`maxSendableSat` runs the same UTXO filter and the same fee model the builder will, so the figure it returns is always buildable and leaves exactly zero change. It routes on the destination prefix, pricing a `ps1…` address as a shielding transaction. `maxSendableSatToMany(recipientCount)` is the multi-recipient form: split its result however you like, as long as the parts sum to it and each clears the 5460 sat dust threshold.

| you want | call |
|---|---|
| the balance to display | `transparentBalanceSat()` |
| the most a send can pay | `maxSendableSat(destination)` |
| the most a *shield* send can pay | `maxShieldSpendableSat(destination)` |
| the fee for a specific amount | `estimateSendTransparentFee(destination, amount)` |
| the fee actually paid | `result.fee`, after the send |

Every row except the shield one applies the same filter (delegated, immature, and outputs tagged to another HD slot), so they agree with each other and with the builder. `result.fee` can exceed the estimate when dust change is absorbed into it, and is the number the user really paid.

**`maxSendableSat` never spends notes.** Both of its branches read transparent UTXOs: a `ps1…` destination prices a *shielding* send (transparent in, shield out), which is a different transaction from spending your shield balance. For that, use `maxShieldSpendableSat(destination)`, which computes from `unspentNotes` under the same fee model and output-shape rule the shield builder uses. It routes on the destination too, since a transparent recipient costs a transparent output and a shield one costs a Sapling output, and `maxShieldSpendableSatToMany(transparentCount, shieldCount)` is the multi-recipient form.

The shield figure is buildable but not razor-sharp: the fee shape charges for a change note the max send does not emit, so it under-states by one Sapling output (~0.00948 PIV at the modelled rate). That is deliberate, and the same direction `maxSendableSat` errs in. Solving it exactly by hand is not worth attempting, because the fee grows with the number of notes selection reaches for, so the amount and the fee are mutually dependent.

## Status

**v0.4.0**: **cold staking**, plus dust handling that was missing crate-wide.

Delegate transparent funds to a staking key that can stake them but never move them,
and withdraw them again: `delegateColdStake`, `withdrawColdStake`,
`withdrawColdStakeKeepingRest`, `stakingAddress` / `stakingAddressAt`,
`inspectColdStakeScript`, and matching fee estimators. Delegations at or above 500 PIV
are split into staking-sized outputs, matching MyPIVXWallet's `stakeSplitTarget`:
staking works per output, so one large delegation is a single staking unit where several
compete independently.

Every script constant was verified byte-for-byte against both PIVX Core and
MyPIVXWallet rather than reconstructed, and the delegate → withdraw cycle is confirmed
on mainnet (blocks 5522082 and 5522083). A wrong P2CS script does not fail loudly: it
produces an output that is either unspendable or spendable by the wrong party.

**Staked delegations are handled too**, which is the state a delegation spends almost
all of its life in: staking consumes the delegation and recreates it inside a coinstake
transaction, immature until it is 101 confirmations deep. Populate `coinstake` and `confirmations` on each
UTXO and no builder will select one before it matures, with `immatureBalanceSat` for what
is being held back. Coinbase outputs (mining and masternode rewards) mature by the same
rule and are covered by the same flag. `parseBlockbookUtxos` fills all of this in by
itself when the explorer reports it, which rusty-blox does, so the enforcement can arrive
unrequested: see [Staked delegations are coinstake
outputs](#staked-delegations-are-coinstake-outputs). The rule is checked against Core's
own consensus and wallet arithmetic in `tests/coinstake_maturity.rs`; it has not yet been
observed against a live node, since a mainnet stake can take weeks to arrive.

**`maxSendableSat` answers "how much can I send".** A wallet that works this out by
summing its own UTXO list will offer amounts the builder then refuses, once its user has
anything delegated or still maturing. The kit now computes it against the same filter and
fee model the builder uses. See [Drive "send max" from
`transparentBalanceSat`](#drive-send-max-from-transparentbalancesat-not-your-own-sum).

**Transparent receive addresses can be rotated.** `transparentAddressAt(change, index)`
derives the address at any HD slot, and tagging a UTXO with the slot it arrived at keeps
the wallet-state builders (which all sign with the `0/0` key) from selecting outputs they
cannot sign for. Without the tag that mistake is silent until broadcast. Shield addresses
were already rotatable and need none of this: every diversified address decrypts to one
spending key. See [Rotating transparent
addresses](#rotating-transparent-addresses).

**One behaviour changed for everyone, not just cold staking.** PIVX rejects any output
worth less than it costs to spend: `IsStandardTx` fails with `reason = "dust"`, so no
node relays the transaction. The crate had no notion of this and would build
transactions nothing would accept. See *Upgrading to 0.4.0*.

### Upgrading to 0.4.0

The cold-staking API is entirely new. One existing type changed shape:

0. **`SerializedUTXO` gained `coinstake`, `confirmations` and `hdSlot`.** All three
   default to "an ordinary, immediately spendable output at slot `0/0`".
   - *Rust consumers*: this is a breaking change if you build the struct with a literal.
     Add `..Default::default()` (the type now derives `Default`) or set the fields.
   - *JS/TS consumers*: all three are optional in the generated types, so nothing is
     required of you. **But `parseBlockbookUtxos` reads `coinstake` and `confirmations`
     off the explorer response**, so if your explorer already returns them, maturity
     enforcement turns itself on and coins you could previously select become
     unselectable until they are 101 confirmations deep. Blockbook proper returns neither
     key; rusty-blox returns both, plus `coinbase`, which folds into the same flag. See
     [Staked delegations are coinstake
     outputs](#staked-delegations-are-coinstake-outputs) and the "send max" note above
     it, which is where this surfaces first.
   - `hdSlot` is different: it is never inferred, only ever set by you, and it changes
     nothing until you set it. See [Rotating transparent
     addresses](#rotating-transparent-addresses).
   - *Persisted wallets*: older JSON deserializes unchanged, reading as mature and
     untagged.

Three additions, which nothing you already call has to change to use:
**`maxSendableSat(destination)` and `maxSendableSatToMany(count)`** give the largest
amount a send can pay after fee, computed against the same filter and fee model the
builder uses. Replace any locally computed "send max" with it: the local version
over-counts delegated and immature coins.

**`maxShieldSpendableSat(destination)`** answers "empty my shield balance", which nothing
previously did: both branches of `maxSendableSat` compute from transparent UTXOs, so a
`ps1…` destination there prices a shielding send rather than a spend of notes.

**`transparentAddressAt(change, index)`** derives the transparent address at any HD slot,
the counterpart to `stakingAddressAt` for the same key. With `hdSlot` on `SerializedUTXO`
and the new `rotatedBalanceSat`, that is enough to rotate transparent receive addresses
safely: see [Rotating transparent addresses](#rotating-transparent-addresses).

Five behaviours differ:

1. **Dust outputs are now handled.** The threshold is 5460 sat for an ordinary output
   (6240 for a cold-staking one). Recipients below it are **rejected** rather than
   silently producing an unrelayable transaction; change below it is **dropped to the
   miner** rather than emitted.

2. **`result.fee` is now the fee actually paid**, computed from inputs minus outputs,
   rather than the estimate. When dust change is absorbed the two differ: the reported
   figure is the larger, true one. Consumers displaying a fee to users will show a
   slightly higher number in that case, which is the number the user actually pays.

3. **Outpoints are validated before they are signed.** A `txid` must be 64 hex characters
   and a `vout` must parse as an unsigned integer. Entries failing either are dropped by
   `parseBlockbookUtxos`, and every builder refuses a set containing one rather than
   signing it.

   This closes a silent failure, not a loud one. A txid is decoded by an unchecked hex
   decoder and written straight into the prevout, so a malformed one produced either a
   structurally corrupt transaction or a well-formed transaction spending an outpoint that
   does not exist, with the signature computed over the same wrong bytes either way. On
   the shielding path it panicked, which in wasm poisons the module for the life of the
   page. Separately, `vout` was read only as a JSON number while `value` was already read
   as a number *or* a string, so an explorer returning `"1"` would have silently spent
   vout 0: a real output, just not the selected one.

   Nothing correct changes. If your explorer returns well-formed data you will not notice.
   If you hand-build UTXOs for `setUtxos` or `sendTransparentFromUtxos*`, a bad entry now
   fails at build time with a message naming it, instead of at broadcast as "missing
   inputs".

4. **Encrypted wallets now carry a nonce, and the old format is still readable.**
   `encrypt_secrets` draws a fresh 16-byte nonce per call and stores it as `cipherNonce`
   beside the ciphertext, and the seed and mnemonic get separately domain-tagged
   keystreams.

   This fixes a two-time pad. Both secrets were previously XORed against the *same*
   keystream, because each `crypt` call restarted its counter at zero, so XORing the two
   stored ciphertexts cancelled the keystream and yielded `seed XOR mnemonic[0..32]` to
   anyone holding the file, with no key.

   **On its own that is not a practical break.** Recovering the seed from the file alone
   means guessing the mnemonic's first 32 characters, and there are 2^67.3 of them
   (1.85e20, counted over the BIP39 English list), each needing a ZIP32 derivation to test
   against the plaintext `extfvk`. What the leak actually does is destroy the margin, and
   turn two situations that should be survivable into total compromise of the shield seed,
   with no search at all:

   - **Part of the mnemonic leaks by any other route.** Knowing the first five or six words
     normally still leaves the rest out of reach. Here it yields the seed directly.
   - **A second secret under the same key is known.** One known seed gives the keystream,
     which decrypts every other wallet encrypted under that key. The native key is intended
     to be machine-derived, so wallets on one machine share it.

   Transparent funds were never reachable this way: the stored seed is `bip39_seed[..32]`,
   enough for Sapling but not for the BIP32 transparent tree, which needs all 64 bytes via
   the mnemonic. Shield funds are the exposure.

   **Nothing breaks and no migration step is needed.** A wallet written before this reads
   with the old keystream automatically (the absence of `cipherNonce` is the signal), and
   re-saving it writes the new format. Move funds only if one of the two situations above
   applies to a wallet whose encrypted file someone else may hold; a file alone, with no
   other leak, was not practically attackable.

5. **`estimateSendTransparentFee` now excludes delegated and immature coins**, matching
   the selection the builder performs. It previously quoted against the raw UTXO set, so
   it could price inputs no builder would reach for. Wallets with no delegations and no
   staking history see the same figure as before.

Detecting delegated outputs needs each UTXO's `script`, and no explorer returns one from
its UTXO endpoint. A delegated output whose script is unknown is treated as ordinary, so
it counts as spendable and an ordinary send may select it, which the network then
rejects. **Consumers using cold staking must join the script on themselves**, from
`/api/v2/tx/{txid}` as `vout[n].hex`; `parseBlockbookUtxos` carries it through when it is
present. See [Cold staking needs scripts](#cold-staking-needs-scripts). Wallets that
never delegate are unaffected.

**v0.3.0**: multi-recipient sends (`sendTransparentToMany`, `sendShieldToMany`,
`sendTransparentFromUtxosToMany`, plus matching fee estimators), and four fixes to
pre-existing bugs found while building them. **The API is purely additive: no existing
signature changed, and existing single-recipient sends produce byte-identical
transactions**, but three fixes tighten validation, so input that was previously accepted
is now refused. See *Upgrading to 0.3.0* below.

### Upgrading to 0.3.0

Existing calls keep working unchanged. Four behaviours differ, all deliberately:

1. **Transparent addresses are now checksum- and version-validated.** Previously
   `address_to_p2pkh_script` decoded base58 without verifying either, so a single mistyped
   character was accepted and paid a pubkey hash nobody holds the key for. Addresses from
   other networks, and PIVX P2SH addresses (`7...`), were also accepted and wrapped in a
   P2PKH script, which is unspendable. All of these now error. If a consumer was relying on
   sending to P2SH addresses, those sends were never recoverable and need a real P2SH path.

2. **Duplicate outpoints are rejected.** Blockbook lists the same UTXO twice while a
   transaction is confirming, which made the wallet read double its balance and build a
   transaction spending one output twice. `parseBlockbookUtxos` now collapses duplicates,
   and the builders refuse a set that still contains any, including UTXOs supplied
   directly to `sendTransparentFromUtxos*`.

3. **`applyBlocks` now advances `lastBlock()` and skips already-applied heights.** This is
   the one that needs an action. Previously `last_block` only ever moved in
   `resetToCheckpoint`, so a consumer syncing from `lastBlock() + 1`: the pattern this
   README and the web-wallet example both document: re-applied the whole range from the
   checkpoint on every sync after the first, advancing the commitment tree twice and
   shifting every witness position.

   **Wallets persisted by an earlier version carry that stale cursor**, so their first sync
   after upgrading re-applies once more. Call `resetToCheckpoint()` and resync once after
   upgrading; that restores state byte-identical to a fresh sync. Wallets created on 0.3.0
   need nothing.

4. **Over-long shield memos are rejected by the fee estimator**, not only by the builder.
   The 512-byte Sapling limit is on encoded bytes, so a 200-character string of multi-byte
   characters (600 bytes) is refused.

**v0.2.5**: **fixes a hang that made every shield send unusable in the browser.** `sendTransparentToShield` (and any other Groth16 proving path) never returned in WASM builds, spinning at 100% CPU indefinitely; the same transaction built in ~0.35s natively. Cause: `bellman` and `sapling` both default-enable a `multicore` feature that pulls in rayon, and this crate declared them without `default-features = false`, so rayon shipped inside the default WASM artifact and blocked forever waiting for worker threads that a threadless build can never spawn. Both dependencies are now pinned single-threaded: matching what librustpivx's own workspace already does, and CI asserts the built artifact is rayon-free. Parallel proving remains available behind the `multicore` feature, which now switches rayon and the `wasm-bindgen-rayon` thread pool together instead of only the latter. Shield proofs take ~6s single-threaded in-browser. No API change.

**v0.2.4**: `sync`: parse compact spend/output counts as CompactSize varint.

**v0.2.3**: exposes `create_raw_transparent_transaction_from_utxos` to JS as `Wallet.sendTransparentFromUtxos(fromChange, fromIndex, utxos, toAddress, amountSat)`. Same primitive that was Rust-only in v0.2.2, now available to web wallets and Node.js consumers. Backwards-compatible; existing callers see no API change.

**v0.2.2**: adds `transparent::builder::create_raw_transparent_transaction_from_utxos` for spending from any HD-indexed address with caller-supplied UTXOs. Unblocks consumers that maintain multiple receive addresses (payment processors, hierarchical accounting). Backwards-compatible; existing callers see no API change.

**v0.2.1**: adds diversifier-based shield address derivation (`shield_address_at`) for merchant use cases where one address per invoice is needed. Backwards-compatible; existing callers see no API change.

**v0.2.0**: class-style WASM API, full audit pass (3 rounds), end-to-end mainnet verification across all four send paths (T↔T, T↔S, S↔T, S↔S). Used in production by [`pivx-agent-kit`](https://github.com/PIVX-Labs/pivx-agent-kit) and [`pivx-tasks`](https://github.com/PIVX-Labs/pivx-tasks).

## License

MIT © JSKitty
