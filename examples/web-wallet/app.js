// PIVX Wallet Kit — tiny browser demo (v0.2 class-style API).
//
// Loads the WASM, derives addresses from a BIP39 mnemonic, fetches transparent
// UTXOs from Blockbook and sums them via the kit's parser, and demonstrates the
// encrypt/decrypt round-trip that a real web wallet would use before writing
// the wallet JSON to localStorage / IndexedDB.
//
// Assumes `wasm-pack build --release --target web` was run at the repo root
// so that `../../pkg/` exists. A `./pkg/` symlink or copy works too if this
// example is served on its own.

import init, {
  Wallet,
  Mnemonic,
  parseBlockbookUtxos,
  parseShieldStream,
  formatSatToPiv,
} from '../../pkg/pivx_wallet_kit.js';

const RPC = 'https://rpc.pivxla.bz/mainnet';
const EXPLORER = 'https://explorer.pivxla.bz';
/// Process decoded blocks in chunks of this size when feeding them to
/// `wallet.applyBlocks`. This is purely for progress UI — the full stream is
/// fetched and parsed in one go, so batch boundaries don't truncate.
const SHIELD_HANDLE_CHUNK = 500;

const $ = (id) => document.getElementById(id);

/** Derive a deterministic 32-byte key from a user passphrase via SHA-256. */
async function passphraseToKey(passphrase) {
  const encoded = new TextEncoder().encode(passphrase);
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  return new Uint8Array(digest);
}

/** Render a snapshot of wallet-visible state for the demo's debug panel. */
function renderState(wallet) {
  const view = {
    locked: !wallet.isUnlocked(),
    last_block: wallet.lastBlock(),
    birthday: wallet.birthdayHeight(),
    shield_balance_sat: wallet.shieldBalanceSat().toString(),
    transparent_balance_sat: wallet.transparentBalanceSat().toString(),
    unspent_notes: wallet.notes().notes.length,
    unspent_utxos: wallet.utxos().utxos.length,
  };
  $('state').textContent = JSON.stringify(view, null, 2);
}

async function main() {
  await init();

  /** @type {Wallet | null} */
  let wallet = null;

  $('generate').onclick = () => {
    $('mnemonic').value = Mnemonic.generate();
  };

  $('import').onclick = async () => {
    const mnemonic = $('mnemonic').value.trim();
    if (!Mnemonic.validate(mnemonic)) {
      alert('Invalid BIP39 mnemonic.');
      return;
    }

    // Fetch the current chain tip so Wallet.fromMnemonic picks the latest
    // embedded checkpoint. Without this, the wallet birthday defaults to the
    // earliest checkpoint (~2.7M) and a full shield sync would be impractical.
    let currentHeight = 0;
    try {
      const resp = await fetch(`${RPC}/getblockcount`);
      if (resp.ok) currentHeight = parseInt((await resp.text()).trim(), 10) || 0;
    } catch { /* fall back to 0 */ }

    // Free the previous Wallet (if any) so its WASM heap allocation is
    // reclaimed before we replace it.
    if (wallet) wallet.free();
    wallet = Wallet.fromMnemonic(mnemonic, currentHeight);

    $('shield-addr').textContent = wallet.shieldAddress();
    $('transparent-addr').textContent = wallet.transparentAddress();
    $('wallet-view').style.display = 'block';

    renderState(wallet);
  };

  $('balance').onclick = async () => {
    if (!wallet) return;
    const addr = wallet.transparentAddress();
    $('balance-result').innerHTML = '<span class="muted">Fetching…</span>';

    try {
      const resp = await fetch(`${EXPLORER}/api/v2/utxo/${addr}?confirmed=true`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const raw = await resp.json();

      // Push the parsed UTXO set into the wallet so it owns the canonical
      // view. Subsequent transparentBalanceSat() / utxos() reads come back
      // straight from the kit, no recomputation in JS.
      const parsed = parseBlockbookUtxos(raw);
      wallet.setUtxos(parsed);

      const totalSat = wallet.transparentBalanceSat();
      const piv = formatSatToPiv(totalSat);
      const n = parsed.utxos.length;

      $('balance-result').innerHTML =
        `<span class="status-ok">${piv} PIV</span> ` +
        `<span class="muted">(${n} UTXO${n === 1 ? '' : 's'})</span>`;

      renderState(wallet);
    } catch (err) {
      $('balance-result').innerHTML =
        `<span class="status-err">Fetch failed: ${err.message}</span>`;
    }
  };

  $('shield-balance').onclick = async () => {
    if (!wallet) return;
    const btn = $('shield-balance');
    btn.disabled = true;
    $('shield-result').innerHTML = '<span class="muted">Syncing from checkpoint…</span>';

    try {
      // Fetch the entire compact stream in a single request. Re-fetching in
      // batches would truncate the last block of each batch (its header is
      // counted but subsequent tx packets aren't read before the cap-exit),
      // silently losing cmus and corrupting every subsequent witness position.
      const startBlock = wallet.lastBlock() + 1;
      const resp = await fetch(
        `${RPC}/getshielddata?startBlock=${startBlock}&format=compact`
      );
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const bytes = new Uint8Array(await resp.arrayBuffer());

      // Parse the whole stream up front. 500k cap is overkill for typical
      // sync ranges but cheap to own a generous ceiling.
      const allBlocks =
        bytes.length === 0 ? { blocks: [] } : parseShieldStream(bytes, 500_000);

      let totalBlocks = 0;

      for (let i = 0; i < allBlocks.blocks.length; i += SHIELD_HANDLE_CHUNK) {
        const chunk = { blocks: allBlocks.blocks.slice(i, i + SHIELD_HANDLE_CHUNK) };

        // applyBlocks mutates the wallet in place: advances commitment tree,
        // pushes any newly-decrypted notes, AND auto-removes own notes whose
        // nullifiers landed in this batch. No follow-up finalize call needed.
        wallet.applyBlocks(chunk);

        totalBlocks += chunk.blocks.length;
        $('shield-result').innerHTML =
          `<span class="muted">Synced ${totalBlocks} / ${allBlocks.blocks.length} blocks (now at ${wallet.lastBlock()})…</span>`;
      }

      const balanceSat = wallet.shieldBalanceSat();
      const piv = formatSatToPiv(balanceSat);
      const n = wallet.notes().notes.length;
      $('shield-result').innerHTML =
        `<span class="status-ok">${piv} PIV</span> ` +
        `<span class="muted">(${n} note${n === 1 ? '' : 's'}, synced ${totalBlocks} block${totalBlocks === 1 ? '' : 's'})</span>`;

      renderState(wallet);
    } catch (err) {
      $('shield-result').innerHTML =
        `<span class="status-err">Sync failed: ${err.message}</span>`;
    } finally {
      btn.disabled = false;
    }
  };

  // The encrypt/decrypt pair demonstrates the round-trip a real web wallet
  // runs before writing to localStorage. The plaintext seed/mnemonic never
  // leaves WASM memory in encrypted form — the JSON returned by
  // toSerializedEncrypted() is safe to persist anywhere.
  $('encrypt').onclick = async () => {
    if (!wallet) return;
    const pass = $('passphrase').value;
    if (!pass) { alert('Enter a passphrase.'); return; }
    const key = await passphraseToKey(pass);
    const encrypted = wallet.toSerializedEncrypted(key);
    // Replace the live wallet with one reconstructed from the ciphertext —
    // it'll come back in the LOCKED state. JS now only holds the encrypted
    // JSON, mirroring the persist→reload cycle a real wallet would run.
    wallet.free();
    wallet = Wallet.fromSerialized(encrypted);
    renderState(wallet);
  };

  $('decrypt').onclick = async () => {
    if (!wallet) return;
    const pass = $('passphrase').value;
    if (!pass) { alert('Enter a passphrase.'); return; }
    const key = await passphraseToKey(pass);
    try {
      wallet.unlock(key);
      renderState(wallet);
    } catch (err) {
      alert(`Decrypt failed: ${err.message || err}`);
    }
  };
}

main().catch((err) => {
  document.body.insertAdjacentHTML(
    'afterbegin',
    `<div class="section status-err">Failed to init WASM: ${err.message}<br>
     Did you run <code>wasm-pack build --release --target web</code> at the repo root?</div>`
  );
  console.error(err);
});
