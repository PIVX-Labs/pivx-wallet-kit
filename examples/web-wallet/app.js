// PIVX Wallet Kit — tiny browser demo.
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
  generate_mnemonic,
  validate_mnemonic,
  import_wallet,
  derive_shield_address,
  derive_transparent_address,
  encrypt_wallet,
  decrypt_wallet,
  parse_blockbook_utxos,
  parse_shield_stream,
  handle_blocks,
  wallet_shield_balance_sat,
  format_sat_to_piv,
} from '../../pkg/pivx_wallet_kit.js';

const RPC = 'https://rpc.pivxla.bz/mainnet';
const EXPLORER = 'https://explorer.pivxla.bz';
/// Process decoded blocks in chunks of this size when feeding them to
/// `handle_blocks`. This is purely for progress UI — the full stream is
/// fetched and parsed in one go, so batch boundaries don't truncate.
const SHIELD_HANDLE_CHUNK = 500;

const $ = (id) => document.getElementById(id);

/** Derive a deterministic 32-byte key from a user passphrase via SHA-256. */
async function passphraseToKey(passphrase) {
  const encoded = new TextEncoder().encode(passphrase);
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  return new Uint8Array(digest);
}

function truncateSecret(value) {
  if (typeof value !== 'string' || value.length < 20) return value;
  return value.slice(0, 10) + '…' + value.slice(-6);
}

/** Render the wallet JSON with the most sensitive fields truncated for display. */
function renderState(wallet) {
  const display = { ...wallet };
  if (display.mnemonic) display.mnemonic = truncateSecret(display.mnemonic);
  if (display.seed) display.seed = '[…]';
  $('state').textContent = JSON.stringify(display, null, 2);
}

async function main() {
  await init();

  let wallet = null;

  $('generate').onclick = () => {
    $('mnemonic').value = generate_mnemonic();
  };

  $('import').onclick = async () => {
    const mnemonic = $('mnemonic').value.trim();
    if (!validate_mnemonic(mnemonic)) {
      alert('Invalid BIP39 mnemonic.');
      return;
    }

    // Fetch the current chain tip so import_wallet picks the latest embedded
    // checkpoint. Without this, the wallet birthday defaults to the earliest
    // checkpoint (~2.7M) and a full shield sync would be impractically large.
    let currentHeight = 0;
    try {
      const resp = await fetch(`${RPC}/getblockcount`);
      if (resp.ok) currentHeight = parseInt((await resp.text()).trim(), 10) || 0;
    } catch { /* fall back to 0 */ }

    wallet = import_wallet(mnemonic, currentHeight);

    $('shield-addr').textContent = derive_shield_address(wallet.extfvk);
    $('transparent-addr').textContent = derive_transparent_address(mnemonic);
    $('wallet-view').style.display = 'block';

    renderState(wallet);
  };

  $('balance').onclick = async () => {
    const addr = $('transparent-addr').textContent;
    if (!addr) return;
    $('balance-result').innerHTML = '<span class="muted">Fetching…</span>';

    try {
      const resp = await fetch(`${EXPLORER}/api/v2/utxo/${addr}?confirmed=true`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const raw = await resp.json();

      const utxos = parse_blockbook_utxos(raw);
      const totalSat = utxos.reduce((sum, u) => sum + BigInt(u.amount), 0n);
      const piv = format_sat_to_piv(totalSat);

      $('balance-result').innerHTML =
        `<span class="status-ok">${piv} PIV</span> ` +
        `<span class="muted">(${utxos.length} UTXO${utxos.length === 1 ? '' : 's'})</span>`;
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
      const startBlock = wallet.last_block + 1;
      const resp = await fetch(
        `${RPC}/getshielddata?startBlock=${startBlock}&format=compact`
      );
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const bytes = new Uint8Array(await resp.arrayBuffer());

      // Parse the whole stream up front. 500k cap is overkill for typical
      // sync ranges but cheap to own a generous ceiling.
      const allBlocks =
        bytes.length === 0 ? [] : parse_shield_stream(bytes, 500_000);

      let totalBlocks = 0;

      for (let i = 0; i < allBlocks.length; i += SHIELD_HANDLE_CHUNK) {
        const blocks = allBlocks.slice(i, i + SHIELD_HANDLE_CHUNK);

        const result = handle_blocks(
          wallet.commitment_tree,
          blocks,
          wallet.extfvk,
          wallet.unspent_notes
        );

        const spent = new Set(result.nullifiers);
        const notes = [...result.updated_notes, ...result.new_notes]
          .filter((n) => !spent.has(n.nullifier));

        wallet = {
          ...wallet,
          commitment_tree: result.commitment_tree,
          unspent_notes: notes,
          last_block: blocks[blocks.length - 1].height,
        };

        totalBlocks += blocks.length;
        $('shield-result').innerHTML =
          `<span class="muted">Synced ${totalBlocks} / ${allBlocks.length} blocks (now at ${wallet.last_block})…</span>`;
      }

      // Use the kit's own get_balance so we're not guessing the JSON shape
      // of a Sapling note.
      const balanceSat = wallet_shield_balance_sat(wallet);
      const piv = format_sat_to_piv(balanceSat);
      const n = wallet.unspent_notes.length;
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

  $('encrypt').onclick = async () => {
    if (!wallet) return;
    const pass = $('passphrase').value;
    if (!pass) { alert('Enter a passphrase.'); return; }
    const key = await passphraseToKey(pass);
    wallet = encrypt_wallet(wallet, key);
    renderState(wallet);
  };

  $('decrypt').onclick = async () => {
    if (!wallet) return;
    const pass = $('passphrase').value;
    if (!pass) { alert('Enter a passphrase.'); return; }
    const key = await passphraseToKey(pass);
    try {
      wallet = decrypt_wallet(wallet, key);
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
