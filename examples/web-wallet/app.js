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
  format_sat_to_piv,
} from '../../pkg/pivx_wallet_kit.js';

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

  $('import').onclick = () => {
    const mnemonic = $('mnemonic').value.trim();
    if (!validate_mnemonic(mnemonic)) {
      alert('Invalid BIP39 mnemonic.');
      return;
    }

    // `current_height = 0` picks the earliest embedded checkpoint; a real
    // wallet would fetch the chain tip from its RPC source so the wallet
    // starts syncing near the current head.
    wallet = import_wallet(mnemonic, 0);

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
      const resp = await fetch(
        `https://explorer.pivxla.bz/api/v2/utxo/${addr}?confirmed=true`
      );
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
