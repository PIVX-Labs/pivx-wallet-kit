//! Mainnet test driver for the cold-staking branch.
//!
//! Deliberately does no I/O: UTXOs come in as a JSON file fetched by curl, and
//! the built transaction goes out as hex on stdout for curl to broadcast. That
//! keeps the harness honest about the kit's "no network, no filesystem"
//! contract, and means every byte broadcast was produced by the library exactly
//! as a consumer would produce it.
//!
//! Usage: mainnet_test <command> [args...]   (mnemonic from $TEST_MNEMONIC)
//!
//! `examples/fetch-utxos.sh <address> <out.json>` is the companion fetcher: it
//! joins each funding transaction's `scriptPubKey` onto the UTXO entries, which
//! the UTXO endpoint never returns and which cold staking cannot work without.

use pivx_wallet_kit::sapling::builder as shield_builder;
use pivx_wallet_kit::transparent::builder::{self as tb, Recipient};
use pivx_wallet_kit::transparent::coldstake as cs;
use pivx_wallet_kit::wallet::{self, HdSlot, SerializedUTXO, WalletData};
use pivx_wallet_kit::{keys, simd};
use std::error::Error;

const BIRTHDAY: u32 = 5_236_346;

fn mnemonic() -> String {
    std::env::var("TEST_MNEMONIC").expect("set TEST_MNEMONIC")
}

fn load() -> Result<WalletData, Box<dyn Error>> {
    wallet::import_wallet(&mnemonic(), BIRTHDAY)
}

fn seed(w: &WalletData) -> Vec<u8> {
    w.get_bip39_seed().unwrap().to_vec()
}

/// Read `utxos.json` (raw explorer response) and ingest it through the kit's
/// own parser, optionally tagging an HD slot.
fn utxos_from(path: &str, slot: Option<HdSlot>) -> Result<Vec<SerializedUTXO>, Box<dyn Error>> {
    let raw: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    Ok(wallet::parse_blockbook_utxos_at(&raw, slot))
}

fn piv(sat: u64) -> String {
    pivx_wallet_kit::amount::format_sat_to_piv(sat)
}

fn report(label: &str, r: &tb::TransparentTransactionResult) {
    println!("--- {label} ---");
    println!("amount : {} PIV", piv(r.amount));
    println!("fee    : {} PIV", piv(r.fee));
    println!("inputs : {}", r.spent.len());
    println!("bytes  : {}", r.txhex.len() / 2);
    println!("TXHEX={}", r.txhex);
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("status");
    let w = load()?;
    let sd = seed(&w);

    match cmd {
        "addresses" => {
            println!("t 0/0   {}", w.get_transparent_address()?);
            for i in 1..=2u32 {
                println!("t 0/{i}   {}", keys::transparent_address_at(&sd, 0, i)?);
            }
            println!("stake   {}", cs::encode_staking_address(&cs::owner_hash_from_seed(&sd, 0, 0)?));
            println!("shield  {}", keys::get_default_address(&w.extfvk)?);
        }

        // Load UTXOs and print every balance accessor.
        "status" => {
            let slot = args.get(3).map(|s| HdSlot {
                change: 0,
                index: s.parse().unwrap(),
            });
            let mut w = load()?;
            w.unspent_utxos = utxos_from(&args[2], slot)?;
            println!("utxos            : {}", w.unspent_utxos.len());
            for u in &w.unspent_utxos {
                println!("  {}:{} {} PIV script={} slot={:?}",
                    &u.txid[..16], u.vout, piv(u.amount),
                    if u.script.is_empty() { "none" } else { "set" }, u.hd_slot);
            }
            println!("transparentSat   : {} PIV", piv(w.get_transparent_balance()));
            println!("rotatedSat       : {} PIV", piv(w.get_rotated_balance()));
            println!("delegatedSat     : {} PIV", piv(w.get_delegated_balance()));
            println!("immatureSat      : {} PIV", piv(w.get_immature_balance()));
            println!("shieldSat        : {} PIV", piv(w.get_balance()));
            let dest = w.get_transparent_address()?;
            println!("maxSendable      : {} PIV", piv(tb::max_sendable_transparent(&w, 1)));
            println!("maxShieldable    : {} PIV", piv(tb::max_shieldable_transparent(&w)));
            println!("maxShieldSpend   : {} PIV",
                piv(shield_builder::max_shield_spendable(&w, &dest)));
        }

        // Wallet-state send to one or more recipients: "to:amountPIV" pairs.
        "send" => {
            let mut w = load()?;
            w.unspent_utxos = utxos_from(&args[2], None)?;
            let recipients: Vec<Recipient> = args[3..]
                .iter()
                .map(|s| {
                    let (a, v) = s.split_once(':').expect("want address:amount");
                    Recipient {
                        address: a.to_string(),
                        amount: pivx_wallet_kit::amount::parse_piv_to_sat(v).unwrap(),
                    }
                })
                .collect();
            let est = tb::estimate_raw_transparent_fee_to_many(&w, &recipients)?;
            println!("estimated fee: {} PIV", piv(est));
            let r = tb::create_raw_transparent_transaction_to_many(&mut w, &sd, &recipients)?;
            assert_eq!(r.fee, est, "estimator and builder disagreed");
            report("send", &r);
        }

        // Spend a specific HD slot's UTXOs: from_utxos <json> <change> <index> <to> <amount>
        "send-from-slot" => {
            let change: u32 = args[3].parse()?;
            let index: u32 = args[4].parse()?;
            let utxos = utxos_from(&args[2], Some(HdSlot { change, index }))?;
            let amount = pivx_wallet_kit::amount::parse_piv_to_sat(&args[6])?;
            let r = tb::create_raw_transparent_transaction_from_utxos(
                &sd, change, index, &utxos, &args[5], amount,
            )?;
            report("send-from-slot", &r);
        }

        "delegate" => {
            let mut w = load()?;
            w.unspent_utxos = utxos_from(&args[2], None)?;
            let amount = pivx_wallet_kit::amount::parse_piv_to_sat(&args[4])?;
            let est = cs::estimate_delegation_fee(&w, &args[3], amount)?;
            println!("estimated fee: {} PIV", piv(est));
            let r = cs::create_delegation_transaction(
                &mut w, &sd, &args[3], amount, cs::ColdStakeVariant::Lof,
            )?;
            report("delegate", &r);
        }

        "withdraw" => {
            let utxos = utxos_from(&args[2], None)?;
            let delegated: Vec<SerializedUTXO> = utxos
                .into_iter()
                .filter(wallet::is_delegated_utxo)
                .collect();
            println!("delegated utxos: {}", delegated.len());
            let amount = pivx_wallet_kit::amount::parse_piv_to_sat(&args[4])?;
            let r = cs::create_coldstake_withdrawal(&sd, 0, 0, &delegated, &args[3], amount)?;
            report("withdraw", &r);
        }

        "sign" => {
            let (_, _, pk) = keys::transparent_key_from_bip39_seed(&sd, 0, 0)?;
            let sig = pivx_wallet_kit::messages::sign_message(&pk, &args[2])?;
            let addr = w.get_transparent_address()?;
            println!("address  : {addr}");
            println!("message  : {}", args[2]);
            println!("signature: {sig}");
            println!("verifies : {}",
                pivx_wallet_kit::messages::verify_message(&addr, &args[2], &sig)?);
        }

        "inspect" => {
            let script = simd::hex::hex_string_to_bytes(&args[2]);
            println!("is_p2cs   : {}", cs::is_p2cs(&script));
            if cs::is_p2cs(&script) {
                let (s, o) = cs::addresses_from_p2cs_script(&script)?;
                println!("staker    : {s}");
                println!("owner     : {o}");
                println!("is_lof    : {}", cs::is_p2cs_lof(&script));
            }
        }

        // Every guard that should refuse, run against real mainnet UTXOs.
        // Each prints PASS only if it was refused for the right reason.
        "guards" => {
            let all = utxos_from(&args[2], None)?;
            // The slot checks need ordinary outputs. A delegated one is refused
            // first and for a different reason, which is the correct precedence
            // (a delegation is the more urgent thing to tell the caller about)
            // but tests the wrong guard.
            let real: Vec<SerializedUTXO> = all
                .iter()
                .filter(|u| !wallet::is_delegated_utxo(u))
                .cloned()
                .collect();
            println!("({} ordinary of {} total utxos)", real.len(), all.len());
            let dest = w.get_transparent_address()?;
            let mut fails = 0;

            let mut check = |name: &str, r: Result<String, String>, want: &str| {
                match r {
                    Err(e) if e.contains(want) => println!("PASS {name}"),
                    Err(e) => { fails += 1; println!("FAIL {name}: wrong reason: {e}"); }
                    Ok(_) => { fails += 1; println!("FAIL {name}: was ACCEPTED"); }
                }
            };

            // 1. A rotated UTXO must not be selectable by a wallet-state send.
            let mut rot = load()?;
            rot.unspent_utxos = real
                .iter()
                .cloned()
                .map(|u| SerializedUTXO { hd_slot: Some(HdSlot { change: 0, index: 5 }), ..u })
                .collect();
            check("rotated coins unreachable by wallet-state send",
                tb::create_raw_transparent_transaction_to_many(
                    &mut rot, &sd, &[Recipient { address: dest.clone(), amount: 100_000 }])
                    .map(|r| r.txhex).map_err(|e| e.to_string()),
                "HD slot");

            // 2. Delegation cannot be funded from rotated coins.
            let mut rot2 = load()?;
            rot2.unspent_utxos = rot.unspent_utxos.clone();
            check("delegation refuses rotated coins",
                cs::create_delegation_transaction(&mut rot2, &sd,
                    &cs::encode_staking_address(&cs::owner_hash_from_seed(&sd, 0, 0)?),
                    100_000_000, cs::ColdStakeVariant::Lof)
                    .map(|r| r.txhex).map_err(|e| e.to_string()),
                "move the coins there first");

            // 3a. Two slots in one call, scripts stripped so only the tag can
            // speak. Isolates the tag check from the script check below.
            let mut mixed = real.clone();
            if mixed.len() >= 2 {
                for u in mixed.iter_mut() {
                    u.script = String::new();
                }
                mixed[0].hd_slot = Some(HdSlot { change: 0, index: 1 });
                mixed[1].hd_slot = Some(HdSlot { change: 0, index: 2 });
                check("mixed-slot input set refused (by tag)",
                    tb::create_raw_transparent_transaction_from_utxos(
                        &sd, 0, 1, &mixed, &dest, 100_000)
                        .map(|r| r.txhex).map_err(|e| e.to_string()),
                    "was received at HD slot");
            }

            // 3b. A real 0/0 output tagged as 0/1: the tag lies, the script does
            // not. The script check has to win, or bad bookkeeping gets signed.
            let mistagged = vec![SerializedUTXO {
                hd_slot: Some(HdSlot { change: 0, index: 1 }),
                ..real[0].clone()
            }];
            check("mis-tagged input caught by its scriptPubKey",
                tb::create_raw_transparent_transaction_from_utxos(
                    &sd, 0, 1, &mistagged, &dest, 100_000)
                    .map(|r| r.txhex).map_err(|e| e.to_string()),
                "cannot sign for");

            // 4. Malformed txid.
            let bad = vec![SerializedUTXO { txid: "z".repeat(64), ..real[0].clone() }];
            check("malformed txid refused",
                tb::create_raw_transparent_transaction_from_utxos(&sd, 0, 0, &bad, &dest, 100_000)
                    .map(|r| r.txhex).map_err(|e| e.to_string()),
                "malformed txid");

            // 5. Dust recipient on the transparent path.
            let mut dw = load()?;
            dw.unspent_utxos = real.clone();
            check("dust recipient refused (transparent)",
                tb::create_raw_transparent_transaction_to_many(
                    &mut dw, &sd, &[Recipient { address: dest.clone(), amount: 1_000 }])
                    .map(|r| r.txhex).map_err(|e| e.to_string()),
                "dust threshold");

            // 6. Dust transparent recipient on the shield path (fixed this pass).
            check("dust recipient refused (shield source)",
                shield_builder::shield_recipient_fee_shape(&[shield_builder::ShieldRecipient {
                    address: dest.clone(), amount: 1_000, memo: String::new() }])
                    .map(|_| String::new()).map_err(|e| e.to_string()),
                "dust threshold");

            // 7. Memo on a transparent recipient.
            check("memo on transparent recipient refused",
                shield_builder::shield_recipient_fee_shape(&[shield_builder::ShieldRecipient {
                    address: dest.clone(), amount: 100_000_000, memo: "hi".into() }])
                    .map(|_| String::new()).map_err(|e| e.to_string()),
                "cannot hold memos");

            // 8. Duplicate outpoint.
            let dupes = vec![real[0].clone(), real[0].clone()];
            check("duplicate outpoint refused",
                tb::create_raw_transparent_transaction_from_utxos(&sd, 0, 0, &dupes, &dest, 100_000)
                    .map(|r| r.txhex).map_err(|e| e.to_string()),
                "Duplicate UTXO");

            // 9. HD index past the non-hardened ceiling.
            check("hardened HD index refused",
                keys::transparent_address_at(&sd, 0, 0x8000_0000).map_err(|e| e.to_string()),
                "non-hardened");

            // 10. Paying a staking address as if it were transparent.
            let s_addr = cs::encode_staking_address(&cs::owner_hash_from_seed(&sd, 0, 0)?);
            check("staking address rejected as a P2PKH destination",
                keys::address_to_p2pkh_script(&s_addr).map(|_| String::new())
                    .map_err(|e| e.to_string()),
                "version byte");

            println!("\n{}", if fails == 0 { "ALL GUARDS PASSED" } else { "SOME GUARDS FAILED" });
            if fails > 0 { std::process::exit(1); }
        }

        // Build transparent -> shield. Needs the prover and the chain tip.
        "shield" => {
            let mut w = load()?;
            w.unspent_utxos = utxos_from(&args[2], None)?;
            let amount = pivx_wallet_kit::amount::parse_piv_to_sat(&args[3])?;
            let height: u32 = args[4].parse()?;
            let prover = pivx_wallet_kit::sapling::prover::verify_and_load_params(
                &std::fs::read(&args[5])?,
                &std::fs::read(&args[6])?,
            )?;
            let to = keys::get_default_address(&w.extfvk)?;
            println!("shielding to {to}");
            let r = tb::create_shielding_transaction(&mut w, &sd, &to, amount, height, &prover)?;
            report("shield", &r);
        }

        // Persist a fresh wallet at its birthday, ready to sync.
        "sync-init" => {
            std::fs::write(&args[2], serde_json::to_string(&w)?)?;
            println!("state written, last_block={}", w.last_block);
        }

        // Apply one batch of shield stream bytes to a persisted state.
        "sync-apply" => {
            let mut w: WalletData = serde_json::from_str(&std::fs::read_to_string(&args[2])?)?;
            let bytes = std::fs::read(&args[3])?;
            let before = w.last_block;
            let blocks = {
                let mut c = std::io::Cursor::new(&bytes[..]);
                pivx_wallet_kit::sync::parse_next_blocks(&mut c, 50_000)?.unwrap_or_default()
            };
            let n = blocks.len();
            let res = pivx_wallet_kit::sapling::sync::apply_blocks_to_wallet(&mut w, blocks)?;
            std::fs::write(&args[2], serde_json::to_string(&w)?)?;
            println!(
                "{} bytes -> {n} blocks | {} -> {} | notes {} | shieldSat {}",
                bytes.len(), before, w.last_block, w.unspent_notes.len(), piv(w.get_balance())
            );
            let _ = res;
        }

        // Spend shield notes, to anywhere.
        "send-shield" => {
            let mut w: WalletData = serde_json::from_str(&std::fs::read_to_string(&args[2])?)?;
            let amount = pivx_wallet_kit::amount::parse_piv_to_sat(&args[4])?;
            let height: u32 = args[5].parse()?;
            let prover = pivx_wallet_kit::sapling::prover::verify_and_load_params(
                &std::fs::read(&args[6])?,
                &std::fs::read(&args[7])?,
            )?;
            println!("max spendable to {}: {} PIV",
                args[3], piv(shield_builder::max_shield_spendable(&w, &args[3])));
            let r = shield_builder::create_shield_transaction(
                &mut w, &args[3], amount, "", height, &prover,
            )?;
            println!("--- send-shield ---");
            println!("fee    : {} PIV", piv(r.fee));
            println!("bytes  : {}", r.txhex.len() / 2);
            println!("TXHEX={}", r.txhex);
        }

        // Encrypted round trip carrying real notes, real UTXOs and real slot
        // tags, which is the state a consumer actually persists.
        "persist" => {
            let mut w: WalletData = serde_json::from_str(&std::fs::read_to_string(&args[2])?)?;
            w.unspent_utxos = utxos_from(&args[3], Some(HdSlot { change: 0, index: 1 }))?;
            let (notes, utxos) = (w.unspent_notes.len(), w.unspent_utxos.len());
            let (shield, rotated) = (w.get_balance(), w.get_rotated_balance());
            println!("before: {notes} note(s), {utxos} utxo(s), shield {} rotated {}",
                piv(shield), piv(rotated));

            let key = [0x5Au8; 32];
            let json = wallet::serialize_encrypted(&w, &key)?;
            let disk: serde_json::Value = serde_json::from_str(&json)?;
            println!("nonce persisted : {}", disk["cipherNonce"].as_str().unwrap_or("MISSING"));
            println!("mnemonic on disk: {}...",
                &disk["mnemonic"].as_str().unwrap_or("")[..32.min(disk["mnemonic"].as_str().unwrap_or("").len())]);

            // Re-encrypting must not reproduce the same bytes.
            let again = wallet::serialize_encrypted(&w, &key)?;
            println!("re-encrypt differs: {}", again != json);

            let back = wallet::deserialize_encrypted(&json, &key)?;
            println!("mnemonic restored : {}", back.get_mnemonic() == mnemonic());
            println!("extfvk restored   : {}", back.extfvk == w.extfvk);
            println!("notes restored    : {}", back.unspent_notes.len() == notes);
            println!("shield restored   : {}", back.get_balance() == shield);
            println!("slot tags survived: {}", back.get_rotated_balance() == rotated);
            println!("tree restored     : {}", back.commitment_tree == w.commitment_tree);

            match wallet::deserialize_encrypted(&json, &[0x5Bu8; 32]) {
                Ok(_) => println!("WRONG KEY ACCEPTED <- BUG"),
                Err(e) => println!("wrong key rejected: {e}"),
            }
        }

        other => return Err(format!("unknown command {other}").into()),
    }
    Ok(())
}
