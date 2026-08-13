#!/bin/bash
# Fetch UTXOs for an address, joining scriptPubKey from each funding tx so cold
# staking detection works (the UTXO endpoint never returns scripts).
ADDR=$1; OUT=${2:-utxos.json}
RAW=$(curl -s --max-time 30 "https://explorer.pivxla.bz/api/v2/utxo/$ADDR?confirmed=true")
echo "$RAW" | python3 -c '
import sys, json, urllib.request
utxos = json.load(sys.stdin)
scripts, cs_txids = {}, set()
for txid in {u["txid"] for u in utxos}:
    tx = json.load(urllib.request.urlopen(f"https://explorer.pivxla.bz/api/v2/tx/{txid}", timeout=30))
    for o in tx.get("vout", []):
        scripts[(txid, o["n"])] = o.get("hex", "")
    vout = tx.get("vout", [])
    if len(vout) >= 2 and vout[0].get("value") == "0" and tx.get("vin", [{}])[0].get("txid"):
        cs_txids.add(txid)
for u in utxos:
    u["script"] = scripts.get((u["txid"], u["vout"]), "")
    u["coinstake"] = u["txid"] in cs_txids
print(json.dumps(utxos, indent=1))
' > "$OUT"
echo "wrote $OUT: $(python3 -c "import json;print(len(json.load(open('$OUT'))))") utxo(s)"
