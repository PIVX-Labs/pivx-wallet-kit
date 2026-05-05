//! Tiny CLI helper: sign a message with the BIP44 transparent key derived
//! from a mnemonic at `m/44'/119'/0'/0/0`.
//!
//! Usage:
//!     cargo run --release --example sign -- "<mnemonic>" "<message>"
//!
//! Prints the matching D-address and the base64 signature, in PIVX Core
//! `signmessage` byte format.

use pivx_wallet_kit::{keys, messages};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mnemonic = args.next().ok_or("usage: sign <mnemonic> <message>")?;
    let message = args.next().ok_or("usage: sign <mnemonic> <message>")?;

    let parsed = bip39::Mnemonic::parse_normalized(&mnemonic)?;
    let bip39_seed = parsed.to_seed("");
    let (address, _pubkey, privkey) = keys::transparent_key_from_bip39_seed(&bip39_seed, 0, 0)?;

    let signature = messages::sign_message(&privkey, &message)?;
    println!("{} {}", address, signature);
    Ok(())
}
