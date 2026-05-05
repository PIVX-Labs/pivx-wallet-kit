//! PIVX Wallet Kit — pure-Rust wallet primitives with Sapling shield support.
//!
//! No I/O, no network, no filesystem. Compiles to native, WASM, and mobile.
//!
//! Consumers provide block data and persistence; the kit provides the cryptographic
//! core: key derivation, address generation, transaction building and signing,
//! Sapling shield note management, and pure sync logic that transforms blocks
//! into wallet state deltas.
//!
//! # Modules
//!
//! | Module                   | Purpose |
//! |--------------------------|---------|
//! | [`amount`]               | PIV decimal ↔ satoshi parsing / formatting |
//! | [`params`]               | PIVX chain constants (coin type, prefixes, magic) |
//! | [`checkpoints`]          | Embedded mainnet checkpoint data for fast sync |
//! | [`keys`]                 | BIP32/BIP44 derivation, address generation, WIF |
//! | [`messages`]             | PIVX Core-compatible message signing / verifying |
//! | [`fees`]                 | Component-based fee estimation |
//! | [`wallet`]               | In-memory wallet state, serialization, encryption |
//! | [`sync`]                 | Pure block → state delta transforms |
//! | [`sapling::sync`]        | `handle_blocks`: decrypt notes, advance tree |
//! | [`sapling::tree`]        | Commitment tree root extraction + empty-tree helper |
//! | [`sapling::prover`]      | SHA256-verified proving parameter loader |
//! | [`sapling::builder`]     | Shield-source transaction builder |
//! | [`transparent::builder`] | Transparent-source builders (v1 P2PKH + v3 mixed) |
//! | [`wasm`]                 | (wasm32 only) `Wallet` / `SaplingParams` / `Mnemonic` / `Fee` classes |
//!
//! Internal modules (`simd::*`) are not part of the public API.

pub mod amount;
pub mod params;
#[doc(hidden)]
pub mod simd;
pub mod checkpoints;
pub mod keys;
pub mod fees;
pub mod messages;
pub mod wallet;
pub mod sync;
pub mod sapling;
pub mod transparent;

#[cfg(target_arch = "wasm32")]
pub mod wasm;
