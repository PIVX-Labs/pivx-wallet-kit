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
//! | Module | Purpose |
//! |--------|---------|
//! | [`params`]      | PIVX chain constants (coin type, prefixes, magic) |
//! | [`checkpoints`] | Embedded mainnet checkpoint data for fast sync |
//! | [`keys`]        | BIP32/BIP44 derivation, address generation, WIF |
//! | [`fees`]        | Component-based fee estimation |
//! | [`wallet`]      | In-memory wallet state, serialization |
//! | [`sync`]        | Pure block → state delta transforms |
//! | [`sapling`]     | Sapling shield keys, notes, tree, tx building |
//! | [`transparent`] | Transparent tx building, UTXO management |

pub mod amount;
pub mod params;
pub mod simd;
pub mod checkpoints;
pub mod keys;
pub mod fees;
pub mod wallet;
pub mod sync;
pub mod sapling;
pub mod transparent;

#[cfg(target_arch = "wasm32")]
pub mod wasm;
