//! Transparent UTXO type alias.
//!
//! The on-disk UTXO representation lives in [`crate::wallet::SerializedUTXO`];
//! this module re-exports it under a shorter name for builders that operate
//! purely on transparent state.

pub use crate::wallet::SerializedUTXO as Utxo;
