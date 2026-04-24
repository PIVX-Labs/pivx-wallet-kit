//! Pure sync logic: transforms pre-fetched block data into wallet state deltas.
//!
//! Consumers handle network I/O; this module handles the deterministic
//! block → (notes, utxos, tree updates) transformation.
