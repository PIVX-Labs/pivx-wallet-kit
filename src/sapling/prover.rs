//! Groth16 proof generation for Sapling spends and outputs.
//!
//! Proving keys are supplied by the consumer (they may be bundled, downloaded,
//! or streamed from disk) — this module performs the proof, not the I/O.
