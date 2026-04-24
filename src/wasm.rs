//! WASM bindings for browser and Node.js consumers.
//!
//! Only compiled for `wasm32-*` targets. Native consumers use the Rust API directly.

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {}
