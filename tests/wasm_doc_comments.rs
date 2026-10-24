//! Doc comments in this crate become JavaScript, so they have to be valid in
//! both languages.
//!
//! wasm-bindgen copies a Rust doc comment straight into a JSDoc block in the
//! glue it generates. A `*/` inside that comment therefore closes the block
//! early, and the emitted `_bg.js` stops being parseable JavaScript. Rust sees
//! nothing wrong, `cargo build` is clean, `cargo build --target
//! wasm32-unknown-unknown` is clean, and the failure only appears when a
//! browser loads the bundle.
//!
//! That is exactly how it shipped: the `maxSendableSat` example wrote
//! `{ /* nothing sendable */ }`, and a downstream consumer patched the built
//! glue by hand for two releases before reporting it.
//!
//! CI has no wasm-bindgen harness to catch this, so the check is a text scan.
//! It is cheap and it runs everywhere.

use std::fs;
use std::path::Path;

/// Walk every `.rs` file under `dir`, depth first.
fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).expect("src/ should be readable") {
        let path = entry.expect("readable entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_doc_comment_closes_a_jsdoc_block_early() {
    let mut files = Vec::new();
    rust_files(Path::new("src"), &mut files);
    assert!(!files.is_empty(), "found no sources to scan");

    let mut offenders = Vec::new();

    for path in &files {
        let text = fs::read_to_string(path).expect("source should be valid UTF-8");
        for (i, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            // Both doc forms reach the generated glue.
            if !(trimmed.starts_with("///") || trimmed.starts_with("//!")) {
                continue;
            }
            if trimmed.contains("*/") {
                offenders.push(format!("{}:{}: {}", path.display(), i + 1, trimmed));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these doc comments contain `*/`, which terminates the JSDoc block wasm-bindgen wraps \
         them in and leaves the generated _bg.js unparseable in the browser. Use a line comment \
         instead:\n{}",
        offenders.join("\n")
    );
}
