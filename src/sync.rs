//! Pure sync logic: parse the binary shield stream into block batches.
//!
//! Consumers handle network I/O (fetching the stream from an RPC node) and
//! persistence (saving `WalletData` between batches). This module only
//! transforms length-prefixed wire bytes into structured blocks, ready to
//! hand off to [`crate::sapling::sync::handle_blocks`].

use crate::sapling::sync::ShieldBlock;
use std::error::Error;
use std::io::Read;

/// Maximum packet size from the network (no single shield tx exceeds 1 MiB).
pub const MAX_PACKET_SIZE: usize = 1_048_576;

/// Parse a 4-byte little-endian length from a `Read`.
///
/// Returns `Ok(None)` on clean EOF, `Ok(Some(len))` on success, and `Err` on
/// a truncated read.
#[inline]
fn read_u32_le(reader: &mut dyn Read) -> Result<Option<u32>, Box<dyn Error>> {
    let mut buf = [0u8; 4];
    match reader.read_exact(&mut buf) {
        Ok(()) => Ok(Some(u32::from_le_bytes(buf))),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Parse the next batch of shield blocks from the binary stream.
///
/// Wire format:
/// ```text
/// [4-byte LE length][payload]
///   payload[0] == 0x5d  → block marker (header before txs OR footer after)
///   payload[0] == 0x03  → full raw tx (PivxNodeController compat)
///   payload[0] == 0x04  → compact tx (default)
/// ```
///
/// Returns `Ok(None)` when the stream has no more complete blocks.
pub fn parse_next_blocks(
    reader: &mut dyn Read,
    max_blocks: usize,
) -> Result<Option<Vec<ShieldBlock>>, Box<dyn Error>> {
    let mut txs: Vec<Vec<u8>> = vec![];
    let mut blocks: Vec<ShieldBlock> = vec![];

    while blocks.len() < max_blocks {
        let length = match read_u32_le(reader)? {
            Some(l) => l as usize,
            None => break,
        };

        if length > MAX_PACKET_SIZE {
            return Err(format!(
                "Packet too large: {} bytes (max {})",
                length, MAX_PACKET_SIZE
            )
            .into());
        }
        if length == 0 {
            return Err("Zero-length packet in shield binary stream".into());
        }

        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload)?;

        match payload[0] {
            0x5d if !txs.is_empty() => {
                // PivxNodeController-compat: block footer AFTER txs (9 bytes with time).
                let height = u32::from_le_bytes(payload[1..5].try_into()?);
                blocks.push(ShieldBlock {
                    height,
                    txs: std::mem::take(&mut txs),
                });
            }
            0x5d => {
                // Compact format: block header BEFORE txs (5 bytes).
                let height = u32::from_le_bytes(payload[1..5].try_into()?);
                blocks.push(ShieldBlock { height, txs: vec![] });
            }
            0x03 | 0x04 => {
                if let Some(last) = blocks.last_mut() {
                    last.txs.push(payload);
                } else {
                    // PivxNodeController-compat: txs arrive before the footer.
                    txs.push(payload);
                }
            }
            other => {
                return Err(
                    format!("Unknown packet type 0x{:02x} in shield binary stream", other).into(),
                );
            }
        }
    }

    // PivxNodeController-compat path: txs accumulate locally and only
    // attach to a block on its footer. If the stream ends while txs
    // are still buffered, the remote sent us a truncated batch — bail
    // loudly instead of silently dropping whatever we managed to read.
    // (Compact format never uses this buffer; this guard is a no-op there.)
    if !txs.is_empty() {
        return Err(format!(
            "shield stream truncated: {} buffered txs without a block footer",
            txs.len()
        )
        .into());
    }

    if blocks.is_empty() {
        Ok(None)
    } else {
        Ok(Some(blocks))
    }
}
