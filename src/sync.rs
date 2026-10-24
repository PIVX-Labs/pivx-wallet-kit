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

/// How a stream associates transaction packets with the block they belong to.
///
/// Nothing in a transaction packet names its block. The association is purely
/// positional, relative to the `0x5d` markers, and there are two conventions
/// for it:
///
/// ```text
/// Header:   M(h1) tx tx   M(h2) tx      marker opens the block it labels
/// Footer:   tx tx M(h1)   tx M(h2)      marker closes the block it labels
/// ```
///
/// A marker is otherwise identical in both, so the framing has to be settled
/// before any transaction can be placed. The marker's payload length settles
/// it: a footer carries a trailing timestamp and a header does not.
///
/// This used to be inferred per packet, from whether any transaction happened
/// to be buffered at the time. That inference is right for the first marker of
/// a footer-framed stream and wrong for every packet after it, because the
/// first marker empties the buffer and the buffer never refills. Every
/// transaction then attached to the block before the one it belonged to. The
/// commitment tree still came out correct, since it depends only on the order
/// commitments are appended, so the fault was invisible until something read a
/// height.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Framing {
    /// `0x5d` + 4-byte height. The marker precedes its transactions.
    Header,
    /// `0x5d` + 4-byte height + 4-byte time. The marker follows its
    /// transactions. This is what PIVX Core's `getshielddata` serves, on both
    /// its default and its `format=compact` responses.
    Footer,
}

const HEADER_MARKER_LEN: usize = 5;
const FOOTER_MARKER_LEN: usize = 9;

impl Framing {
    fn from_marker_len(len: usize) -> Result<Self, Box<dyn Error>> {
        match len {
            HEADER_MARKER_LEN => Ok(Framing::Header),
            FOOTER_MARKER_LEN => Ok(Framing::Footer),
            other => Err(format!(
                "Block marker is {other} bytes; expected {HEADER_MARKER_LEN} (header framing) \
                 or {FOOTER_MARKER_LEN} (footer framing)"
            )
            .into()),
        }
    }
}

/// Parse the next batch of shield blocks from the binary stream.
///
/// Wire format:
/// ```text
/// [4-byte LE length][payload]
///   payload[0] == 0x5d  → block marker; see [`Framing`] for header vs footer
///   payload[0] == 0x03  → full raw tx (this is the tx's own version field,
///                         not a tag, so the whole payload is the transaction)
///   payload[0] == 0x04  → compact tx (a real tag, stripped by the decoder)
/// ```
///
/// The framing is decided once, from the first marker, and held for the rest
/// of the call. A later marker that disagrees is an error rather than a silent
/// switch: mixing the two conventions in one stream has no correct reading, and
/// guessing per packet is exactly the bug this replaced.
///
/// Returns `Ok(None)` when the stream has no more complete blocks.
pub fn parse_next_blocks(
    reader: &mut dyn Read,
    max_blocks: usize,
) -> Result<Option<Vec<ShieldBlock>>, Box<dyn Error>> {
    let mut txs: Vec<Vec<u8>> = vec![];
    let mut blocks: Vec<ShieldBlock> = vec![];
    let mut framing: Option<Framing> = None;

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
            0x5d => {
                let seen = Framing::from_marker_len(payload.len())?;
                match framing {
                    None => framing = Some(seen),
                    Some(locked) if locked != seen => {
                        return Err(format!(
                            "Shield stream changes framing mid-batch: started {locked:?}, \
                             then saw a {seen:?} marker"
                        )
                        .into());
                    }
                    Some(_) => {}
                }

                // Safe for both: `from_marker_len` accepted the length, and
                // both layouts carry the height at the same offset.
                let height = u32::from_le_bytes(payload[1..5].try_into()?);
                let txs = match seen {
                    // Everything buffered since the previous marker belongs to
                    // this block. An empty buffer means a block with no shield
                    // transactions, which is a legitimate thing to be told.
                    Framing::Footer => std::mem::take(&mut txs),
                    Framing::Header => vec![],
                };
                blocks.push(ShieldBlock { height, txs });
            }
            0x03 | 0x04 => match framing {
                Some(Framing::Header) => {
                    blocks
                        .last_mut()
                        .ok_or("Transaction packet before any block header")?
                        .txs
                        .push(payload);
                }
                // Footer framing, or a framing not yet settled. Buffering is
                // the only correct choice in both cases: under footer framing
                // the transaction belongs to the marker still to come, and
                // before the first marker there is no block to attach it to.
                Some(Framing::Footer) | None => txs.push(payload),
            },
            other => {
                return Err(
                    format!("Unknown packet type 0x{:02x} in shield binary stream", other).into(),
                );
            }
        }
    }

    // Footer framing attaches transactions only when their marker arrives, so
    // anything still buffered is a batch that ended mid-block: the remote cut
    // us off, or a header-framed stream opened with a transaction. Bail loudly
    // rather than silently dropping what we read, or worse, attributing it to
    // whichever block happens to be last.
    if !txs.is_empty() {
        return Err(format!(
            "shield stream truncated: {} transaction packet(s) with no block marker to \
             attach them to",
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
