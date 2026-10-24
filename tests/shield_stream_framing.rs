//! Transactions must attach to the block they belong to.
//!
//! Nothing in a transaction packet names its block: the association is
//! positional relative to the `0x5d` markers, and two conventions exist for it.
//! A header marker opens the block it labels, a footer marker closes it. The
//! parser used to guess per packet, from whether any transaction happened to be
//! buffered, and that guess is correct only for the first marker of a
//! footer-framed stream. Afterwards every transaction attached to the block
//! *before* the one it belonged to, and the last block of every stream came out
//! empty.
//!
//! It stayed invisible because the commitment tree depends only on the order
//! commitments are appended, and the order was never disturbed. A full sync to
//! the tip produced the right tree and the right balance. Only the heights were
//! wrong, so it surfaced as double-counted commitments on resume, checkpoints
//! stamped with a height whose tree already contained later blocks, and note
//! confirmation counts off by a block.
//!
//! `fixtures/shield_stream_footer.bin` is 6313 bytes of a real mainnet response
//! from `rpc.duddino.com/mainnet/getshielddata?startBlock=5532290`, covering
//! four blocks with one shield transaction each.

use pivx_wallet_kit::sync;
use std::io::Cursor;

const FOOTER_FIXTURE: &[u8] = include_bytes!("fixtures/shield_stream_footer.bin");

/// Heights and transaction counts in the fixture, confirmed against the
/// explorer rather than against our own parser.
const FIXTURE_BLOCKS: [(u32, usize); 4] =
    [(5_532_290, 1), (5_532_291, 1), (5_532_292, 1), (5_532_309, 1)];

fn packet(payload: &[u8]) -> Vec<u8> {
    let mut v = (payload.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(payload);
    v
}

/// `0x5d` + height + time. What PIVX Core actually serves.
fn footer(height: u32) -> Vec<u8> {
    let mut p = vec![0x5du8];
    p.extend_from_slice(&height.to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes());
    packet(&p)
}

/// `0x5d` + height.
fn header(height: u32) -> Vec<u8> {
    let mut p = vec![0x5du8];
    p.extend_from_slice(&height.to_le_bytes());
    packet(&p)
}

/// A compact tx carrying `tag` so a test can tell one from another.
fn tx(tag: u8) -> Vec<u8> {
    packet(&[0x04u8, tag, 0])
}

/// `ShieldBlock` is not `Debug`, so unwrap the error side by hand.
fn parse_err(stream: &[u8]) -> String {
    match sync::parse_next_blocks(&mut Cursor::new(stream), 100) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("stream should not have parsed"),
    }
}

fn parse(stream: &[u8], cap: usize) -> Vec<(u32, Vec<u8>)> {
    let mut cursor = Cursor::new(stream);
    sync::parse_next_blocks(&mut cursor, cap)
        .expect("stream must parse")
        .expect("stream must yield blocks")
        .into_iter()
        .map(|b| (b.height, b.txs.iter().map(|t| t[1]).collect()))
        .collect()
}

// ---------------------------------------------------------------------------
// Against the real stream
// ---------------------------------------------------------------------------

/// The node serves footer framing, with 9-byte markers and `0x03` full raw
/// transactions. Pin that, because every test we had used the other framing.
#[test]
fn the_real_mainnet_stream_is_footer_framed() {
    let mut cursor = Cursor::new(FOOTER_FIXTURE);
    let blocks = sync::parse_next_blocks(&mut cursor, 100).unwrap().unwrap();

    let seen: Vec<(u32, usize)> = blocks.iter().map(|b| (b.height, b.txs.len())).collect();
    assert_eq!(seen, FIXTURE_BLOCKS, "block attribution disagrees with the explorer");

    for b in &blocks {
        for t in &b.txs {
            assert_eq!(
                t[0], 0x03,
                "the node serves full raw transactions; 0x03 is the tx version, not a tag"
            );
        }
    }
}

/// The specific shape of the old bug: first block over-filled, last block
/// empty, total preserved. Asserting the total alone would have passed
/// throughout, which is why it went unnoticed.
#[test]
fn no_block_in_the_real_stream_is_empty_or_doubled() {
    let mut cursor = Cursor::new(FOOTER_FIXTURE);
    let blocks = sync::parse_next_blocks(&mut cursor, 100).unwrap().unwrap();

    assert!(
        blocks.iter().all(|b| !b.txs.is_empty()),
        "a block parsed as empty means its transaction was attributed to the block before it"
    );
    assert_eq!(blocks.first().unwrap().txs.len(), 1, "the first block must not absorb the second's");
    assert_eq!(
        blocks.iter().map(|b| b.txs.len()).sum::<usize>(),
        FIXTURE_BLOCKS.iter().map(|(_, n)| n).sum::<usize>()
    );
}

/// Capping mid-stream must yield a prefix of the uncapped parse, or a consumer
/// that syncs in batches lands on a different history than one that does not.
#[test]
fn a_capped_parse_is_a_prefix_of_the_full_parse() {
    let full = parse(FOOTER_FIXTURE, 100);
    for cap in 1..=full.len() {
        assert_eq!(parse(FOOTER_FIXTURE, cap), full[..cap], "cap {cap}");
    }
}

// ---------------------------------------------------------------------------
// Attribution, both framings
// ---------------------------------------------------------------------------

/// Uneven transaction counts are what expose a one-block shift. With one
/// transaction per block the wrong answer still has the right shape.
#[test]
fn footer_framing_attributes_uneven_blocks_correctly() {
    let mut s = Vec::new();
    s.extend(tx(1));
    s.extend(footer(100));
    s.extend(tx(2));
    s.extend(footer(200));
    s.extend(tx(3));
    s.extend(tx(4));
    s.extend(footer(300));
    s.extend(tx(5));
    s.extend(footer(400));

    assert_eq!(
        parse(&s, 100),
        vec![(100, vec![1]), (200, vec![2]), (300, vec![3, 4]), (400, vec![5])]
    );
}

#[test]
fn header_framing_attributes_uneven_blocks_correctly() {
    let mut s = Vec::new();
    s.extend(header(100));
    s.extend(tx(1));
    s.extend(header(200));
    s.extend(tx(2));
    s.extend(header(300));
    s.extend(tx(3));
    s.extend(tx(4));
    s.extend(header(400));
    s.extend(tx(5));

    assert_eq!(
        parse(&s, 100),
        vec![(100, vec![1]), (200, vec![2]), (300, vec![3, 4]), (400, vec![5])]
    );
}

/// The case a "was anything buffered?" rule cannot get right: under footer
/// framing an empty first block looks exactly like a header.
#[test]
fn footer_framing_survives_an_empty_first_block() {
    let mut s = Vec::new();
    s.extend(footer(100));
    s.extend(tx(1));
    s.extend(footer(200));

    assert_eq!(parse(&s, 100), vec![(100, vec![]), (200, vec![1])]);
}

/// An empty block anywhere else must not swallow the next block's work either.
#[test]
fn footer_framing_survives_an_empty_middle_block() {
    let mut s = Vec::new();
    s.extend(tx(1));
    s.extend(footer(100));
    s.extend(footer(200));
    s.extend(tx(2));
    s.extend(footer(300));

    assert_eq!(parse(&s, 100), vec![(100, vec![1]), (200, vec![]), (300, vec![2])]);
}

// ---------------------------------------------------------------------------
// Malformed streams
// ---------------------------------------------------------------------------

/// Mixing the conventions has no correct reading. Erroring beats picking one.
#[test]
fn a_stream_that_switches_framing_is_rejected() {
    let mut s = Vec::new();
    s.extend(tx(1));
    s.extend(footer(100));
    s.extend(header(200));
    s.extend(tx(2));

    let err = parse_err(&s);
    assert!(err.contains("framing"), "unexpected error: {err}");
}

#[test]
fn a_marker_of_unknown_length_is_rejected() {
    let mut s = Vec::new();
    s.extend(packet(&[0x5du8, 1, 0, 0, 0, 7])); // 6 bytes: neither framing
    let err = parse_err(&s);
    assert!(err.contains("Block marker"), "unexpected error: {err}");
}

/// A footer stream cut off mid-block must say so rather than hand the
/// transactions to whichever block happens to be last.
#[test]
fn a_truncated_footer_batch_is_rejected() {
    let mut s = Vec::new();
    s.extend(tx(1));
    s.extend(footer(100));
    s.extend(tx(2)); // its marker never arrives

    let err = parse_err(&s);
    assert!(err.contains("truncated"), "unexpected error: {err}");
}

/// Transactions only, no marker at all: nothing can be placed.
#[test]
fn a_stream_with_no_markers_is_rejected() {
    let mut s = Vec::new();
    s.extend(tx(1));
    let err = parse_err(&s);
    assert!(err.contains("truncated"), "unexpected error: {err}");
}
