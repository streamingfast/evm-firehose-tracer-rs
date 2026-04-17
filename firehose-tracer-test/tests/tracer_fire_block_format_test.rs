// Tests for the FIRE BLOCK output line format.
//
// Wire format:
//
//   FIRE BLOCK <block_num> <flash_block_idx> <block_hash> <prev_num> <prev_hash> <lib_num> <timestamp_unix_nano> <payload_base64>
//
// Every test in this file validates ALL header fields, not just the one(s) under
// test, to catch regressions in field ordering or formatting.

use alloy_primitives::{Bloom, Bytes, B256};
use firehose_tracer::types::{BlockData, BlockEvent, FinalizedBlockRef, FlashBlockData};
use firehose_tracer_test::{hash32, miner_addr, test_block, FirehoseBlockEntry, TracerTester};

/// Validates every wire-level header field of a FirehoseBlockEntry against expected values.
fn assert_all_fields(
    entry: &FirehoseBlockEntry,
    want_block_num: u64,
    want_flash_idx: u64,
    want_block_hash: B256,
    want_prev_num: u64,
    want_prev_hash: B256,
    want_lib_num: u64,
    want_timestamp: u64, // Unix seconds from BlockData.time
) {
    assert_eq!(want_block_num, entry.block_num, "block_num");
    assert_eq!(want_flash_idx, entry.flash_block_idx, "flash_block_idx");
    assert_eq!(
        hex::encode(want_block_hash.as_slice()),
        entry.block_hash,
        "block_hash"
    );
    assert_eq!(want_prev_num, entry.prev_num, "prev_num");
    assert_eq!(
        hex::encode(want_prev_hash.as_slice()),
        entry.prev_hash,
        "prev_hash"
    );
    assert_eq!(want_lib_num, entry.lib_num, "lib_num");
    assert_eq!(
        (want_timestamp as i64) * 1_000_000_000,
        entry.timestamp_nano,
        "timestamp_nano"
    );

    // Also verify the protobuf payload is consistent with the header
    assert_eq!(want_block_num, entry.block.number, "protobuf block.Number");
    assert_eq!(
        want_block_hash.as_slice(),
        entry.block.hash.as_slice(),
        "protobuf block.Hash"
    );
    let header = entry.block.header.as_ref().expect("protobuf block.Header");
    assert_eq!(
        want_prev_hash.as_slice(),
        header.parent_hash.as_slice(),
        "protobuf block.Header.ParentHash"
    );
}

/// Creates a minimal BlockData for the given block number.
fn block_data_with_number(number: u64) -> BlockData {
    let parent_num = if number == 0 { 0 } else { number - 1 };

    BlockData {
        number,
        hash: hash32(number),
        parent_hash: hash32(parent_num),
        uncle_hash: B256::ZERO,
        coinbase: miner_addr(),
        root: B256::ZERO,
        tx_hash: B256::ZERO,
        receipt_hash: B256::ZERO,
        bloom: Bloom::ZERO,
        difficulty: alloy_primitives::U256::ZERO,
        gas_limit: 30_000_000,
        gas_used: 0,
        time: 1704067200 + number,
        extra: Bytes::new(),
        mix_digest: B256::ZERO,
        nonce: 0,
        base_fee: None,
        uncles: vec![],
        size: 509,
        withdrawals: vec![],
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_root: None,
        requests_hash: None,
        tx_dependency: None,
    }
}

// ===========================================================================
// lib_num tests
// ===========================================================================

#[test]
fn test_fire_block_format_lib_num_empty_finality() {
    // When no finalized block is reported, lib_num follows max(block_num-200, 0) fallback.
    let cases: Vec<(u64, u64)> = vec![
        (100, 0),   // block_below_200
        (200, 0),   // block_at_200
        (201, 1),   // block_at_201
        (500, 300), // block_at_500
    ];

    for (block_number, expected_lib_num) in cases {
        let bd = block_data_with_number(block_number);
        let mut tester = TracerTester::new();

        tester.tracer.on_block_start(BlockEvent::new(bd.clone()));
        tester.tracer.on_block_end(None);

        let entries = tester.parse_firehose_block_entries();
        assert_eq!(1, entries.len(), "block_number={block_number}");

        let prev_num = if block_number == 0 {
            0
        } else {
            block_number - 1
        };
        assert_all_fields(
            &entries[0],
            block_number,
            0,
            bd.hash,
            prev_num,
            bd.parent_hash,
            expected_lib_num,
            bd.time,
        );
    }
}

#[test]
fn test_fire_block_format_lib_num_with_finality() {
    // When a finalized block is reported, lib_num uses it directly.
    let cases: Vec<(u64, u64, u64)> = vec![
        (500, 450, 450), // finalized_close
        (500, 300, 300), // finalized_exactly_200_behind
        (500, 500, 500), // finalized_equal_to_block
    ];

    for (block_number, finalized_number, expected_lib_num) in cases {
        let bd = block_data_with_number(block_number);
        let mut tester = TracerTester::new();

        tester
            .tracer
            .on_block_start(
                BlockEvent::new(bd.clone()).with_finalized(FinalizedBlockRef {
                    number: finalized_number,
                    hash: None,
                }),
            );
        tester.tracer.on_block_end(None);

        let entries = tester.parse_firehose_block_entries();
        assert_eq!(1, entries.len());

        assert_all_fields(
            &entries[0],
            block_number,
            0,
            bd.hash,
            block_number - 1,
            bd.parent_hash,
            expected_lib_num,
            bd.time,
        );
    }
}

#[test]
fn test_fire_block_format_lib_num_clamped_at_200() {
    // Even when a finalized block is reported, lib_num is clamped to at most 200 blocks behind.
    let bd = block_data_with_number(500);
    let mut tester = TracerTester::new();

    tester.tracer.on_block_start(
        BlockEvent::new(bd.clone()).with_finalized(FinalizedBlockRef {
            number: 100,
            hash: None,
        }),
    );
    tester.tracer.on_block_end(None);

    let entries = tester.parse_firehose_block_entries();
    assert_eq!(1, entries.len());

    assert_all_fields(
        &entries[0],
        500,
        0,
        bd.hash,
        499,
        bd.parent_hash,
        300, // clamped to 500-200
        bd.time,
    );
}

#[test]
fn test_fire_block_format_lib_num_across_multiple_blocks() {
    // Finality set on one block does not leak to the next block.
    let mut tester = TracerTester::new();

    let bd300 = block_data_with_number(300);
    let bd301 = block_data_with_number(301);

    // Block 300, finalized at 250
    tester
        .tracer
        .on_block_start(
            BlockEvent::new(bd300.clone()).with_finalized(FinalizedBlockRef {
                number: 250,
                hash: None,
            }),
        );
    tester.tracer.on_block_end(None);

    // Block 301, no finality → empty heuristic → max(301-200,0) = 101
    tester.tracer.on_block_start(BlockEvent::new(bd301.clone()));
    tester.tracer.on_block_end(None);

    let entries = tester.parse_firehose_block_entries();
    assert_eq!(2, entries.len());

    assert_all_fields(
        &entries[0],
        300,
        0,
        bd300.hash,
        299,
        bd300.parent_hash,
        250,
        bd300.time,
    );
    assert_all_fields(
        &entries[1],
        301,
        0,
        bd301.hash,
        300,
        bd301.parent_hash,
        101,
        bd301.time,
    );
}

// ===========================================================================
// flash_block_idx tests
// ===========================================================================

#[test]
fn test_fire_block_format_flash_block_idx_non_flash() {
    // Non-flash blocks emit flash_block_idx=0.
    let mut tester = TracerTester::new();
    let bd = test_block().block.clone();

    tester.tracer.on_block_start(test_block());
    tester.tracer.on_block_end(None);

    let entries = tester.parse_firehose_block_entries();
    assert_eq!(1, entries.len());

    assert_all_fields(
        &entries[0],
        bd.number,
        0,
        bd.hash,
        bd.number - 1,
        bd.parent_hash,
        0,
        bd.time,
    );
}

#[test]
fn test_fire_block_format_flash_block_idx_partial() {
    // Partial flash blocks emit their flash block index directly.
    let mut tester = TracerTester::new();
    let bd = test_block().block.clone();

    tester.tracer.on_block_start(
        BlockEvent::new(bd.clone()).with_flash_block(FlashBlockData {
            idx: 5,
            is_final: false,
        }),
    );
    tester.tracer.on_block_end(None);

    let entries = tester.parse_firehose_block_entries();
    assert_eq!(1, entries.len());

    assert_all_fields(
        &entries[0],
        bd.number,
        5,
        bd.hash,
        bd.number - 1,
        bd.parent_hash,
        0,
        bd.time,
    );
}

#[test]
fn test_fire_block_format_flash_block_idx_final() {
    // The final flash block emits flash_block_idx = Idx + 1000.
    let mut tester = TracerTester::new();
    let bd = test_block().block.clone();

    tester.tracer.on_block_start(
        BlockEvent::new(bd.clone()).with_flash_block(FlashBlockData {
            idx: 10,
            is_final: true,
        }),
    );
    tester.tracer.on_block_end(None);

    let entries = tester.parse_firehose_block_entries();
    assert_eq!(1, entries.len());

    assert_all_fields(
        &entries[0],
        bd.number,
        1010,
        bd.hash,
        bd.number - 1,
        bd.parent_hash,
        0,
        bd.time,
    );
}

#[test]
fn test_fire_block_format_flash_block_idx_sequence() {
    // A sequence of partial then final flash blocks emits the correct indices.
    let mut tester = TracerTester::new();
    let bd = test_block().block.clone();

    // Partial 1
    tester.tracer.on_block_start(
        BlockEvent::new(bd.clone()).with_flash_block(FlashBlockData {
            idx: 1,
            is_final: false,
        }),
    );
    tester.tracer.snapshot_flash_block_for_next_iteration();
    tester.tracer.on_block_end(None);

    // Partial 3 (indices can skip)
    tester.tracer.on_block_start(
        BlockEvent::new(bd.clone()).with_flash_block(FlashBlockData {
            idx: 3,
            is_final: false,
        }),
    );
    tester.tracer.snapshot_flash_block_for_next_iteration();
    tester.tracer.on_block_end(None);

    // Final 5
    tester.tracer.on_block_start(
        BlockEvent::new(bd.clone()).with_flash_block(FlashBlockData {
            idx: 5,
            is_final: true,
        }),
    );
    tester.tracer.on_block_end(None);

    let entries = tester.parse_firehose_block_entries();
    assert_eq!(3, entries.len());

    assert_all_fields(
        &entries[0],
        bd.number,
        1,
        bd.hash,
        bd.number - 1,
        bd.parent_hash,
        0,
        bd.time,
    );
    assert_all_fields(
        &entries[1],
        bd.number,
        3,
        bd.hash,
        bd.number - 1,
        bd.parent_hash,
        0,
        bd.time,
    );
    assert_all_fields(
        &entries[2],
        bd.number,
        1005,
        bd.hash,
        bd.number - 1,
        bd.parent_hash,
        0,
        bd.time,
    );
}

// ===========================================================================
// prev_num edge case
// ===========================================================================

#[test]
fn test_fire_block_format_prev_num_block_zero() {
    // Block 0 emits prev_num=0 (not underflow).
    let bd = block_data_with_number(0);
    let mut tester = TracerTester::new();

    tester.tracer.on_block_start(BlockEvent::new(bd.clone()));
    tester.tracer.on_block_end(None);

    let entries = tester.parse_firehose_block_entries();
    assert_eq!(1, entries.len());

    assert_all_fields(
        &entries[0],
        0,       // block_num
        0,       // flash_block_idx
        bd.hash, // block_hash
        0,       // prev_num (no underflow)
        bd.parent_hash,
        0, // lib_num
        bd.time,
    );
}

// ===========================================================================
// Combined: finality + flash
// ===========================================================================

#[test]
fn test_fire_block_format_finality_and_flash_block() {
    // Both lib_num and flash_block_idx are set correctly on the same FIRE BLOCK line.
    let bd = block_data_with_number(500);
    let mut tester = TracerTester::new();

    tester.tracer.on_block_start(
        BlockEvent::new(bd.clone())
            .with_finalized(FinalizedBlockRef {
                number: 480,
                hash: None,
            })
            .with_flash_block(FlashBlockData {
                idx: 7,
                is_final: true,
            }),
    );
    tester.tracer.on_block_end(None);

    let entries = tester.parse_firehose_block_entries();
    assert_eq!(1, entries.len());

    assert_all_fields(
        &entries[0],
        500,
        1007, // 7 + 1000 (final)
        bd.hash,
        499,
        bd.parent_hash,
        480, // finalized
        bd.time,
    );
}
