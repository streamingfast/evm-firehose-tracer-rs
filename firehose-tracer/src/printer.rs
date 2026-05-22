//! Firehose printer functions
//!
//! This module contains functions for writing Firehose protocol output,
//! separated from the main tracer logic (similar to Golang's tracer_printer.go).

use super::finality::FinalityStatus;
use crate::pb::sf::ethereum::r#type::v2::Block;
use base64_simd::STANDARD as B64_SIMD;
use prost::Message;
use std::io::Write;

/// Print a formatted message to the Firehose output stream
pub fn print_to_firehose<W: Write>(
    writer: &mut W,
    prefix: &str,
    args: &str,
    args2: &str,
    args3: &str,
) {
    let line = format!("{} {} {} {}\n", prefix, args, args2, args3);
    let _ = writer.write_all(line.as_bytes());
    let _ = writer.flush();
}

/// Print a block to the Firehose output stream in the protocol format.
///
/// Output format (one line):
///
///   FIRE BLOCK <block_num> <flash_block_idx> <block_hash> <prev_num> <prev_hash> <lib_num> <timestamp_unix_nano> <payload_base64>
///
/// flash_block_idx is 0 for non-flash blocks; for flash blocks it is the current
/// flash block index plus 1000 when this is the final iteration for the block.
pub fn print_block_to_firehose<W: Write>(
    writer: &mut W,
    block: Block,
    lib_num: u64,
    printed_flash_block_index: u64,
) {
    let block_number = block.number;
    let block_hash = hex::encode(&block.hash);

    // Get previous block info from header
    let (previous_block_number, previous_block_hash, timestamp_ns) =
        if let Some(header) = &block.header {
            let previous_number = if block_number > 0 {
                block_number - 1
            } else {
                0
            };
            let previous_hash = hex::encode(&header.parent_hash);
            let timestamp_ns = if let Some(timestamp) = &header.timestamp {
                timestamp.seconds as u64 * 1_000_000_000 + timestamp.nanos as u64
            } else {
                0
            };
            (previous_number, previous_hash, timestamp_ns)
        } else {
            // Fallback if header is missing
            let previous_number = if block_number > 0 {
                block_number - 1
            } else {
                0
            };
            (previous_number, "0".to_string(), 0)
        };

    // Marshal the protobuf block to bytes
    let marshalled = block.encode_to_vec();

    // Encode the marshalled protobuf to base64
    let encoded = B64_SIMD.encode_to_string(&marshalled);

    let line = format!(
        "FIRE BLOCK {} {} {} {} {} {} {} {}\n",
        block_number,
        printed_flash_block_index,
        block_hash,
        previous_block_number,
        previous_block_hash,
        lib_num,
        timestamp_ns,
        encoded
    );

    let _ = writer.write_all(line.as_bytes());
    let _ = writer.flush();
}

/// Computes the last irreversible block number to advertise for the given block
/// using the current finality status. Mirrors the Optimism Geth firehose tracer logic:
///   - When finality is known, use LastFinalizedBlock.
///   - When finality is empty, fall back to max(blockNumber-200, 0).
///   - In all cases, never let libNum fall more than 200 blocks behind blockNumber.
pub fn compute_lib_num(block_number: u64, finality: &FinalityStatus) -> u64 {
    let mut lib_num = finality.last_irreversible_block_number();

    if finality.is_empty() {
        lib_num = if block_number >= 200 {
            block_number - 200
        } else {
            0
        };
    }

    // Cap: libNum must never trail blockNumber by more than 200 blocks.
    if block_number >= 200 && lib_num < block_number - 200 {
        lib_num = block_number - 200;
    }

    lib_num
}

/// Returns the value to emit in the flash-block-index slot of the FIRE BLOCK line.
/// Returns 0 for non-flash blocks, equals the flash block index for partials,
/// and equals `idx + 1000` for the final flash block iteration.
pub fn compute_printed_flash_block_index(flash_block_index: Option<&u64>, is_final: bool) -> u64 {
    match flash_block_index {
        None => 0,
        Some(&idx) => {
            if is_final {
                idx + 1000
            } else {
                idx
            }
        }
    }
}

/// Prints block in Firehose protocol format to stdout
/// (convenience function for backward compatibility)
pub fn firehose_block_to_stdout(block: Block, finality_status: FinalityStatus) {
    let mut stdout = std::io::stdout();
    let lib_num = compute_lib_num(block.number, &finality_status);
    print_block_to_firehose(&mut stdout, block, lib_num, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_lib_num_empty_finality() {
        let fs = FinalityStatus::default();

        assert_eq!(compute_lib_num(0, &fs), 0);
        assert_eq!(compute_lib_num(1, &fs), 0);
        assert_eq!(compute_lib_num(199, &fs), 0);
        assert_eq!(compute_lib_num(200, &fs), 0);
        assert_eq!(compute_lib_num(201, &fs), 1);
        assert_eq!(compute_lib_num(1000, &fs), 800);
    }

    #[test]
    fn test_compute_lib_num_with_finality() {
        let mut fs = FinalityStatus::default();
        fs.set_last_finalized_block(400);
        assert_eq!(compute_lib_num(500, &fs), 400);

        let mut fs = FinalityStatus::default();
        fs.set_last_finalized_block(300);
        assert_eq!(compute_lib_num(500, &fs), 300);

        let mut fs = FinalityStatus::default();
        fs.set_last_finalized_block(500);
        assert_eq!(compute_lib_num(500, &fs), 500);

        let mut fs = FinalityStatus::default();
        fs.set_last_finalized_block(499);
        assert_eq!(compute_lib_num(500, &fs), 499);
    }

    #[test]
    fn test_compute_lib_num_clamped() {
        let mut fs = FinalityStatus::default();
        fs.set_last_finalized_block(100);
        assert_eq!(compute_lib_num(500, &fs), 300); // clamped to 500-200

        let mut fs = FinalityStatus::default();
        fs.set_last_finalized_block(1);
        assert_eq!(compute_lib_num(1000, &fs), 800);

        let mut fs = FinalityStatus::default();
        fs.set_last_finalized_block(1);
        assert_eq!(compute_lib_num(250, &fs), 50);
    }

    #[test]
    fn test_compute_lib_num_small_block_no_clamp() {
        let mut fs = FinalityStatus::default();
        fs.set_last_finalized_block(10);
        assert_eq!(compute_lib_num(50, &fs), 10); // 50-10=40 < 200, no clamp
    }

    #[test]
    fn test_compute_printed_flash_block_index() {
        // nil → not flash block
        assert_eq!(compute_printed_flash_block_index(None, false), 0);

        // partial index
        assert_eq!(compute_printed_flash_block_index(Some(&1), false), 1);
        assert_eq!(compute_printed_flash_block_index(Some(&9), false), 9);

        // final index
        assert_eq!(compute_printed_flash_block_index(Some(&10), true), 1010);
        assert_eq!(compute_printed_flash_block_index(Some(&1), true), 1001);
        assert_eq!(compute_printed_flash_block_index(Some(&0), true), 1000);
    }
}
