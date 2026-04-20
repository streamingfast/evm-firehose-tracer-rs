//! Firehose printer functions
//!
//! This module contains functions for writing Firehose protocol output,
//! separated from the main tracer logic (similar to Golang's tracer_printer.go).

use super::finality::FinalityStatus;
use crate::pb::sf::ethereum::r#type::v2::Block;
use base64::{engine::general_purpose, Engine as _};
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

/// Print a block to the Firehose output stream in the protocol format
pub fn print_block_to_firehose<W: Write>(
    writer: &mut W,
    block: Block,
    finality_status: &FinalityStatus,
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

    // Handle finalized block number using finality status
    let lib_num = if finality_status.is_empty() {
        if block_number >= 200 {
            block_number - 200
        } else {
            // Ideally we would have chain's genesis block height, 0 isn't harmful anyway and finality
            // should always be present which avoids this.
            0
        }
    } else {
        finality_status.last_irreversible_block_number()
    };

    // Marshal the protobuf block to bytes
    let marshalled = block.encode_to_vec();

    // Encode the marshalled protobuf to base64
    let encoded = general_purpose::STANDARD.encode(&marshalled);

    let line = format!(
        "FIRE BLOCK {} {} {} {} {} {} {}\n",
        block_number,
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

/// Prints block in Firehose protocol format to stdout
/// (convenience function for backward compatibility)
pub fn firehose_block_to_stdout(block: Block, finality_status: FinalityStatus) {
    let mut stdout = std::io::stdout();
    print_block_to_firehose(&mut stdout, block, &finality_status);
}
