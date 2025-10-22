use super::finality::FinalityStatus;
use crate::pb::sf::ethereum::r#type::v2::Block;
use base64::{Engine as _, engine::general_purpose};
use prost::Message;

/// Prints block in Firehose protocol format to stdout
pub(super) fn firehose_block_to_stdout(block: Block, finality_status: FinalityStatus) {
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
        // FIXME: We should have access to the genesis block to perform this operation to ensure we never go below the
        // the genesis block
        if block_number >= 200 {
            block_number - 200
        } else {
            0
        }
    } else {
        finality_status.last_irreversible_block_number()
    };

    // Marshal the protobuf block to bytes
    let marshalled = block.encode_to_vec();

    // Print in Firehose format: FIRE BLOCK <blockNumber> <blockHash> <previousBlockNumber> <previousBlockHash> <libNum> <timestamp>
    // **Important* The final space in the print template is mandatory!
    print!(
        "FIRE BLOCK {} {} {} {} {} {} ",
        block_number, block_hash, previous_block_number, previous_block_hash, lib_num, timestamp_ns
    );

    // Encode the marshalled protobuf to base64 and print it
    let encoded = general_purpose::STANDARD.encode(&marshalled);
    print!("{}", encoded);

    // Print final newline and flush
    println!();

    use std::io::{self, Write};
    let _ = io::stdout().flush();
}

/// Prints init message in Firehose protocol format to stdout
pub(super) fn firehose_init_to_stdout(protocol_version: &str, client_name: &str) {
    println!(
        "FIRE INIT {} {} {}",
        protocol_version,
        client_name,
        env!("CARGO_PKG_VERSION")
    );
}
