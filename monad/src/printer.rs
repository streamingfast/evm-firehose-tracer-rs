//! Firehose protocol printer

use crate::{Block, FinalityStatus, TracerConfig, TRACER_NAME, TRACER_VERSION};
use eyre::Result;
use tracing::{debug, info};

/// Prints Firehose protocol messages to stdout
pub struct FirehosePrinter {
    config: TracerConfig,
    finality: FinalityStatus,
    initialized: bool,
}

impl FirehosePrinter {
    /// Create a new Firehose printer
    pub fn new(config: TracerConfig) -> Self {
        Self {
            config,
            finality: FinalityStatus::new(),
            initialized: false,
        }
    }

    /// Print the FIRE INIT message
    pub fn print_init(&mut self) -> Result<()> {
        if !self.initialized {
            println!("FIRE INIT {} {}", TRACER_VERSION, TRACER_NAME);
            self.initialized = true;
            info!("Printed FIRE INIT message");
        }
        Ok(())
    }

    /// Print a FIRE BLOCK message
    pub fn print_block(&mut self, block: &Block) -> Result<()> {
        // Serialize the block to protobuf bytes
        let block_bytes = self.serialize_block(&block)?;

        // Encode as base64
        use base64::Engine;
        let block_b64 = base64::engine::general_purpose::STANDARD.encode(&block_bytes);

        // Format block hash and parent hash as hex (without 0x prefix)
        let block_hash = hex::encode(&block.hash);
        let parent_hash = if let Some(ref header) = block.header {
            hex::encode(&header.parent_hash)
        } else {
            "0".to_string()
        };

        // Get parent number (block number - 1)
        let parent_num = if block.number > 0 {
            block.number - 1
        } else {
            0
        };

        // Get timestamp in nanoseconds (required by Firehose protocol v3)
        let timestamp_nanos = if let Some(ref header) = block.header {
            if let Some(ref ts) = header.timestamp {
                // Convert seconds to nanoseconds
                (ts.seconds as u64) * 1_000_000_000 + (ts.nanos as u64)
            } else {
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64
            }
        } else {
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64
        };

        // Print the FIRE BLOCK line
        // Note: Hashes should NOT have 0x prefix for Firehose protocol v3
        println!(
            "FIRE BLOCK {} {} {} {} {} {} {}",
            block.number,
            block_hash,
            parent_num,
            parent_hash,
            self.finality.lib_num(),
            timestamp_nanos,
            block_b64
        );

        debug!("Printed FIRE BLOCK for block {}", block.number);

        // Debug: Log system calls
        if !block.system_calls.is_empty() {
            debug!("Block {} has {} system calls:", block.number, block.system_calls.len());
            for (i, call) in block.system_calls.iter().enumerate() {
                debug!("  SystemCall {}: caller={}, address={}, input={}",
                       i,
                       hex::encode(&call.caller),
                       hex::encode(&call.address),
                       hex::encode(&call.input));
            }
        }

        Ok(())
    }

    /// Serialize block to protobuf bytes
    fn serialize_block(&self, block: &Block) -> Result<Vec<u8>> {
        use prost::Message;
        let mut buf = Vec::new();
        block
            .encode(&mut buf)
            .map_err(|e| eyre::eyre!("Failed to encode block: {}", e))?;
        Ok(buf)
    }

    /// Update finality status
    pub fn update_finality(&mut self, lib_num: u64) {
        self.finality.update_lib(lib_num);
    }
}
