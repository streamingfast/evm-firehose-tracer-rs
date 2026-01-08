//! Configuration for the Monad Firehose tracer

use serde::{Deserialize, Serialize};

/// Configuration for the Firehose tracer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerConfig {
    /// Chain ID for the blockchain
    pub chain_id: u64,
    /// Network name (e.g., "monad", "monad-testnet")
    pub network_name: String,
    /// Enable debug mode
    pub debug: bool,
    /// Buffer size for event processing
    pub buffer_size: usize,
    /// Output format for Firehose messages
    pub output_format: OutputFormat,
    /// Enable no-op mode
    pub no_op: bool,

    // Temporary flags for performance profiling - REMOVE AFTER OPTIMIZATION
    /// Skip event mapping (JSON parse, hex decode, data structures) - CAUSES MEMORY LEAK
    pub skip_event_mapping: bool,
    /// Skip block finalization (bloom filter, gas calculations)
    pub skip_finalization: bool,
    /// Skip protobuf serialization
    pub skip_serialization: bool,
    /// Skip base64 encoding and stdout output
    pub skip_output: bool,
    /// Skip logging (info! statements with hex encoding)
    pub skip_logging: bool,
    /// Skip everything after event mapper returns (all post-processing)
    pub skip_after_mapper: bool,
    /// Process events but skip JSON parsing and data building (just call finalize immediately)
    pub skip_event_processing: bool,
}

/// Output format for Firehose messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Standard Firehose protocol format
    Firehose,
    /// JSON format for debugging
    Json,
    /// Binary protobuf format
    Binary,
}

impl Default for TracerConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            network_name: "monad".to_string(),
            debug: false,
            buffer_size: 1024,
            output_format: OutputFormat::Firehose,
            no_op: false,
            skip_event_mapping: false,
            skip_finalization: false,
            skip_serialization: false,
            skip_output: false,
            skip_logging: false,
            skip_after_mapper: false,
            skip_event_processing: false,
        }
    }
}

impl TracerConfig {
    /// Create a new tracer configuration
    pub fn new(chain_id: u64, network_name: String) -> Self {
        Self {
            chain_id,
            network_name,
            ..Default::default()
        }
    }

    /// Set debug mode
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Set buffer size
    pub fn with_buffer_size(mut self, buffer_size: usize) -> Self {
        self.buffer_size = buffer_size;
        self
    }

    /// Set output format
    pub fn with_output_format(mut self, output_format: OutputFormat) -> Self {
        self.output_format = output_format;
        self
    }

    /// Set no-op mode
    pub fn with_no_op(mut self, no_op: bool) -> Self {
        self.no_op = no_op;
        self
    }

    // TEMPORARY - REMOVE AFTER OPTIMIZATION
    /// Skip event mapping
    pub fn with_skip_event_mapping(mut self, skip: bool) -> Self {
        self.skip_event_mapping = skip;
        self
    }

    /// Skip block finalization
    pub fn with_skip_finalization(mut self, skip: bool) -> Self {
        self.skip_finalization = skip;
        self
    }

    /// Skip protobuf serialization
    pub fn with_skip_serialization(mut self, skip: bool) -> Self {
        self.skip_serialization = skip;
        self
    }

    /// Skip output (base64 + stdout)
    pub fn with_skip_output(mut self, skip: bool) -> Self {
        self.skip_output = skip;
        self
    }

    /// Skip logging
    pub fn with_skip_logging(mut self, skip: bool) -> Self {
        self.skip_logging = skip;
        self
    }

    /// Skip everything after mapper
    pub fn with_skip_after_mapper(mut self, skip: bool) -> Self {
        self.skip_after_mapper = skip;
        self
    }

    /// Skip event processing (JSON parse, data building)
    pub fn with_skip_event_processing(mut self, skip: bool) -> Self {
        self.skip_event_processing = skip;
        self
    }
}
