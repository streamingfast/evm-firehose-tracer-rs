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
}
