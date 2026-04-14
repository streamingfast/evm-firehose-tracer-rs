//! Configuration for the Monad Firehose tracer
use serde::{Deserialize, Serialize};

/// Configuration for the Firehose tracer for Monad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonadConsumerPlugin {
    /// Chain ID for the blockchain
    pub chain_id: u64,
    /// Enable debug mode
    pub debug: bool,
    /// Buffer size for event processing
    pub event_channel_buffer_size: usize,
    /// Enable no-op mode
    pub no_op: bool,
}

impl Default for MonadConsumerPlugin {
    fn default() -> Self {
        Self {
            chain_id: 1,
            debug: false,
            event_channel_buffer_size: 1024,
            no_op: false,
        }
    }
}

impl MonadConsumerPlugin {
    /// Create a new tracer configuration
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            ..Default::default()
        }
    }

    /// Set debug mode
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Set buffer size
    pub fn with_event_channel_buffer_size(mut self, event_channel_buffer_size: usize) -> Self {
        self.event_channel_buffer_size = event_channel_buffer_size;
        self
    }

    /// Set no-op mode
    pub fn with_no_op(mut self, no_op: bool) -> Self {
        self.no_op = no_op;
        self
    }
}
