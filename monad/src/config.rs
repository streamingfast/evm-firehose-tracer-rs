//! Configuration for the Monad Firehose tracer
//!
//! # Event ordering

//!
//! - execute_block.cpp` promise chain enforcing serial merge+event-emit order
//! - execute_transaction.cpp execute_final() emits all txn events before merge
//! - record_txn_events.cpp record_txn_output_events() emits TxnEvmOutput → TxnLog* → TxnCallFrame* → AccountAccessListHeader → AccountAccess* → StorageAccess → TxnEnd in one shot
//! - exec_event_ctypes.h `MONAD_FLOW_TXN_ID` in content_ext, monad_exec_account_access_context enum
use serde::{Deserialize, Serialize};

/// Configuration for the Firehose tracer for Monad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirehosePluginConfig {
    /// Chain ID for the blockchain
    pub chain_id: u64,
    /// Network name (e.g., "monad", "monad-testnet")
    pub network_name: String,
    /// Enable debug mode
    pub debug: bool,
    /// Buffer size for event processing
    pub buffer_size: usize,
    /// Enable no-op mode
    pub no_op: bool,
}

impl Default for FirehosePluginConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            network_name: "monad".to_string(),
            debug: false,
            buffer_size: 1024,
            no_op: false,
        }
    }
}

impl FirehosePluginConfig {
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

    /// Set no-op mode
    pub fn with_no_op(mut self, no_op: bool) -> Self {
        self.no_op = no_op;
        self
    }
}
