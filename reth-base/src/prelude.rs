//! Common imports for the Base Firehose tracer binary.
//!
//! Combines the generic reth-firehose prelude with Base-node-specific types so
//! that `main.rs` (and any future modules in this crate) only need a single
//! glob import.

// ---------------------------------------------------------------------------
// Re-export the generic reth-firehose prelude
// ---------------------------------------------------------------------------

// Reth core types
pub use reth_cli_util;
pub use reth_evm::{evm::Evm, system_calls::SystemCaller};
pub use reth_exex::{ExExContext, ExExEvent, ExExNotification};
pub use reth_node_api::{ConfigureEvm, FullNodeComponents};
pub use reth_provider::{StateProviderBox, StateProviderFactory};
pub use reth_revm::database::StateProviderDatabase;
pub use reth_tracing::tracing::{debug, error, info, trace, warn};

// Alloy types
pub use alloy_consensus::{BlockHeader, Transaction};
pub use alloy_eips;
pub use alloy_primitives::{B256, U256};

// Other common imports
pub use eyre;
pub use std::path::PathBuf;
pub use std::sync::Arc;

// Generic node type aliases (parameterised over any FullNodeComponents impl)
pub use reth_firehose::prelude::{ChainSpec, Receipt, RecoveredBlock, SignedTx};

// ---------------------------------------------------------------------------
// Base-node-specific re-exports
// ---------------------------------------------------------------------------

// Node runner and extension machinery
pub use base_node_runner::{BaseNodeExtension, BaseNodeRunner, FromExtensionConfig, NodeHooks};

// Rollup CLI arguments required by BaseNodeRunner::new
pub use base_node_core::args::RollupArgs;
