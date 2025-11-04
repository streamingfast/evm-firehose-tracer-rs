// Common imports used across both ethereum and optimism implementations

// Reth core types
pub use reth::builder::NodeHandle;
pub use reth_cli_util;
pub use reth_node_api::{ConfigureEvm, FullNodeComponents};
pub use reth_provider::{StateProviderBox, StateProviderFactory};
pub use reth_evm::{evm::Evm, system_calls::SystemCaller};
pub use reth_exex::{ExExContext, ExExEvent, ExExNotification};
pub use reth_tracing::tracing::{debug, info};
pub use reth_revm::database::StateProviderDatabase;

// Alloy types
pub use alloy_primitives::{B256, U256};
pub use alloy_consensus::{BlockHeader, Transaction};
pub use alloy_eips;

// Other common imports
pub use eyre;
pub use futures_util::TryStreamExt;
pub use std::sync::Arc;
pub use std::path::PathBuf;

/// Type alias for RecoveredBlock that can be used with any Node that implements FullNodeComponents
pub type RecoveredBlock<Node> = reth::primitives::RecoveredBlock<
    <<<Node as reth_node_api::FullNodeTypes>::Types as reth_node_api::NodeTypes>::Primitives as reth_node_api::NodePrimitives>::Block,
>;

/// Type alias for ChainSpec that can be used with any Node that implements FullNodeComponents
pub type ChainSpec<Node> =
    <<Node as reth_node_api::FullNodeTypes>::Types as reth_node_api::NodeTypes>::ChainSpec;

/// Type alias for SignedTx from a Node primitives
pub type SignedTx<Node> =
    <<<Node as reth_node_api::FullNodeTypes>::Types as reth_node_api::NodeTypes>::Primitives as reth_node_api::NodePrimitives>::SignedTx;
