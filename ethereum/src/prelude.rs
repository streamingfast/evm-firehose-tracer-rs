/// Type alias for:
///     ```
///     reth::primitives::RecoveredBlock<<<<Node as FullNodeTypes>::Types as NodeTypes>::Primitives as NodePrimitives>::Block>;
///     ```
///
///  That can be used with any Node that implements FullNodeComponents
pub type RecoveredBlock<Node> = reth::primitives::RecoveredBlock<
    <<<Node as reth::api::FullNodeTypes>::Types as reth::api::NodeTypes>::Primitives as reth::api::NodePrimitives>::Block,
>;

/// Type alias for ChainSpec that can be used with any Node that implements FullNodeComponents
pub type ChainSpec<Node> =
    <<Node as reth::api::FullNodeTypes>::Types as reth::api::NodeTypes>::ChainSpec;

/// Type alias for SignedTx from a Node primitives
pub type SignedTx<Node> =
    <<<Node as reth::api::FullNodeTypes>::Types as reth::api::NodeTypes>::Primitives as reth::api::NodePrimitives>::SignedTx;

// Re-export commonly used items directly at module level for convenience
pub use alloy_primitives::U256;
pub use futures_util::TryStreamExt;
pub use reth::api::FullNodeComponents;
pub use reth::chainspec::EthChainSpec;
pub use reth::core::primitives::AlloyBlockHeader;
pub use reth_tracing::tracing::{debug, info};
