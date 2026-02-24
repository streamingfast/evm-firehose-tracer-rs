pub mod config;
pub mod finality;
// pub mod inspector; // TODO: Not yet implemented
pub mod logging;
pub mod mapper;
mod ordinal;
pub mod printer;
mod tracer;
mod tracer_checks;
pub mod types;
mod version;

// Re-export public items to maintain the same API
pub use config::{ChainConfig, Config, Rules};
// pub use inspector::FirehoseInspector; // TODO: Not yet implemented
pub use logging::HexView;
pub use tracer::Tracer;
pub use types::{
    BlockData, BlockEvent, CallFrame, CallType, FinalizedBlockRef, LogData, OpcodeScopeData,
    ReceiptData, TxEvent, UncleData, WithdrawalData,
};
pub use version::{BLOCK_VERSION, PROTOCOL_VERSION};

// Re-export pb from the pb crate
pub use pb;

// // Type aliases for generic Node types
// /// Type alias for RecoveredBlock that can be used with any Node that implements FullNodeComponents
// pub type RecoveredBlock<Node> = reth::primitives::RecoveredBlock<
//     <<<Node as reth::api::FullNodeTypes>::Types as reth::api::NodeTypes>::Primitives as reth::api::NodePrimitives>::Block,
// >;

// /// Type alias for ChainSpec that can be used with any Node that implements FullNodeComponents
// pub type ChainSpec<Node> =
//     <<Node as reth::api::FullNodeTypes>::Types as reth::api::NodeTypes>::ChainSpec;

// /// Type alias for SignedTx from a Node primitives
// pub type SignedTx<Node> =
//     <<<Node as reth::api::FullNodeTypes>::Types as reth::api::NodeTypes>::Primitives as reth::api::NodePrimitives>::SignedTx;
