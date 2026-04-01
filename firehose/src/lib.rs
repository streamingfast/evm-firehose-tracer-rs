mod callstack;
pub mod config;
mod deferred_call_state;
pub mod open_callstack;
mod eip7702;
pub mod finality;
pub mod logging;
pub mod mapper;
mod ordinal;
pub mod printer;
mod tracer;
pub mod types;
pub mod utils;
mod version;

// Re-export public items to maintain the same API
pub use config::{ChainClient, ChainConfig, Config, Rules};
pub use finality::FinalityStatus;
pub use logging::HexView;
pub use tracer::Tracer;
pub use types::{
    BlockData, BlockEvent, FinalizedBlockRef, LogData, Opcode, ReceiptData, StringError, TxEvent,
    TxType, UncleData, WithdrawalData,
};
pub use version::{BLOCK_VERSION, PROTOCOL_VERSION};

// pb module backed by buf-generated protobuf files in pb/src/
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
