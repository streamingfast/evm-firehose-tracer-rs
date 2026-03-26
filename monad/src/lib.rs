//! Monad Firehose Tracer

pub mod config;
pub mod event_mapper;
pub mod ring_consumer;
pub mod tracer;

pub use config::FirehosePluginConfig;
pub use event_mapper::EventMapper;
pub use ring_consumer::{MonadConsumer, PluginConfig};
pub use tracer::FirehosePlugin;

// Re-export commonly used types
pub use firehose::pb::sf::ethereum::r#type::v2::{Block, BlockHeader, TransactionTrace};

/// Version of the Firehose tracer
pub const TRACER_VERSION: &str = "1.0";

/// Name of the Firehose tracer
pub const TRACER_NAME: &str = "monad-firehose-tracer";
