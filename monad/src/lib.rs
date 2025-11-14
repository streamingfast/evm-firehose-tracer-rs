//! Monad Firehose Tracer
//!
//! This crate provides the core Firehose tracer implementation for Monad,
//! handling the transformation of Monad execution events into Firehose
//! protocol messages.

pub mod config;
pub mod event_mapper;
pub mod finality;
pub mod ordinal;
pub mod printer;
pub mod tracer;

pub use config::{OutputFormat, TracerConfig};
pub use event_mapper::EventMapper;
pub use finality::FinalityStatus;
pub use ordinal::Ordinal;
pub use printer::FirehosePrinter;
pub use tracer::FirehoseTracer;

// Re-export commonly used types
pub use pb::sf::ethereum::r#type::v2::{Block, BlockHeader, TransactionTrace};
pub use monad_plugin::{MonadConsumer, ProcessedEvent};

/// Version of the Firehose tracer
pub const TRACER_VERSION: &str = "1.0";

/// Name of the Firehose tracer
pub const TRACER_NAME: &str = "monad-firehose-tracer";
