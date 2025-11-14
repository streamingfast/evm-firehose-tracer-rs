//! Monad Execution Events Plugin
//!
//! This crate provides the integration layer between Monad's execution events
//! system and the Firehose tracer. It handles consuming events from Monad's
//! shared memory queues and processing them for the tracer.

pub mod event_processor;
pub mod monad_consumer;

pub use event_processor::EventProcessor;
pub use monad_consumer::{MonadConsumer, ProcessedEvent};

use eyre::Result;

/// Configuration for the Monad plugin
#[derive(Debug, Clone)]
pub struct PluginConfig {
    /// Path to the Monad event ring buffer
    pub event_ring_path: String,
    /// Buffer size for event processing
    pub buffer_size: usize,
    /// Timeout for event consumption in milliseconds
    pub timeout_ms: u64,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            event_ring_path: "/tmp/monad_events".to_string(),
            buffer_size: 1024,
            timeout_ms: 1000,
        }
    }
}

/// Initialize the Monad plugin with the given configuration
pub async fn initialize_plugin(config: PluginConfig) -> Result<MonadConsumer> {
    tracing::info!("Initializing Monad plugin with config: {:?}", config);

    let consumer = MonadConsumer::new(config).await?;

    tracing::info!("Monad plugin initialized successfully");
    Ok(consumer)
}
