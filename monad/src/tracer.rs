//! Main Firehose tracer implementation

use crate::{EventMapper, FirehosePrinter, MonadConsumer, ProcessedEvent, TracerConfig};
use eyre::Result;
use futures_util::StreamExt;
use std::time::Instant;
use tracing::{error, info, warn};

/// Main Firehose tracer for Monad
pub struct FirehoseTracer {
    config: TracerConfig,
    event_mapper: EventMapper,
    printer: FirehosePrinter,
    consumer: Option<MonadConsumer>,
    /// Current HEAD block number for LIB calculation
    current_head: u64,
    lib_delta: u64,
}

impl FirehoseTracer {
    /// Create a new Firehose tracer
    pub fn new(config: TracerConfig) -> Self {
        let event_mapper = EventMapper::new();
        let printer = FirehosePrinter::new(config.clone());

        Self {
            config,
            event_mapper,
            printer,
            consumer: None,
            current_head: 0,
            lib_delta: 10,
        }
    }

    /// Set the Monad consumer
    pub fn with_consumer(mut self, consumer: MonadConsumer) -> Self {
        self.consumer = Some(consumer);
        self
    }

    /// Get the tracer configuration
    pub fn config(&self) -> &TracerConfig {
        &self.config
    }

    /// Start the tracer
    pub async fn start(&mut self) -> Result<()> {
        info!(
            "Starting Firehose tracer for network: {}",
            self.config.network_name
        );

        // Print the FIRE INIT message
        self.printer.print_init()?;

        // Get the consumer
        let consumer = self
            .consumer
            .take()
            .ok_or_else(|| eyre::eyre!("No consumer configured"))?;

        // Start consuming events
        let mut event_stream = consumer.start_consuming().await?;

        info!("Tracer started, processing events...");

        // Main event processing loop
        while let Some(event) = event_stream.next().await {
            if let Err(e) = self.process_event(event).await {
                error!("Failed to process event: {}", e);
                if !self.config.debug {
                    // In production, we might want to continue processing
                    // In debug mode, we'll let the error bubble up
                    continue;
                }
            }
        }

        warn!("Event stream ended");

        // Finalize any pending block
        if let Some(block) = self.event_mapper.finalize_pending()? {
            self.printer.print_block(&block)?;
        }

        Ok(())
    }

    /// Process a single event
    async fn process_event(&mut self, event: ProcessedEvent) -> Result<()> {
        // If no-op mode is enabled, only log the block number and skip processing
        if self.config.no_op {
            info!("NO-OP: Seen block {}", event.block_number);
            return Ok(());
        }

        let start = Instant::now();

        // Process the event through the mapper
        if let Some(block) = self.event_mapper.process_event(event).await? {
            let elapsed = start.elapsed();

            // Update HEAD block number
            self.current_head = block.number;

            // Calculate LIB
            let lib = if self.current_head > self.lib_delta {
                self.current_head - self.lib_delta
            } else {
                0
            };

            // Update finality status with new LIB
            self.printer.update_finality(lib);

            // Log block summary with metrics
            let hash_short = if block.hash.len() >= 6 {
                format!("{}..{}",
                    hex::encode(&block.hash[..3]),
                    hex::encode(&block.hash[block.hash.len()-3..]))
            } else {
                hex::encode(&block.hash)
            };

            let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
            let timestamp = block.header.as_ref()
                .and_then(|h| h.timestamp.as_ref())
                .map(|ts| ts.seconds)
                .unwrap_or(0);

            info!(
                "Processed new block number={} hash={} lib={} size={} txs={} timestamp={} elapsed={:.2}ms",
                block.number,
                hash_short,
                lib,
                block.size,
                block.transaction_traces.len(),
                timestamp,
                elapsed_ms
            );

            // Print the completed block
            self.printer.print_block(&block)?;
        }

        Ok(())
    }
}
