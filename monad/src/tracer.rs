//! Main Firehose tracer implementation

use crate::{EventMapper, FirehosePrinter, MonadConsumer, ProcessedEvent, TracerConfig};
use eyre::Result;
use futures_util::StreamExt;
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
        let event_mapper = EventMapper::new_with_full_config(
            config.skip_finalization,
            config.skip_event_processing,
        );
        let printer = FirehosePrinter::new_with_config(
            config.clone(),
            config.skip_serialization,
        );

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

        // PROFILING: Skip event mapping if requested
        if self.config.skip_event_mapping {
            // Just log that we saw the event
            if event.event_type == "BLOCK_END" {
                info!("PROFILING: Seen BLOCK_END for block {}", event.block_number);
            }
            return Ok(());
        }

        // Process the event through the mapper
        if let Some(block) = self.event_mapper.process_event(event).await? {
            // PROFILING: Skip everything after mapper if requested
            if self.config.skip_after_mapper {
                return Ok(());
            }

            // PROFILING: Skip block field access if requested
            if self.config.skip_block_access {
                // Just access the block number (unavoidable) and return
                let _ = block.number;
                return Ok(());
            }

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

            // PROFILING: Skip logging if requested
            if !self.config.skip_logging {
                // Log block summary
                let hash_short = if block.hash.len() >= 6 {
                    format!("{}..{}",
                        hex::encode(&block.hash[..3]),
                        hex::encode(&block.hash[block.hash.len()-3..]))
                } else {
                    hex::encode(&block.hash)
                };

                let gas_used = block.header.as_ref().map(|h| h.gas_used).unwrap_or(0);
                let gas_mgas = gas_used as f64 / 1_000_000.0;

                info!(
                    "Firehose block finalized number={:>9} hash={} lib={:>9} txs={:>3} mgas={:.3}",
                    block.number,
                    hash_short,
                    lib,
                    block.transaction_traces.len(),
                    gas_mgas
                );
            }

            // PROFILING: Skip output if requested
            if !self.config.skip_output {
                // Print the completed block
                self.printer.print_block(&block)?;
            }
        }

        Ok(())
    }
}
