//! Monad Event Consumer
//!
//! This module handles consuming execution events from Monad's shared memory
//! event ring buffer system.

use crate::{EventProcessor, PluginConfig};
use eyre::Result;
use monad_event_ring::{EventDescriptor, EventNextResult, EventPayloadResult, EventRingPath};
use monad_exec_events::{
    ffi::DEFAULT_FILE_NAME, ExecEvent, ExecEventDecoder, ExecEventDescriptorExt,
    ExecEventReaderExt, ExecEventRing, ExecEventType,
};
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tracing::{debug, error, info, warn};
use monad_event_ring::DecodedEventRing;

/// Consumer for Monad execution events
pub struct MonadConsumer {
    config: PluginConfig,
    event_processor: EventProcessor,
    event_ring: ExecEventRing,
}

impl MonadConsumer {
    /// Create a new Monad consumer with the given configuration
    pub async fn new(config: PluginConfig) -> Result<Self> {
        info!(
            "Creating Monad consumer with event ring path: {}",
            config.event_ring_path
        );

        let event_processor = EventProcessor::new();

        // Initialize the SDK event ring
        let path_str = if config.event_ring_path.is_empty() {
            DEFAULT_FILE_NAME
        } else {
            &config.event_ring_path
        };

        let path = EventRingPath::resolve(path_str)
            .map_err(|e| eyre::eyre!("Failed to resolve event ring path: {}", e))?;

        let event_ring = ExecEventRing::new(&path)
            .map_err(|e| eyre::eyre!("Failed to open Monad event ring: {:?}", e))?;

        info!("Successfully opened Monad event ring");

        Ok(Self {
            config,
            event_processor,
            event_ring,
        })
    }

    /// Start consuming events and return a stream of processed events
    pub async fn start_consuming(self) -> Result<impl Stream<Item = ProcessedEvent>> {
        info!("Starting Monad event consumption");

        let (tx, rx) = mpsc::channel(self.config.buffer_size);

        // Spawn the event consumption task
        tokio::spawn(async move {
            if let Err(e) = self.consume_events_loop(tx).await {
                error!("Event consumption loop failed: {}", e);
            }
        });

        Ok(ReceiverStream::new(rx))
    }

    /// Main event consumption loop
    async fn consume_events_loop(self, tx: mpsc::Sender<ProcessedEvent>) -> Result<()> {
        info!("Starting event consumption loop");

        // Move fields out to avoid borrowing `self` both mutably and immutably at the same time.
        let MonadConsumer {
            config: _,
            mut event_processor,
            event_ring,
        } = self;

        // Create event reader from the event ring (borrows `event_ring`)
        let mut event_reader = event_ring.create_reader();

        // Start on a block boundary
        event_reader.consensus_prev(Some(ExecEventType::BlockStart));

        // Setup graceful shutdown signal handling
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to setup SIGTERM handler");
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("failed to setup SIGINT handler");

        loop {
            // Read events from Monad SDK
            match event_reader.next_descriptor() {
                EventNextResult::Gap => {
                    error!("Event sequence number gap occurred!");
                    event_reader.reset();
                }
                EventNextResult::NotReady => {
                    // No event available, check for signals with timeout
                    tokio::select! {
                        _ = sigterm.recv() => {
                            info!("Received SIGTERM, shutting down gracefully");
                            break;
                        }
                        _ = sigint.recv() => {
                            info!("Received SIGINT (Ctrl+C), shutting down gracefully");
                            break;
                        }
                        _ = tokio::time::sleep(tokio::time::Duration::from_millis(1)) => {
                            // Timeout, continue polling
                            continue;
                        }
                    }
                }
                EventNextResult::Ready(event) => {
                    // Process the event inline
                    let block_number = event.get_block_number().unwrap_or(0);

                    let exec_event = match event.try_read() {
                        EventPayloadResult::Expired => {
                            warn!("Event payload expired!");
                            continue;
                        }
                        EventPayloadResult::Ready(exec_event) => exec_event,
                    };

                    // Event descriptor will drop here at end of scope
                    // Process and send asynchronously
                    match event_processor.process_monad_event(exec_event, block_number).await {
                        Ok(Some(processed_event)) => {
                            if let Err(e) = tx.send(processed_event).await {
                                warn!("Failed to send processed event: {}", e);
                                break; // Channel closed
                            }
                        }
                        Ok(None) => {
                            // Event processed but no output needed
                        }
                        Err(e) => {
                            error!("Failed to process event: {}", e);
                        }
                    }
                }
            }
        }

        info!("Event consumption loop terminated gracefully");
        Ok(())
    }
}

/// Processed event ready for the Firehose tracer
#[derive(Debug, Clone)]
pub struct ProcessedEvent {
    pub block_number: u64,
    pub event_type: String,
    pub firehose_data: Vec<u8>,
}
