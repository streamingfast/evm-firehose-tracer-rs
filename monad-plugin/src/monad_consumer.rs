//! Monad Event Consumer
//!
//! This module handles consuming execution events from Monad's shared memory
//! event ring buffer system.

use crate::{EventProcessor, PluginConfig};
use eyre::Result;
use monad_event_ring::{DecodedEventRing, EventDecoder, EventDescriptorInfo, EventNextResult, EventPayloadResult};
use monad_exec_events::{ExecEvent, ExecEventDecoder, ExecEventRing};
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Copy)]
pub struct EventMeta {
    pub seqno: u64,
}

fn decode_with_meta(
    info: EventDescriptorInfo<ExecEventDecoder>,
    bytes: &[u8],
) -> Option<(EventMeta, ExecEvent)> {
    let seqno = info.seqno;
    let event_ref = ExecEventDecoder::raw_to_event_ref(info, bytes);
    let event = ExecEventDecoder::event_ref_to_event(event_ref);
    Some((EventMeta { seqno }, event))
}

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

        let event_ring = ExecEventRing::new_from_path(&config.event_ring_path)
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
                EventNextResult::Ready(event_descriptor) => {
                    let (meta, exec_event) = match event_descriptor.try_filter_map_raw(decode_with_meta) {
                        EventPayloadResult::Expired => {
                            warn!("Event payload expired!");
                            continue;
                        }
                        EventPayloadResult::Ready(Some(pair)) => pair,
                        EventPayloadResult::Ready(None) => continue,
                    };

                    let block_number =
                        if let ExecEvent::BlockStart(ref bs) = exec_event {
                            bs.block_tag.block_number
                        } else {
                            event_processor.current_block().unwrap_or(0)
                        };

                    // Process and send asynchronously
                    match event_processor
                        .process_monad_event(exec_event, meta, block_number)
                        .await
                    {
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
