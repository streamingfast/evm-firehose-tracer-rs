//! Monad Event Consumer
//!
//! This module handles consuming execution events from Monad's shared memory
//! event ring buffer system.

use eyre::Result;
use monad_event_ring::{
    DecodedEventRing, EventDecoder, EventDescriptorInfo, EventNextResult, EventPayloadResult,
};
use monad_exec_events::{ExecEvent, ExecEventDecoder, ExecEventRing};
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub event_ring_path: String,
    pub buffer_size: usize,
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
    event_ring: ExecEventRing,
}

impl MonadConsumer {
    /// Create a new Monad consumer with the given configuration
    pub async fn new(config: PluginConfig) -> Result<Self> {
        info!(
            "Creating Monad consumer with event ring path: {}",
            config.event_ring_path
        );

        let event_ring = ExecEventRing::new_from_path(&config.event_ring_path)
            .map_err(|e| eyre::eyre!("Failed to open Monad event ring: {:?}", e))?;

        info!("Successfully opened Monad event ring");

        Ok(Self { config, event_ring })
    }

    /// Start consuming events and return a stream of (seqno, ExecEvent)
    pub async fn start_consuming(self) -> Result<impl Stream<Item = (u64, ExecEvent)>> {
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
    async fn consume_events_loop(self, tx: mpsc::Sender<(u64, ExecEvent)>) -> Result<()> {
        info!("Starting event consumption loop");

        // Move fields out to avoid borrowing `self` both mutably and immutably at the same time.
        let MonadConsumer {
            config: _,
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
                    let (meta, exec_event) =
                        match event_descriptor.try_filter_map_raw(decode_with_meta) {
                            EventPayloadResult::Expired => {
                                warn!("Event payload expired!");
                                continue;
                            }
                            EventPayloadResult::Ready(Some(pair)) => pair,
                            EventPayloadResult::Ready(None) => continue,
                        };

                    if let Err(e) = tx.send((meta.seqno, exec_event)).await {
                        warn!("Failed to send processed event: {}", e);
                        break; // Channel closed
                    }
                }
            }
        }

        info!("Event consumption loop terminated gracefully");
        Ok(())
    }
}
