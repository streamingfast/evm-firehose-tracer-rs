//! Main Firehose tracer implementation

use crate::{EventMapper, MonadConsumer, TracerConfig};
use eyre::Result;
use firehose::{FinalityStatus, PROTOCOL_VERSION};
use firehose::printer::{print_block_to_firehose, print_to_firehose};
use futures_util::StreamExt;
use monad_exec_events::ExecEvent;
use std::io::stdout;
use std::time::Instant;
use tracing::{error, info, warn};

use crate::{TRACER_NAME, TRACER_VERSION};

/// Main Firehose tracer for Monad
pub struct FirehoseTracer {
    config: TracerConfig,
    event_mapper: EventMapper,
    finality: FinalityStatus,
    consumer: Option<MonadConsumer>,
    current_head: u64,
    lib_delta: u64,
}

impl FirehoseTracer {
    pub fn new(config: TracerConfig) -> Self {
        Self {
            config,
            event_mapper: EventMapper::new(),
            finality: FinalityStatus::default(),
            consumer: None,
            current_head: 0,
            lib_delta: 10,
        }
    }

    pub fn with_consumer(mut self, consumer: MonadConsumer) -> Self {
        self.consumer = Some(consumer);
        self
    }

    pub fn config(&self) -> &TracerConfig {
        &self.config
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Firehose tracer for network: {}", self.config.network_name);

        print_to_firehose(
            &mut stdout(),
            "FIRE INIT",
            PROTOCOL_VERSION,
            TRACER_NAME,
            TRACER_VERSION,
        );
        info!("Printed FIRE INIT message");

        let consumer = self
            .consumer
            .take()
            .ok_or_else(|| eyre::eyre!("No consumer configured"))?;

        let mut event_stream = consumer.start_consuming().await?;

        info!("Tracer started, processing events...");

        while let Some((seqno, event)) = event_stream.next().await {
            if let Err(e) = self.process_event(seqno, event).await {
                error!("Failed to process event: {}", e);
                if !self.config.debug {
                    continue;
                }
            }
        }

        warn!("Event stream ended");

        if let Some(block) = self.event_mapper.finalize_pending()? {
            print_block_to_firehose(&mut stdout(), *block, &self.finality);
        }

        Ok(())
    }

    async fn process_event(&mut self, seqno: u64, event: ExecEvent) -> Result<()> {
        if self.config.no_op {
            info!("NO-OP: seqno={}", seqno);
            return Ok(());
        }

        let start = Instant::now();

        if let Some(block) = self.event_mapper.process_event(seqno, event).await? {
            let elapsed = start.elapsed();

            // Update HEAD block number
            self.current_head = block.number;

            // Calculate LIB
            let lib = if self.current_head > self.lib_delta {
                self.current_head - self.lib_delta
            } else {
                0
            };
            self.finality.set_last_finalized_block(lib);

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

            let total_calls: usize = block.transaction_traces.iter().map(|tx| tx.calls.len()).sum();
            let total_logs: usize = block.transaction_traces.iter()
                .filter_map(|tx| tx.receipt.as_ref())
                .map(|r| r.logs.len())
                .sum();

            info!(
                "Processed new block number={} hash={} lib={} size={} txs={} calls={} logs={} timestamp={} elapsed={:.2}ms",
                block.number,
                hash_short,
                lib,
                block.size,
                block.transaction_traces.len(),
                total_calls,
                total_logs,
                timestamp,
                elapsed_ms
            );

            // Print the completed block
            print_block_to_firehose(&mut stdout(), *block, &self.finality);
        }

        Ok(())
    }
}
