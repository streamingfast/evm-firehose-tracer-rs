//! Event Processor
//!
//! This module handles processing raw Monad execution events and transforming
//! them into a format suitable for the Firehose tracer.

use crate::monad_consumer::ProcessedEvent;
use eyre::Result;
use monad_exec_events::ExecEvent;
use tracing::{debug, info};

/// Processes raw Monad events into Firehose-compatible format
pub struct EventProcessor {
    // State tracking for event processing
    current_block: Option<u64>,
    event_count: u64,
}

impl EventProcessor {
    /// Create a new event processor
    pub fn new() -> Self {
        Self {
            current_block: None,
            event_count: 0,
        }
    }

    /// Process a Monad ExecEvent into a Firehose-compatible format
    pub async fn process_monad_event(
        &mut self,
        exec_event: ExecEvent,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        self.event_count += 1;

        // Update current block tracking
        if self.current_block != Some(block_number) && block_number > 0 {
            info!("Processing new block: {}", block_number);
            self.current_block = Some(block_number);
        }

        // Match on the actual Monad event type
        match exec_event {
            ExecEvent::BlockStart(block_start) => {
                self.process_block_start(block_start, block_number).await
            }
            ExecEvent::BlockEnd(block_end) => {
                self.process_block_end(block_end, block_number).await
            }
            ExecEvent::TxnHeaderStart { txn_header_start, .. } => {
                self.process_txn_header(txn_header_start, block_number).await
            }
            ExecEvent::TxnEnd => self.process_txn_end(block_number).await,
            ExecEvent::TxnLog { txn_log, .. } => {
                self.process_txn_log(txn_log, block_number).await
            }
            ExecEvent::BlockQC(qc) => self.process_block_qc(qc, block_number).await,
            ExecEvent::BlockFinalized(finalized) => {
                self.process_block_finalized(finalized, block_number).await
            }
            _ => {
                // Other event types we might not need to process for Firehose
                debug!("Skipping event type: {:?}", exec_event);
                Ok(None)
            }
        }
    }

    /// Process BlockStart event - contains block header information
    async fn process_block_start(
        &self,
        block_start: monad_exec_events::ffi::monad_exec_block_start,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        info!(
            "BlockStart: block #{}, timestamp={}",
            block_number, block_start.eth_block_input.timestamp
        );

        // Extract header information from block_start
        let event_type = "BLOCK_START".to_string();

        // Serialize the block header data
        // For now, we'll create a simple format - in a full implementation,
        // this would be serialized as protobuf
        let firehose_data = format!(
            "BLOCK_START:{}:{}:{}:{}",
            block_number,
            hex::encode(&block_start.parent_eth_hash.bytes),
            block_start.eth_block_input.timestamp,
            block_start.eth_block_input.gas_limit,
        )
        .into_bytes();

        Ok(Some(ProcessedEvent {
            block_number,
            event_type,
            firehose_data,
        }))
    }

    /// Process BlockEnd event - contains execution results
    async fn process_block_end(
        &self,
        block_end: monad_exec_events::ffi::monad_exec_block_end,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        info!(
            "BlockEnd: block #{}, gas_used={}",
            block_number, block_end.exec_output.gas_used
        );

        let event_type = "BLOCK_END".to_string();

        let firehose_data = format!(
            "BLOCK_END:{}:{}:{}:{}",
            block_number,
            hex::encode(&block_end.eth_block_hash.bytes),
            hex::encode(&block_end.exec_output.state_root.bytes),
            block_end.exec_output.gas_used,
        )
        .into_bytes();

        Ok(Some(ProcessedEvent {
            block_number,
            event_type,
            firehose_data,
        }))
    }

    /// Process transaction header event
    async fn process_txn_header(
        &self,
        _txn_header: monad_exec_events::ffi::monad_exec_txn_header_start,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        // For now, we skip detailed transaction processing
        debug!("TxnHeader: block #{}", block_number);
        Ok(None)
    }

    /// Process transaction end event
    async fn process_txn_end(&self, block_number: u64) -> Result<Option<ProcessedEvent>> {
        debug!("TxnEnd: block #{}", block_number);
        Ok(None)
    }

    /// Process transaction log event
    async fn process_txn_log(
        &self,
        _log: monad_exec_events::ffi::monad_exec_txn_log,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!("TxnLog: block #{}", block_number);
        Ok(None)
    }

    /// Process block QC (quorum certificate) event
    async fn process_block_qc(
        &self,
        qc: monad_exec_events::ffi::monad_exec_block_qc,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        info!("BlockQC: block #{}, round={}", block_number, qc.round);
        Ok(None)
    }

    /// Process block finalized event
    async fn process_block_finalized(
        &self,
        finalized: monad_exec_events::ffi::monad_exec_block_finalized,
        _block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        info!("BlockFinalized: block #{}", finalized.block_number);
        Ok(None)
    }
}

impl Default for EventProcessor {
    fn default() -> Self {
        Self::new()
    }
}
