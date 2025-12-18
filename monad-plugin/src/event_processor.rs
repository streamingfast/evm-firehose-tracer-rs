//! Event Processor
//!
//! Processes raw Monad execution events and transforms them into
//! a format suitable for the Firehose tracer.

use crate::monad_consumer::ProcessedEvent;
use eyre::Result;
use monad_exec_events::ExecEvent;
use serde_json;
use tracing::{debug, info};

/// Processes raw Monad events into Firehose-compatible format
pub struct EventProcessor {
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
            ExecEvent::TxnHeaderStart {
                txn_index,
                txn_header_start,
                data_bytes,
                blob_bytes,
            } => {
                self.process_txn_header(txn_header_start, data_bytes, blob_bytes, txn_index, block_number)
                    .await
            }
            ExecEvent::TxnEvmOutput { txn_index, output } => {
                self.process_txn_evm_output(output, txn_index, block_number).await
            }
            ExecEvent::TxnEnd => self.process_txn_end(block_number).await,
            ExecEvent::TxnLog {
                txn_index,
                txn_log,
                topic_bytes,
                data_bytes,
            } => {
                self.process_txn_log(txn_log, topic_bytes, data_bytes, txn_index, block_number)
                    .await
            }
            ExecEvent::BlockQC(qc) => self.process_block_qc(qc, block_number).await,
            ExecEvent::BlockFinalized(finalized) => {
                self.process_block_finalized(finalized, block_number).await
            }
            _ => {
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

        let event_type = "BLOCK_START".to_string();

        // Extract all header fields from eth_block_input
        // Convert nonce from 8-byte array to u64 (little-endian)
        let nonce = u64::from_le_bytes(block_start.eth_block_input.nonce.bytes);

        let block_data = serde_json::json!({
            "parent_hash": hex::encode(block_start.parent_eth_hash.bytes),
            "uncle_hash": hex::encode(block_start.eth_block_input.ommers_hash.bytes),
            "coinbase": hex::encode(block_start.eth_block_input.beneficiary.bytes),
            "transactions_root": hex::encode(block_start.eth_block_input.transactions_root.bytes),
            "difficulty": block_start.eth_block_input.difficulty,
            "number": block_start.eth_block_input.number,
            "gas_limit": block_start.eth_block_input.gas_limit,
            "timestamp": block_start.eth_block_input.timestamp,
            "extra_data": hex::encode(&block_start.eth_block_input.extra_data.bytes[..block_start.eth_block_input.extra_data_length as usize]),
            "mix_hash": hex::encode(block_start.eth_block_input.prev_randao.bytes),
            "nonce": nonce,
            "base_fee_per_gas": {
                "limbs": block_start.eth_block_input.base_fee_per_gas.limbs.to_vec()
            },
            "withdrawals_root": hex::encode(block_start.eth_block_input.withdrawals_root.bytes),
        });

        let firehose_data = serde_json::to_vec(&block_data)?;

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

        // Extract all execution output fields
        let block_data = serde_json::json!({
            "hash": hex::encode(block_end.eth_block_hash.bytes),
            "state_root": hex::encode(block_end.exec_output.state_root.bytes),
            "receipts_root": hex::encode(block_end.exec_output.receipts_root.bytes),
            "logs_bloom": hex::encode(block_end.exec_output.logs_bloom.bytes),
            "gas_used": block_end.exec_output.gas_used,
        });

        let firehose_data = serde_json::to_vec(&block_data)?;

        Ok(Some(ProcessedEvent {
            block_number,
            event_type,
            firehose_data,
        }))
    }

    /// Process transaction header event
    async fn process_txn_header(
        &self,
        txn_header: monad_exec_events::ffi::monad_exec_txn_header_start,
        data_bytes: Box<[u8]>,
        blob_bytes: Box<[u8]>,
        txn_index: usize,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        let event_type = "TX_HEADER".to_string();

        // Serialize transaction header data using serde_json for structured format
        let tx_data = serde_json::json!({
            "txn_index": txn_index,
            "hash": hex::encode(txn_header.txn_hash.bytes),
            "from": hex::encode(txn_header.sender.bytes),
            "to": hex::encode(txn_header.txn_header.to.bytes),
            "is_contract_creation": txn_header.txn_header.is_contract_creation,
            "nonce": txn_header.txn_header.nonce,
            "gas_limit": txn_header.txn_header.gas_limit,
            "value": {
                "limbs": txn_header.txn_header.value.limbs.to_vec()
            },
            "max_fee_per_gas": {
                "limbs": txn_header.txn_header.max_fee_per_gas.limbs.to_vec()
            },
            "max_priority_fee_per_gas": {
                "limbs": txn_header.txn_header.max_priority_fee_per_gas.limbs.to_vec()
            },
            "r": {
                "limbs": txn_header.txn_header.r.limbs.to_vec()
            },
            "s": {
                "limbs": txn_header.txn_header.s.limbs.to_vec()
            },
            "y_parity": txn_header.txn_header.y_parity,
            "txn_type": txn_header.txn_header.txn_type,
            "chain_id": {
                "limbs": txn_header.txn_header.chain_id.limbs.to_vec()
            },
            "input": hex::encode(&*data_bytes),
            "access_list_count": txn_header.txn_header.access_list_count,
            // TODO: Extract actual access_list entries from txn_header
            // For now, placeholder empty array - needs to be populated from transaction data
            "access_list": [],
            "blob_versioned_hash_length": txn_header.txn_header.blob_versioned_hash_length,
            "blob_hashes": if blob_bytes.len() > 0 { hex::encode(&*blob_bytes) } else { String::new() },
            "max_fee_per_blob_gas": {
                "limbs": txn_header.txn_header.max_fee_per_blob_gas.limbs.to_vec()
            },
        });

        let firehose_data = serde_json::to_vec(&tx_data)?;

        Ok(Some(ProcessedEvent {
            block_number,
            event_type,
            firehose_data,
        }))
    }

    /// Process transaction EVM output event (receipt data)
    async fn process_txn_evm_output(
        &self,
        output: monad_exec_events::ffi::monad_exec_txn_evm_output,
        txn_index: usize,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!(
            "TxnEvmOutput: block #{}, txn_index={}, status={}, gas_used={}",
            block_number, txn_index, output.receipt.status, output.receipt.gas_used
        );

        let event_type = "TX_RECEIPT".to_string();

        // Serialize receipt data
        let receipt_data = serde_json::json!({
            "txn_index": txn_index,
            "status": output.receipt.status,
            "gas_used": output.receipt.gas_used,
            "log_count": output.receipt.log_count,
            "call_frame_count": output.call_frame_count,
        });

        let firehose_data = serde_json::to_vec(&receipt_data)?;

        Ok(Some(ProcessedEvent {
            block_number,
            event_type,
            firehose_data,
        }))
    }

    async fn process_txn_end(&self, block_number: u64) -> Result<Option<ProcessedEvent>> {
        debug!("TxnEnd: block #{}", block_number);
        Ok(None)
    }

    /// Process transaction log event
    async fn process_txn_log(
        &self,
        log: monad_exec_events::ffi::monad_exec_txn_log,
        topic_bytes: Box<[u8]>,
        data_bytes: Box<[u8]>,
        txn_index: usize,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        let event_type = "TX_LOG".to_string();

        // Parse topics from topic_bytes (each topic is 32 bytes)
        let mut topics = Vec::new();
        for i in 0..log.topic_count as usize {
            let start = i * 32;
            let end = start + 32;
            if end <= topic_bytes.len() {
                topics.push(hex::encode(&topic_bytes[start..end]));
            }
        }

        // Serialize log data
        let log_data = serde_json::json!({
            "txn_index": txn_index,
            "log_index": log.index,
            "address": hex::encode(log.address.bytes),
            "topics": topics,
            "data": hex::encode(&*data_bytes),
        });

        let firehose_data = serde_json::to_vec(&log_data)?;

        Ok(Some(ProcessedEvent {
            block_number,
            event_type,
            firehose_data,
        }))
    }

    async fn process_block_qc(
        &self,
        qc: monad_exec_events::ffi::monad_exec_block_qc,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        info!("BlockQC: block #{}, round={}", block_number, qc.round);
        Ok(None)
    }

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
