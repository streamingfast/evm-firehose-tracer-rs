//! Event Processor
//!
//! Processes raw Monad execution events and transforms them into
//! a format suitable for the Firehose tracer.

use crate::monad_consumer::ProcessedEvent;
use eyre::Result;
use monad_exec_events::ExecEvent;
use serde_json;
use tracing::debug;

// Event type constants to avoid repeated string allocations
const EVENT_TYPE_BLOCK_START: &str = "BLOCK_START";
const EVENT_TYPE_BLOCK_END: &str = "BLOCK_END";
const EVENT_TYPE_TX_HEADER: &str = "TX_HEADER";
const EVENT_TYPE_TX_RECEIPT: &str = "TX_RECEIPT";
const EVENT_TYPE_TX_LOG: &str = "TX_LOG";
const EVENT_TYPE_TX_CALL_FRAME: &str = "TX_CALL_FRAME";
const EVENT_TYPE_ACCOUNT_ACCESS_LIST_HEADER: &str = "ACCOUNT_ACCESS_LIST_HEADER";
const EVENT_TYPE_ACCOUNT_ACCESS: &str = "ACCOUNT_ACCESS";
const EVENT_TYPE_STORAGE_ACCESS: &str = "STORAGE_ACCESS";

/// Buffered transaction header waiting for access list entries
struct PendingTxnHeader {
    txn_header: monad_exec_events::ffi::monad_exec_txn_header_start,
    data_bytes: Box<[u8]>,
    #[allow(dead_code)]
    blob_bytes: Box<[u8]>,
    #[allow(dead_code)]
    txn_index: usize,
    block_number: u64,
    expected_access_list_count: u32,
}

/// Processes raw Monad events into Firehose-compatible format
pub struct EventProcessor {
    current_block: Option<u64>,
    event_count: u64,
    /// Pending access list entries for transactions (txn_index -> access_list)
    pending_access_lists: std::collections::HashMap<usize, Vec<serde_json::Value>>,
    /// Buffered transaction headers waiting for access list entries
    pending_txn_headers: std::collections::HashMap<usize, PendingTxnHeader>,
}

impl EventProcessor {
    /// Create a new event processor
    pub fn new() -> Self {
        Self {
            current_block: None,
            event_count: 0,
            pending_access_lists: std::collections::HashMap::new(),
            pending_txn_headers: std::collections::HashMap::new(),
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
            debug!("Processing new block: {}", block_number);
            self.current_block = Some(block_number);
            // Clear pending access lists and headers when starting a new block
            self.pending_access_lists.clear();
            self.pending_txn_headers.clear();
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
            ExecEvent::TxnAccessListEntry {
                txn_index,
                txn_access_list_entry,
                storage_key_bytes,
            } => {
                self.process_txn_access_list_entry(txn_index, txn_access_list_entry, storage_key_bytes)
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
            ExecEvent::TxnCallFrame {
                txn_index,
                txn_call_frame,
                input_bytes,
                return_bytes,
            } => {
                self.process_txn_call_frame(txn_call_frame, input_bytes, return_bytes, txn_index, block_number)
                    .await
            }
            ExecEvent::AccountAccessListHeader { txn_index, account_access_list_header } => {
                self.process_account_access_list_header(account_access_list_header, txn_index, block_number).await
            }
            ExecEvent::AccountAccess { txn_index, account_access } => {
                self.process_account_access(account_access, txn_index, block_number).await
            }
            ExecEvent::StorageAccess { txn_index, account_index, storage_access } => {
                self.process_storage_access(storage_access, txn_index, account_index, block_number).await
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
        debug!(
            "BlockStart: block #{}, timestamp={}",
            block_number, block_start.eth_block_input.timestamp
        );

        let event_type = EVENT_TYPE_BLOCK_START;

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
            event_type: event_type.to_string(),
            firehose_data,
        }))
    }

    /// Process BlockEnd event - contains execution results
    async fn process_block_end(
        &self,
        block_end: monad_exec_events::ffi::monad_exec_block_end,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!(
            "BlockEnd: block #{}, gas_used={}",
            block_number, block_end.exec_output.gas_used
        );

        let event_type = EVENT_TYPE_BLOCK_END;

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
            event_type: event_type.to_string(),
            firehose_data,
        }))
    }

    /// Process transaction header event - buffers header until access list is complete
    async fn process_txn_header(
        &mut self,
        txn_header: monad_exec_events::ffi::monad_exec_txn_header_start,
        data_bytes: Box<[u8]>,
        blob_bytes: Box<[u8]>,
        txn_index: usize,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        let expected_access_list_count = txn_header.txn_header.access_list_count;

        // Buffer the transaction header - we'll emit it later when all access list entries arrive
        self.pending_txn_headers.insert(
            txn_index,
            PendingTxnHeader {
                txn_header,
                data_bytes,
                blob_bytes,
                txn_index,
                block_number,
                expected_access_list_count,
            },
        );

        // If there are no access list entries expected, emit immediately
        if expected_access_list_count == 0 {
            return self.try_emit_txn_header(txn_index);
        }

        // Otherwise wait for access list entries
        Ok(None)
    }

    /// Emit a buffered transaction header if ready (all access list entries collected)
    fn try_emit_txn_header(&mut self, txn_index: usize) -> Result<Option<ProcessedEvent>> {
        let pending = match self.pending_txn_headers.get(&txn_index) {
            Some(p) => p,
            None => return Ok(None),
        };

        let collected_count = self
            .pending_access_lists
            .get(&txn_index)
            .map(|list| list.len())
            .unwrap_or(0);

        // Check if we have all expected access list entries
        if collected_count < pending.expected_access_list_count as usize {
            return Ok(None); // Not ready yet
        }

        // Remove the pending header and access list
        let pending = self.pending_txn_headers.remove(&txn_index)
            .expect("pending transaction header must exist after count validation");
        let access_list = self.pending_access_lists.remove(&txn_index).unwrap_or_default();

        let event_type = EVENT_TYPE_TX_HEADER;

        // Serialize transaction header data using serde_json for structured format
        let tx_data = serde_json::json!({
            "txn_index": txn_index,
            "hash": hex::encode(pending.txn_header.txn_hash.bytes),
            "from": hex::encode(pending.txn_header.sender.bytes),
            "to": hex::encode(pending.txn_header.txn_header.to.bytes),
            "is_contract_creation": pending.txn_header.txn_header.is_contract_creation,
            "nonce": pending.txn_header.txn_header.nonce,
            "gas_limit": pending.txn_header.txn_header.gas_limit,
            "value": {
                "limbs": pending.txn_header.txn_header.value.limbs.to_vec()
            },
            "max_fee_per_gas": {
                "limbs": pending.txn_header.txn_header.max_fee_per_gas.limbs.to_vec()
            },
            "max_priority_fee_per_gas": {
                "limbs": pending.txn_header.txn_header.max_priority_fee_per_gas.limbs.to_vec()
            },
            "r": {
                "limbs": pending.txn_header.txn_header.r.limbs.to_vec()
            },
            "s": {
                "limbs": pending.txn_header.txn_header.s.limbs.to_vec()
            },
            "y_parity": pending.txn_header.txn_header.y_parity,
            "txn_type": pending.txn_header.txn_header.txn_type,
            "chain_id": {
                "limbs": pending.txn_header.txn_header.chain_id.limbs.to_vec()
            },
            "input": hex::encode(&*pending.data_bytes),
            "access_list_count": pending.txn_header.txn_header.access_list_count,
            "access_list": access_list,
        });

        let firehose_data = serde_json::to_vec(&tx_data)?;

        Ok(Some(ProcessedEvent {
            block_number: pending.block_number,
            event_type: event_type.to_string(),
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

        let event_type = EVENT_TYPE_TX_RECEIPT;

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
            event_type: event_type.to_string(),
            firehose_data,
        }))
    }

    /// Process transaction access list entry event
    async fn process_txn_access_list_entry(
        &mut self,
        txn_index: usize,
        txn_access_list_entry: monad_exec_events::ffi::monad_exec_txn_access_list_entry,
        storage_key_bytes: Box<[u8]>,
    ) -> Result<Option<ProcessedEvent>> {
        debug!(
            "TxnAccessListEntry: txn_index={}, index={}, storage_key_count={}",
            txn_index, txn_access_list_entry.index, txn_access_list_entry.entry.storage_key_count
        );

        // Parse address
        let address = hex::encode(txn_access_list_entry.entry.address.bytes);

        // Parse storage keys (each is 32 bytes)
        let mut storage_keys = Vec::new();
        let key_size = 32;
        for i in 0..txn_access_list_entry.entry.storage_key_count as usize {
            let start = i * key_size;
            let end = start + key_size;
            if end <= storage_key_bytes.len() {
                let key = hex::encode(&storage_key_bytes[start..end]);
                storage_keys.push(key);
            }
        }

        // Create access list entry JSON
        let entry = serde_json::json!({
            "address": address,
            "storage_keys": storage_keys
        });

        // Add to pending access list for this transaction
        self.pending_access_lists
            .entry(txn_index)
            .or_default()
            .push(entry);

        // Try to emit the TX_HEADER if we now have all access list entries
        self.try_emit_txn_header(txn_index)
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
        let event_type = EVENT_TYPE_TX_LOG;

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
            event_type: event_type.to_string(),
            firehose_data,
        }))
    }

    async fn process_block_qc(
        &self,
        qc: monad_exec_events::ffi::monad_exec_block_qc,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!("BlockQC: block #{}, round={}", block_number, qc.round);
        Ok(None)
    }

    async fn process_block_finalized(
        &self,
        finalized: monad_exec_events::ffi::monad_exec_block_finalized,
        _block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!("BlockFinalized: block #{}", finalized.block_number);
        Ok(None)
    }

    /// Process transaction call frame event - execution trace data
    async fn process_txn_call_frame(
        &self,
        call_frame: monad_exec_events::ffi::monad_exec_txn_call_frame,
        input_bytes: Box<[u8]>,
        return_bytes: Box<[u8]>,
        txn_index: Option<usize>,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        if let Some(idx) = txn_index {
            debug!(
                "CallFrame: tx #{}, depth={}, opcode={:#x}, gas={}, status={}",
                idx, call_frame.depth, call_frame.opcode, call_frame.gas, call_frame.evmc_status
            );
        } else {
            debug!(
                "CallFrame (system call): depth={}, opcode={:#x}, gas={}, status={}",
                call_frame.depth, call_frame.opcode, call_frame.gas, call_frame.evmc_status
            );
        }

        let event_type = EVENT_TYPE_TX_CALL_FRAME;

        // Serialize call frame data
        let call_frame_data = serde_json::json!({
            "txn_index": txn_index,
            "index": call_frame.index,
            "caller": hex::encode(call_frame.caller.bytes),
            "call_target": hex::encode(call_frame.call_target.bytes),
            "opcode": call_frame.opcode,
            "value": {
                "limbs": call_frame.value.limbs.to_vec()
            },
            "gas": call_frame.gas,
            "gas_used": call_frame.gas_used,
            "evmc_status": call_frame.evmc_status,
            "depth": call_frame.depth,
            "input": hex::encode(&*input_bytes),
            "return_data": hex::encode(&*return_bytes),
        });

        let firehose_data = serde_json::to_vec(&call_frame_data)?;

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: event_type.to_string(),
            firehose_data,
        }))
    }

    /// Process account access list header - batch metadata for account changes
    async fn process_account_access_list_header(
        &self,
        header: monad_exec_events::ffi::monad_exec_account_access_list_header,
        txn_index: Option<usize>,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!(
            "AccountAccessListHeader: tx {:?}, entry_count={}",
            txn_index, header.entry_count
        );

        let event_type = EVENT_TYPE_ACCOUNT_ACCESS_LIST_HEADER;

        let header_data = serde_json::json!({
            "txn_index": txn_index,
            "entry_count": header.entry_count,
            "access_context": header.access_context,
        });

        let firehose_data = serde_json::to_vec(&header_data)?;

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: event_type.to_string(),
            firehose_data,
        }))
    }

    /// Process account access event - balance/nonce changes
    async fn process_account_access(
        &self,
        account_access: monad_exec_events::ffi::monad_exec_account_access,
        txn_index: Option<usize>,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!(
            "AccountAccess: tx {:?}, addr={}, balance_mod={}, nonce_mod={}",
            txn_index,
            hex::encode(&account_access.address.bytes[..8]),
            account_access.is_balance_modified,
            account_access.is_nonce_modified
        );

        let event_type = EVENT_TYPE_ACCOUNT_ACCESS;

        let access_data = serde_json::json!({
            "txn_index": txn_index,
            "index": account_access.index,
            "address": hex::encode(account_access.address.bytes),
            "access_context": account_access.access_context,
            "is_balance_modified": account_access.is_balance_modified,
            "is_nonce_modified": account_access.is_nonce_modified,
            "prestate": {
                "balance": {
                    "limbs": account_access.prestate.balance.limbs.to_vec()
                },
                "nonce": account_access.prestate.nonce,
            },
            "modified_balance": {
                "limbs": account_access.modified_balance.limbs.to_vec()
            },
            "modified_nonce": account_access.modified_nonce,
            "storage_key_count": account_access.storage_key_count,
        });

        let firehose_data = serde_json::to_vec(&access_data)?;

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: event_type.to_string(),
            firehose_data,
        }))
    }

    /// Process storage access event - storage slot modifications
    async fn process_storage_access(
        &self,
        storage_access: monad_exec_events::ffi::monad_exec_storage_access,
        txn_index: Option<usize>,
        account_index: u64,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!(
            "StorageAccess: tx {:?}, addr={}, modified={}, transient={}",
            txn_index,
            hex::encode(&storage_access.address.bytes[..8]),
            storage_access.modified,
            storage_access.transient
        );

        let event_type = EVENT_TYPE_STORAGE_ACCESS;

        let storage_data = serde_json::json!({
            "txn_index": txn_index,
            "account_index": account_index,
            "address": hex::encode(storage_access.address.bytes),
            "access_context": storage_access.access_context,
            "index": storage_access.index,
            "modified": storage_access.modified,
            "transient": storage_access.transient,
            "key": hex::encode(storage_access.key.bytes),
            "start_value": hex::encode(storage_access.start_value.bytes),
            "end_value": hex::encode(storage_access.end_value.bytes),
        });

        let firehose_data = serde_json::to_vec(&storage_data)?;

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: event_type.to_string(),
            firehose_data,
        }))
    }
}

impl Default for EventProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EventProcessor {
    fn drop(&mut self) {
        // Clean up any remaining pending access lists and headers
        self.pending_access_lists.clear();
        self.pending_txn_headers.clear();
    }
}
