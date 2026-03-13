use crate::monad_consumer::{EventMeta, ProcessedEvent};
use crate::pb::sf::monad::events::v1 as pb;
use eyre::Result;
use monad_exec_events::ExecEvent;
use prost::Message;
use tracing::debug;

const EVENT_TYPE_BLOCK_START: &str = "BLOCK_START";
const EVENT_TYPE_BLOCK_END: &str = "BLOCK_END";
const EVENT_TYPE_TX_HEADER: &str = "TX_HEADER";
const EVENT_TYPE_TX_RECEIPT: &str = "TX_RECEIPT";
const EVENT_TYPE_TX_LOG: &str = "TX_LOG";
const EVENT_TYPE_TX_CALL_FRAME: &str = "TX_CALL_FRAME";
const EVENT_TYPE_ACCOUNT_ACCESS_LIST_HEADER: &str = "ACCOUNT_ACCESS_LIST_HEADER";
const EVENT_TYPE_ACCOUNT_ACCESS: &str = "ACCOUNT_ACCESS";
const EVENT_TYPE_STORAGE_ACCESS: &str = "STORAGE_ACCESS";
const EVENT_TYPE_TX_END: &str = "TX_END";

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
    current_txn_idx: Option<usize>,
    pending_access_lists: std::collections::HashMap<usize, Vec<pb::AccessListEntry>>,
    pending_txn_headers: std::collections::HashMap<usize, PendingTxnHeader>,
    current_account_idx: u64,
}

impl EventProcessor {
    pub fn new() -> Self {
        Self {
            current_block: None,
            event_count: 0,
            current_txn_idx: None,
            pending_access_lists: std::collections::HashMap::new(),
            pending_txn_headers: std::collections::HashMap::new(),
            current_account_idx: 0,
        }
    }

    pub fn current_block(&self) -> Option<u64> {
        self.current_block
    }

    pub async fn process_monad_event(
        &mut self,
        exec_event: ExecEvent,
        meta: EventMeta,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        self.event_count += 1;

        if self.current_block != Some(block_number) && block_number > 0 {
            debug!("Processing new block: {}", block_number);
            self.current_block = Some(block_number);
            self.current_txn_idx = None;
            self.current_account_idx = 0;
            self.pending_access_lists.clear();
            self.pending_txn_headers.clear();
        }

        match exec_event {
            ExecEvent::BlockStart(block_start) => {
                self.current_txn_idx = None;
                self.process_block_start(block_start, meta.seqno, block_number).await
            }
            ExecEvent::BlockEnd(block_end) => {
                self.current_txn_idx = None;
                self.process_block_end(block_end, meta.seqno, block_number).await
            }
            ExecEvent::TxnHeaderStart {
                txn_index,
                txn_header_start,
                data_bytes,
                blob_bytes,
            } => {
                self.current_txn_idx = Some(txn_index);
                self.process_txn_header(txn_header_start, data_bytes, blob_bytes, txn_index, block_number).await
            }
            ExecEvent::TxnAccessListEntry {
                txn_index,
                txn_access_list_entry,
                storage_key_bytes,
            } => {
                self.process_txn_access_list_entry(txn_index, txn_access_list_entry, storage_key_bytes).await
            }
            ExecEvent::TxnEvmOutput { txn_index, output } => {
                self.current_txn_idx = Some(txn_index);
                self.process_txn_evm_output(output, txn_index, block_number).await
            }
            ExecEvent::TxnEnd => {
                self.process_txn_end(block_number).await
            }
            ExecEvent::TxnLog { txn_index, txn_log, topic_bytes, data_bytes } => {
                self.process_txn_log(txn_log, topic_bytes, data_bytes, txn_index, block_number).await
            }
            ExecEvent::BlockQC(qc) => self.process_block_qc(qc, block_number).await,
            ExecEvent::BlockFinalized(finalized) => {
                self.process_block_finalized(finalized, block_number).await
            }
            ExecEvent::TxnCallFrame { txn_index, txn_call_frame, input_bytes, return_bytes } => {
                self.process_txn_call_frame(txn_call_frame, input_bytes, return_bytes, txn_index, block_number).await
            }
            ExecEvent::AccountAccessListHeader(header) => {
                let txn_index = self.current_txn_idx;
                self.current_account_idx = 0;
                self.process_account_access_list_header(header, txn_index, block_number).await
            }
            ExecEvent::AccountAccess(account_access) => {
                let txn_index = self.current_txn_idx;
                self.current_account_idx = account_access.index as u64;
                self.process_account_access(account_access, txn_index, block_number).await
            }
            ExecEvent::StorageAccess(storage_access) => {
                let txn_index = self.current_txn_idx;
                let account_index = self.current_account_idx;
                self.process_storage_access(storage_access, txn_index, account_index, block_number).await
            }
            _ => {
                debug!("Skipping event type: {:?}", exec_event);
                Ok(None)
            }
        }
    }

    async fn process_block_start(
        &self,
        block_start: monad_exec_events::ffi::monad_exec_block_start,
        seqno: u64,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!(
            "BlockStart: block #{}, timestamp={}, parent_hash={}",
            block_number,
            block_start.eth_block_input.timestamp,
            hex::encode(block_start.parent_eth_hash.bytes)
        );

        let nonce = u64::from_le_bytes(block_start.eth_block_input.nonce.bytes);
        let extra_data_len = block_start.eth_block_input.extra_data_length as usize;

        let msg = pb::BlockStart {
            seqno,
            parent_hash: block_start.parent_eth_hash.bytes.to_vec(),
            uncle_hash: block_start.eth_block_input.ommers_hash.bytes.to_vec(),
            coinbase: block_start.eth_block_input.beneficiary.bytes.to_vec(),
            transactions_root: block_start.eth_block_input.transactions_root.bytes.to_vec(),
            difficulty: block_start.eth_block_input.difficulty,
            number: block_start.eth_block_input.number,
            gas_limit: block_start.eth_block_input.gas_limit,
            timestamp: block_start.eth_block_input.timestamp,
            extra_data: block_start.eth_block_input.extra_data.bytes[..extra_data_len].to_vec(),
            mix_hash: block_start.eth_block_input.prev_randao.bytes.to_vec(),
            nonce,
            base_fee_per_gas_limbs: block_start.eth_block_input.base_fee_per_gas.limbs.to_vec(),
            withdrawals_root: block_start.eth_block_input.withdrawals_root.bytes.to_vec(),
        };

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: EVENT_TYPE_BLOCK_START.to_string(),
            firehose_data: msg.encode_to_vec(),
        }))
    }

    async fn process_block_end(
        &self,
        block_end: monad_exec_events::ffi::monad_exec_block_end,
        seqno: u64,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!(
            "BlockEnd: block #{}, gas_used={}, block_hash={}",
            block_number,
            block_end.exec_output.gas_used,
            hex::encode(block_end.eth_block_hash.bytes)
        );

        let msg = pb::BlockEnd {
            seqno,
            hash: block_end.eth_block_hash.bytes.to_vec(),
            state_root: block_end.exec_output.state_root.bytes.to_vec(),
            receipts_root: block_end.exec_output.receipts_root.bytes.to_vec(),
            logs_bloom: block_end.exec_output.logs_bloom.bytes.to_vec(),
            gas_used: block_end.exec_output.gas_used,
        };

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: EVENT_TYPE_BLOCK_END.to_string(),
            firehose_data: msg.encode_to_vec(),
        }))
    }

    async fn process_txn_header(
        &mut self,
        txn_header: monad_exec_events::ffi::monad_exec_txn_header_start,
        data_bytes: Box<[u8]>,
        blob_bytes: Box<[u8]>,
        txn_index: usize,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        let expected_access_list_count = txn_header.txn_header.access_list_count;

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

        Ok(None)
    }

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

        if collected_count < pending.expected_access_list_count as usize {
            return Ok(None);
        }

        let pending = self.pending_txn_headers.remove(&txn_index).unwrap();
        let access_list = self.pending_access_lists.remove(&txn_index).unwrap_or_default();

        let msg = pb::TxHeader {
            txn_index: txn_index as u32,
            hash: pending.txn_header.txn_hash.bytes.to_vec(),
            from: pending.txn_header.sender.bytes.to_vec(),
            to: pending.txn_header.txn_header.to.bytes.to_vec(),
            is_contract_creation: pending.txn_header.txn_header.is_contract_creation,
            nonce: pending.txn_header.txn_header.nonce,
            gas_limit: pending.txn_header.txn_header.gas_limit,
            value_limbs: pending.txn_header.txn_header.value.limbs.to_vec(),
            max_fee_per_gas_limbs: pending.txn_header.txn_header.max_fee_per_gas.limbs.to_vec(),
            max_priority_fee_per_gas_limbs: pending.txn_header.txn_header.max_priority_fee_per_gas.limbs.to_vec(),
            r_limbs: pending.txn_header.txn_header.r.limbs.to_vec(),
            s_limbs: pending.txn_header.txn_header.s.limbs.to_vec(),
            y_parity: pending.txn_header.txn_header.y_parity,
            txn_type: pending.txn_header.txn_header.txn_type as u32,
            chain_id_limbs: pending.txn_header.txn_header.chain_id.limbs.to_vec(),
            input: pending.data_bytes.to_vec(),
            access_list,
        };

        Ok(Some(ProcessedEvent {
            block_number: pending.block_number,
            event_type: EVENT_TYPE_TX_HEADER.to_string(),
            firehose_data: msg.encode_to_vec(),
        }))
    }

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

        let msg = pb::TxReceipt {
            txn_index: txn_index as u32,
            status: output.receipt.status,
            gas_used: output.receipt.gas_used,
            log_count: output.receipt.log_count,
            call_frame_count: output.call_frame_count,
        };

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: EVENT_TYPE_TX_RECEIPT.to_string(),
            firehose_data: msg.encode_to_vec(),
        }))
    }

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

        let mut storage_keys = Vec::new();
        for i in 0..txn_access_list_entry.entry.storage_key_count as usize {
            let start = i * 32;
            let end = start + 32;
            if end <= storage_key_bytes.len() {
                storage_keys.push(storage_key_bytes[start..end].to_vec());
            }
        }

        let entry = pb::AccessListEntry {
            address: txn_access_list_entry.entry.address.bytes.to_vec(),
            storage_keys,
        };

        self.pending_access_lists.entry(txn_index).or_default().push(entry);
        self.try_emit_txn_header(txn_index)
    }

    async fn process_txn_end(&self, block_number: u64) -> Result<Option<ProcessedEvent>> {
        let txn_index = self.current_txn_idx.unwrap_or(0);
        debug!("TxnEnd: block #{}, txn_index={}", block_number, txn_index);

        let msg = pb::TxEnd { txn_index: txn_index as u32 };

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: EVENT_TYPE_TX_END.to_string(),
            firehose_data: msg.encode_to_vec(),
        }))
    }

    async fn process_txn_log(
        &self,
        log: monad_exec_events::ffi::monad_exec_txn_log,
        topic_bytes: Box<[u8]>,
        data_bytes: Box<[u8]>,
        txn_index: usize,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        let mut topics = Vec::new();
        for i in 0..log.topic_count as usize {
            let start = i * 32;
            let end = start + 32;
            if end <= topic_bytes.len() {
                topics.push(topic_bytes[start..end].to_vec());
            }
        }

        let msg = pb::TxLog {
            txn_index: txn_index as u32,
            log_index: log.index,
            address: log.address.bytes.to_vec(),
            topics,
            data: data_bytes.to_vec(),
        };

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: EVENT_TYPE_TX_LOG.to_string(),
            firehose_data: msg.encode_to_vec(),
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
                "CallFrame (system): depth={}, opcode={:#x}, target={}",
                call_frame.depth, call_frame.opcode, hex::encode(call_frame.call_target.bytes)
            );
        }

        let msg = pb::TxCallFrame {
            txn_index: txn_index.map(|i| i as u32),
            index: call_frame.index,
            caller: call_frame.caller.bytes.to_vec(),
            call_target: call_frame.call_target.bytes.to_vec(),
            opcode: call_frame.opcode as u32,
            value_limbs: call_frame.value.limbs.to_vec(),
            gas: call_frame.gas,
            gas_used: call_frame.gas_used,
            evmc_status: call_frame.evmc_status,
            depth: call_frame.depth,
            input: input_bytes.to_vec(),
            return_data: return_bytes.to_vec(),
        };

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: EVENT_TYPE_TX_CALL_FRAME.to_string(),
            firehose_data: msg.encode_to_vec(),
        }))
    }

    async fn process_account_access_list_header(
        &self,
        header: monad_exec_events::ffi::monad_exec_account_access_list_header,
        txn_index: Option<usize>,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!(
            "AccountAccessListHeader: tx {:?}, entry_count={}, access_context={}",
            txn_index, header.entry_count, header.access_context
        );

        let msg = pb::AccountAccessListHeader {
            txn_index: txn_index.map(|i| i as u32),
            entry_count: header.entry_count,
            access_context: header.access_context as u32,
        };

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: EVENT_TYPE_ACCOUNT_ACCESS_LIST_HEADER.to_string(),
            firehose_data: msg.encode_to_vec(),
        }))
    }

    async fn process_account_access(
        &self,
        account_access: monad_exec_events::ffi::monad_exec_account_access,
        txn_index: Option<usize>,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!(
            "AccountAccess: tx {:?}, index={}, addr={}, balance_mod={}, nonce_mod={}",
            txn_index,
            account_access.index,
            hex::encode(&account_access.address.bytes[..8]),
            account_access.is_balance_modified,
            account_access.is_nonce_modified,
        );

        let msg = pb::AccountAccess {
            txn_index: txn_index.map(|i| i as u32),
            index: account_access.index,
            address: account_access.address.bytes.to_vec(),
            access_context: account_access.access_context as u32,
            is_balance_modified: account_access.is_balance_modified,
            is_nonce_modified: account_access.is_nonce_modified,
            prestate_balance_limbs: account_access.prestate.balance.limbs.to_vec(),
            prestate_nonce: account_access.prestate.nonce,
            prestate_code_hash: account_access.prestate.code_hash.bytes.to_vec(),
            modified_balance_limbs: account_access.modified_balance.limbs.to_vec(),
            modified_nonce: account_access.modified_nonce,
            storage_key_count: account_access.storage_key_count,
        };

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: EVENT_TYPE_ACCOUNT_ACCESS.to_string(),
            firehose_data: msg.encode_to_vec(),
        }))
    }

    async fn process_storage_access(
        &self,
        storage_access: monad_exec_events::ffi::monad_exec_storage_access,
        txn_index: Option<usize>,
        account_index: u64,
        block_number: u64,
    ) -> Result<Option<ProcessedEvent>> {
        debug!(
            "StorageAccess: tx {:?}, account_index={}, addr={}, modified={}, transient={}",
            txn_index,
            account_index,
            hex::encode(&storage_access.address.bytes[..8]),
            storage_access.modified,
            storage_access.transient
        );

        let msg = pb::StorageAccess {
            txn_index: txn_index.map(|i| i as u32),
            account_index: account_index as u32,
            address: storage_access.address.bytes.to_vec(),
            access_context: storage_access.access_context as u32,
            index: storage_access.index,
            modified: storage_access.modified,
            transient: storage_access.transient,
            key: storage_access.key.bytes.to_vec(),
            start_value: storage_access.start_value.bytes.to_vec(),
            end_value: storage_access.end_value.bytes.to_vec(),
        };

        Ok(Some(ProcessedEvent {
            block_number,
            event_type: EVENT_TYPE_STORAGE_ACCESS.to_string(),
            firehose_data: msg.encode_to_vec(),
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
        self.pending_access_lists.clear();
        self.pending_txn_headers.clear();
    }
}
