use crate::{Block, BlockHeader, TransactionTrace};
use firehose::pb::sf::ethereum::r#type::v2::{block, BigInt, AccessTuple, CodeChange};
use alloy_primitives::{Bloom, BloomInput, keccak256};
use eyre::Result;
use monad_exec_events::ExecEvent;
use tracing::debug;

// Constants for Monad-specific values
const MONAD_BLOCK_SIZE: u64 = 783;
const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

fn encode_v_bytes(v_value: u64) -> Vec<u8> {
    let mut bytes = v_value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    bytes
}

/// Convert U256 limbs (4x u64 in little-endian) to big-endian bytes with leading zero compaction
fn u256_limbs_to_bytes(limbs: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    for i in (0..4).rev() {
        let limb = limbs.get(i).copied().unwrap_or(0);
        bytes.extend_from_slice(&limb.to_be_bytes());
    }
    compact_bytes(bytes)
}

/// Strip leading zeros from byte array (Ethereum hex compaction)
fn compact_bytes(bytes: Vec<u8>) -> Vec<u8> {
    let first_non_zero = bytes.iter().position(|&b| b != 0);
    match first_non_zero {
        Some(pos) => bytes[pos..].to_vec(),
        None => vec![],
    }
}

/// Add two u256 values represented as big-endian byte arrays
fn add_u256_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut a_padded = [0u8; 32];
    let mut b_padded = [0u8; 32];

    let a_start = 32 - a.len();
    let b_start = 32 - b.len();
    a_padded[a_start..].copy_from_slice(a);
    b_padded[b_start..].copy_from_slice(b);

    let mut result = vec![0u8; 32];
    let mut carry = 0u16;

    for i in (0..32).rev() {
        let sum = a_padded[i] as u16 + b_padded[i] as u16 + carry;
        result[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }

    compact_bytes(result)
}

/// Compare two u256 values represented as big-endian byte arrays
fn compare_u256_bytes(a: &[u8], b: &[u8]) -> i32 {
    let a_len = a.len();
    let b_len = b.len();

    if a_len != b_len {
        return if a_len > b_len { 1 } else { -1 };
    }

    for i in 0..a_len {
        if a[i] != b[i] {
            return if a[i] > b[i] { 1 } else { -1 };
        }
    }

    0
}

fn is_precompile_address(addr: &[u8]) -> bool {
    matches!(addr, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1..=10])
}

fn ensure_address_bytes(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() { vec![0u8; 20] } else { bytes }
}

fn ensure_hash_bytes(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() { vec![0u8; 32] } else { bytes }
}

fn calculate_logs_bloom(logs: &[firehose::pb::sf::ethereum::r#type::v2::Log]) -> Vec<u8> {
    let mut bloom = Bloom::default();
    for log in logs {
        if log.address.len() == 20 {
            bloom.accrue(BloomInput::Raw(&log.address));
        }
        for topic in &log.topics {
            if topic.len() == 32 {
                bloom.accrue(BloomInput::Raw(topic));
            }
        }
    }
    bloom.as_slice().to_vec()
}

fn evmc_status_to_failure_reason(evmc_status: i32) -> String {
    match evmc_status {
        0 => String::new(),
        1 => "execution failed".to_string(),
        2 => "execution reverted".to_string(),
        3 => "out of gas".to_string(),
        4 => "invalid instruction".to_string(),
        5 => "undefined instruction".to_string(),
        6 => "stack overflow".to_string(),
        7 => "stack underflow".to_string(),
        8 => "bad jump destination".to_string(),
        9 => "invalid memory access".to_string(),
        10 => "call depth exceeded".to_string(),
        11 => "static mode violation".to_string(),
        12 => "precompile failure".to_string(),
        13 => "contract validation failure".to_string(),
        14 => "argument out of range".to_string(),
        15 => "wasm unreachable instruction".to_string(),
        16 => "wasm trap".to_string(),
        17 => "insufficient balance for transfer".to_string(),
        _ => format!("unknown error (status {})", evmc_status),
    }
}

fn opcode_to_call_type(opcode: u8) -> firehose::pb::sf::ethereum::r#type::v2::CallType {
    match opcode {
        0xF0 => firehose::pb::sf::ethereum::r#type::v2::CallType::Create,
        0xF5 => firehose::pb::sf::ethereum::r#type::v2::CallType::Create,
        0xF1 => firehose::pb::sf::ethereum::r#type::v2::CallType::Call,
        0xF4 => firehose::pb::sf::ethereum::r#type::v2::CallType::Delegate,
        0xF2 => firehose::pb::sf::ethereum::r#type::v2::CallType::Callcode,
        0xFA => firehose::pb::sf::ethereum::r#type::v2::CallType::Static,
        _ => firehose::pb::sf::ethereum::r#type::v2::CallType::Call,
    }
}

// Buffered until all access list entries arrive
struct PendingTxnHeader {
    txn_header: monad_exec_events::ffi::monad_exec_txn_header_start,
    data_bytes: Box<[u8]>,
    expected_access_list_count: u32,
}

// Per-tx live state, pending_* fields are flushed into trace.calls at TxnEnd
struct TxState {
    trace: TransactionTrace,
    pending_calls: Vec<firehose::pb::sf::ethereum::r#type::v2::Call>,
    // Buffered state changes, applied to root call at TxnEnd
    pending_balance_changes: Vec<firehose::pb::sf::ethereum::r#type::v2::BalanceChange>,
    pending_nonce_changes: Vec<firehose::pb::sf::ethereum::r#type::v2::NonceChange>,
    pending_storage_changes: Vec<firehose::pb::sf::ethereum::r#type::v2::StorageChange>,
}

struct BlockBuilder {
    block_number: u64,
    block_hash: Vec<u8>,
    parent_hash: Vec<u8>,
    uncle_hash: Vec<u8>,
    state_root: Vec<u8>,
    transactions_root: Vec<u8>,
    receipts_root: Vec<u8>,
    logs_bloom: Vec<u8>,
    coinbase: Vec<u8>,
    difficulty: u64,
    timestamp: u64,
    extra_data: Vec<u8>,
    mix_hash: Vec<u8>,
    nonce: u64,
    base_fee_per_gas: Vec<u64>,
    withdrawals_root: Vec<u8>,
    size: u64,
    gas_used: u64,
    gas_limit: u64,
    cumulative_gas_used: u64,
    total_log_count: usize,
    next_ordinal: u64,
    txns: std::collections::HashMap<usize, TxState>,
    // System call frames (txn_index=None)
    system_calls_calls: Vec<firehose::pb::sf::ethereum::r#type::v2::Call>,
    // System account/storage accesses buffered as raw data, applied to system_calls at finalize
    system_calls_account_accesses: Vec<(Vec<u8>, bool, Vec<u8>, Vec<u8>, bool, u64, u64)>,
    system_calls_storage_accesses: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>,
    // TxnHeaderStart arrives before TxnAccessListEntry
    pending_txn_headers: std::collections::HashMap<usize, PendingTxnHeader>,
    pending_access_lists: std::collections::HashMap<usize, Vec<AccessTuple>>,
    // AccountAccess/StorageAccess don't carry txn_index directly
    current_txn_idx: Option<usize>,
    current_account_idx: u64,
}

impl BlockBuilder {
    fn new(block_number: u64) -> Self {
        Self {
            block_number,
            block_hash: vec![0u8; 32],
            parent_hash: vec![0u8; 32],
            uncle_hash: vec![0u8; 32],
            state_root: vec![0u8; 32],
            transactions_root: vec![0u8; 32],
            receipts_root: vec![0u8; 32],
            logs_bloom: vec![0u8; 256],
            coinbase: vec![0u8; 20],
            difficulty: 0,
            timestamp: chrono::Utc::now().timestamp() as u64,
            extra_data: Vec::new(),
            mix_hash: vec![0u8; 32],
            nonce: 0,
            base_fee_per_gas: vec![0u64; 4],
            withdrawals_root: vec![0u8; 32],
            size: 0,
            gas_used: 0,
            gas_limit: DEFAULT_GAS_LIMIT,
            cumulative_gas_used: 0,
            total_log_count: 0,
            next_ordinal: 1,
            txns: std::collections::HashMap::new(),
            system_calls_calls: Vec::new(),
            system_calls_account_accesses: Vec::new(),
            system_calls_storage_accesses: Vec::new(),
            pending_txn_headers: std::collections::HashMap::new(),
            pending_access_lists: std::collections::HashMap::new(),
            current_txn_idx: None,
            current_account_idx: 0,
        }
    }

    fn add_event_old(&mut self, event: ExecEvent) -> Result<()> {
        match event {
            ExecEvent::BlockStart(block_start) => {
                self.current_txn_idx = None;
                self.handle_block_start(block_start)?;
            }
            ExecEvent::BlockEnd(block_end) => {
                self.current_txn_idx = None;
                self.handle_block_end(block_end)?;
            }
            ExecEvent::TxnHeaderStart {
                txn_index,
                txn_header_start,
                data_bytes,
                blob_bytes: _,
            } => {
                self.current_txn_idx = Some(txn_index);
                self.handle_txn_header(txn_index, txn_header_start, data_bytes)?;
            }
            ExecEvent::TxnAccessListEntry {
                txn_index,
                txn_access_list_entry,
                storage_key_bytes,
            } => {
                self.handle_txn_access_list_entry(txn_index, txn_access_list_entry, storage_key_bytes)?;
            }
            ExecEvent::TxnEvmOutput { txn_index, output } => {
                self.current_txn_idx = Some(txn_index);
                self.handle_txn_evm_output(txn_index, output)?;
            }
            ExecEvent::TxnEnd => {
                self.handle_txn_end()?;
            }
            ExecEvent::TxnLog { txn_index, txn_log, topic_bytes, data_bytes } => {
                self.handle_txn_log(txn_index, txn_log, topic_bytes, data_bytes)?;
            }
            ExecEvent::TxnCallFrame { txn_index, txn_call_frame, input_bytes, return_bytes } => {
                self.handle_call_frame(txn_index, txn_call_frame, input_bytes, return_bytes)?;
            }
            ExecEvent::AccountAccessListHeader(header) => {
                self.current_account_idx = 0;
                let _ = header;
            }
            ExecEvent::AccountAccess(account_access) => {
                let txn_index = self.current_txn_idx;
                self.current_account_idx = account_access.index as u64;
                self.handle_account_access(account_access, txn_index)?;
            }
            ExecEvent::StorageAccess(storage_access) => {
                let txn_index = self.current_txn_idx;
                let _account_index = self.current_account_idx;
                self.handle_storage_access(storage_access, txn_index)?;
            }
            _ => {
                debug!("Skipping event type: {:?}", event);
            }
        }
        Ok(())
    }

    fn handle_block_start(&mut self, block_start: monad_exec_events::ffi::monad_exec_block_start) -> Result<()> {
        debug!("BlockStart: block #{}", self.block_number);

        let nonce = u64::from_le_bytes(block_start.eth_block_input.nonce.bytes);
        let extra_data_len = block_start.eth_block_input.extra_data_length as usize;

        self.parent_hash = ensure_hash_bytes(block_start.parent_eth_hash.bytes.to_vec());
        self.uncle_hash = ensure_hash_bytes(block_start.eth_block_input.ommers_hash.bytes.to_vec());
        self.coinbase = ensure_address_bytes(block_start.eth_block_input.beneficiary.bytes.to_vec());
        self.transactions_root = ensure_hash_bytes(block_start.eth_block_input.transactions_root.bytes.to_vec());
        self.difficulty = block_start.eth_block_input.difficulty;
        self.gas_limit = block_start.eth_block_input.gas_limit;
        self.timestamp = block_start.eth_block_input.timestamp;
        self.extra_data = block_start.eth_block_input.extra_data.bytes[..extra_data_len].to_vec();
        self.mix_hash = ensure_hash_bytes(block_start.eth_block_input.prev_randao.bytes.to_vec());
        self.nonce = nonce;
        self.base_fee_per_gas = block_start.eth_block_input.base_fee_per_gas.limbs.to_vec();
        self.withdrawals_root = ensure_hash_bytes(block_start.eth_block_input.withdrawals_root.bytes.to_vec());

        debug!("BLOCK_START parent_hash: {}", hex::encode(&self.parent_hash));
        Ok(())
    }

    fn handle_block_end(&mut self, block_end: monad_exec_events::ffi::monad_exec_block_end) -> Result<()> {
        debug!("BlockEnd: block #{}", self.block_number);

        self.block_hash = ensure_hash_bytes(block_end.eth_block_hash.bytes.to_vec());
        self.state_root = ensure_hash_bytes(block_end.exec_output.state_root.bytes.to_vec());
        self.receipts_root = ensure_hash_bytes(block_end.exec_output.receipts_root.bytes.to_vec());
        self.logs_bloom = if block_end.exec_output.logs_bloom.bytes.iter().all(|&b| b == 0) {
            vec![0u8; 256]
        } else {
            block_end.exec_output.logs_bloom.bytes.to_vec()
        };
        self.gas_used = block_end.exec_output.gas_used;
        self.size = MONAD_BLOCK_SIZE;

        debug!("BLOCK_END hash: {}", hex::encode(&self.block_hash));
        Ok(())
    }

    fn handle_txn_header(
        &mut self,
        txn_index: usize,
        txn_header: monad_exec_events::ffi::monad_exec_txn_header_start,
        data_bytes: Box<[u8]>,
    ) -> Result<()> {
        let expected_access_list_count = txn_header.txn_header.access_list_count;

        self.pending_txn_headers.insert(txn_index, PendingTxnHeader {
            txn_header,
            data_bytes,
            expected_access_list_count,
        });

        if expected_access_list_count == 0 {
            self.try_emit_txn_header(txn_index)?;
        }

        Ok(())
    }

    fn handle_txn_access_list_entry(
        &mut self,
        txn_index: usize,
        entry: monad_exec_events::ffi::monad_exec_txn_access_list_entry,
        storage_key_bytes: Box<[u8]>,
    ) -> Result<()> {
        let mut storage_keys = Vec::new();
        for i in 0..entry.entry.storage_key_count as usize {
            let start = i * 32;
            let end = start + 32;
            if end <= storage_key_bytes.len() {
                storage_keys.push(storage_key_bytes[start..end].to_vec());
            }
        }

        let access_tuple = AccessTuple {
            address: entry.entry.address.bytes.to_vec(),
            storage_keys,
        };

        self.pending_access_lists.entry(txn_index).or_default().push(access_tuple);
        self.try_emit_txn_header(txn_index)?;
        Ok(())
    }

    fn try_emit_txn_header(&mut self, txn_index: usize) -> Result<()> {
        let pending = match self.pending_txn_headers.get(&txn_index) {
            Some(p) => p,
            None => return Ok(()),
        };

        let collected_count = self.pending_access_lists
            .get(&txn_index)
            .map(|l| l.len())
            .unwrap_or(0);

        if collected_count < pending.expected_access_list_count as usize {
            return Ok(());
        }

        let pending = self.pending_txn_headers.remove(&txn_index).unwrap();
        let access_list = self.pending_access_lists.remove(&txn_index).unwrap_or_default();

        let txn_type = pending.txn_header.txn_header.txn_type as u32;
        let max_fee_limbs = pending.txn_header.txn_header.max_fee_per_gas.limbs.to_vec();
        let max_priority_fee_limbs = pending.txn_header.txn_header.max_priority_fee_per_gas.limbs.to_vec();
        let gas_price = self.calculate_effective_gas_price(&max_fee_limbs, &max_priority_fee_limbs, txn_type);

        let value = u256_limbs_to_bytes(&pending.txn_header.txn_header.value.limbs);
        let r = u256_limbs_to_bytes(&pending.txn_header.txn_header.r.limbs);
        let s = u256_limbs_to_bytes(&pending.txn_header.txn_header.s.limbs);
        let chain_id = pending.txn_header.txn_header.chain_id.limbs.first().copied().unwrap_or(0);
        let y_parity = pending.txn_header.txn_header.y_parity;

        let v = match txn_type {
            0 => {
                let v_value = chain_id * 2 + 35 + (y_parity as u64);
                encode_v_bytes(v_value)
            }
            2 => {
                if y_parity { vec![1] } else { vec![] }
            }
            _ => {
                if y_parity { vec![1] } else { vec![] }
            }
        };

        let hash = ensure_hash_bytes(pending.txn_header.txn_hash.bytes.to_vec());
        let from = ensure_address_bytes(pending.txn_header.sender.bytes.to_vec());
        let to = {
            let raw = pending.txn_header.txn_header.to.bytes.to_vec();
            if raw.is_empty() { vec![] } else { ensure_address_bytes(raw) }
        };

        let trace = TransactionTrace {
            index: txn_index as u32,
            hash,
            from,
            to,
            nonce: pending.txn_header.txn_header.nonce,
            gas_limit: pending.txn_header.txn_header.gas_limit,
            value: if value.iter().any(|&b| b != 0) { Some(BigInt { bytes: value }) } else { None },
            gas_price: Some(BigInt { bytes: gas_price }),
            max_fee_per_gas: if txn_type == 2 {
                Some(BigInt { bytes: u256_limbs_to_bytes(&max_fee_limbs) })
            } else {
                None
            },
            max_priority_fee_per_gas: if txn_type == 2 {
                Some(BigInt { bytes: u256_limbs_to_bytes(&max_priority_fee_limbs) })
            } else {
                None
            },
            input: pending.data_bytes.to_vec(),
            v,
            r,
            s,
            r#type: txn_type as i32,
            access_list,
            begin_ordinal: 0,
            end_ordinal: 0,
            ..Default::default()
        };

        self.txns.insert(txn_index, TxState {
            trace,
            pending_calls: Vec::new(),
            pending_balance_changes: Vec::new(),
            pending_nonce_changes: Vec::new(),
            pending_storage_changes: Vec::new(),
        });
        Ok(())
    }

    fn handle_txn_evm_output(
        &mut self,
        txn_index: usize,
        output: monad_exec_events::ffi::monad_exec_txn_evm_output,
    ) -> Result<()> {
        debug!("TxnEvmOutput: txn_index={}, status={}, gas_used={}", txn_index, output.receipt.status, output.receipt.gas_used);

        // TODO: use index if parallel
        self.cumulative_gas_used += output.receipt.gas_used;

        if let Some(tx) = self.txns.get_mut(&txn_index) {
            tx.trace.gas_used = output.receipt.gas_used;
            tx.trace.status = if output.receipt.status { 1 } else { 2 };
            tx.trace.receipt = Some(firehose::pb::sf::ethereum::r#type::v2::TransactionReceipt {
                cumulative_gas_used: self.cumulative_gas_used,
                logs_bloom: vec![0u8; 256],
                logs: Vec::new(),
                ..Default::default()
            });
        }

        Ok(())
    }

    fn handle_txn_log(
        &mut self,
        txn_index: usize,
        log: monad_exec_events::ffi::monad_exec_txn_log,
        topic_bytes: Box<[u8]>,
        data_bytes: Box<[u8]>,
    ) -> Result<()> {
        let mut topics = Vec::new();
        for i in 0..log.topic_count as usize {
            let start = i * 32;
            let end = start + 32;
            if end <= topic_bytes.len() {
                topics.push(ensure_hash_bytes(topic_bytes[start..end].to_vec()));
            }
        }

        let log_index = self.total_log_count as u32;
        self.total_log_count += 1;

        let log_entry = firehose::pb::sf::ethereum::r#type::v2::Log {
            address: ensure_address_bytes(log.address.bytes.to_vec()),
            topics,
            data: data_bytes.to_vec(),
            index: log_index,
            block_index: log_index,
            ..Default::default()
        };

        if let Some(tx) = self.txns.get_mut(&txn_index) {
            if let Some(receipt) = tx.trace.receipt.as_mut() {
                receipt.logs.push(log_entry);
            }
        }

        Ok(())
    }

    fn handle_call_frame(
        &mut self,
        txn_index: Option<usize>,
        call_frame: monad_exec_events::ffi::monad_exec_txn_call_frame,
        input_bytes: Box<[u8]>,
        return_bytes: Box<[u8]>,
    ) -> Result<()> {
        let call = Self::build_call_from_frame(&call_frame, &input_bytes, &return_bytes);

        if let Some(idx) = txn_index {
            if let Some(tx) = self.txns.get_mut(&idx) {
                tx.pending_calls.push(call);
            }
        } else {
            debug!("BLOCK_PROLOGUE call frame for: {}", hex::encode(call_frame.call_target.bytes));
            // System calls: group by address at finalize time — store directly
            self.system_calls_calls.push(call);
        }

        Ok(())
    }

    fn build_call_from_frame(
        call_frame: &monad_exec_events::ffi::monad_exec_txn_call_frame,
        input_bytes: &[u8],
        return_bytes: &[u8],
    ) -> firehose::pb::sf::ethereum::r#type::v2::Call {
        let firehose_index = call_frame.index + 1;
        let call_type = opcode_to_call_type(call_frame.opcode as u8);
        let normalized_call_target = ensure_address_bytes(call_frame.call_target.bytes.to_vec());
        let is_precompile = is_precompile_address(&normalized_call_target);
        let status_reverted = call_frame.evmc_status == 2 || call_frame.evmc_status == 17;
        let status_failed = call_frame.evmc_status != 0;
        let failure_reason = evmc_status_to_failure_reason(call_frame.evmc_status);
        let value = u256_limbs_to_bytes(&call_frame.value.limbs);

        let is_call_opcode = call_frame.opcode == 0xF1;
        let is_pure_transfer = is_call_opcode
            && call_frame.depth == 0
            && input_bytes.is_empty()
            && return_bytes.is_empty()
            && !is_precompile;
        let executed_code = if is_precompile {
            true
        } else if is_pure_transfer {
            false
        } else {
            call_frame.gas_used > 0
        };

        let state_reverted = call_frame.evmc_status != 0;

        let is_create = call_frame.opcode == 0xF0 || call_frame.opcode == 0xF5;
        let is_successful_create = is_create && call_frame.evmc_status == 0 && !return_bytes.is_empty();
        let return_data = if is_successful_create { vec![] } else { return_bytes.to_vec() };
        let code_changes = if is_successful_create {
            let target_addr = ensure_address_bytes(call_frame.call_target.bytes.to_vec());
            // old_hash is always the empty code hash (keccak256 of empty bytes) for a new contract
            vec![CodeChange {
                old_hash: keccak256(&[]).to_vec(),
                new_hash: keccak256(return_bytes).to_vec(),
                new_code: return_bytes.to_vec(),
                address: target_addr,
                old_code: vec![],
                ordinal: 0,
            }]
        } else {
            vec![]
        };

        firehose::pb::sf::ethereum::r#type::v2::Call {
            index: firehose_index,
            parent_index: 0, // assigned below in assign_parent_indices
            depth: call_frame.depth as u32,
            call_type: call_type as i32,
            caller: ensure_address_bytes(call_frame.caller.bytes.to_vec()),
            address: normalized_call_target,
            value: if value.iter().any(|&b| b != 0) { Some(BigInt { bytes: value }) } else { None },
            gas_limit: call_frame.gas,
            gas_consumed: call_frame.gas_used,
            return_data,
            input: input_bytes.to_vec(),
            executed_code,
            suicide: call_frame.opcode == 0xFF,
            status_failed,
            status_reverted,
            state_reverted,
            failure_reason,
            code_changes,
            ..Default::default()
        }
    }

    fn assign_parent_indices(calls: &mut Vec<firehose::pb::sf::ethereum::r#type::v2::Call>) {
        let mut parent_stack: Vec<u32> = Vec::new();
        for call in calls.iter_mut() {
            let depth = call.depth as usize;
            call.parent_index = if depth == 0 {
                0
            } else if depth <= parent_stack.len() {
                parent_stack[depth - 1]
            } else {
                call.index
            };

            if depth >= parent_stack.len() {
                parent_stack.resize(depth + 1, call.index);
            } else {
                parent_stack[depth] = call.index;
                parent_stack.truncate(depth + 1);
            }
        }
    }

    fn handle_txn_end(&mut self) -> Result<()> {
        let txn_index = self.current_txn_idx.unwrap_or(0);
        debug!("TX_END: finalizing tx #{}", txn_index);

        let tx = match self.txns.get_mut(&txn_index) {
            Some(t) => t,
            None => {
                debug!("TX_END: no transaction found for index {}", txn_index);
                return Ok(());
            }
        };

        if !tx.pending_calls.is_empty() {
            tx.trace.calls = std::mem::take(&mut tx.pending_calls);
            Self::assign_parent_indices(&mut tx.trace.calls);

            // Propagate state_reverted down the call tree
            let reverted: std::collections::HashSet<u32> = tx.trace.calls.iter()
                .filter(|c| c.state_reverted)
                .map(|c| c.index)
                .collect();
            let mut reverted_indices = reverted;
            for i in 0..tx.trace.calls.len() {
                if reverted_indices.contains(&tx.trace.calls[i].parent_index) {
                    tx.trace.calls[i].state_reverted = true;
                    reverted_indices.insert(tx.trace.calls[i].index);
                }
            }

            // Fill in contract creation `to` from the root frame's deployed address
            if tx.trace.to.is_empty() || tx.trace.to == vec![0u8; 20] {
                if let Some(root_call) = tx.trace.calls.first() {
                    if root_call.address != vec![0u8; 20] {
                        tx.trace.to = root_call.address.clone();
                    }
                }
            }
        }

        // No call frames — synthetic root call
        if tx.trace.calls.is_empty() {
            debug!("TX_END: creating synthetic root call for tx #{}", txn_index);
            let root_call = firehose::pb::sf::ethereum::r#type::v2::Call {
                index: 1,
                parent_index: 0,
                depth: 0,
                call_type: if tx.trace.to.is_empty() || tx.trace.to == vec![0u8; 20] {
                    firehose::pb::sf::ethereum::r#type::v2::CallType::Create as i32
                } else {
                    firehose::pb::sf::ethereum::r#type::v2::CallType::Call as i32
                },
                caller: tx.trace.from.clone(),
                address: tx.trace.to.clone(),
                value: tx.trace.value.clone(),
                gas_limit: 0,
                gas_consumed: 0,
                return_data: Vec::new(),
                input: tx.trace.input.clone(),
                executed_code: false,
                suicide: false,
                status_failed: tx.trace.status != 1,
                status_reverted: false,
                failure_reason: String::new(),
                state_reverted: false,
                ..Default::default()
            };
            tx.trace.calls.push(root_call);
        }

        if let Some(root_call) = tx.trace.calls.first_mut() {
            if let Some(ref receipt) = tx.trace.receipt {
                root_call.logs = receipt.logs.clone();
            }
        }

        // Flush pending state changes onto root call
        if !tx.pending_balance_changes.is_empty() || !tx.pending_nonce_changes.is_empty() || !tx.pending_storage_changes.is_empty() {
            if let Some(root_call) = tx.trace.calls.first_mut() {
                root_call.balance_changes.extend(std::mem::take(&mut tx.pending_balance_changes));
                root_call.nonce_changes.extend(std::mem::take(&mut tx.pending_nonce_changes));
                root_call.storage_changes.extend(std::mem::take(&mut tx.pending_storage_changes));
            }
        }

        if let Some(root_call) = tx.trace.calls.first() {
            use firehose::pb::sf::ethereum::r#type::v2::TransactionTraceStatus;
            if tx.trace.status != TransactionTraceStatus::Succeeded as i32 {
                tx.trace.status = if root_call.status_reverted {
                    TransactionTraceStatus::Reverted as i32
                } else {
                    TransactionTraceStatus::Failed as i32
                };
            }
            tx.trace.return_data = root_call.return_data.clone();
        }

        Ok(())
    }

    fn handle_account_access(
        &mut self,
        account_access: monad_exec_events::ffi::monad_exec_account_access,
        txn_index: Option<usize>,
    ) -> Result<()> {
        use firehose::pb::sf::ethereum::r#type::v2::{BalanceChange, BigInt as PbBigInt, NonceChange};
        use firehose::pb::sf::ethereum::r#type::v2::balance_change::Reason as BalanceReason;

        let prestate_balance = u256_limbs_to_bytes(&account_access.prestate.balance.limbs);
        let modified_balance = u256_limbs_to_bytes(&account_access.modified_balance.limbs);
        let address = ensure_address_bytes(account_access.address.bytes.to_vec());

        debug!("ACCOUNT_ACCESS: addr={} ctx={} bal_mod={} nonce_mod={}",
               hex::encode(&address), account_access.access_context as u8,
               account_access.is_balance_modified, account_access.is_nonce_modified);

        if account_access.access_context as u8 == 0 {
            // BLOCK_PROLOGUE — buffer for finalize
            self.system_calls_account_accesses.push((
                address,
                account_access.is_balance_modified,
                prestate_balance,
                modified_balance,
                account_access.is_nonce_modified,
                account_access.prestate.nonce,
                account_access.modified_nonce,
            ));
            return Ok(());
        }

        let txn_index = txn_index.unwrap_or(0);

        if let Some(tx) = self.txns.get_mut(&txn_index) {
            if let Some(root_call) = tx.trace.calls.first_mut() {
                if account_access.is_balance_modified {
                    root_call.balance_changes.push(BalanceChange {
                        address: address.clone(),
                        old_value: Some(PbBigInt { bytes: prestate_balance }),
                        new_value: Some(PbBigInt { bytes: modified_balance }),
                        reason: BalanceReason::MonadTxPostState as i32,
                        ordinal: 0,
                    });
                }
                if account_access.is_nonce_modified {
                    root_call.nonce_changes.push(NonceChange {
                        address,
                        old_value: account_access.prestate.nonce,
                        new_value: account_access.modified_nonce,
                        ordinal: 0,
                    });
                }
            } else {
                // Call tree not built yet, buffer until TxnEnd
                if account_access.is_balance_modified {
                    tx.pending_balance_changes.push(BalanceChange {
                        address: address.clone(),
                        old_value: Some(PbBigInt { bytes: prestate_balance }),
                        new_value: Some(PbBigInt { bytes: modified_balance }),
                        reason: BalanceReason::MonadTxPostState as i32,
                        ordinal: 0,
                    });
                }
                if account_access.is_nonce_modified {
                    tx.pending_nonce_changes.push(NonceChange {
                        address,
                        old_value: account_access.prestate.nonce,
                        new_value: account_access.modified_nonce,
                        ordinal: 0,
                    });
                }
            }
        }

        Ok(())
    }

    fn handle_storage_access(
        &mut self,
        storage_access: monad_exec_events::ffi::monad_exec_storage_access,
        txn_index: Option<usize>,
    ) -> Result<()> {
        use firehose::pb::sf::ethereum::r#type::v2::StorageChange;

        let access_context = storage_access.access_context as u8;
        let address = ensure_address_bytes(storage_access.address.bytes.to_vec());

        if access_context == 0 {
            if storage_access.modified && !storage_access.transient {
                self.system_calls_storage_accesses.push((
                    address,
                    storage_access.key.bytes.to_vec(),
                    storage_access.start_value.bytes.to_vec(),
                    storage_access.end_value.bytes.to_vec(),
                ));
            }
            return Ok(());
        }

        if !storage_access.modified || storage_access.transient {
            return Ok(());
        }

        let txn_index = txn_index.unwrap_or(0);

        if let Some(tx) = self.txns.get_mut(&txn_index) {
            let change = StorageChange {
                address,
                key: ensure_hash_bytes(storage_access.key.bytes.to_vec()),
                old_value: ensure_hash_bytes(storage_access.start_value.bytes.to_vec()),
                new_value: ensure_hash_bytes(storage_access.end_value.bytes.to_vec()),
                ordinal: 0,
            };
            if let Some(root_call) = tx.trace.calls.first_mut() {
                root_call.storage_changes.push(change);
            } else {
                tx.pending_storage_changes.push(change);
            }
        }

        Ok(())
    }

    fn calculate_effective_gas_price(
        &self,
        max_fee_limbs: &[u64],
        priority_fee_limbs: &[u64],
        txn_type: u32,
    ) -> Vec<u8> {
        match txn_type {
            0 => u256_limbs_to_bytes(max_fee_limbs),
            2 => {
                let max_fee = u256_limbs_to_bytes(max_fee_limbs);
                let priority_fee = u256_limbs_to_bytes(priority_fee_limbs);
                let base_fee = u256_limbs_to_bytes(&self.base_fee_per_gas);
                let sum = add_u256_bytes(&base_fee, &priority_fee);
                if compare_u256_bytes(&max_fee, &sum) <= 0 { max_fee } else { sum }
            }
            _ => u256_limbs_to_bytes(max_fee_limbs),
        }
    }

    fn finalize(mut self) -> Result<Block> {
        debug!("Finalizing block {}", self.block_number);

        // Collect and sort transactions
        let mut transactions: Vec<TransactionTrace> = self.txns.into_values().map(|mut tx_state| {
            let tx = &mut tx_state.trace;
            if tx.receipt.is_none() {
                tx.receipt = Some(firehose::pb::sf::ethereum::r#type::v2::TransactionReceipt {
                    cumulative_gas_used: 0,
                    logs_bloom: vec![0u8; 256],
                    logs: Vec::new(),
                    ..Default::default()
                });
            }
            if let Some(ref mut receipt) = tx.receipt {
                receipt.logs_bloom = calculate_logs_bloom(&receipt.logs);
            }
            tx_state.trace
        }).collect();
        transactions.sort_by_key(|tx| tx.index);

        // Assign ordinals
        for tx in &mut transactions {
            tx.begin_ordinal = self.next_ordinal;
            self.next_ordinal += 1;

            // Assign call begin/end ordinals in execution order
            let n = tx.calls.len();
            let mut open: Vec<usize> = Vec::new();
            for i in 0..n {
                let depth = tx.calls[i].depth;
                while open.last().map(|&j| tx.calls[j].depth >= depth).unwrap_or(false) {
                    let j = open.pop().unwrap();
                    tx.calls[j].end_ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }
                tx.calls[i].begin_ordinal = self.next_ordinal;
                self.next_ordinal += 1;
                open.push(i);
            }
            // Close all inner calls (depth > 0) root call stays open until after state changes
            while open.last().map(|&j| tx.calls[j].depth > 0).unwrap_or(false) {
                let j = open.pop().unwrap();
                tx.calls[j].end_ordinal = self.next_ordinal;
                self.next_ordinal += 1;
            }

            // depth-0 call, end ordinal assigned after state changes
            let root_call_idx = open.pop();

            // Assign log ordinals in emission order (log.index is deterministic)
            if let Some(root_call) = tx.calls.first_mut() {
                root_call.logs.sort_by_key(|l| l.index);
                for log in &mut root_call.logs {
                    log.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }
            }

            // Receipt logs share ordinals with their matching call logs
            if let Some(ref mut receipt) = tx.receipt {
                for rlog in &mut receipt.logs {
                    if let Some(root_call) = tx.calls.first() {
                        if let Some(clog) = root_call.logs.iter().find(|l| l.index == rlog.index) {
                            rlog.ordinal = clog.ordinal;
                        }
                    }
                }
            }

            // Assign ordinals to state changes on root call
            if let Some(root_call) = tx.calls.first_mut() {
                for change in &mut root_call.balance_changes {
                    change.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }
                for change in &mut root_call.nonce_changes {
                    change.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }
                for change in &mut root_call.storage_changes {
                    change.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }
            }

            // Close root call after state changes
            if let Some(idx) = root_call_idx {
                tx.calls[idx].end_ordinal = self.next_ordinal;
                self.next_ordinal += 1;
            }

            tx.end_ordinal = self.next_ordinal;
            self.next_ordinal += 1;
        }

        // Apply system account/storage accesses to matching system calls
        {
            use firehose::pb::sf::ethereum::r#type::v2::{BalanceChange, BigInt as PbBigInt, NonceChange, StorageChange};
            use firehose::pb::sf::ethereum::r#type::v2::balance_change::Reason as BalanceReason;

            for (addr, bal_mod, pre_bal, mod_bal, nonce_mod, pre_nonce, mod_nonce) in self.system_calls_account_accesses.drain(..) {
                let call = self.system_calls_calls.iter_mut().find(|c| c.address == addr);
                if let Some(call) = call {
                    if bal_mod {
                        call.balance_changes.push(BalanceChange {
                            address: addr.clone(),
                            old_value: Some(PbBigInt { bytes: pre_bal }),
                            new_value: Some(PbBigInt { bytes: mod_bal }),
                            reason: BalanceReason::MonadTxPostState as i32,
                            ordinal: 0,
                        });
                    }
                    if nonce_mod {
                        call.nonce_changes.push(NonceChange {
                            address: addr,
                            old_value: pre_nonce,
                            new_value: mod_nonce,
                            ordinal: 0,
                        });
                    }
                }
            }
            for (addr, key, start, end) in self.system_calls_storage_accesses.drain(..) {
                let call = self.system_calls_calls.iter_mut().find(|c| c.address == addr);
                if let Some(call) = call {
                    call.storage_changes.push(StorageChange {
                        address: ensure_address_bytes(addr),
                        key: ensure_hash_bytes(key),
                        old_value: ensure_hash_bytes(start),
                        new_value: ensure_hash_bytes(end),
                        ordinal: 0,
                    });
                }
            }
        }

        // Re-index system calls
        for (i, call) in self.system_calls_calls.iter_mut().enumerate() {
            call.index = i as u32;
        }
        let system_calls = self.system_calls_calls;

        let header = BlockHeader {
            parent_hash: self.parent_hash,
            uncle_hash: self.uncle_hash,
            coinbase: self.coinbase,
            state_root: self.state_root,
            transactions_root: self.transactions_root,
            receipt_root: self.receipts_root,
            logs_bloom: self.logs_bloom,
            difficulty: Some(BigInt { bytes: vec![] }),
            #[allow(deprecated)]
            total_difficulty: None,
            number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: Some(prost_types::Timestamp {
                seconds: self.timestamp as i64,
                nanos: 0,
            }),
            extra_data: self.extra_data,
            mix_hash: self.mix_hash,
            nonce: self.nonce,
            hash: self.block_hash,
            base_fee_per_gas: Some(BigInt { bytes: u256_limbs_to_bytes(&self.base_fee_per_gas) }),
            withdrawals_root: self.withdrawals_root,
            tx_dependency: None,
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_root: vec![0u8; 32],
            requests_hash: vec![0u8; 32],
        };

        let total_calls: usize = transactions.iter().map(|tx| tx.calls.len()).sum();
        let total_logs: usize = transactions.iter()
            .filter_map(|tx| tx.receipt.as_ref())
            .map(|r| r.logs.len())
            .sum();

        let block = Block {
            number: self.block_number,
            hash: header.hash.clone(),
            size: self.size,
            header: Some(header),
            transaction_traces: transactions,
            system_calls: system_calls.clone(),
            ver: 3,
            detail_level: block::DetailLevel::DetaillevelExtended as i32,
            ..Default::default()
        };

        debug!(
            "Finalized block #{}: {} txs, {} calls, {} logs, {} system_calls",
            self.block_number, block.transaction_traces.len(), total_calls, total_logs, block.system_calls.len()
        );
        debug!(
            "Block #{} hashes: block_hash={}, parent_hash={}",
            self.block_number,
            hex::encode(&block.hash),
            block.header.as_ref().map(|h| hex::encode(&h.parent_hash)).unwrap_or_default()
        );
        for (i, syscall) in block.system_calls.iter().enumerate() {
            debug!("Block #{} SystemCall {}: address={}, input={}",
                self.block_number, i, hex::encode(&syscall.address), hex::encode(&syscall.input));
        }

        Ok(block)
    }
}

pub struct EventMapper {
    blocks: std::collections::HashMap<u64, BlockBuilder>,
    current_block_num: u64,
}

impl EventMapper {
    pub fn new() -> Self {
        Self {
            blocks: std::collections::HashMap::new(),
            current_block_num: 0,
        }
    }

    pub fn finalize_pending(&mut self) -> Result<Option<Box<Block>>> {
        if let Some(builder) = self.blocks.remove(&self.current_block_num) {
            return Ok(Some(Box::new(builder.finalize()?)));
        }
        Ok(None)
    }

    pub async fn process_event(&mut self, event: ExecEvent) -> Result<Option<Box<Block>>> {
        // Determine block number from BlockStart events; otherwise use current
        let block_num = if let ExecEvent::BlockStart(ref bs) = event {
            let num = bs.eth_block_input.number;
            self.current_block_num = num;
            num
        } else {
            self.current_block_num
        };

        let is_block_end = matches!(event, ExecEvent::BlockEnd(_));

        debug!("Processing event block={}", block_num);

        let builder = self.blocks.entry(block_num).or_insert_with(|| BlockBuilder::new(block_num));
        builder.add_event_old(event)?;

        if is_block_end {
            if let Some(builder) = self.blocks.remove(&block_num) {
                return Ok(Some(Box::new(builder.finalize()?)));
            }
        }

        Ok(None)
    }
}
