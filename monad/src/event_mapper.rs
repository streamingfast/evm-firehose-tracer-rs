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
    // Remove leading zeros but keep at least one byte
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    bytes
}

/// Convert U256 limbs (4x u64 in little-endian) to big-endian bytes with leading zero compaction
fn u256_limbs_to_bytes(limbs: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    // U256 is stored as 4 limbs in little-endian order
    // We need to convert to big-endian for protobuf
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
    // Pad to 32 bytes for addition
    let mut a_padded = [0u8; 32];
    let mut b_padded = [0u8; 32];

    let a_start = 32 - a.len();
    let b_start = 32 - b.len();
    a_padded[a_start..].copy_from_slice(a);
    b_padded[b_start..].copy_from_slice(b);

    let mut result = vec![0u8; 32];
    let mut carry = 0u16;

    // Add from least significant byte
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

    // Compare lengths first (longer is larger, assuming no leading zeros)
    if a_len != b_len {
        return if a_len > b_len { 1 } else { -1 };
    }

    // Same length, compare byte by byte from most significant
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

/// Raw call frame data from Monad events
#[derive(Clone, Debug)]
struct CallFrameData {
    index: u32,
    caller: Vec<u8>,
    call_target: Vec<u8>,
    opcode: u8,
    value: Vec<u8>,
    gas: u64,
    gas_used: u64,
    evmc_status: i32,
    depth: u64,
    input: Vec<u8>,
    return_data: Vec<u8>,
}

/// Raw account access data from Monad events
#[derive(Clone, Debug)]
struct AccountAccessData {
    address: Vec<u8>,
    access_context: u8,
    is_balance_modified: bool,
    is_nonce_modified: bool,
    prestate_balance: Vec<u8>,
    prestate_nonce: u64,
    prestate_code_hash: Vec<u8>,
    modified_balance: Vec<u8>,
    modified_nonce: u64,
}

/// Raw storage access data from Monad events
#[derive(Clone, Debug)]
struct StorageAccessData {
    address: Vec<u8>,
    modified: bool,
    transient: bool,
    key: Vec<u8>,
    start_value: Vec<u8>,
    end_value: Vec<u8>,
}

/// Buffered transaction header waiting for access list entries
struct PendingTxnHeader {
    txn_header: monad_exec_events::ffi::monad_exec_txn_header_start,
    data_bytes: Box<[u8]>,
    expected_access_list_count: u32,
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
    transactions_map: std::collections::HashMap<usize, TransactionTrace>,
    cumulative_gas_used: u64,
    total_log_count: usize,
    next_ordinal: u64,
    call_frames: std::collections::HashMap<usize, Vec<CallFrameData>>,
    account_accesses: std::collections::HashMap<usize, Vec<AccountAccessData>>,
    storage_accesses: std::collections::HashMap<usize, Vec<StorageAccessData>>,
    system_calls_account_accesses: Vec<AccountAccessData>,
    system_calls_storage_accesses: Vec<StorageAccessData>,
    system_calls_call_frames: Vec<CallFrameData>,
    // Access list buffering (TxnHeaderStart arrives before TxnAccessListEntry)
    pending_txn_headers: std::collections::HashMap<usize, PendingTxnHeader>,
    pending_access_lists: std::collections::HashMap<usize, Vec<AccessTuple>>,
    // Track current txn index for events that don't carry it
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
            transactions_map: std::collections::HashMap::new(),
            cumulative_gas_used: 0,
            total_log_count: 0,
            next_ordinal: 0,
            call_frames: std::collections::HashMap::new(),
            account_accesses: std::collections::HashMap::new(),
            storage_accesses: std::collections::HashMap::new(),
            system_calls_account_accesses: Vec::new(),
            system_calls_storage_accesses: Vec::new(),
            system_calls_call_frames: Vec::new(),
            pending_txn_headers: std::collections::HashMap::new(),
            pending_access_lists: std::collections::HashMap::new(),
            current_txn_idx: None,
            current_account_idx: 0,
        }
    }

    fn add_event(&mut self, event: ExecEvent) -> Result<()> {
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
                // Just metadata, no need to store
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

        let tx_trace = TransactionTrace {
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

        self.transactions_map.insert(txn_index, tx_trace);
        Ok(())
    }

    fn handle_txn_evm_output(
        &mut self,
        txn_index: usize,
        output: monad_exec_events::ffi::monad_exec_txn_evm_output,
    ) -> Result<()> {
        debug!("TxnEvmOutput: txn_index={}, status={}, gas_used={}", txn_index, output.receipt.status, output.receipt.gas_used);

        self.cumulative_gas_used += output.receipt.gas_used;

        if let Some(tx) = self.transactions_map.get_mut(&txn_index) {
            tx.gas_used = output.receipt.gas_used;
            tx.status = if output.receipt.status { 1 } else { 2 };
            tx.receipt = Some(firehose::pb::sf::ethereum::r#type::v2::TransactionReceipt {
                cumulative_gas_used: self.cumulative_gas_used,
                logs_bloom: vec![0u8; 256],
                logs: Vec::new(),
                ..Default::default()
            });
        }

        Ok(())
    }

    fn handle_txn_end(&mut self) -> Result<()> {
        let txn_index = self.current_txn_idx.unwrap_or(0);
        debug!("TX_END: building call tree eagerly for tx #{}", txn_index);

        if !self.transactions_map.contains_key(&txn_index) {
            debug!("TX_END: no transaction found for index {}", txn_index);
            return Ok(());
        }

        if self.transactions_map[&txn_index].calls.is_empty() {
            let frames = self.call_frames.remove(&txn_index).unwrap_or_default();
            let code_hash_by_address: std::collections::HashMap<Vec<u8>, Vec<u8>> = std::collections::HashMap::new();

            let tx = self.transactions_map.get_mut(&txn_index).unwrap();

            if !frames.is_empty() {
                debug!("TX_END: building call tree for tx #{} with {} frames", txn_index, frames.len());
                tx.calls = Self::build_call_tree(&frames, txn_index, &code_hash_by_address);

                if tx.to.is_empty() || tx.to == vec![0u8; 20] {
                    if let Some(root_frame) = frames.first() {
                        let deployed = ensure_address_bytes(root_frame.call_target.clone());
                        if deployed != vec![0u8; 20] {
                            tx.to = deployed;
                        }
                    }
                }

                let reverted: std::collections::HashSet<u32> = tx.calls.iter()
                    .filter(|c| c.state_reverted)
                    .map(|c| c.index)
                    .collect();
                let mut reverted_indices = reverted;
                for i in 0..tx.calls.len() {
                    if reverted_indices.contains(&tx.calls[i].parent_index) {
                        tx.calls[i].state_reverted = true;
                        reverted_indices.insert(tx.calls[i].index);
                    }
                }
            }

            if tx.calls.is_empty() {
                debug!("TX_END: creating synthetic root call for tx #{}", txn_index);
                let root_call = firehose::pb::sf::ethereum::r#type::v2::Call {
                    index: 1,
                    parent_index: 0,
                    depth: 0,
                    call_type: if tx.to.is_empty() || tx.to == vec![0u8; 20] {
                        firehose::pb::sf::ethereum::r#type::v2::CallType::Create as i32
                    } else {
                        firehose::pb::sf::ethereum::r#type::v2::CallType::Call as i32
                    },
                    caller: tx.from.clone(),
                    address: tx.to.clone(),
                    value: tx.value.clone(),
                    gas_limit: 0,
                    gas_consumed: 0,
                    return_data: Vec::new(),
                    input: tx.input.clone(),
                    executed_code: false,
                    suicide: false,
                    status_failed: tx.status != 1,
                    status_reverted: false,
                    failure_reason: String::new(),
                    state_reverted: false,
                    ..Default::default()
                };
                tx.calls.push(root_call);
            }
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

        if let Some(tx) = self.transactions_map.get_mut(&txn_index) {
            if let Some(receipt) = tx.receipt.as_mut() {
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
        if txn_index.is_none() {
            debug!("System call frame: target={}, input={} bytes", hex::encode(call_frame.call_target.bytes), input_bytes.len());
        }

        let frame = CallFrameData {
            index: call_frame.index,
            caller: call_frame.caller.bytes.to_vec(),
            call_target: call_frame.call_target.bytes.to_vec(),
            opcode: call_frame.opcode as u8,
            value: u256_limbs_to_bytes(&call_frame.value.limbs),
            gas: call_frame.gas,
            gas_used: call_frame.gas_used,
            evmc_status: call_frame.evmc_status,
            depth: call_frame.depth,
            input: input_bytes.to_vec(),
            return_data: return_bytes.to_vec(),
        };

        if let Some(idx) = txn_index {
            self.call_frames.entry(idx).or_default().push(frame);
        } else {
            debug!("BLOCK_PROLOGUE call frame for: {}", hex::encode(&frame.call_target));
            self.system_calls_call_frames.push(frame);
        }

        Ok(())
    }

    fn handle_account_access(
        &mut self,
        account_access: monad_exec_events::ffi::monad_exec_account_access,
        txn_index: Option<usize>,
    ) -> Result<()> {
        let prestate_balance = u256_limbs_to_bytes(&account_access.prestate.balance.limbs);
        let modified_balance = u256_limbs_to_bytes(&account_access.modified_balance.limbs);

        let access = AccountAccessData {
            address: account_access.address.bytes.to_vec(),
            access_context: account_access.access_context as u8,
            is_balance_modified: account_access.is_balance_modified,
            is_nonce_modified: account_access.is_nonce_modified,
            prestate_balance,
            prestate_nonce: account_access.prestate.nonce,
            prestate_code_hash: account_access.prestate.code_hash.bytes.to_vec(),
            modified_balance,
            modified_nonce: account_access.modified_nonce,
        };

        debug!("ACCOUNT_ACCESS: addr={} ctx={} bal_mod={} nonce_mod={}",
               hex::encode(&access.address), access.access_context,
               access.is_balance_modified, access.is_nonce_modified);

        if access.access_context == 0 {
            // BLOCK_PROLOGUE — system call
            self.system_calls_account_accesses.push(access);
        } else {
            use firehose::pb::sf::ethereum::r#type::v2::{BalanceChange, BigInt as PbBigInt, NonceChange};
            use firehose::pb::sf::ethereum::r#type::v2::balance_change::Reason as BalanceReason;

            let txn_index = txn_index.unwrap_or(0);

            if let Some(tx) = self.transactions_map.get_mut(&txn_index) {
                if let Some(root_call) = tx.calls.first_mut() {
                    // Call tree already built — push eagerly
                    if access.is_balance_modified {
                        root_call.balance_changes.push(BalanceChange {
                            address: ensure_address_bytes(access.address.clone()),
                            old_value: Some(PbBigInt { bytes: access.prestate_balance.clone() }),
                            new_value: Some(PbBigInt { bytes: access.modified_balance.clone() }),
                            reason: BalanceReason::MonadTxPostState as i32,
                            ordinal: 0,
                        });
                    }
                    if access.is_nonce_modified {
                        root_call.nonce_changes.push(NonceChange {
                            address: ensure_address_bytes(access.address.clone()),
                            old_value: access.prestate_nonce,
                            new_value: access.modified_nonce,
                            ordinal: 0,
                        });
                    }
                    return Ok(());
                }
            }

            // Call tree not yet built — buffer
            self.account_accesses.entry(txn_index).or_default().push(access);
        }

        Ok(())
    }

    fn handle_storage_access(
        &mut self,
        storage_access: monad_exec_events::ffi::monad_exec_storage_access,
        txn_index: Option<usize>,
    ) -> Result<()> {
        let access_context = storage_access.access_context as u8;

        let access = StorageAccessData {
            address: storage_access.address.bytes.to_vec(),
            modified: storage_access.modified,
            transient: storage_access.transient,
            key: storage_access.key.bytes.to_vec(),
            start_value: storage_access.start_value.bytes.to_vec(),
            end_value: storage_access.end_value.bytes.to_vec(),
        };

        if access_context == 0 {
            self.system_calls_storage_accesses.push(access);
        } else if access.modified && !access.transient {
            use firehose::pb::sf::ethereum::r#type::v2::StorageChange;

            let txn_index = txn_index.unwrap_or(0);

            if let Some(tx) = self.transactions_map.get_mut(&txn_index) {
                if let Some(root_call) = tx.calls.first_mut() {
                    root_call.storage_changes.push(StorageChange {
                        address: ensure_address_bytes(access.address.clone()),
                        key: ensure_hash_bytes(access.key.clone()),
                        old_value: ensure_hash_bytes(access.start_value.clone()),
                        new_value: ensure_hash_bytes(access.end_value.clone()),
                        ordinal: 0,
                    });
                    return Ok(());
                }
            }

            self.storage_accesses.entry(txn_index).or_default().push(access);
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

    fn build_call_tree(
        call_frames: &[CallFrameData],
        _txn_index: usize,
        code_hash_by_address: &std::collections::HashMap<Vec<u8>, Vec<u8>>,
    ) -> Vec<firehose::pb::sf::ethereum::r#type::v2::Call> {
        let mut parent_stack: Vec<u32> = Vec::new();

        call_frames.iter().map(|frame| {
            let depth = frame.depth as usize;
            let firehose_index = frame.index + 1;

            let parent_index = if depth == 0 {
                0
            } else if depth <= parent_stack.len() {
                parent_stack[depth - 1]
            } else {
                frame.index
            };

            if depth >= parent_stack.len() {
                parent_stack.resize(depth + 1, firehose_index);
            } else {
                parent_stack[depth] = firehose_index;
                parent_stack.truncate(depth + 1);
            }

            let call_type = Self::opcode_to_call_type(frame.opcode);
            let normalized_call_target = ensure_address_bytes(frame.call_target.clone());
            let is_precompile = is_precompile_address(&normalized_call_target);
            let status_reverted = frame.evmc_status == 2 || frame.evmc_status == 17;
            let status_failed = frame.evmc_status != 0;

            let failure_reason = match frame.evmc_status {
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
                _ => format!("unknown error (status {})", frame.evmc_status),
            };

            let is_call_opcode = frame.opcode == 0xF1;
            let is_pure_transfer = is_call_opcode
                && frame.depth == 0
                && frame.input.is_empty()
                && frame.return_data.is_empty()
                && !is_precompile;
            let executed_code = if is_precompile {
                true
            } else if is_pure_transfer {
                false
            } else {
                frame.gas_used > 0
            };

            let state_reverted = frame.evmc_status != 0;

            let is_create = frame.opcode == 0xF0 || frame.opcode == 0xF5;
            let is_successful_create = is_create && frame.evmc_status == 0 && !frame.return_data.is_empty();
            let return_data = if is_successful_create { vec![] } else { frame.return_data.clone() };
            let code_changes = if is_successful_create {
                let target_addr = ensure_address_bytes(frame.call_target.clone());
                vec![CodeChange {
                    old_hash: code_hash_by_address.get(&target_addr).cloned().unwrap_or_default(),
                    new_hash: keccak256(&frame.return_data).to_vec(),
                    new_code: frame.return_data.clone(),
                    address: target_addr,
                    old_code: vec![],
                    ordinal: 0,
                }]
            } else {
                vec![]
            };

            firehose::pb::sf::ethereum::r#type::v2::Call {
                index: firehose_index,
                parent_index,
                depth: frame.depth as u32,
                call_type: call_type as i32,
                caller: ensure_address_bytes(frame.caller.clone()),
                address: ensure_address_bytes(frame.call_target.clone()),
                value: if frame.value.iter().any(|&b| b != 0) { Some(BigInt { bytes: frame.value.clone() }) } else { None },
                gas_limit: frame.gas,
                gas_consumed: frame.gas_used,
                return_data,
                input: frame.input.clone(),
                executed_code,
                suicide: frame.opcode == 0xFF,
                status_failed,
                status_reverted,
                state_reverted,
                failure_reason,
                code_changes,
                ..Default::default()
            }
        }).collect()
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

    fn create_system_call_from_frames(
        &self,
        to_address: Vec<u8>,
        call_frames: Vec<&CallFrameData>,
        all_storage_accesses: &[StorageAccessData],
        index: u32,
    ) -> firehose::pb::sf::ethereum::r#type::v2::Call {
        use firehose::pb::sf::ethereum::r#type::v2::StorageChange;

        let system_caller = hex::decode("fffffffffffffffffffffffffffffffffffffffe").unwrap();
        let input = call_frames.first().map(|f| f.input.clone()).unwrap_or_default();

        let mut call = firehose::pb::sf::ethereum::r#type::v2::Call {
            index,
            parent_index: 0,
            depth: 0,
            call_type: firehose::pb::sf::ethereum::r#type::v2::CallType::Call as i32,
            caller: system_caller,
            address: to_address.clone(),
            value: None,
            gas_limit: 30_000_000,
            gas_consumed: 0,
            return_data: Vec::new(),
            input,
            executed_code: true,
            suicide: false,
            status_failed: false,
            status_reverted: false,
            failure_reason: String::new(),
            state_reverted: false,
            ..Default::default()
        };

        for storage in all_storage_accesses {
            if storage.address == to_address && storage.modified && !storage.transient {
                call.storage_changes.push(StorageChange {
                    address: ensure_address_bytes(storage.address.clone()),
                    key: ensure_hash_bytes(storage.key.clone()),
                    old_value: ensure_hash_bytes(storage.start_value.clone()),
                    new_value: ensure_hash_bytes(storage.end_value.clone()),
                    ordinal: 0,
                });
            }
        }

        call
    }

    fn create_system_call(
        &self,
        to_address: Vec<u8>,
        account_accesses: Vec<&AccountAccessData>,
        all_storage_accesses: &[StorageAccessData],
        all_call_frames: &[CallFrameData],
        index: u32,
    ) -> firehose::pb::sf::ethereum::r#type::v2::Call {
        use firehose::pb::sf::ethereum::r#type::v2::{BalanceChange, NonceChange, StorageChange};
        use firehose::pb::sf::ethereum::r#type::v2::balance_change::Reason as BalanceReason;

        let system_caller = hex::decode("fffffffffffffffffffffffffffffffffffffffe").unwrap();
        let call_frame = all_call_frames.iter().find(|f| f.call_target == to_address);
        let input = call_frame.map(|f| f.input.clone()).unwrap_or_default();

        let mut call = firehose::pb::sf::ethereum::r#type::v2::Call {
            index,
            parent_index: 0,
            depth: 0,
            call_type: firehose::pb::sf::ethereum::r#type::v2::CallType::Call as i32,
            caller: system_caller,
            address: to_address.clone(),
            value: None,
            gas_limit: 30_000_000,
            gas_consumed: 0,
            return_data: Vec::new(),
            input,
            executed_code: true,
            suicide: false,
            status_failed: false,
            status_reverted: false,
            failure_reason: String::new(),
            state_reverted: false,
            ..Default::default()
        };

        for access in account_accesses {
            if access.is_balance_modified {
                call.balance_changes.push(BalanceChange {
                    address: access.address.clone(),
                    old_value: Some(BigInt { bytes: access.prestate_balance.clone() }),
                    new_value: Some(BigInt { bytes: access.modified_balance.clone() }),
                    reason: BalanceReason::MonadTxPostState as i32,
                    ordinal: 0,
                });
            }
            if access.is_nonce_modified {
                call.nonce_changes.push(NonceChange {
                    address: access.address.clone(),
                    old_value: access.prestate_nonce,
                    new_value: access.modified_nonce,
                    ordinal: 0,
                });
            }
        }

        for storage in all_storage_accesses {
            if storage.address == to_address && storage.modified && !storage.transient {
                call.storage_changes.push(StorageChange {
                    address: ensure_address_bytes(storage.address.clone()),
                    key: ensure_hash_bytes(storage.key.clone()),
                    old_value: ensure_hash_bytes(storage.start_value.clone()),
                    new_value: ensure_hash_bytes(storage.end_value.clone()),
                    ordinal: 0,
                });
            }
        }

        call
    }

    fn finalize(mut self) -> Result<Block> {
        debug!("Finalizing block {}", self.block_number);

        let mut system_calls = Vec::new();

        debug!("System call data: {} account accesses, {} storage accesses, {} call frames",
               self.system_calls_account_accesses.len(),
               self.system_calls_storage_accesses.len(),
               self.system_calls_call_frames.len());

        if !self.system_calls_account_accesses.is_empty() {
            let mut system_calls_by_address: std::collections::HashMap<Vec<u8>, Vec<&AccountAccessData>> =
                std::collections::HashMap::new();
            for acc in &self.system_calls_account_accesses {
                system_calls_by_address.entry(acc.address.clone()).or_default().push(acc);
            }
            for (address, accesses) in system_calls_by_address {
                let call = self.create_system_call(
                    address,
                    accesses,
                    &self.system_calls_storage_accesses,
                    &self.system_calls_call_frames,
                    system_calls.len() as u32,
                );
                system_calls.push(call);
            }
        } else if !self.system_calls_call_frames.is_empty() {
            let mut frames_by_address: std::collections::BTreeMap<Vec<u8>, Vec<&CallFrameData>> =
                std::collections::BTreeMap::new();
            for frame in &self.system_calls_call_frames {
                frames_by_address.entry(frame.call_target.clone()).or_default().push(frame);
            }
            for (address, frames) in frames_by_address {
                let call = self.create_system_call_from_frames(
                    address,
                    frames,
                    &self.system_calls_storage_accesses,
                    system_calls.len() as u32,
                );
                system_calls.push(call);
            }
        }

        let mut transactions: Vec<TransactionTrace> = self.transactions_map.into_values().map(|mut tx| {
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
            tx
        }).collect();
        transactions.sort_by_key(|tx| tx.index);

        let account_accesses = std::mem::take(&mut self.account_accesses);
        let storage_accesses = std::mem::take(&mut self.storage_accesses);
        let remaining_call_frames = std::mem::take(&mut self.call_frames);

        for tx in &mut transactions {
            let txn_index = tx.index as usize;

            if tx.calls.is_empty() {
                let code_hash_by_address: std::collections::HashMap<Vec<u8>, Vec<u8>> =
                    account_accesses.get(&txn_index)
                        .map(|accesses| {
                            accesses.iter()
                                .filter(|a| !a.prestate_code_hash.is_empty())
                                .map(|a| (a.address.clone(), a.prestate_code_hash.clone()))
                                .collect()
                        })
                        .unwrap_or_default();

                if let Some(frames) = remaining_call_frames.get(&txn_index) {
                    if !frames.is_empty() {
                        debug!("FALLBACK: building call tree for tx #{} with {} frames", txn_index, frames.len());
                        tx.calls = Self::build_call_tree(frames, txn_index, &code_hash_by_address);

                        if tx.to.is_empty() || tx.to == vec![0u8; 20] {
                            if let Some(root_frame) = frames.first() {
                                let deployed = ensure_address_bytes(root_frame.call_target.clone());
                                if deployed != vec![0u8; 20] {
                                    tx.to = deployed;
                                }
                            }
                        }

                        let reverted: std::collections::HashSet<u32> = tx.calls.iter()
                            .filter(|c| c.state_reverted)
                            .map(|c| c.index)
                            .collect();
                        let mut reverted_indices = reverted;
                        for i in 0..tx.calls.len() {
                            if reverted_indices.contains(&tx.calls[i].parent_index) {
                                tx.calls[i].state_reverted = true;
                                reverted_indices.insert(tx.calls[i].index);
                            }
                        }
                    }
                }

                if tx.calls.is_empty() {
                    let root_call = firehose::pb::sf::ethereum::r#type::v2::Call {
                        index: 1,
                        parent_index: 0,
                        depth: 0,
                        call_type: if tx.to.is_empty() || tx.to == vec![0u8; 20] {
                            firehose::pb::sf::ethereum::r#type::v2::CallType::Create as i32
                        } else {
                            firehose::pb::sf::ethereum::r#type::v2::CallType::Call as i32
                        },
                        caller: tx.from.clone(),
                        address: tx.to.clone(),
                        value: tx.value.clone(),
                        gas_limit: 0,
                        gas_consumed: 0,
                        return_data: Vec::new(),
                        input: tx.input.clone(),
                        executed_code: false,
                        suicide: false,
                        status_failed: tx.status != 1,
                        status_reverted: false,
                        failure_reason: String::new(),
                        state_reverted: false,
                        ..Default::default()
                    };
                    tx.calls.push(root_call);
                }
            }

            if let Some(root_call) = tx.calls.first_mut() {
                if let Some(ref receipt) = tx.receipt {
                    root_call.logs = receipt.logs.clone();
                }
            }

            if let Some(root_call) = tx.calls.first() {
                use firehose::pb::sf::ethereum::r#type::v2::TransactionTraceStatus;
                if tx.status != TransactionTraceStatus::Succeeded as i32 {
                    tx.status = if root_call.status_reverted {
                        TransactionTraceStatus::Reverted as i32
                    } else {
                        TransactionTraceStatus::Failed as i32
                    };
                }
                tx.return_data = root_call.return_data.clone();
            }

            use firehose::pb::sf::ethereum::r#type::v2::{BalanceChange, BigInt as PbBigInt, NonceChange, StorageChange};
            use firehose::pb::sf::ethereum::r#type::v2::balance_change::Reason as BalanceReason;

            if let Some(root_call) = tx.calls.first_mut() {
                if let Some(accesses) = account_accesses.get(&txn_index) {
                    for access in accesses {
                        if access.is_balance_modified {
                            root_call.balance_changes.push(BalanceChange {
                                address: ensure_address_bytes(access.address.clone()),
                                old_value: Some(PbBigInt { bytes: access.prestate_balance.clone() }),
                                new_value: Some(PbBigInt { bytes: access.modified_balance.clone() }),
                                reason: BalanceReason::MonadTxPostState as i32,
                                ordinal: 0,
                            });
                        }
                        if access.is_nonce_modified {
                            root_call.nonce_changes.push(NonceChange {
                                address: ensure_address_bytes(access.address.clone()),
                                old_value: access.prestate_nonce,
                                new_value: access.modified_nonce,
                                ordinal: 0,
                            });
                        }
                    }
                }

                if let Some(storages) = storage_accesses.get(&txn_index) {
                    for storage in storages {
                        if storage.modified && !storage.transient {
                            root_call.storage_changes.push(StorageChange {
                                address: ensure_address_bytes(storage.address.clone()),
                                key: ensure_hash_bytes(storage.key.clone()),
                                old_value: ensure_hash_bytes(storage.start_value.clone()),
                                new_value: ensure_hash_bytes(storage.end_value.clone()),
                                ordinal: 0,
                            });
                        }
                    }
                }
            }
        }

        // Assign ordinals
        for tx in &mut transactions {
            tx.begin_ordinal = self.next_ordinal;
            self.next_ordinal += 1;

            for call in &mut tx.calls {
                call.begin_ordinal = self.next_ordinal;
                self.next_ordinal += 1;

                for gas_change in &mut call.gas_changes {
                    gas_change.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }
                for nonce_change in &mut call.nonce_changes {
                    nonce_change.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }
                for balance_change in &mut call.balance_changes {
                    balance_change.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }
                for storage_change in &mut call.storage_changes {
                    storage_change.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }
                for log in &mut call.logs {
                    log.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }

                call.end_ordinal = self.next_ordinal;
                self.next_ordinal += 1;
            }

            if let Some(ref mut receipt) = tx.receipt {
                for log in &mut receipt.logs {
                    log.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }
            }

            tx.end_ordinal = self.next_ordinal;
            self.next_ordinal += 1;
        }

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

/// Maps ExecEvents to Firehose blocks
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

    /// Process a raw event and potentially return a completed block.
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
        builder.add_event(event)?;

        if is_block_end {
            if let Some(builder) = self.blocks.remove(&block_num) {
                return Ok(Some(Box::new(builder.finalize()?)));
            }
        }

        Ok(None)
    }

    pub fn finalize_pending(&mut self) -> Result<Option<Box<Block>>> {
        if let Some((&block_num, _)) = self.blocks.iter().next() {
            if let Some(builder) = self.blocks.remove(&block_num) {
                return Ok(Some(Box::new(builder.finalize()?)));
            }
        }
        Ok(None)
    }
}

impl Default for EventMapper {
    fn default() -> Self {
        Self::new()
    }
}
