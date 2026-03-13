use crate::{Block, BlockHeader, ProcessedEvent, TransactionTrace};
use firehose::pb::sf::ethereum::r#type::v2::{block, BigInt, AccessTuple, CodeChange};
use alloy_primitives::{Bloom, BloomInput, keccak256};
use eyre::Result;
use monad_plugin::pb::sf::monad::events::v1 as pb;
use prost::Message;
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

fn pb_access_list_to_tuples(entries: Vec<pb::AccessListEntry>) -> Vec<AccessTuple> {
    entries.into_iter().map(|e| AccessTuple {
        address: e.address,
        storage_keys: e.storage_keys,
    }).collect()
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

    // Strip leading zeros for Ethereum hex compaction
    // For zero values, compact_bytes returns empty vec (serializes as "00" in protobuf JSON)
    compact_bytes(bytes)
}

/// Strip leading zeros from byte array (Ethereum hex compaction)
/// Returns empty vec for zero values (protobuf serializes this as "00" in JSON)
fn compact_bytes(bytes: Vec<u8>) -> Vec<u8> {
    // Find first non-zero byte
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

/// Ensure address bytes are 20 bytes (zero-pad if empty)
fn ensure_address_bytes(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        vec![0u8; 20]
    } else {
        bytes
    }
}

/// Ensure hash bytes are 32 bytes (zero-pad if empty)
fn ensure_hash_bytes(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        vec![0u8; 32]
    } else {
        bytes
    }
}

/// Calculate logs bloom filter from logs
fn calculate_logs_bloom(logs: &[firehose::pb::sf::ethereum::r#type::v2::Log]) -> Vec<u8> {
    let mut bloom = Bloom::default();

    for log in logs {
        // Add log address to bloom
        if log.address.len() == 20 {
            bloom.accrue(BloomInput::Raw(&log.address));
        }

        // Add each topic to bloom
        for topic in &log.topics {
            if topic.len() == 32 {
                bloom.accrue(BloomInput::Raw(topic));
            }
        }
    }

    bloom.as_slice().to_vec()
}

/// Maps processed events to Firehose blocks
pub struct EventMapper {
    blocks: std::collections::HashMap<u64, BlockBuilder>,
}

impl EventMapper {
    /// Create a new event mapper
    pub fn new() -> Self {
        Self {
            blocks: std::collections::HashMap::new(),
        }
    }

    /// Process an event and potentially return a completed block
    pub async fn process_event(&mut self, event: ProcessedEvent) -> Result<Option<Box<Block>>> {
        debug!(
            "Processing event: block={}, type={}",
            event.block_number, event.event_type
        );

        let block_num = event.block_number;
        let is_block_end = event.event_type == "BLOCK_END";

        // Get or create the block builder for this block number
        let builder = self.blocks.entry(block_num).or_insert_with(|| BlockBuilder::new(block_num));

        // Add the event to the block
        builder.add_event(event).await?;

        // Check if this is a BLOCK_END event, finalize the block
        if is_block_end {
            if let Some(builder) = self.blocks.remove(&block_num) {
                let completed_block = builder.finalize()?;
                // Box the block to avoid expensive move - only moves a pointer instead of the whole struct
                return Ok(Some(Box::new(completed_block)));
            }
        }

        Ok(None)
    }

    /// Finalize any pending blocks
    pub fn finalize_pending(&mut self) -> Result<Option<Box<Block>>> {
        // Finalize the oldest pending block if any exist
        if let Some((&block_num, _)) = self.blocks.iter().next() {
            if let Some(builder) = self.blocks.remove(&block_num) {
                // Box the block to avoid expensive move
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
    // index: u32,
    address: Vec<u8>,
    access_context: u8,
    is_balance_modified: bool,
    is_nonce_modified: bool,
    prestate_balance: Vec<u8>,
    prestate_nonce: u64,
    prestate_code_hash: Vec<u8>,
    modified_balance: Vec<u8>,
    modified_nonce: u64,
    // storage_key_count: u32,
}

/// Raw storage access data from Monad events
#[derive(Clone, Debug)]
struct StorageAccessData {
    address: Vec<u8>,
    // index: u32,
    modified: bool,
    transient: bool,
    key: Vec<u8>,
    start_value: Vec<u8>,
    end_value: Vec<u8>,
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
    // Extended blocks data
    call_frames: std::collections::HashMap<usize, Vec<CallFrameData>>,
    account_accesses: std::collections::HashMap<usize, Vec<AccountAccessData>>,
    storage_accesses: std::collections::HashMap<usize, Vec<StorageAccessData>>,
    // System transactions from BLOCK_PROLOGUE
    system_calls_account_accesses: Vec<AccountAccessData>,
    system_calls_storage_accesses: Vec<StorageAccessData>,
    system_calls_call_frames: Vec<CallFrameData>,
}

/// Builder for constructing Firehose blocks from events
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
        }
    }

    /// Add an event to the block
    async fn add_event(&mut self, event: ProcessedEvent) -> Result<()> {
        match event.event_type.as_str() {
            "BLOCK_START" => self.handle_block_start(event).await?,
            "BLOCK_END" => self.handle_block_end(event).await?,
            "TX_HEADER" => self.handle_transaction_header(event).await?,
            "TX_RECEIPT" => self.handle_transaction_receipt(event).await?,
            "TX_LOG" => self.handle_transaction_log(event).await?,
            "TX_CALL_FRAME" => self.handle_call_frame(event).await?,
            "TX_END" => self.handle_tx_end(event).await?,
            "ACCOUNT_ACCESS_LIST_HEADER" => {
                // Just metadata, we don't need to store it
            }
            "ACCOUNT_ACCESS" => self.handle_account_access(event).await?,
            "STORAGE_ACCESS" => self.handle_storage_access(event).await?,
            _ => {
                debug!("Unknown event type: {}", event.event_type);
            }
        }

        Ok(())
    }

    /// Handle block start events
    async fn handle_block_start(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling block start for block {}", event.block_number);

        let msg = pb::BlockStart::decode(&*event.firehose_data)?;

        debug!("BLOCK_START parent_hash for block {}: {}", event.block_number, hex::encode(&msg.parent_hash));
        self.parent_hash = ensure_hash_bytes(msg.parent_hash);
        self.uncle_hash = ensure_hash_bytes(msg.uncle_hash);
        self.coinbase = ensure_address_bytes(msg.coinbase);
        self.transactions_root = ensure_hash_bytes(msg.transactions_root);
        self.difficulty = msg.difficulty;
        self.gas_limit = msg.gas_limit;
        self.timestamp = msg.timestamp;
        self.extra_data = msg.extra_data;
        self.mix_hash = ensure_hash_bytes(msg.mix_hash);
        self.nonce = msg.nonce;
        self.base_fee_per_gas = msg.base_fee_per_gas_limbs;
        self.withdrawals_root = ensure_hash_bytes(msg.withdrawals_root);

        Ok(())
    }

    async fn handle_block_end(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling block end for block {}", event.block_number);

        let msg = pb::BlockEnd::decode(&*event.firehose_data)?;

        debug!("BLOCK_END hash for block {}: {}", event.block_number, hex::encode(&msg.hash));
        self.block_hash = ensure_hash_bytes(msg.hash);
        self.state_root = ensure_hash_bytes(msg.state_root);
        self.receipts_root = ensure_hash_bytes(msg.receipts_root);
        self.logs_bloom = if msg.logs_bloom.is_empty() { vec![0u8; 256] } else { msg.logs_bloom };
        self.gas_used = msg.gas_used;

        // Monad's RPC always returns 0x30f (783) for block size its not actually calculated per block
        self.size = MONAD_BLOCK_SIZE;

        Ok(())
    }

    /// Handle transaction header events
    async fn handle_transaction_header(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling transaction header");

        let msg = pb::TxHeader::decode(&*event.firehose_data)?;

        let txn_index = msg.txn_index as usize;
        let txn_type = msg.txn_type;

        let access_list_entries = pb_access_list_to_tuples(msg.access_list);
        let hash = ensure_hash_bytes(msg.hash);
        let from = ensure_address_bytes(msg.from);
        let to = if msg.to.is_empty() { vec![] } else { ensure_address_bytes(msg.to) };
        let nonce = msg.nonce;
        let gas_limit = msg.gas_limit;
        let input = msg.input;

        let value = u256_limbs_to_bytes(&msg.value_limbs);
        let max_fee_limbs = msg.max_fee_per_gas_limbs;
        let max_priority_fee_limbs = msg.max_priority_fee_per_gas_limbs;

        let gas_price = self.calculate_effective_gas_price(&max_fee_limbs, &max_priority_fee_limbs, txn_type);

        let r = u256_limbs_to_bytes(&msg.r_limbs);
        let s = u256_limbs_to_bytes(&msg.s_limbs);
        let chain_id = msg.chain_id_limbs.first().copied().unwrap_or(0);

        let y_parity = msg.y_parity;

        // Calculate proper v based on transaction type
        let v = match txn_type {
            0 => {
                // Legacy transaction: EIP-155 v = chain_id * 2 + 35 + y_parity
                let v_value = chain_id * 2 + 35 + (y_parity as u64);
                // Encode as big-endian bytes with leading zero trimming
                encode_v_bytes(v_value)
            }
            2 => {
                // EIP-1559 transaction: v = y_parity (0 or 1)
                // Use empty vec for 0
                if y_parity {
                    vec![1]
                } else {
                    vec![]
                }
            }
            _ => {
                // Default to y_parity
                if y_parity {
                    vec![1]
                } else {
                    vec![]
                }
            }
        };

        let tx_trace = TransactionTrace {
            index: txn_index as u32,
            hash,
            from,
            to,
            nonce,
            gas_limit,
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
            input,
            v,
            r,
            s,
            r#type: txn_type as i32,
            access_list: access_list_entries,
            begin_ordinal: 0, // Will be properly set during finalization
            end_ordinal: 0,   // Will be properly set during finalization
            ..Default::default()
        };

        self.transactions_map.insert(txn_index, tx_trace);

        Ok(())
    }

    async fn handle_transaction_receipt(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling transaction receipt");

        let msg = pb::TxReceipt::decode(&*event.firehose_data)?;

        let txn_index = msg.txn_index as usize;
        let status = msg.status;
        let gas_used = msg.gas_used;

        self.cumulative_gas_used += gas_used;

        if let Some(tx) = self.transactions_map.get_mut(&txn_index) {
            tx.gas_used = gas_used;
            tx.status = if status { 1 } else { 2 };

            // Create receipt with empty bloom - will be calculated in finalize() after logs are added
            tx.receipt = Some(firehose::pb::sf::ethereum::r#type::v2::TransactionReceipt {
                cumulative_gas_used: self.cumulative_gas_used,
                logs_bloom: vec![0u8; 256],
                logs: Vec::new(),
                ..Default::default()
            });
        }

        Ok(())
    }

    async fn handle_transaction_log(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling transaction log");

        let msg = pb::TxLog::decode(&*event.firehose_data)?;

        let txn_index = msg.txn_index as usize;
        let address = ensure_address_bytes(msg.address);
        let topics: Vec<Vec<u8>> = msg.topics.into_iter().map(ensure_hash_bytes).collect();
        let data = msg.data;

        // This counter tracks all logs across all transactions in the block
        let log_index = self.total_log_count as u32;
        self.total_log_count += 1;

        let log = firehose::pb::sf::ethereum::r#type::v2::Log {
            address,
            topics,
            data,
            index: log_index,
            block_index: log_index,
            ..Default::default()
        };

        if let Some(tx) = self.transactions_map.get_mut(&txn_index) {
            if let Some(receipt) = tx.receipt.as_mut() {
                receipt.logs.push(log);
            }
        }

        Ok(())
    }

    /// Handle call frame event - execution trace data
    async fn handle_call_frame(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling call frame");

        let msg = pb::TxCallFrame::decode(&*event.firehose_data)?;

        if msg.txn_index.is_none() {
            debug!("System call frame raw data - input: {} bytes, call_target: {}", msg.input.len(), hex::encode(&msg.call_target));
        }

        let call_frame = CallFrameData {
            index: msg.index,
            caller: msg.caller,
            call_target: msg.call_target,
            opcode: msg.opcode as u8,
            value: u256_limbs_to_bytes(&msg.value_limbs),
            gas: msg.gas,
            gas_used: msg.gas_used,
            evmc_status: msg.evmc_status,
            depth: msg.depth,
            input: msg.input,
            return_data: msg.return_data,
        };

        // Check if this is a system call (BLOCK_PROLOGUE) by checking if txn_index is present
        if let Some(txn_index) = msg.txn_index {
            self.call_frames.entry(txn_index as usize).or_default().push(call_frame);
        } else {
            debug!("BLOCK_PROLOGUE call frame detected for address: {}", hex::encode(&call_frame.call_target));
            self.system_calls_call_frames.push(call_frame);
        }

        Ok(())
    }

    /// Handle TX_END event, build call tree so account/storage accesses can push to calls[0]
    async fn handle_tx_end(&mut self, event: ProcessedEvent) -> Result<()> {
        let msg = pb::TxEnd::decode(&*event.firehose_data)?;
        let txn_index = msg.txn_index as usize;

        debug!("TX_END: building call tree eagerly for tx #{}", txn_index);

        if !self.transactions_map.contains_key(&txn_index) {
            debug!("TX_END: no transaction found for index {}", txn_index);
            return Ok(());
        }

        // Only build if calls aren't already populated
        if self.transactions_map[&txn_index].calls.is_empty() {
            // Remove frames before borrowing tx mutably
            let frames = self.call_frames.remove(&txn_index).unwrap_or_default();

            // code_hash_by_address will be empty since account accesses arrive after TX_END
            let code_hash_by_address: std::collections::HashMap<Vec<u8>, Vec<u8>> = std::collections::HashMap::new();

            let tx = self.transactions_map.get_mut(&txn_index).unwrap();

            if !frames.is_empty() {
                debug!("TX_END: building call tree for tx #{} with {} frames", txn_index, frames.len());
                tx.calls = Self::build_call_tree(&frames, txn_index, &code_hash_by_address);

                // For CREATE transactions fix the "to" field from the root frame's call_target
                if tx.to.is_empty() || tx.to == vec![0u8; 20] {
                    if let Some(root_frame) = frames.first() {
                        let deployed = ensure_address_bytes(root_frame.call_target.clone());
                        if deployed != vec![0u8; 20] {
                            tx.to = deployed;
                        }
                    }
                }

                // Propagate state_reverted to children when parent is reverted
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

            // If no calls exist, create a synthetic root call
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

    /// Handle account access event - balance/nonce changes
    async fn handle_account_access(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling account access");

        let msg = pb::AccountAccess::decode(&*event.firehose_data)?;

        let txn_index = msg.txn_index.map(|i| i as usize).unwrap_or(0);

        let prestate_balance_bytes = u256_limbs_to_bytes(&msg.prestate_balance_limbs);
        let modified_balance_bytes = u256_limbs_to_bytes(&msg.modified_balance_limbs);

        debug!("Balance bytes - prestate: {} bytes ({}), modified: {} bytes ({})",
               prestate_balance_bytes.len(), hex::encode(&prestate_balance_bytes),
               modified_balance_bytes.len(), hex::encode(&modified_balance_bytes));

        let account_access = AccountAccessData {
            address: msg.address,
            access_context: msg.access_context as u8,
            is_balance_modified: msg.is_balance_modified,
            is_nonce_modified: msg.is_nonce_modified,
            prestate_balance: prestate_balance_bytes,
            prestate_nonce: msg.prestate_nonce,
            prestate_code_hash: msg.prestate_code_hash,
            modified_balance: modified_balance_bytes,
            modified_nonce: msg.modified_nonce,
        };

        debug!("ACCOUNT_ACCESS_CREATED: addr={} ctx={} bal_mod={} nonce_mod={}",
               hex::encode(&account_access.address),
               account_access.access_context,
               account_access.is_balance_modified,
               account_access.is_nonce_modified);

        // BLOCK_PROLOGUE (context = 0) are system calls that should be separate from transactions
        if account_access.access_context == 0 {
            debug!("BLOCK_PROLOGUE account access detected for address: {}", hex::encode(&account_access.address));
            self.system_calls_account_accesses.push(account_access);
        } else {
            use firehose::pb::sf::ethereum::r#type::v2::{BalanceChange, BigInt as PbBigInt, NonceChange};
            use firehose::pb::sf::ethereum::r#type::v2::balance_change::Reason as BalanceReason;

            // If call tree already built (TX_END received), push directly to root call
            if let Some(tx) = self.transactions_map.get_mut(&txn_index) {
                if let Some(root_call) = tx.calls.first_mut() {
                    debug!("ACCOUNT_ACCESS_EAGER: txn_index={} addr={}", txn_index, hex::encode(&account_access.address));
                    if account_access.is_balance_modified {
                        root_call.balance_changes.push(BalanceChange {
                            address: ensure_address_bytes(account_access.address.clone()),
                            old_value: Some(PbBigInt { bytes: account_access.prestate_balance.clone() }),
                            new_value: Some(PbBigInt { bytes: account_access.modified_balance.clone() }),
                            reason: BalanceReason::MonadTxPostState as i32,
                            ordinal: 0,
                        });
                    }
                    if account_access.is_nonce_modified {
                        root_call.nonce_changes.push(NonceChange {
                            address: ensure_address_bytes(account_access.address.clone()),
                            old_value: account_access.prestate_nonce,
                            new_value: account_access.modified_nonce,
                            ordinal: 0,
                        });
                    }
                    return Ok(());
                }
            }

            // Call tree not yet built — buffer for finalize
            debug!("ACCOUNT_ACCESS_STORED: txn_index={} addr={}", txn_index, hex::encode(&account_access.address));
            self.account_accesses.entry(txn_index).or_default().push(account_access);
        }

        Ok(())
    }

    /// Handle storage access event - storage slot modifications
    async fn handle_storage_access(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling storage access");

        let msg = pb::StorageAccess::decode(&*event.firehose_data)?;

        let txn_index = msg.txn_index.map(|i| i as usize).unwrap_or(0);
        // access_context: 0=BLOCK_PROLOGUE, 1=TRANSACTION, 2=BLOCK_EPILOGUE
        let access_context = msg.access_context as u8;

        let storage_access = StorageAccessData {
            address: msg.address,
            modified: msg.modified,
            transient: msg.transient,
            key: msg.key,
            start_value: msg.start_value,
            end_value: msg.end_value,
        };

        // BLOCK_PROLOGUE (context = 0) storage accesses are system call related
        if access_context == 0 {
            debug!("BLOCK_PROLOGUE storage access detected for address: {}", hex::encode(&storage_access.address));
            self.system_calls_storage_accesses.push(storage_access);
        } else if storage_access.modified && !storage_access.transient {
            use firehose::pb::sf::ethereum::r#type::v2::StorageChange;

            // If call tree already built (TX_END received), push directly to root call
            if let Some(tx) = self.transactions_map.get_mut(&txn_index) {
                if let Some(root_call) = tx.calls.first_mut() {
                    debug!("STORAGE_ACCESS_EAGER: txn_index={} addr={}", txn_index, hex::encode(&storage_access.address));
                    root_call.storage_changes.push(StorageChange {
                        address: ensure_address_bytes(storage_access.address.clone()),
                        key: ensure_hash_bytes(storage_access.key.clone()),
                        old_value: ensure_hash_bytes(storage_access.start_value.clone()),
                        new_value: ensure_hash_bytes(storage_access.end_value.clone()),
                        ordinal: 0,
                    });
                    return Ok(());
                }
            }

            // Call tree not yet built — buffer for finalize
            self.storage_accesses.entry(txn_index).or_default().push(storage_access);
        }
        // Non-modified or transient storage — skip entirely

        Ok(())
    }

    /// Calculate gas price for a transaction
    /// Standard EIP-1559 behavior:
    /// - Type 0 (Legacy): uses max_fee_per_gas as the gas price
    /// - Type 2 (Dynamic Fee): effective_price = min(max_fee_per_gas, base_fee_per_gas + max_priority_fee_per_gas)
    fn calculate_effective_gas_price(
        &self,
        max_fee_limbs: &[u64],
        priority_fee_limbs: &[u64],
        txn_type: u32,
    ) -> Vec<u8> {
        match txn_type {
            0 => {
                // Legacy transactions: gas_price = max_fee_per_gas
                u256_limbs_to_bytes(max_fee_limbs)
            }
            2 => {
                // EIP-1559: effective_gas_price = min(max_fee_per_gas, base_fee_per_gas + max_priority_fee_per_gas)
                let max_fee = u256_limbs_to_bytes(max_fee_limbs);
                let priority_fee = u256_limbs_to_bytes(priority_fee_limbs);
                let base_fee = u256_limbs_to_bytes(&self.base_fee_per_gas);

                // Calculate base_fee + priority_fee
                let sum = add_u256_bytes(&base_fee, &priority_fee);

                if compare_u256_bytes(&max_fee, &sum) <= 0 {
                    max_fee
                } else {
                    sum
                }
            }
            _ => {

                u256_limbs_to_bytes(max_fee_limbs)
            }
        }
    }

    /// Build call tree from call frames
    /// Converts flat list of call frames into hierarchical Call structures
    fn build_call_tree(call_frames: &[CallFrameData], _txn_index: usize, code_hash_by_address: &std::collections::HashMap<Vec<u8>, Vec<u8>>) -> Vec<firehose::pb::sf::ethereum::r#type::v2::Call> {
        // Track parent indices based on depth changes
        // parent_stack[depth] = index of call at that depth
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

            // Map opcode to CallType
            let call_type = Self::opcode_to_call_type(frame.opcode);

            // Map EVMC status to Firehose status
            let normalized_call_target = ensure_address_bytes(frame.call_target.clone());
            let is_precompile = is_precompile_address(&normalized_call_target);
            let status_reverted = frame.evmc_status == 2 || frame.evmc_status == 17;
            let status_failed = frame.evmc_status != 0;

            // https://github.com/ipsilon/evmc/blob/663a1c239b026501c5a1235ed815e14903c7f35e/include/evmc/evmc.h#L289
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

    /// Map EVM opcode to CallType enum
    fn opcode_to_call_type(opcode: u8) -> firehose::pb::sf::ethereum::r#type::v2::CallType {
        match opcode {
            0xF0 => firehose::pb::sf::ethereum::r#type::v2::CallType::Create,       // CREATE
            0xF5 => firehose::pb::sf::ethereum::r#type::v2::CallType::Create,       // CREATE2
            0xF1 => firehose::pb::sf::ethereum::r#type::v2::CallType::Call,         // CALL
            0xF4 => firehose::pb::sf::ethereum::r#type::v2::CallType::Delegate, // DELEGATECALL
            0xF2 => firehose::pb::sf::ethereum::r#type::v2::CallType::Callcode,     // CALLCODE
            0xFA => firehose::pb::sf::ethereum::r#type::v2::CallType::Static,       // STATICCALL
            _ => firehose::pb::sf::ethereum::r#type::v2::CallType::Call,            // Default to CALL
        }
    }

    /// Create a system call from call frames alone (when account accesses are not available)
    fn create_system_call_from_frames(
        &self,
        to_address: Vec<u8>,
        call_frames: Vec<&CallFrameData>,
        all_storage_accesses: &[StorageAccessData],
        index: u32,
    ) -> firehose::pb::sf::ethereum::r#type::v2::Call {
        use firehose::pb::sf::ethereum::r#type::v2::StorageChange;

        debug!("Creating system call from frames for address: {}", hex::encode(&to_address));

        // System address is 0xfffffffffffffffffffffffffffffffffffffffe
        let system_caller = hex::decode("fffffffffffffffffffffffffffffffffffffffe").unwrap();

        // Use the first frame's input data
        let input = call_frames.first().map(|frame| frame.input.clone()).unwrap_or_default();

        debug!("System call input data: {} bytes", input.len());
        if !input.is_empty() {
            debug!("System call input hex: {}", hex::encode(&input));
        }

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

        // Add storage changes that belong to this address
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

        debug!("Creating system call for address: {}", hex::encode(&to_address));

        // System address is 0xfffffffffffffffffffffffffffffffffffffffe
        let system_caller = hex::decode("fffffffffffffffffffffffffffffffffffffffe").unwrap();

        // Find the call frame for this system call by matching the call_target address
        let call_frame = all_call_frames.iter().find(|frame| frame.call_target == to_address);

        // Extract input data from call frame if available
        let input = call_frame.map(|frame| frame.input.clone()).unwrap_or_default();

        debug!("System call input data: {} bytes", input.len());
        if !input.is_empty() {
            debug!("System call input hex: {}", hex::encode(&input));
        }

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

        // Add balance and nonce changes from account accesses
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

        // Add storage changes that belong to this address
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

    /// Finalize the block and return it
    fn finalize(mut self) -> Result<Block> {
        debug!("Finalizing block {}", self.block_number);

        // Create system calls from BLOCK_PROLOGUE account/storage accesses or call frames
        // These go into block.system_calls, not as transactions
        let mut system_calls = Vec::new();

        debug!("System call data before finalization: {} account accesses, {} storage accesses, {} call frames",
               self.system_calls_account_accesses.len(),
               self.system_calls_storage_accesses.len(),
               self.system_calls_call_frames.len());

        if !self.system_calls_account_accesses.is_empty() {
            debug!("Creating system calls for {} BLOCK_PROLOGUE account accesses",
                   self.system_calls_account_accesses.len());

            // Group account accesses by address to create one call per system contract
            let mut system_calls_by_address: std::collections::HashMap<Vec<u8>, Vec<&AccountAccessData>> =
                std::collections::HashMap::new();

            for acc in &self.system_calls_account_accesses {
                system_calls_by_address.entry(acc.address.clone()).or_default().push(acc);
            }

            // Create a system call for each unique system contract address
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
            debug!("Creating system calls from {} call frames (no account accesses available)",
                   self.system_calls_call_frames.len());

            for (i, frame) in self.system_calls_call_frames.iter().enumerate() {
                debug!("Frame {}: address={}, input={} bytes, input_hex={}",
                       i, hex::encode(&frame.call_target), frame.input.len(), hex::encode(&frame.input));
            }

            // Create system calls from call frames alone
            // Group by call target address
            let mut frames_by_address: std::collections::BTreeMap<Vec<u8>, Vec<&CallFrameData>> =
                std::collections::BTreeMap::new();

            for frame in &self.system_calls_call_frames {
                frames_by_address.entry(frame.call_target.clone()).or_default().push(frame);
            }

            // Create a system call for each unique address
            for (address, frames) in frames_by_address {
                debug!("Creating system call for address: {} from {} frames",
                       hex::encode(&address), frames.len());
                let call = self.create_system_call_from_frames(
                    address,
                    frames,
                    &self.system_calls_storage_accesses,
                    system_calls.len() as u32,
                );
                system_calls.push(call);
            }
        }

        // Move transactions from map to vec, sorted by index
        let mut transactions: Vec<TransactionTrace> = self
            .transactions_map.into_values().map(|tx| {
                let mut tx = tx;

                // Ensure receipt exists
                if tx.receipt.is_none() {
                    tx.receipt = Some(firehose::pb::sf::ethereum::r#type::v2::TransactionReceipt {
                        cumulative_gas_used: 0,
                        logs_bloom: vec![0u8; 256],
                        logs: Vec::new(),
                        ..Default::default()
                    });
                }

                // Calculate logs bloom from actual logs
                if let Some(ref mut receipt) = tx.receipt {
                    receipt.logs_bloom = calculate_logs_bloom(&receipt.logs);
                }

                tx
            })
            .collect();
        transactions.sort_by_key(|tx| tx.index);

        // Drain remaining buffered accesses (fallback for txns that didn't receive TX_END before accesses)
        let account_accesses = std::mem::take(&mut self.account_accesses);
        let storage_accesses = std::mem::take(&mut self.storage_accesses);

        // Drain any call frames not yet processed by handle_tx_end (safety fallback)
        let remaining_call_frames = std::mem::take(&mut self.call_frames);

        for tx in &mut transactions {
            let txn_index = tx.index as usize;

            // Build call tree from remaining frames (TX_END not received)
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

                // Synthetic root call if still empty (TODO: We'll see)
                if tx.calls.is_empty() {
                    debug!("FALLBACK: creating synthetic root call for tx #{}", txn_index);
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

            // Copy receipt logs to the root call frame
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

            // Flush any buffered account/storage accesses (fallback path for TX_END not received)
            use firehose::pb::sf::ethereum::r#type::v2::{BalanceChange, BigInt as PbBigInt, NonceChange, StorageChange};
            use firehose::pb::sf::ethereum::r#type::v2::balance_change::Reason as BalanceReason;

            if let Some(root_call) = tx.calls.first_mut() {
                if let Some(accesses) = account_accesses.get(&txn_index) {
                    debug!("FINALIZE_FLUSH_ACCESSES: txn_index={} count={}", txn_index, accesses.len());
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

        // Assign ordinals to transactions, calls, and all state changes
        for tx in &mut transactions {
            tx.begin_ordinal = self.next_ordinal;
            self.next_ordinal += 1;

            // Assign ordinals to calls and their state changes
            for call in &mut tx.calls {
                call.begin_ordinal = self.next_ordinal;
                self.next_ordinal += 1;

                // Assign ordinals to gas changes
                for gas_change in &mut call.gas_changes {
                    gas_change.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }

                // Assign ordinals to nonce changes
                for nonce_change in &mut call.nonce_changes {
                    nonce_change.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }

                // Assign ordinals to balance changes
                for balance_change in &mut call.balance_changes {
                    balance_change.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }

                // Assign ordinals to storage changes
                for storage_change in &mut call.storage_changes {
                    storage_change.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }

                // Assign ordinals to logs
                for log in &mut call.logs {
                    log.ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                }

                call.end_ordinal = self.next_ordinal;
                self.next_ordinal += 1;
            }

            // Assign ordinals to receipt logs (duplicate from calls for compatibility)
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
            blob_gas_used: Some(0),  // Monad doesn't support EIP-4844 blob transactions
            excess_blob_gas: Some(0),  // Monad doesn't support EIP-4844 blob transactions
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
            "Finalized extended block #{}: {} txs, {} calls, {} logs, {} system_calls",
            self.block_number, block.transaction_traces.len(), total_calls, total_logs, block.system_calls.len()
        );

        // Debug: Log final block hash and parent hash
        debug!(
            "Block #{} final hashes: block_hash={}, parent_hash={}",
            self.block_number,
            hex::encode(&block.hash),
            if let Some(ref header) = block.header {
                hex::encode(&header.parent_hash)
            } else {
                "NO_HEADER".to_string()
            }
        );

        // Debug: Log all system calls with their inputs
        for (i, syscall) in block.system_calls.iter().enumerate() {
            debug!(
                "Block #{} SystemCall {}: address={}, input={}",
                self.block_number,
                i,
                hex::encode(&syscall.address),
                hex::encode(&syscall.input)
            );
        }

        Ok(block)
    }

}
