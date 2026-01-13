use crate::{Block, BlockHeader, ProcessedEvent, TransactionTrace};
use pb::sf::ethereum::r#type::v2::{block, BigInt, AccessTuple};
use alloy_primitives::{Bloom, BloomInput};
use eyre::Result;
use serde_json;
use tracing::debug;

// Constants for Monad-specific values
const MONAD_BLOCK_SIZE: u64 = 783;
const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

/// Encode v value as big-endian bytes with leading zero trimming
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

    // Add from least significant byte (end of array)
    for i in (0..32).rev() {
        let sum = a_padded[i] as u16 + b_padded[i] as u16 + carry;
        result[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }

    compact_bytes(result)
}

/// Compare two u256 values represented as big-endian byte arrays
/// Returns: -1 if a < b, 0 if a == b, 1 if a > b
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
fn calculate_logs_bloom(logs: &[pb::sf::ethereum::r#type::v2::Log]) -> Vec<u8> {
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
    index: u32,
    address: Vec<u8>,
    is_balance_modified: bool,
    is_nonce_modified: bool,
    prestate_balance: Vec<u8>,
    prestate_nonce: u64,
    modified_balance: Vec<u8>,
    modified_nonce: u64,
    storage_key_count: u32,
}

/// Raw storage access data from Monad events
#[derive(Clone, Debug)]
struct StorageAccessData {
    address: Vec<u8>,
    index: u32,
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

        let block_data: serde_json::Value = serde_json::from_slice(&event.firehose_data)?;

        // Extract all header fields
        if let Some(parent_hash) = block_data["parent_hash"].as_str() {
            self.parent_hash = ensure_hash_bytes(hex::decode(parent_hash).unwrap_or_default());
        }
        if let Some(uncle_hash) = block_data["uncle_hash"].as_str() {
            self.uncle_hash = ensure_hash_bytes(hex::decode(uncle_hash).unwrap_or_default());
        }
        if let Some(coinbase) = block_data["coinbase"].as_str() {
            self.coinbase = ensure_address_bytes(hex::decode(coinbase).unwrap_or_default());
        }
        if let Some(transactions_root) = block_data["transactions_root"].as_str() {
            self.transactions_root = ensure_hash_bytes(hex::decode(transactions_root).unwrap_or_default());
        }
        if let Some(difficulty) = block_data["difficulty"].as_u64() {
            self.difficulty = difficulty;
        }
        if let Some(gas_limit) = block_data["gas_limit"].as_u64() {
            self.gas_limit = gas_limit;
        }
        if let Some(timestamp) = block_data["timestamp"].as_u64() {
            self.timestamp = timestamp;
        }
        if let Some(extra_data) = block_data["extra_data"].as_str() {
            self.extra_data = hex::decode(extra_data).unwrap_or_default();
        }
        if let Some(mix_hash) = block_data["mix_hash"].as_str() {
            self.mix_hash = ensure_hash_bytes(hex::decode(mix_hash).unwrap_or_default());
        }
        if let Some(nonce) = block_data["nonce"].as_u64() {
            self.nonce = nonce;
        }
        if let Some(base_fee_limbs) = block_data["base_fee_per_gas"]["limbs"].as_array() {
            self.base_fee_per_gas = base_fee_limbs
                .iter()
                .map(|v| v.as_u64().unwrap_or(0))
                .collect();
        }
        if let Some(withdrawals_root) = block_data["withdrawals_root"].as_str() {
            self.withdrawals_root = ensure_hash_bytes(hex::decode(withdrawals_root).unwrap_or_default());
        }

        Ok(())
    }

    async fn handle_block_end(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling block end for block {}", event.block_number);

        let block_data: serde_json::Value = serde_json::from_slice(&event.firehose_data)?;

        if let Some(hash) = block_data["hash"].as_str() {
            self.block_hash = ensure_hash_bytes(hex::decode(hash).unwrap_or_default());
        }
        if let Some(state_root) = block_data["state_root"].as_str() {
            self.state_root = ensure_hash_bytes(hex::decode(state_root).unwrap_or_default());
        }
        if let Some(receipts_root) = block_data["receipts_root"].as_str() {
            self.receipts_root = ensure_hash_bytes(hex::decode(receipts_root).unwrap_or_default());
        }
        if let Some(logs_bloom) = block_data["logs_bloom"].as_str() {
            self.logs_bloom = hex::decode(logs_bloom).unwrap_or_else(|_| vec![0u8; 256]);
        }
        if let Some(gas_used) = block_data["gas_used"].as_u64() {
            self.gas_used = gas_used;
        }

        // Monad's RPC always returns 0x30f (783) for block size its not actually calculated per block
        self.size = MONAD_BLOCK_SIZE;

        Ok(())
    }

    /// Handle transaction header events
    async fn handle_transaction_header(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling transaction header");

        let tx_data: serde_json::Value = serde_json::from_slice(&event.firehose_data)?;

        let txn_index = tx_data["txn_index"].as_u64().unwrap_or(0) as usize;

        // Extract access_list from tx_data
        let access_list_entries = if let Some(access_list_json) = tx_data.get("access_list") {
            if let Some(access_list_array) = access_list_json.as_array() {
                access_list_array.iter().filter_map(|entry| {
                    if let (Some(address), Some(storage_keys)) = (entry.get("address"), entry.get("storage_keys")) {
                        if let (Some(address_str), Some(storage_keys_array)) = (address.as_str(), storage_keys.as_array()) {
                            if let Ok(address_bytes) = hex::decode(address_str.trim_start_matches("0x")) {
                                let storage_keys_bytes = storage_keys_array.iter().filter_map(|key| {
                                    key.as_str().and_then(|k| hex::decode(k.trim_start_matches("0x")).ok())
                                }).collect::<Vec<Vec<u8>>>();
                                Some(AccessTuple {
                                    address: address_bytes,
                                    storage_keys: storage_keys_bytes,
                                })
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }).collect::<Vec<AccessTuple>>()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let hash = ensure_hash_bytes(hex::decode(tx_data["hash"].as_str().unwrap_or("")).unwrap_or_default());
        let from = ensure_address_bytes(hex::decode(tx_data["from"].as_str().unwrap_or("")).unwrap_or_default());
        // For contract creation, 'to' is empty, not zero address
        let to = if let Some(to_str) = tx_data["to"].as_str() {
            if to_str.is_empty() {
                vec![]
            } else {
                ensure_address_bytes(hex::decode(to_str).unwrap_or_default())
            }
        } else {
            vec![]
        };
        let nonce = tx_data["nonce"].as_u64().unwrap_or(0);
        let gas_limit = tx_data["gas_limit"].as_u64().unwrap_or(0);
        let input = hex::decode(tx_data["input"].as_str().unwrap_or("")).unwrap_or_default();
        let txn_type = tx_data["txn_type"].as_u64().unwrap_or(2) as u32;

        // Parse U256 values from limbs
        let value_limbs = tx_data["value"]["limbs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| v.as_u64().unwrap_or(0))
                    .collect::<Vec<u64>>()
            })
            .unwrap_or_else(|| vec![0u64; 4]);
        let value = u256_limbs_to_bytes(&value_limbs);

        let max_fee_limbs = tx_data["max_fee_per_gas"]["limbs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| v.as_u64().unwrap_or(0))
                    .collect::<Vec<u64>>()
            })
            .unwrap_or_else(|| vec![0u64; 4]);

        let max_priority_fee_limbs = tx_data["max_priority_fee_per_gas"]["limbs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| v.as_u64().unwrap_or(0))
                    .collect::<Vec<u64>>()
            })
            .unwrap_or_else(|| vec![0u64; 4]);

        // Calculate effective gas price based on EIP-1559
        // For Type 2 (Dynamic Fee) transactions:
        // effective_gas_price = base_fee_per_gas + min(max_priority_fee_per_gas, max_fee_per_gas - base_fee_per_gas)
        let gas_price = self.calculate_effective_gas_price(&max_fee_limbs, &max_priority_fee_limbs, txn_type);

        // Parse signature
        let r_limbs = tx_data["r"]["limbs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| v.as_u64().unwrap_or(0))
                    .collect::<Vec<u64>>()
            })
            .unwrap_or_else(|| vec![0u64; 4]);
        let r = u256_limbs_to_bytes(&r_limbs);

        let s_limbs = tx_data["s"]["limbs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| v.as_u64().unwrap_or(0))
                    .collect::<Vec<u64>>()
            })
            .unwrap_or_else(|| vec![0u64; 4]);
        let s = u256_limbs_to_bytes(&s_limbs);

        // Parse chain_id for v calculation
        let chain_id_limbs = tx_data["chain_id"]["limbs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| v.as_u64().unwrap_or(0))
                    .collect::<Vec<u64>>()
            })
            .unwrap_or_else(|| vec![0u64; 4]);

        // Chain ID fits in u64
        let chain_id = chain_id_limbs[0];

        let y_parity = tx_data["y_parity"].as_bool().unwrap_or(false);

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
            value: Some(BigInt { bytes: value }),
            gas_price: Some(BigInt { bytes: gas_price }),
            input,
            v,
            r,
            s,
            r#type: txn_type as i32,
            access_list: access_list_entries,
            begin_ordinal: 0,
            end_ordinal: 0,
            ..Default::default()
        };

        self.transactions_map.insert(txn_index, tx_trace);

        Ok(())
    }

    async fn handle_transaction_receipt(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling transaction receipt");

        let receipt_data: serde_json::Value = serde_json::from_slice(&event.firehose_data)?;

        let txn_index = receipt_data["txn_index"].as_u64().unwrap_or(0) as usize;
        let status = receipt_data["status"].as_bool().unwrap_or(false);
        let gas_used = receipt_data["gas_used"].as_u64().unwrap_or(0);

        self.cumulative_gas_used += gas_used;

        if let Some(tx) = self.transactions_map.get_mut(&txn_index) {
            tx.gas_used = gas_used;
            tx.status = if status { 1 } else { 2 };

            // Create receipt with empty bloom - will be calculated in finalize() after logs are added
            tx.receipt = Some(pb::sf::ethereum::r#type::v2::TransactionReceipt {
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

        let log_data: serde_json::Value = serde_json::from_slice(&event.firehose_data)?;

        let txn_index = log_data["txn_index"].as_u64().unwrap_or(0) as usize;
        let address = ensure_address_bytes(hex::decode(log_data["address"].as_str().unwrap_or("")).unwrap_or_default());
        let topics = log_data["topics"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| hex::decode(v.as_str().unwrap_or("")).ok().map(ensure_hash_bytes))
                    .collect::<Vec<Vec<u8>>>()
            })
            .unwrap_or_default();
        let data = hex::decode(log_data["data"].as_str().unwrap_or("")).unwrap_or_default();

        // This counter tracks all logs across all transactions in the block
        let log_index = self.total_log_count as u32;
        self.total_log_count += 1;

        let log = pb::sf::ethereum::r#type::v2::Log {
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

        let call_data: serde_json::Value = serde_json::from_slice(&event.firehose_data)?;

        let txn_index = call_data["txn_index"].as_u64().unwrap_or(0) as usize;

        let value_limbs = call_data["value"]["limbs"]
            .as_array()
            .map(|arr| arr.iter().map(|v| v.as_u64().unwrap_or(0)).collect::<Vec<u64>>())
            .unwrap_or_else(|| vec![0u64; 4]);

        let call_frame = CallFrameData {
            index: call_data["index"].as_u64().unwrap_or(0) as u32,
            caller: hex::decode(call_data["caller"].as_str().unwrap_or("")).unwrap_or_default(),
            call_target: hex::decode(call_data["call_target"].as_str().unwrap_or("")).unwrap_or_default(),
            opcode: call_data["opcode"].as_u64().unwrap_or(0) as u8,
            value: u256_limbs_to_bytes(&value_limbs),
            gas: call_data["gas"].as_u64().unwrap_or(0),
            gas_used: call_data["gas_used"].as_u64().unwrap_or(0),
            evmc_status: call_data["evmc_status"].as_i64().unwrap_or(0) as i32,
            depth: call_data["depth"].as_u64().unwrap_or(0),
            input: hex::decode(call_data["input"].as_str().unwrap_or("")).unwrap_or_default(),
            return_data: hex::decode(call_data["return_data"].as_str().unwrap_or("")).unwrap_or_default(),
        };

        self.call_frames.entry(txn_index).or_default().push(call_frame);

        Ok(())
    }

    /// Handle account access event - balance/nonce changes
    async fn handle_account_access(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling account access");

        let access_data: serde_json::Value = serde_json::from_slice(&event.firehose_data)?;

        // txn_index is Option<usize> from the event
        // If None, these are block-level changes (associate with transaction 0)
        let txn_index = access_data["txn_index"].as_u64().map(|i| i as usize).unwrap_or(0);

        let prestate_balance_limbs = access_data["prestate"]["balance"]["limbs"]
            .as_array()
            .map(|arr| arr.iter().map(|v| v.as_u64().unwrap_or(0)).collect::<Vec<u64>>())
            .unwrap_or_else(|| vec![0u64; 4]);

        let modified_balance_limbs = access_data["modified_balance"]["limbs"]
            .as_array()
            .map(|arr| arr.iter().map(|v| v.as_u64().unwrap_or(0)).collect::<Vec<u64>>())
            .unwrap_or_else(|| vec![0u64; 4]);

        let account_access = AccountAccessData {
            index: access_data["index"].as_u64().unwrap_or(0) as u32,
            address: hex::decode(access_data["address"].as_str().unwrap_or("")).unwrap_or_default(),
            is_balance_modified: access_data["is_balance_modified"].as_bool().unwrap_or(false),
            is_nonce_modified: access_data["is_nonce_modified"].as_bool().unwrap_or(false),
            prestate_balance: u256_limbs_to_bytes(&prestate_balance_limbs),
            prestate_nonce: access_data["prestate"]["nonce"].as_u64().unwrap_or(0),
            modified_balance: u256_limbs_to_bytes(&modified_balance_limbs),
            modified_nonce: access_data["modified_nonce"].as_u64().unwrap_or(0),
            storage_key_count: access_data["storage_key_count"].as_u64().unwrap_or(0) as u32,
        };

        self.account_accesses.entry(txn_index).or_default().push(account_access);

        Ok(())
    }

    /// Handle storage access event - storage slot modifications
    async fn handle_storage_access(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling storage access");

        let storage_data: serde_json::Value = serde_json::from_slice(&event.firehose_data)?;

        // txn_index is Option<usize> from the event
        // If None, these are block-level changes (associate with transaction 0)
        let txn_index = storage_data["txn_index"].as_u64().map(|i| i as usize).unwrap_or(0);

        let storage_access = StorageAccessData {
            address: hex::decode(storage_data["address"].as_str().unwrap_or("")).unwrap_or_default(),
            index: storage_data["index"].as_u64().unwrap_or(0) as u32,
            modified: storage_data["modified"].as_bool().unwrap_or(false),
            transient: storage_data["transient"].as_bool().unwrap_or(false),
            key: hex::decode(storage_data["key"].as_str().unwrap_or("")).unwrap_or_default(),
            start_value: hex::decode(storage_data["start_value"].as_str().unwrap_or("")).unwrap_or_default(),
            end_value: hex::decode(storage_data["end_value"].as_str().unwrap_or("")).unwrap_or_default(),
        };

        self.storage_accesses.entry(txn_index).or_default().push(storage_access);

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
    fn build_call_tree(call_frames: &[CallFrameData], _txn_index: usize) -> Vec<pb::sf::ethereum::r#type::v2::Call> {
        // Track parent indices based on depth changes
        // parent_stack[depth] = index of call at that depth
        let mut parent_stack: Vec<u32> = Vec::new();

        call_frames.iter().map(|frame| {
            let depth = frame.depth as usize;

            // Determine parent_index based on depth
            let parent_index = if depth == 0 {
                // Root call - parent is always 0
                0
            } else if depth <= parent_stack.len() && depth > 0 {
                // Child call - parent is the call at depth-1
                parent_stack[depth - 1]
            } else {
                // Shouldn't happen, but fallback to previous call
                frame.index.saturating_sub(1)
            };

            // Update parent stack for this depth level
            if depth >= parent_stack.len() {
                parent_stack.resize(depth + 1, frame.index);
            } else {
                parent_stack[depth] = frame.index;
                // Truncate stack when returning from deeper calls
                parent_stack.truncate(depth + 1);
            }

            // Map opcode to CallType
            let call_type = Self::opcode_to_call_type(frame.opcode);

            // Map EVMC status to Firehose status
            // EVMC_SUCCESS = 0
            // EVMC_FAILURE = 1
            // EVMC_REVERT = 2
            // EVMC_OUT_OF_GAS = 3
            let status_reverted = frame.evmc_status == 2;
            let status_failed = frame.evmc_status != 0 && frame.evmc_status != 2;

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
                17 => "insufficient balance".to_string(),
                _ => format!("unknown error (status {})", frame.evmc_status),
            };

            pb::sf::ethereum::r#type::v2::Call {
                index: frame.index,
                parent_index,
                depth: frame.depth as u32,
                call_type: call_type as i32,
                caller: ensure_address_bytes(frame.caller.clone()),
                address: ensure_address_bytes(frame.call_target.clone()),
                value: Some(BigInt { bytes: frame.value.clone() }),
                gas_limit: frame.gas,
                gas_consumed: frame.gas_used,
                return_data: frame.return_data.clone(),
                input: frame.input.clone(),
                executed_code: !frame.input.is_empty(),
                suicide: false,
                status_failed,
                status_reverted,
                failure_reason,
                ..Default::default()
            }
        }).collect()
    }

    /// Map EVM opcode to CallType enum
    fn opcode_to_call_type(opcode: u8) -> pb::sf::ethereum::r#type::v2::CallType {
        match opcode {
            0xF0 => pb::sf::ethereum::r#type::v2::CallType::Create,       // CREATE
            0xF5 => pb::sf::ethereum::r#type::v2::CallType::Create,       // CREATE2
            0xF1 => pb::sf::ethereum::r#type::v2::CallType::Call,         // CALL
            0xF4 => pb::sf::ethereum::r#type::v2::CallType::Delegate, // DELEGATECALL
            0xF2 => pb::sf::ethereum::r#type::v2::CallType::Callcode,     // CALLCODE
            0xFA => pb::sf::ethereum::r#type::v2::CallType::Static,       // STATICCALL
            _ => pb::sf::ethereum::r#type::v2::CallType::Call,            // Default to CALL
        }
    }

    /// Finalize the block and return it
    fn finalize(mut self) -> Result<Block> {
        debug!("Finalizing block {}", self.block_number);

        // Extract call_frames before consuming transactions_map
        let call_frames = self.call_frames;

        // Move transactions from map to vec, sorted by index
        let mut transactions: Vec<TransactionTrace> = self
            .transactions_map.into_values().map(|tx| {
                let mut tx = tx;

                // Ensure receipt exists
                if tx.receipt.is_none() {
                    tx.receipt = Some(pb::sf::ethereum::r#type::v2::TransactionReceipt {
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

        // Build call trees for each transaction with call frames
        let total_call_frames: usize = call_frames.values().map(|v| v.len()).sum();
        if total_call_frames > 0 {
            debug!("Building call trees for {} transactions with {} total call frames", call_frames.len(), total_call_frames);
        }

        for tx in &mut transactions {
            let txn_index = tx.index as usize;

            if let Some(frames) = call_frames.get(&txn_index) {
                if !frames.is_empty() {
                    debug!("Building call tree for tx #{} with {} frames", txn_index, frames.len());
                    tx.calls = Self::build_call_tree(frames, txn_index);
                }
            }
        }

        // Assign ordinals to transactions, calls, and logs
        for tx in &mut transactions {
            tx.begin_ordinal = self.next_ordinal;
            self.next_ordinal += 1;

            // Assign ordinals to calls in execution order
            for call in &mut tx.calls {
                call.begin_ordinal = self.next_ordinal;
                self.next_ordinal += 1;

                // Ordinals for call's storage changes, balance changes, nonce changes, logs, etc.
                // For now just end ordinal
                call.end_ordinal = self.next_ordinal;
                self.next_ordinal += 1;
            }

            // Assign ordinals to logs
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
            requests_hash: vec![],
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
            ver: 3,
            detail_level: block::DetailLevel::DetaillevelExtended as i32,
            ..Default::default()
        };

        debug!(
            "Finalized extended block #{}: {} txs, {} calls, {} logs",
            self.block_number, block.transaction_traces.len(), total_calls, total_logs
        );

        Ok(block)
    }

}
