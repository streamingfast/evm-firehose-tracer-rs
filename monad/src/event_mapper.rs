use crate::{Block, BlockHeader, ProcessedEvent, TransactionTrace};
use pb::sf::ethereum::r#type::v2::{block, BigInt, AccessTuple};
use alloy_primitives::{Bloom, BloomInput};
use eyre::Result;
use serde_json;
use tracing::{debug, info};

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
    eprintln!("DEBUG: u256_limbs_to_bytes input limbs = {:?}", limbs);
    let mut bytes = Vec::with_capacity(32);
    // U256 is stored as 4 limbs in little-endian order
    // We need to convert to big-endian for protobuf
    for i in (0..4).rev() {
        let limb = limbs.get(i).copied().unwrap_or(0);
        bytes.extend_from_slice(&limb.to_be_bytes());
    }
    eprintln!("DEBUG: raw bytes before compaction = {:?}", bytes);

    // Strip leading zeros for Ethereum hex compaction
    // For zero values, compact_bytes returns empty vec (serializes as "00" in protobuf JSON)
    let result = compact_bytes(bytes);
    eprintln!("DEBUG: compacted/final result = {:?}", result);
    result
}

/// Strip leading zeros from byte array (Ethereum hex compaction)
/// Returns empty vec for zero values (protobuf serializes this as "00" in JSON)
fn compact_bytes(bytes: Vec<u8>) -> Vec<u8> {
    // eprintln!("DEBUG: compact_bytes input = {:?}", bytes);
    // Find first non-zero byte
    let first_non_zero = bytes.iter().position(|&b| b != 0);
    // eprintln!("DEBUG: first_non_zero = {:?}", first_non_zero);

    // eprintln!("DEBUG: compact_bytes result = {:?}", result);
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
    pub async fn process_event(&mut self, event: ProcessedEvent) -> Result<Option<Block>> {
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
                return Ok(Some(completed_block));
            }
        }

        Ok(None)
    }

    /// Finalize any pending blocks
    pub fn finalize_pending(&mut self) -> Result<Option<Block>> {
        // Finalize the oldest pending block if any exist
        if let Some((&block_num, _)) = self.blocks.iter().next() {
            if let Some(builder) = self.blocks.remove(&block_num) {
                return Ok(Some(builder.finalize()?));
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
        // Debug: always log what we're doing with base_fee
        eprintln!("DEBUG: BlockStart {} - checking base_fee_per_gas", self.block_number);
        if let Some(base_fee_limbs) = block_data["base_fee_per_gas"]["limbs"].as_array() {
            self.base_fee_per_gas = base_fee_limbs
                .iter()
                .map(|v| v.as_u64().unwrap_or(0))
                .collect();
            // Debug logging for base fee
            eprintln!("DEBUG: BlockStart {} base_fee_limbs: {:?} -> bytes: {:?}",
                     self.block_number, self.base_fee_per_gas, u256_limbs_to_bytes(&self.base_fee_per_gas));
        } else {
            eprintln!("DEBUG: BlockStart {} - NO base_fee_per_gas in event! Using previous: {:?}",
                     self.block_number, self.base_fee_per_gas);
        }
        if let Some(withdrawals_root) = block_data["withdrawals_root"].as_str() {
            self.withdrawals_root = ensure_hash_bytes(hex::decode(withdrawals_root).unwrap_or_default());
        }

        Ok(())
    }

    async fn handle_block_end(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling block end for block {}", event.block_number);

        let block_data: serde_json::Value = serde_json::from_slice(&event.firehose_data)?;

        // Debug: check if BlockEnd has base_fee
        if let Some(base_fee_limbs) = block_data["base_fee_per_gas"]["limbs"].as_array() {
            let base_fee: Vec<u64> = base_fee_limbs
                .iter()
                .map(|v| v.as_u64().unwrap_or(0))
                .collect();
            eprintln!("DEBUG: BlockEnd for {} has base_fee_limbs: {:?} -> bytes: {:?}",
                     self.block_number, base_fee, u256_limbs_to_bytes(&base_fee));
        }

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
        // eprintln!("DEBUG: Processing tx_data keys: {:?}", tx_data.as_object().map(|o| o.keys().collect::<Vec<_>>()));

        let txn_index = tx_data["txn_index"].as_u64().unwrap_or(0) as usize;
        // eprintln!("DEBUG: txn_index = {}", txn_index);

        // Extract access_list from tx_data
        let access_list_entries = if let Some(access_list_json) = tx_data.get("access_list") {
            // eprintln!("DEBUG: access_list FOUND in tx_data for tx {}: {:?}", txn_index, access_list_json);
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
            // eprintln!("DEBUG: access_list NOT found in tx_data for tx {}", txn_index);
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
        // eprintln!("DEBUG: value_limbs = {:?}", value_limbs);
        let value = u256_limbs_to_bytes(&value_limbs);
        // eprintln!("DEBUG: value bytes after u256_limbs_to_bytes = {:?}", value);

        let max_fee_limbs = tx_data["max_fee_per_gas"]["limbs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| v.as_u64().unwrap_or(0))
                    .collect::<Vec<u64>>()
            })
            .unwrap_or_else(|| vec![0u64; 4]);
        // eprintln!("DEBUG: max_fee_limbs = {:?}", max_fee_limbs);

        let max_priority_fee_limbs = tx_data["max_priority_fee_per_gas"]["limbs"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| v.as_u64().unwrap_or(0))
                    .collect::<Vec<u64>>()
            })
            .unwrap_or_else(|| vec![0u64; 4]);
        // eprintln!("DEBUG: max_priority_fee_limbs = {:?}", max_priority_fee_limbs);

        // Calculate effective gas price based on EIP-1559
        // For Type 2 (Dynamic Fee) transactions:
        // effective_gas_price = base_fee_per_gas + min(max_priority_fee_per_gas, max_fee_per_gas - base_fee_per_gas)
        let gas_price = self.calculate_effective_gas_price(&max_fee_limbs, &max_priority_fee_limbs, txn_type);
        // eprintln!("DEBUG: gas_price bytes after calculation = {:?}", gas_price);

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

        // eprintln!("DEBUG: txn_index={}, txn_type={}, y_parity={}, v={:?}, chain_id={}", txn_index, txn_type, y_parity, v, chain_id);
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

        // Debug: Check access_list content
        // eprintln!("DEBUG: ACCESS_LIST for tx {}: len={}", txn_index, tx_trace.access_list.len());
        // if !tx_trace.access_list.is_empty() {
        //     eprintln!("DEBUG: ACCESS_LIST CONTENT for tx {}: {:?}", txn_index, tx_trace.access_list);
        // }

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
        // eprintln!("DEBUG: calculate_effective_gas_price: txn_type={}, max_fee_limbs={:?}, priority_fee_limbs={:?}", txn_type, max_fee_limbs, priority_fee_limbs);
        match txn_type {
            0 => {
                // Legacy transactions: gas_price = max_fee_per_gas

                // eprintln!("DEBUG: type 0 gas_price result = {:?}", result);
                u256_limbs_to_bytes(max_fee_limbs)
            }
            2 => {
                // EIP-1559: effective_gas_price = min(max_fee_per_gas, base_fee_per_gas + max_priority_fee_per_gas)
                let max_fee = u256_limbs_to_bytes(max_fee_limbs);
                let priority_fee = u256_limbs_to_bytes(priority_fee_limbs);
                let base_fee = u256_limbs_to_bytes(&self.base_fee_per_gas);
                // eprintln!("DEBUG: EIP-1559: max_fee={:?}, priority_fee={:?}, base_fee={:?}", max_fee, priority_fee, base_fee);

                // Calculate base_fee + priority_fee
                let sum = add_u256_bytes(&base_fee, &priority_fee);
                // eprintln!("DEBUG: base_fee + priority_fee = {:?}", sum);

                // Return min(max_fee, sum)

                // eprintln!("DEBUG: type 2 gas_price result = {:?}", result);
                if compare_u256_bytes(&max_fee, &sum) <= 0 {
                    // eprintln!("DEBUG: using max_fee");
                    max_fee
                } else {
                    // eprintln!("DEBUG: using sum");
                    sum
                }
            }
            _ => {

                // eprintln!("DEBUG: type {} gas_price result = {:?}", txn_type, result);
                u256_limbs_to_bytes(max_fee_limbs)
            }
        }
    }

    /// Finalize the block and return it
    fn finalize(mut self) -> Result<Block> {
        info!("Finalizing block {}", self.block_number);

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

        // Assign ordinals to transactions and logs
        for tx in &mut transactions {
            tx.begin_ordinal = self.next_ordinal;
            self.next_ordinal += 1;

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

        let block = Block {
            number: self.block_number,
            hash: header.hash.clone(),
            size: self.size,
            header: Some(header),
            transaction_traces: transactions,
            ver: 3,
            detail_level: block::DetailLevel::DetaillevelBase as i32,
            ..Default::default()
        };

        Ok(block)
    }

}
