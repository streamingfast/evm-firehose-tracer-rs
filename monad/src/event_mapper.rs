//! Event Mapper
//!
//! Maps processed Monad events to Firehose protobuf blocks.

use crate::{Block, BlockHeader, ProcessedEvent, TransactionTrace};
use pb::sf::ethereum::r#type::v2::{block, BigInt};
use alloy_primitives::{Bloom, BloomInput};
use eyre::Result;
use serde_json;
use tracing::{debug, info};

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
    // Ensure at least one byte for zero values to match RPC "00" format
    let compacted = compact_bytes(bytes);
    if compacted.is_empty() {
        vec![0]
    } else {
        compacted
    }
}

/// Strip leading zeros from byte array (Ethereum hex compaction)
/// Returns at least one byte (0x00) for zero values to match RPC format
fn compact_bytes(bytes: Vec<u8>) -> Vec<u8> {
    // Find first non-zero byte
    let first_non_zero = bytes.iter().position(|&b| b != 0);

    match first_non_zero {
        Some(pos) => bytes[pos..].to_vec(),
        None => vec![0], // All zeros -> return vec![0x00] to match RPC "00" format
    }
}

/// Add two u256 values represented as big-endian byte arrays
fn add_u256_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    // Pad to 32 bytes for addition
    let mut a_padded = vec![0u8; 32];
    let mut b_padded = vec![0u8; 32];

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
    current_block: Option<BlockBuilder>,
}

impl EventMapper {
    /// Create a new event mapper
    pub fn new() -> Self {
        Self {
            current_block: None,
        }
    }

    /// Process an event and potentially return a completed block
    pub async fn process_event(&mut self, event: ProcessedEvent) -> Result<Option<Block>> {
        debug!(
            "Processing event: block={}, type={}",
            event.block_number, event.event_type
        );

        // Check if we need to start a new block
        if self.current_block.is_none()
            || self.current_block.as_ref().unwrap().block_number != event.block_number
        {
            // Finalize the previous block if it exists
            let completed_block = if let Some(builder) = self.current_block.take() {
                Some(builder.finalize()?)
            } else {
                None
            };

            // Start a new block
            self.current_block = Some(BlockBuilder::new(event.block_number));

            // Add the event to the new block
            if let Some(ref mut builder) = self.current_block {
                builder.add_event(event).await?;
            }

            return Ok(completed_block);
        }

        // Add the event to the current block
        if let Some(ref mut builder) = self.current_block {
            builder.add_event(event.clone()).await?;

            // Check if this is a BLOCK_END event - if so, finalize the block
            if event.event_type == "BLOCK_END" {
                let completed_block = self.current_block.take().unwrap().finalize()?;
                return Ok(Some(completed_block));
            }
        }

        Ok(None)
    }

    /// Finalize any pending block
    pub fn finalize_pending(&mut self) -> Result<Option<Block>> {
        if let Some(builder) = self.current_block.take() {
            Ok(Some(builder.finalize()?))
        } else {
            Ok(None)
        }
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
            gas_limit: 30_000_000,
            transactions_map: std::collections::HashMap::new(),
            cumulative_gas_used: 0,
            total_log_count: 0,
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

        self.size = event.firehose_data.len() as u64;

        Ok(())
    }

    /// Handle transaction header events
    async fn handle_transaction_header(&mut self, event: ProcessedEvent) -> Result<()> {
        debug!("Handling transaction header");

        let tx_data: serde_json::Value = serde_json::from_slice(&event.firehose_data)?;

        let txn_index = tx_data["txn_index"].as_u64().unwrap_or(0) as usize;

        // Debug: check if access_list is in tx_data
        if tx_data.get("access_list").is_some() {
            eprintln!("DEBUG: access_list found in tx_data for tx {}: {:?}", txn_index, tx_data["access_list"]);
        }
        let hash = ensure_hash_bytes(hex::decode(tx_data["hash"].as_str().unwrap_or("")).unwrap_or_default());
        let from = ensure_address_bytes(hex::decode(tx_data["from"].as_str().unwrap_or("")).unwrap_or_default());
        let to = ensure_address_bytes(hex::decode(tx_data["to"].as_str().unwrap_or("")).unwrap_or_default());
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
        // Debug: check value bytes
        if value.is_empty() {
            eprintln!("WARNING: value bytes is empty for tx {}, limbs: {:?}", txn_index, value_limbs);
        }

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
        // Debug: check gas_price bytes
        if gas_price.is_empty() {
            eprintln!("WARNING: gas_price bytes is empty for tx {}, type {}, max_fee_limbs: {:?}, priority_fee_limbs: {:?}", txn_index, txn_type, max_fee_limbs, max_priority_fee_limbs);
        }

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
        let chain_id = chain_id_limbs[0]; // Chain ID fits in u64

        let y_parity = tx_data["y_parity"].as_bool().unwrap_or(false);

        // Calculate v based on transaction type
        // For Monad: Use raw y_parity for all transaction types to match RPC
        let v = vec![y_parity as u8];

        let tx_trace = TransactionTrace {
            index: txn_index as u32,
            hash,
            from,
            to,
            nonce,
            gas_limit,
            value: Some(BigInt { bytes: if value.is_empty() { vec![0] } else { value } }),
            gas_price: Some(BigInt { bytes: if gas_price.is_empty() { vec![0] } else { gas_price } }),
            input,
            v,
            r,
            s,
            r#type: txn_type as i32,
             // access_list: Not populated for BASE block compliance with RPC
             access_list: {
                 let access_list = Vec::new();
                 if !access_list.is_empty() {
                     eprintln!("WARNING: access_list populated for tx {}: {:?}", txn_index, access_list);
                 }
                 access_list
             },
            // Deterministic ordinals based on transaction index for BASE blocks
            begin_ordinal: (txn_index * 2) as u64,
            end_ordinal: (txn_index * 2 + 1) as u64,
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
            // Monad only provides boolean status. Map false to REVERTED since most
            // unsuccessful transactions are reverts, not catastrophic failures.
            tx.status = if status { 1 } else { 3 };

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
        let log_index = log_data["log_index"].as_u64().unwrap_or(0) as u32;
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

        // Calculate blockIndex: this is the global log index within the block
        // We track this by incrementing for each log we see
        let block_index = self.total_log_count as u32;
        self.total_log_count += 1;

        let log = pb::sf::ethereum::r#type::v2::Log {
            address,
            topics,
            data,
            index: log_index,
            block_index,
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

                // Return min(max_fee, sum)
                if compare_u256_bytes(&max_fee, &sum) <= 0 {
                    max_fee
                } else {
                    sum
                }
            }
            _ => u256_limbs_to_bytes(max_fee_limbs)
        }
    }

    /// Finalize the block and return it
    fn finalize(mut self) -> Result<Block> {
        info!("Finalizing block {}", self.block_number);

        // Move transactions from map to vec, sorted by index
        let mut transactions: Vec<TransactionTrace> = self
            .transactions_map
            .into_iter()
            .map(|(_, tx)| {
                let mut tx = tx;
                // Calculate logs bloom from actual logs
                if let Some(ref mut receipt) = tx.receipt {
                    receipt.logs_bloom = calculate_logs_bloom(&receipt.logs);
                }
                tx
            })
            .collect();
        transactions.sort_by_key(|tx| tx.index);

        let header = BlockHeader {
            number: self.block_number,
            hash: self.block_hash.clone(),
            parent_hash: self.parent_hash,
            uncle_hash: self.uncle_hash,
            state_root: self.state_root,
            transactions_root: self.transactions_root,
            receipt_root: self.receipts_root,
            logs_bloom: self.logs_bloom,
            difficulty: Some(BigInt { bytes: vec![0u8; 32] }),
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: Some(prost_types::Timestamp {
                seconds: self.timestamp as i64,
                nanos: 0,
            }),
            extra_data: self.extra_data,
            mix_hash: self.mix_hash,
            nonce: self.nonce,
            coinbase: self.coinbase,
            base_fee_per_gas: Some(BigInt { bytes: u256_limbs_to_bytes(&self.base_fee_per_gas) }),
            withdrawals_root: self.withdrawals_root,
            parent_beacon_root: vec![0u8; 32],
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            requests_hash: vec![0u8; 32],
            ..Default::default()
        };

        let block = Block {
            number: self.block_number,
            hash: self.block_hash,
            size: self.size,
            header: Some(header),
            transaction_traces: transactions,
            ver: 4, // Version 4 for Firehose 3.0
            detail_level: block::DetailLevel::DetaillevelBase as i32,
            ..Default::default()
        };

        Ok(block)
    }
}
