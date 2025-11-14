//! Event Mapper
//!
//! This module handles mapping processed Monad events to Firehose protobuf blocks.

use crate::{Block, BlockHeader, Ordinal, ProcessedEvent, TransactionTrace};
use pb::sf::ethereum::r#type::v2::{balance_change, block, BalanceChange, BigInt, Call, CallType, CodeChange};
use eyre::Result;
use tracing::{debug, info};

/// Maps processed events to Firehose blocks
pub struct EventMapper {
    /// Current block being built
    current_block: Option<BlockBuilder>,
    /// Ordinal counter for execution ordering
    ordinal: Ordinal,
}

impl EventMapper {
    /// Create a new event mapper
    pub fn new() -> Self {
        Self {
            current_block: None,
            ordinal: Ordinal::new(),
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
                builder.add_event(event, &mut self.ordinal).await?;
            }

            // Return the completed block if we had one
            return Ok(completed_block);
        }

        // Add the event to the current block
        if let Some(ref mut builder) = self.current_block {
            builder.add_event(event.clone(), &mut self.ordinal).await?;

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

/// Builder for constructing Firehose blocks from events
struct BlockBuilder {
    block_number: u64,
    block_hash: Vec<u8>,
    parent_hash: Vec<u8>,
    timestamp: u64,
    transactions: Vec<TransactionTrace>,
    balance_changes: Vec<BalanceChange>,
    code_changes: Vec<CodeChange>,
    system_calls: Vec<Call>,
    size: u64,
    gas_used: u64,
    gas_limit: u64,
}

impl BlockBuilder {
    /// Create a new block builder
    fn new(block_number: u64) -> Self {
        Self {
            block_number,
            block_hash: vec![0u8; 32],  // TODO: Get actual hash from events
            parent_hash: vec![0u8; 32], // TODO: Get actual parent hash
            timestamp: chrono::Utc::now().timestamp() as u64,
            transactions: Vec::new(),
            balance_changes: Vec::new(),
            code_changes: Vec::new(),
            system_calls: Vec::new(),
            size: 0,
            gas_used: 0,
            gas_limit: 30_000_000, // Default gas limit
        }
    }

    /// Add an event to the block
    async fn add_event(&mut self, event: ProcessedEvent, ordinal: &mut Ordinal) -> Result<()> {
        match event.event_type.as_str() {
            "BLOCK_START" => self.handle_block_start(event, ordinal).await?,
            "BLOCK_END" => self.handle_block_end(event, ordinal).await?,
            "TX_START" => self.handle_transaction_start(event, ordinal).await?,
            "TX_END" => self.handle_transaction_end(event, ordinal).await?,
            "BALANCE_CHANGE" => self.handle_balance_change(event, ordinal).await?,
            "CODE_CHANGE" => self.handle_code_change(event, ordinal).await?,
            "CALL_START" | "CALL_END" => self.handle_call(event, ordinal).await?,
            _ => {
                debug!("Unknown event type: {}", event.event_type);
            }
        }

        Ok(())
    }

    /// Handle block start events
    async fn handle_block_start(
        &mut self,
        event: ProcessedEvent,
        _ordinal: &mut Ordinal,
    ) -> Result<()> {
        debug!("Handling block start for block {}", event.block_number);

        // Parse block data from event.firehose_data
        // Format: "BLOCK_START:{block_num}:{parent_hash_hex}:{timestamp}:{gas_limit}"
        let data_str = String::from_utf8(event.firehose_data.clone())?;
        let parts: Vec<&str> = data_str.split(':').collect();

        if parts.len() >= 3 && parts[0] == "BLOCK_START" {
            // Parse parent hash from hex
            if let Ok(parent_hash_bytes) = hex::decode(parts[2]) {
                self.parent_hash = parent_hash_bytes;
            }

            // Parse timestamp
            if parts.len() >= 4 {
                if let Ok(ts) = parts[3].parse::<u64>() {
                    self.timestamp = ts;
                }
            }

            // Parse gas limit
            if parts.len() >= 5 {
                if let Ok(gas_limit) = parts[4].parse::<u64>() {
                    self.gas_limit = gas_limit;
                }
            }
        }

        Ok(())
    }

    /// Handle block end events
    async fn handle_block_end(
        &mut self,
        event: ProcessedEvent,
        _ordinal: &mut Ordinal,
    ) -> Result<()> {
        debug!("Handling block end for block {}", event.block_number);

        // Parse block data from event.firehose_data
        // Format: "BLOCK_END:{block_num}:{block_hash_hex}:{state_root_hex}:{gas_used}"
        let data_str = String::from_utf8(event.firehose_data.clone())?;
        let parts: Vec<&str> = data_str.split(':').collect();

        if parts.len() >= 3 && parts[0] == "BLOCK_END" {
            // Parse block hash from hex
            if let Ok(block_hash_bytes) = hex::decode(parts[2]) {
                self.block_hash = block_hash_bytes;
            }

            // Parse gas used
            if parts.len() >= 5 {
                if let Ok(gas_used) = parts[4].parse::<u64>() {
                    self.gas_used = gas_used;
                }
            }
        }

        self.size = event.firehose_data.len() as u64;

        Ok(())
    }

    /// Handle transaction start events
    async fn handle_transaction_start(
        &mut self,
        event: ProcessedEvent,
        ordinal: &mut Ordinal,
    ) -> Result<()> {
        debug!("Handling transaction start");

        // TODO: Parse transaction data from event.firehose_data
        let tx_trace = TransactionTrace {
            index: self.transactions.len() as u32,
            hash: event.firehose_data.clone(),
            begin_ordinal: ordinal.next(),
            end_ordinal: 0, // Will be set on transaction end
            ..Default::default()
        };

        self.transactions.push(tx_trace);

        Ok(())
    }

    /// Handle transaction end events
    async fn handle_transaction_end(
        &mut self,
        _event: ProcessedEvent,
        ordinal: &mut Ordinal,
    ) -> Result<()> {
        debug!("Handling transaction end");

        // Update the last transaction's end ordinal
        if let Some(last_tx) = self.transactions.last_mut() {
            last_tx.end_ordinal = ordinal.next();
        }

        Ok(())
    }

    /// Handle balance change events
    async fn handle_balance_change(
        &mut self,
        event: ProcessedEvent,
        ordinal: &mut Ordinal,
    ) -> Result<()> {
        debug!("Handling balance change");

        // TODO: Parse balance change data from event.firehose_data
        let balance_change = BalanceChange {
            address: vec![0u8; 20], // TODO: Parse from event data
            old_value: Some(BigInt { bytes: vec![0] }),
            new_value: Some(BigInt {
                bytes: event.firehose_data,
            }),
            reason: balance_change::Reason::Transfer as i32,
            ordinal: ordinal.next(),
        };

        self.balance_changes.push(balance_change);

        Ok(())
    }

    /// Handle code change events
    async fn handle_code_change(
        &mut self,
        event: ProcessedEvent,
        ordinal: &mut Ordinal,
    ) -> Result<()> {
        debug!("Handling code change");

        // TODO: Parse code change data from event.firehose_data
        let code_change = CodeChange {
            address: vec![0u8; 20], // TODO: Parse from event data
            old_hash: vec![0u8; 32],
            old_code: Vec::new(),
            new_hash: vec![1u8; 32],
            new_code: event.firehose_data,
            ordinal: ordinal.next(),
        };

        self.code_changes.push(code_change);

        Ok(())
    }

    /// Handle call events
    async fn handle_call(&mut self, event: ProcessedEvent, ordinal: &mut Ordinal) -> Result<()> {
        debug!("Handling call event: {}", event.event_type);

        // TODO: Parse call data from event.firehose_data
        let call = Call {
            index: self.system_calls.len() as u32,
            call_type: CallType::Call as i32,
            begin_ordinal: ordinal.next(),
            end_ordinal: ordinal.next(),
            ..Default::default()
        };

        self.system_calls.push(call);

        Ok(())
    }

    /// Finalize the block and return it
    fn finalize(self) -> Result<Block> {
        info!("Finalizing block {}", self.block_number);

        let header = BlockHeader {
            number: self.block_number,
            hash: self.block_hash.clone(),
            parent_hash: self.parent_hash,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: Some(prost_types::Timestamp {
                seconds: self.timestamp as i64,
                nanos: 0,
            }),
            ..Default::default()
        };

        let block = Block {
            number: self.block_number,
            hash: self.block_hash,
            size: self.size,
            header: Some(header),
            transaction_traces: self.transactions,
            balance_changes: self.balance_changes,
            code_changes: self.code_changes,
            system_calls: self.system_calls,
            ver: 1,
            detail_level: block::DetailLevel::DetaillevelExtended as i32,
            ..Default::default()
        };

        Ok(block)
    }
}
