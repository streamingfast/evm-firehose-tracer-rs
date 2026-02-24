//! Minimal data types for tracer hooks
//!
//! These types are independent of any blockchain client implementation (Reth, etc.)
//! and define the minimal data needed by the tracer at various lifecycle points.
//! The integration layer (client code) is responsible for converting from
//! client-specific types to these tracer types.

use alloy_primitives::{Address, Bloom, Bytes, TxHash, B256, U256};

/// BlockEvent contains the data needed for OnBlockStart
pub struct BlockEvent {
    pub block: BlockData,
    pub finalized: Option<FinalizedBlockRef>,

    /// Precompile Detection (at least one should be provided by chain implementation)
    ///
    /// The chain implementation should provide precompile information since it varies by:
    /// - Chain type (Ethereum, BSC, Polygon, etc.)
    /// - Fork rules (Istanbul adds blake2f, Cancun adds point evaluation, etc.)
    /// - Custom chain precompiles
    ///
    /// Option 1: Provide a pre-built checker function
    pub is_precompiled_addr: Option<Box<dyn Fn(Address) -> bool + Send + Sync>>,
    //
    // Option 2: Provide the list of addresses (tracer will build the checker)
    // If neither is provided, all addresses will be treated as non-precompiled.
    pub active_precompiles: Vec<Address>,
}

/// BlockData contains the minimal block data needed by the tracer
#[derive(Debug, Clone)]
pub struct BlockData {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub uncle_hash: B256,
    pub coinbase: Address,
    pub root: B256,
    pub tx_hash: B256,
    pub receipt_hash: B256,
    pub bloom: Bloom,
    pub difficulty: U256,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub time: u64,
    pub extra: Bytes,
    pub mix_digest: B256,
    pub nonce: u64,
    pub base_fee: Option<U256>,
    pub uncles: Vec<UncleData>,
    pub size: u64,
    pub withdrawals: Vec<WithdrawalData>,
    pub is_merge: bool,
}

/// UncleData contains uncle block header data
#[derive(Debug, Clone)]
pub struct UncleData {
    pub hash: B256,
    pub parent_hash: B256,
    pub uncle_hash: B256,
    pub coinbase: Address,
    pub root: B256,
    pub tx_hash: B256,
    pub receipt_hash: B256,
    pub bloom: Bloom,
    pub difficulty: U256,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub time: u64,
    pub extra: Bytes,
    pub mix_digest: B256,
    pub nonce: u64,
    pub base_fee: Option<U256>,
}

/// WithdrawalData contains withdrawal data
#[derive(Debug, Clone)]
pub struct WithdrawalData {
    pub index: u64,
    pub validator_index: u64,
    pub address: Address,
    pub amount: u64,
}

/// FinalizedBlockRef contains information about the finalized block
#[derive(Debug, Clone)]
pub struct FinalizedBlockRef {
    pub number: u64,
    pub hash: B256,
}

/// TxEvent contains the data needed for OnTxStart
#[derive(Debug, Clone)]
pub struct TxEvent {
    pub tx_type: u8,
    pub hash: TxHash,
    pub from: Address,
    pub to: Option<Address>, // None for contract creation
    pub input: Bytes,
    pub value: U256,
    pub gas: u64,
    pub gas_price: U256,
    pub nonce: u64,
    pub index: u32,
}

/// CallFrame contains the data for OnCallEnter/OnCallExit
#[derive(Debug, Clone)]
pub struct CallFrame {
    pub call_type: CallType,
    pub from: Address,
    pub to: Address,
    pub input: Bytes,
    pub gas: u64,
    pub value: U256,
    pub code_address: Option<Address>, // For DELEGATECALL
}

/// CallType represents the type of call
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CallType {
    Call = 0,
    CallCode = 1,
    DelegateCall = 2,
    StaticCall = 3,
    Create = 4,
    Create2 = 5,
    SelfDestruct = 6,
}

/// ReceiptData contains transaction receipt data
#[derive(Debug, Clone)]
pub struct ReceiptData {
    pub transaction_index: u32,
    pub gas_used: u64,
    pub status: u64,
    pub logs: Vec<LogData>,
    pub cumulative_gas_used: u64,
}

/// LogData contains log event data
#[derive(Debug, Clone)]
pub struct LogData {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

/// OpcodeScopeData contains data about opcode execution scope
/// (used for tracking stack depth and call contexts)
#[derive(Debug, Clone)]
pub struct OpcodeScopeData {
    pub depth: usize,
    pub pc: u64,
    pub op: u8,
    pub gas: u64,
    pub gas_cost: u64,
    pub memory_size: u64,
}

impl BlockEvent {
    /// Creates a new BlockEvent with the given block data
    pub fn new(block: BlockData) -> Self {
        Self {
            block,
            finalized: None,
            is_precompiled_addr: None,
            active_precompiles: Vec::new(),
        }
    }

    /// Sets the finalized block reference
    pub fn with_finalized(mut self, finalized: FinalizedBlockRef) -> Self {
        self.finalized = Some(finalized);
        self
    }

    /// Sets the precompile checker function
    pub fn with_precompile_checker<F>(mut self, checker: F) -> Self
    where
        F: Fn(Address) -> bool + Send + Sync + 'static,
    {
        self.is_precompiled_addr = Some(Box::new(checker));
        self
    }

    /// Sets the active precompile addresses
    pub fn with_active_precompiles(mut self, precompiles: Vec<Address>) -> Self {
        self.active_precompiles = precompiles;
        self
    }

    /// Checks if an address is a precompiled contract
    pub fn is_precompile(&self, addr: Address) -> bool {
        if let Some(ref checker) = self.is_precompiled_addr {
            return checker(addr);
        }

        self.active_precompiles.contains(&addr)
    }
}

impl TxEvent {
    /// Creates a new TxEvent
    pub fn new(
        tx_type: u8,
        hash: TxHash,
        from: Address,
        to: Option<Address>,
        input: Bytes,
        value: U256,
        gas: u64,
        gas_price: U256,
        nonce: u64,
        index: u32,
    ) -> Self {
        Self {
            tx_type,
            hash,
            from,
            to,
            input,
            value,
            gas,
            gas_price,
            nonce,
            index,
        }
    }

    /// Returns true if this is a contract creation transaction
    pub fn is_create(&self) -> bool {
        self.to.is_none()
    }
}

impl CallFrame {
    /// Creates a new CallFrame
    pub fn new(
        call_type: CallType,
        from: Address,
        to: Address,
        input: Bytes,
        gas: u64,
        value: U256,
    ) -> Self {
        Self {
            call_type,
            from,
            to,
            input,
            gas,
            value,
            code_address: None,
        }
    }

    /// Sets the code address (for DELEGATECALL)
    pub fn with_code_address(mut self, code_address: Address) -> Self {
        self.code_address = Some(code_address);
        self
    }

    /// Returns true if this is a delegate call
    pub fn is_delegate_call(&self) -> bool {
        self.call_type == CallType::DelegateCall
    }

    /// Returns true if this is a static call
    pub fn is_static_call(&self) -> bool {
        self.call_type == CallType::StaticCall
    }

    /// Returns true if this is a create operation
    pub fn is_create(&self) -> bool {
        matches!(self.call_type, CallType::Create | CallType::Create2)
    }
}

impl ReceiptData {
    /// Creates a new ReceiptData
    pub fn new(
        transaction_index: u32,
        gas_used: u64,
        status: u64,
        cumulative_gas_used: u64,
    ) -> Self {
        Self {
            transaction_index,
            gas_used,
            status,
            logs: Vec::new(),
            cumulative_gas_used,
        }
    }

    /// Adds a log to the receipt
    pub fn add_log(&mut self, log: LogData) {
        self.logs.push(log);
    }

    /// Returns true if the transaction was successful
    pub fn is_success(&self) -> bool {
        self.status == 1
    }
}

impl LogData {
    /// Creates a new LogData
    pub fn new(address: Address, topics: Vec<B256>, data: Bytes) -> Self {
        Self {
            address,
            topics,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_event_is_create() {
        let tx = TxEvent::new(
            0,
            TxHash::default(),
            Address::default(),
            None,
            Bytes::default(),
            U256::ZERO,
            21000,
            U256::from(1000000000u64),
            0,
            0,
        );
        assert!(tx.is_create());

        let tx_with_to = TxEvent::new(
            0,
            TxHash::default(),
            Address::default(),
            Some(Address::default()),
            Bytes::default(),
            U256::ZERO,
            21000,
            U256::from(1000000000u64),
            0,
            0,
        );
        assert!(!tx_with_to.is_create());
    }

    #[test]
    fn test_call_frame_types() {
        let frame = CallFrame::new(
            CallType::DelegateCall,
            Address::default(),
            Address::default(),
            Bytes::default(),
            21000,
            U256::ZERO,
        );
        assert!(frame.is_delegate_call());
        assert!(!frame.is_static_call());
        assert!(!frame.is_create());

        let static_frame = CallFrame::new(
            CallType::StaticCall,
            Address::default(),
            Address::default(),
            Bytes::default(),
            21000,
            U256::ZERO,
        );
        assert!(static_frame.is_static_call());
    }

    #[test]
    fn test_receipt_status() {
        let mut receipt = ReceiptData::new(0, 21000, 1, 21000);
        assert!(receipt.is_success());

        receipt.status = 0;
        assert!(!receipt.is_success());
    }

    #[test]
    fn test_block_event_precompiles() {
        let block = BlockData {
            number: 1,
            hash: B256::default(),
            parent_hash: B256::default(),
            uncle_hash: B256::default(),
            coinbase: Address::default(),
            root: B256::default(),
            tx_hash: B256::default(),
            receipt_hash: B256::default(),
            bloom: Bloom::default(),
            difficulty: U256::ZERO,
            gas_limit: 10000000,
            gas_used: 0,
            time: 1000000,
            extra: Bytes::default(),
            mix_digest: B256::default(),
            nonce: 0,
            base_fee: Some(U256::from(1000000000u64)),
            uncles: Vec::new(),
            size: 1000,
            withdrawals: Vec::new(),
            is_merge: true,
        };

        let precompile_addr = Address::from([1u8; 20]);
        let event = BlockEvent::new(block).with_active_precompiles(vec![precompile_addr]);

        assert!(event.is_precompile(precompile_addr));
        assert!(!event.is_precompile(Address::default()));
    }

    #[test]
    fn test_block_event_precompile_checker() {
        let block = BlockData {
            number: 1,
            hash: B256::default(),
            parent_hash: B256::default(),
            uncle_hash: B256::default(),
            coinbase: Address::default(),
            root: B256::default(),
            tx_hash: B256::default(),
            receipt_hash: B256::default(),
            bloom: Bloom::default(),
            difficulty: U256::ZERO,
            gas_limit: 10000000,
            gas_used: 0,
            time: 1000000,
            extra: Bytes::default(),
            mix_digest: B256::default(),
            nonce: 0,
            base_fee: Some(U256::from(1000000000u64)),
            uncles: Vec::new(),
            size: 1000,
            withdrawals: Vec::new(),
            is_merge: true,
        };

        let precompile_addr = Address::from([1u8; 20]);
        let event = BlockEvent::new(block)
            .with_precompile_checker(move |addr| addr == precompile_addr);

        assert!(event.is_precompile(precompile_addr));
        assert!(!event.is_precompile(Address::default()));
    }
}
