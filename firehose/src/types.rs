//! Minimal data types for tracer hooks
//!
//! These types are independent of any blockchain client implementation (Reth, etc.)
//! and define the minimal data needed by the tracer at various lifecycle points.
//! The integration layer (client code) is responsible for converting from
//! client-specific types to these tracer types.

use std::fmt::Display;

use alloy_primitives::{Address, Bloom, Bytes, TxHash, B256, U256};
use num_enum::TryFromPrimitive;

/// BlockEvent contains the data needed for OnBlockStart
#[derive(Debug, Clone, Default)]
pub struct BlockEvent {
    pub block: BlockData,
    pub finalized: Option<FinalizedBlockRef>,
}

/// BlockData contains the minimal block data needed by the tracer
#[derive(Debug, Clone, Default)]
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

    // EIP-4895: Shanghai withdrawals
    pub withdrawals_root: Option<B256>, // Root hash of withdrawals tree (None for pre-Shanghai blocks)

    // EIP-4844: Cancun blob gas tracking
    pub blob_gas_used: Option<u64>, // Total blob gas consumed by blob transactions (None for pre-Cancun blocks)
    pub excess_blob_gas: Option<u64>, // Running total of excess blob gas (None for pre-Cancun blocks)

    // EIP-4788: Cancun beacon block root
    pub parent_beacon_root: Option<B256>, // Parent beacon block root for CL/EL sync (None for pre-Cancun blocks)

    // EIP-7685: Prague execution requests
    pub requests_hash: Option<B256>, // Root hash of execution layer requests (None for pre-Prague blocks)

    // Polygon-specific: Transaction dependency metadata
    // List of transaction indexes that are dependent on each other in the block
    // Used by Polygon's parallel execution engine (None for non-Polygon chains)
    pub tx_dependency: Option<Vec<Vec<u64>>>,
}

impl BlockData {
    /// Returns true if this block is a merge (post-merge blocks have difficulty == 0)
    pub fn is_merge(&self) -> bool {
        self.difficulty == U256::ZERO
    }
}

/// UncleData contains uncle block header data
#[derive(Debug, Clone, Default)]
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
#[derive(Debug, Clone, Default)]
pub struct WithdrawalData {
    pub index: u64,
    pub validator_index: u64,
    pub address: Address,
    pub amount: u64,
}

/// FinalizedBlockRef contains information about the finalized block
#[derive(Debug, Clone, Default)]
pub struct FinalizedBlockRef {
    pub number: u64,
    /// Hash may be None if the finalized block is not available (e.g., due to pruning), it's
    /// optional because Firehose protocol only relies on the finalized block number for finality
    /// notifications, the hash being used for logging purposes when available.
    pub hash: Option<B256>,
}

impl FinalizedBlockRef {
    /// Creates a new FinalizedBlockRef with the given number and no hash (hence the `minimal` name)
    pub fn minimal(number: u64) -> Self {
        Self { number, hash: None }
    }

    /// Creates a new FinalizedBlockRef with the given number and optional hash
    pub fn new(number: u64, hash: B256) -> Self {
        Self {
            number,
            hash: Some(hash),
        }
    }
}

/// AccessTuple is a single entry in an EIP-2930 access list
#[derive(Debug, Clone, Default)]
pub struct AccessTuple {
    pub address: Address,
    pub storage_keys: Vec<B256>,
}

/// SetCodeAuthorization represents EIP-7702 authorization
#[derive(Debug, Clone, Default)]
pub struct SetCodeAuthorization {
    pub chain_id: B256, // Using B256 to match [32]byte in Go
    pub address: Address,
    pub nonce: u64,
    pub v: u32,
    pub r: B256,
    pub s: B256,
}

/// TxEvent contains the data needed for OnTxStart
#[derive(Debug, Clone, Default)]
pub struct TxEvent {
    pub tx_type: TxType,
    pub hash: TxHash,
    pub from: Address,
    pub to: Option<Address>, // None for contract creation
    pub input: Bytes,
    pub value: U256,
    pub gas: u64,
    pub gas_price: U256,
    pub nonce: u64,
    pub index: u32,

    // Signature fields
    pub v: Option<Bytes>, // Signature V value (can be None for unsigned transactions)
    pub r: B256,          // Signature R point
    pub s: B256,          // Signature S point

    // EIP-1559 fields (type 2, 3, 4)
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,

    // EIP-2930/EIP-1559 access list (type 1, 2, 3, 4)
    pub access_list: Vec<AccessTuple>,

    // EIP-4844 blob fields (type 3)
    pub blob_gas_fee_cap: Option<U256>,
    pub blob_hashes: Vec<B256>,

    // EIP-7702 set code authorization list (type 4)
    pub set_code_authorizations: Vec<SetCodeAuthorization>,
}

/// TxType represents Ethereum transaction types (EIP-2718 envelope types).
///
/// Values match the type byte in the transaction envelope, as defined by each EIP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TxType {
    Legacy = 0,     // Pre-EIP-2718 legacy transaction
    AccessList = 1, // EIP-2930 access list transaction
    DynamicFee = 2, // EIP-1559 dynamic fee transaction
    Blob = 3,       // EIP-4844 blob transaction
    SetCode = 4,    // EIP-7702 set code transaction
}

impl Default for TxType {
    fn default() -> Self {
        TxType::Legacy
    }
}

impl Display for TxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let type_str = match self {
            TxType::Legacy => "TrxLegacy",
            TxType::AccessList => "TrxAccessList",
            TxType::DynamicFee => "TrxDynamicFee",
            TxType::Blob => "TrxBlob",
            TxType::SetCode => "TrxSetCode",
        };
        write!(f, "{}", type_str)
    }
}

/// Opcode represents EVM opcodes used by Firehose tracing hooks.
///
/// This enum is not exhaustive — it only includes opcodes that are directly
/// referenced by Firehose tracer hooks (call/create/selfdestruct boundaries and
/// the opcode step hook). All values match the Ethereum Yellow Paper opcode table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum Opcode {
    Keccak256 = 0x20,
    Create = 0xf0,
    Call = 0xf1,
    CallCode = 0xf2,
    DelegateCall = 0xf4,
    Create2 = 0xf5,
    StaticCall = 0xfa,
    SelfDestruct = 0xff,
}

/// A simple error type wrapping a string message, used when passing failure
/// reasons from EVM execution into the `&dyn std::error::Error` slots of the
/// tracer hooks (e.g. `on_call_exit`).
#[derive(Debug, Clone)]
pub struct StringError(pub String);

impl std::fmt::Display for StringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StringError {}

/// ReceiptData contains transaction receipt data
#[derive(Debug, Clone)]
pub struct ReceiptData {
    pub transaction_index: u32,
    pub gas_used: u64,
    pub status: u64,
    pub logs: Vec<LogData>,
    pub logs_bloom: [u8; 256],
    pub cumulative_gas_used: u64,
    pub blob_gas_used: u64,           // EIP-4844: Gas used for blob data
    pub blob_gas_price: Option<U256>, // EIP-4844: Price per unit of blob gas
    pub state_root: Option<Bytes>, // State root after transaction execution (for genesis blocks and pre-Byzantium)
}

impl Default for ReceiptData {
    fn default() -> Self {
        Self {
            transaction_index: 0,
            gas_used: 0,
            status: 0,
            logs: Vec::new(),
            logs_bloom: [0u8; 256],
            cumulative_gas_used: 0,
            blob_gas_used: 0,
            blob_gas_price: None,
            state_root: None,
        }
    }
}

/// LogData contains log event data
#[derive(Debug, Clone, Default)]
pub struct LogData {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub block_index: u32, // Block-wide index of the log (prepopulated by chain implementation, matches go-ethereum behavior)
}

/// GenesisAccount represents an account in the genesis block allocation
/// This is a simplified version of go-ethereum's types.Account for tracer use
#[derive(Debug, Clone, Default)]
pub struct GenesisAccount {
    /// Code is the contract bytecode (if this is a contract account)
    pub code: Option<Bytes>,

    /// Storage is the contract storage (key-value pairs)
    pub storage: std::collections::HashMap<B256, B256>,

    /// Balance is the account balance in wei
    pub balance: Option<U256>,

    /// Nonce is the account nonce
    pub nonce: u64,
}

/// GenesisAlloc is a map of addresses to genesis accounts
/// This represents the initial state allocation in the genesis block
pub type GenesisAlloc = std::collections::HashMap<Address, GenesisAccount>;

/// StateReader provides read-only access to blockchain state during transaction execution.
/// Required for EIP-7702 delegation detection, CREATE address calculation, etc.
/// Blockchain implementations must provide this (e.g., from EVM StateDB)
pub trait StateReader {
    /// Returns the account nonce for the given address
    fn get_nonce(&self, address: Address) -> u64;

    /// Returns the contract code for the given address
    /// Returns empty bytes if the account has no code
    fn get_code(&self, address: Address) -> Bytes;

    /// Returns if the account exists for the given address
    fn exists(&self, address: Address) -> bool;
}

pub struct NoOpStateReader {}
impl StateReader for NoOpStateReader {
    fn get_nonce(&self, _address: Address) -> u64 {
        0
    }

    fn get_code(&self, _address: Address) -> Bytes {
        Bytes::new()
    }

    fn exists(&self, _address: Address) -> bool {
        false
    }
}

impl BlockEvent {
    /// Creates a new BlockEvent with the given block data
    pub fn new(block: BlockData) -> Self {
        Self {
            block,
            finalized: None,
        }
    }

    /// Sets the finalized block reference
    pub fn with_finalized(mut self, finalized: FinalizedBlockRef) -> Self {
        self.finalized = Some(finalized);
        self
    }
}

impl TxEvent {
    /// Creates a new TxEvent with minimal required fields
    pub fn new(
        tx_type: TxType,
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
            v: None,
            r: B256::ZERO,
            s: B256::ZERO,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: Vec::new(),
            blob_gas_fee_cap: None,
            blob_hashes: Vec::new(),
            set_code_authorizations: Vec::new(),
        }
    }

    /// Returns true if this is a contract creation transaction
    pub fn is_create(&self) -> bool {
        self.to.is_none()
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
            logs_bloom: [0u8; 256],
            cumulative_gas_used,
            blob_gas_used: 0,
            blob_gas_price: None,
            state_root: None,
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
    pub fn new(address: Address, topics: Vec<B256>, data: Bytes, block_index: u32) -> Self {
        Self {
            address,
            topics,
            data,
            block_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_event_is_create() {
        let tx = TxEvent::new(
            TxType::Legacy,
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
            TxType::Legacy,
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
    fn test_receipt_status() {
        let mut receipt = ReceiptData::new(0, 21000, 1, 21000);
        assert!(receipt.is_success());

        receipt.status = 0;
        assert!(!receipt.is_success());
    }
}
