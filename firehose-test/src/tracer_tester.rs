use alloy_primitives::{Address, Bloom, Bytes, B256, U256};
use base64::Engine;
use firehose::{
    BlockData, BlockEvent, CallType, ChainConfig, Config, ReceiptData, Tracer, TxEvent,
};
use pb::sf::ethereum::r#type::v2 as pbeth;
use prost::Message;
use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};

use crate::mock_state::MockStateDB;
use crate::testing_helpers::*;

/// Compute a deterministic genesis block hash from key block components.
/// This doesn't match Ethereum's exact RLP encoding but is sufficient for tests
/// and matches the Golang implementation for Protobuf validation.
fn compute_genesis_block_hash(
    block_number: u64,
    state_root: B256,
    uncle_hash: B256,
    tx_hash: B256,
) -> B256 {
    use alloy_primitives::Keccak256;

    // Create a simple deterministic hash by hashing key block components
    let mut hasher = Keccak256::new();

    // Add state root
    hasher.update(state_root.as_slice());

    // Add block number (8 bytes, big-endian)
    hasher.update(&block_number.to_be_bytes());

    // Add uncle hash
    hasher.update(uncle_hash.as_slice());

    // Add tx hash
    hasher.update(tx_hash.as_slice());

    hasher.finalize()
}

/// TestBlock provides a standard test block with reasonable defaults
/// This block represents block #100 with typical Ethereum mainnet settings
pub fn test_block() -> BlockEvent {
    BlockEvent::new(BlockData {
        number: 100,
        hash: hash_from_hex("0xe74fcc728df762055c71a999736bb89dd47c541807c3021a1b94de6761afaf25"),
        parent_hash: hash_from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000063",
        ),
        uncle_hash: B256::ZERO, // Use zeros to match Golang testdata
        coinbase: miner_addr(),
        root: B256::ZERO,
        tx_hash: B256::ZERO, // Use zeros to match Golang testdata (transactions_root)
        receipt_hash: B256::ZERO, // Use zeros to match Golang testdata
        bloom: Bloom::ZERO,
        difficulty: U256::ZERO,
        gas_limit: 30_000_000,
        gas_used: 0,
        time: 1704067200,
        extra: Bytes::new(),
        mix_digest: B256::ZERO,
        nonce: 0,
        base_fee: None,
        uncles: vec![],
        size: 509,
        withdrawals: vec![],
        is_merge: false,
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_root: None,
        requests_hash: None,
        tx_dependency: None,
    })
}

/// TestLegacyTrx provides a legacy (type 0) test transaction
pub fn test_legacy_trx() -> TxEvent {
    TxEvent {
        tx_type: 0, // Legacy
        hash: B256::ZERO,
        from: alice_addr(),
        to: Some(bob_addr()),
        input: Bytes::new(),
        value: big_int(100),
        gas: 21000,
        gas_price: big_int(10),
        nonce: 0,
        index: 0,
        v: None,
        r: B256::ZERO,
        s: B256::ZERO,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: vec![],
        blob_gas_fee_cap: None,
        blob_hashes: vec![],
        set_code_authorizations: vec![],
    }
}

/// TestAccessListTrx provides an EIP-2930 access list (type 1) test transaction
pub fn test_access_list_trx() -> TxEvent {
    TxEvent {
        tx_type: 1, // EIP-2930
        hash: B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]),
        from: alice_addr(),
        to: Some(bob_addr()),
        input: Bytes::new(),
        value: big_int(100),
        gas: 21000,
        gas_price: big_int(10),
        nonce: 0,
        index: 0,
        v: None,
        r: B256::ZERO,
        s: B256::ZERO,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: vec![firehose::types::AccessTuple {
            address: bob_addr(),
            storage_keys: vec![B256::from([
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])],
        }],
        blob_gas_fee_cap: None,
        blob_hashes: vec![],
        set_code_authorizations: vec![],
    }
}

/// TestDynamicFeeTrx provides an EIP-1559 dynamic fee (type 2) test transaction
pub fn test_dynamic_fee_trx() -> TxEvent {
    TxEvent {
        tx_type: 2, // EIP-1559
        hash: B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ]),
        from: alice_addr(),
        to: Some(bob_addr()),
        input: Bytes::new(),
        value: big_int(100),
        gas: 21000,
        gas_price: big_int(10),
        nonce: 0,
        index: 0,
        v: None,
        r: B256::ZERO,
        s: B256::ZERO,
        max_fee_per_gas: Some(big_int(20)),
        max_priority_fee_per_gas: Some(big_int(2)),
        access_list: vec![firehose::types::AccessTuple {
            address: bob_addr(),
            storage_keys: vec![B256::from([
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])],
        }],
        blob_gas_fee_cap: None,
        blob_hashes: vec![],
        set_code_authorizations: vec![],
    }
}

/// TestBlobTrx provides an EIP-4844 blob (type 3) test transaction
pub fn test_blob_trx() -> TxEvent {
    TxEvent {
        tx_type: 3, // EIP-4844
        hash: B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 3,
        ]),
        from: alice_addr(),
        to: Some(bob_addr()),
        input: Bytes::new(),
        value: big_int(100),
        gas: 21000,
        gas_price: big_int(10),
        nonce: 0,
        index: 0,
        v: None,
        r: B256::ZERO,
        s: B256::ZERO,
        max_fee_per_gas: Some(big_int(20)),
        max_priority_fee_per_gas: Some(big_int(2)),
        access_list: vec![],
        blob_gas_fee_cap: Some(big_int(5)),
        blob_hashes: vec![B256::from([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])],
        set_code_authorizations: vec![],
    }
}

/// TestSetCodeTrx provides an EIP-7702 set code (type 4) test transaction
/// TestSetCodeTrx provides an EIP-7702 SetCode (type 4) test transaction
///
/// NOTE: This uses FIXED signature values matching the Golang golden file.
/// The Golang implementation uses non-deterministic ECDSA signing (rand.Reader),
/// while the Rust implementation uses deterministic signing (RFC 6979). To achieve
/// byte-for-byte protobuf validation, we use the exact signature from the Golang
/// golden file rather than generating a new one.
pub fn test_set_code_trx() -> TxEvent {
    // Use the exact signature values from Golang golden file
    // Generated from: SignSetCodeAuth(AliceKey, 1, CharlieAddr, 0)
    // where AliceKey = 0x0000...0001
    let chain_id = B256::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]);
    let v = 1u32;
    let r = B256::from([
        56, 220, 16, 104, 151, 230, 71, 126, 199, 48, 19, 93, 118, 214, 77, 140, 65, 206, 17, 56,
        95, 32, 235, 91, 180, 224, 180, 254, 233, 252, 245, 38,
    ]);
    let s = B256::from([
        62, 196, 89, 234, 97, 242, 118, 108, 254, 198, 34, 23, 160, 213, 139, 78, 218, 45, 198,
        223, 217, 63, 226, 158, 251, 143, 233, 242, 223, 199, 87, 33,
    ]);

    TxEvent {
        tx_type: 4, // EIP-7702
        hash: B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 4,
        ]),
        from: alice_addr(),
        to: Some(bob_addr()),
        input: Bytes::new(),
        value: big_int(100),
        gas: 21000,
        gas_price: big_int(10),
        nonce: 0,
        index: 0,
        v: None,
        r: B256::ZERO,
        s: B256::ZERO,
        max_fee_per_gas: Some(big_int(20)),
        max_priority_fee_per_gas: Some(big_int(2)),
        access_list: vec![],
        blob_gas_fee_cap: None,
        blob_hashes: vec![],
        set_code_authorizations: vec![firehose::types::SetCodeAuthorization {
            chain_id,
            address: charlie_addr(),
            nonce: 0,
            v,
            r,
            s,
        }],
    }
}

pub fn test_set_code_trx_with_auth(
    authorizations: Vec<firehose::types::SetCodeAuthorization>,
) -> TxEvent {
    TxEvent {
        tx_type: 4, // EIP-7702
        hash: B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 4,
        ]),
        from: alice_addr(),
        to: Some(bob_addr()),
        input: Bytes::new(),
        value: big_int(100),
        gas: 21000,
        gas_price: big_int(10),
        nonce: 0,
        index: 0,
        v: None,
        r: B256::ZERO,
        s: B256::ZERO,
        max_fee_per_gas: Some(big_int(20)),
        max_priority_fee_per_gas: Some(big_int(2)),
        access_list: vec![],
        blob_gas_fee_cap: None,
        blob_hashes: vec![],
        set_code_authorizations: authorizations,
    }
}

/// InMemoryBuffer is a thread-safe in-memory buffer that implements Write
#[derive(Clone)]
pub struct InMemoryBuffer {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl InMemoryBuffer {
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        self.buffer.lock().unwrap().clone()
    }
}

impl Write for InMemoryBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.buffer.lock().unwrap().flush()
    }
}

/// TracerTester provides a fluent API for building test scenarios
pub struct TracerTester {
    pub tracer: Tracer,
    mock_state_db: MockStateDB,
    depth: i32,
    block_log_index: u32,
    output_buffer: InMemoryBuffer,
}

impl TracerTester {
    /// Creates a new tester with default chain config
    pub fn new() -> Self {
        Self::new_with_config(ChainConfig::new(1))
    }

    /// Creates a tester with Prague fork enabled (for EIP-7702 testing)
    pub fn new_prague() -> Self {
        let mut config = ChainConfig::new(1);
        config.prague_time = Some(0); // Prague activated at genesis
        Self::new_with_config(config)
    }

    /// Creates a tester with a specific chain config
    pub fn new_with_config(chain_config: ChainConfig) -> Self {
        let output_buffer = InMemoryBuffer::new();
        let config = Config::new(chain_config.clone());

        let tracer = Tracer::new_with_writer(
            config,
            Arc::new(chain_config.clone()),
            Box::new(output_buffer.clone()),
        );

        let mut tester = Self {
            tracer,
            mock_state_db: MockStateDB::new(),
            depth: 0,
            block_log_index: 0,
            output_buffer,
        };

        // Initialize the tracer
        tester.tracer.on_blockchain_init("test", "1.0.0");

        tester
    }

    // ========================================================================
    // Mock State Management
    // ========================================================================

    pub fn set_mock_state_code(&mut self, addr: Address, code: Vec<u8>) -> &mut Self {
        self.mock_state_db.set_code(addr, code);
        self
    }

    pub fn set_mock_state_nonce(&mut self, addr: Address, nonce: u64) -> &mut Self {
        self.mock_state_db.set_nonce(addr, nonce);
        self
    }

    pub fn set_mock_state_exist(&mut self, addr: Address, exists: bool) -> &mut Self {
        self.mock_state_db.set_exist(addr, exists);
        self
    }

    // ========================================================================
    // Block Lifecycle
    // ========================================================================

    pub fn start_block(&mut self) -> &mut Self {
        self.tracer.on_block_start(test_block());
        self.block_log_index = 0; // Reset log counter for new block
        self
    }

    /// Creates a genesis block with the given allocation
    /// This is a complete block processing including on_block_start, on_genesis_block, and on_block_end
    pub fn genesis_block(
        &mut self,
        number: u64,
        state_root: B256,
        alloc: std::collections::HashMap<Address, firehose::types::GenesisAccount>,
    ) -> &mut Self {
        // Standard genesis block header values
        let empty_uncle_hash =
            hash_from_hex("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");
        let empty_txs_hash =
            hash_from_hex("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

        // Compute deterministic block hash from state root (matching Golang implementation)
        let block_hash =
            compute_genesis_block_hash(number, state_root, empty_uncle_hash, empty_txs_hash);

        // Create a minimal block event for genesis
        let block_event = BlockEvent::new(BlockData {
            number,
            hash: block_hash,
            parent_hash: B256::ZERO,
            uncle_hash: empty_uncle_hash,
            coinbase: Address::ZERO,
            root: state_root,
            tx_hash: empty_txs_hash,
            receipt_hash: empty_txs_hash,
            bloom: Bloom::ZERO,
            difficulty: U256::ZERO,
            gas_limit: 8_000_000,
            gas_used: 0,
            time: 0,
            extra: Bytes::new(),
            mix_digest: B256::ZERO,
            nonce: 0,
            base_fee: None,
            uncles: vec![],
            size: 539,
            withdrawals: vec![],
            is_merge: false,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_root: None,
            requests_hash: None,
            tx_dependency: None,
        });

        self.tracer.on_genesis_block(block_event, alloc);
        self.block_log_index = 0;
        self
    }

    pub fn start_block_trx(&mut self, tx: TxEvent) -> &mut Self {
        self.tracer.on_block_start(test_block());
        self.block_log_index = 0;

        // Clone the mock state DB and wrap it in the expected type
        let state_reader: Box<dyn firehose::types::StateReader> =
            Box::new(self.mock_state_db.clone());
        self.tracer.on_tx_start(tx, Some(state_reader));
        self
    }

    pub fn start_trx(&mut self, tx: TxEvent) -> &mut Self {
        let state_reader: Box<dyn firehose::types::StateReader> =
            Box::new(self.mock_state_db.clone());
        self.tracer.on_tx_start(tx, Some(state_reader));
        self
    }

    pub fn end_block(&mut self, err: Option<&dyn std::error::Error>) -> &mut Self {
        self.tracer.on_block_end(err);
        self
    }

    // ========================================================================
    // Transaction Lifecycle
    // ========================================================================

    pub fn end_trx(
        &mut self,
        receipt: Option<ReceiptData>,
        tx_err: Option<&dyn std::error::Error>,
    ) -> &mut Self {
        if let Some(mut receipt) = receipt {
            self.populate_receipt_log_block_index(&mut receipt);
            self.tracer.on_tx_end(Some(&receipt), tx_err);
        } else {
            self.tracer.on_tx_end(None, tx_err);
        }
        self
    }

    pub fn end_block_trx(
        &mut self,
        receipt: Option<ReceiptData>,
        tx_err: Option<&dyn std::error::Error>,
        block_err: Option<&dyn std::error::Error>,
    ) -> &mut Self {
        if let Some(mut receipt) = receipt {
            self.populate_receipt_log_block_index(&mut receipt);
            self.tracer.on_tx_end(Some(&receipt), tx_err);
        } else {
            self.tracer.on_tx_end(None, tx_err);
        }
        self.tracer.on_block_end(block_err);
        self
    }

    fn populate_receipt_log_block_index(&self, receipt: &mut ReceiptData) {
        for (i, log) in receipt.logs.iter_mut().enumerate() {
            log.block_index = i as u32;
        }
    }

    // ========================================================================
    // Call Lifecycle
    // ========================================================================

    pub fn start_call(
        &mut self,
        from: Address,
        to: Address,
        value: U256,
        gas: u64,
        input: Vec<u8>,
    ) -> &mut Self {
        self.start_call_raw(CallType::Call as u8, from, to, input, gas, value)
    }

    pub fn start_static_call(
        &mut self,
        from: Address,
        to: Address,
        gas: u64,
        input: Vec<u8>,
    ) -> &mut Self {
        self.start_call_raw(CallType::StaticCall as u8, from, to, input, gas, U256::ZERO)
    }

    pub fn start_create_call(
        &mut self,
        from: Address,
        to: Address,
        value: U256,
        gas: u64,
        input: Vec<u8>,
    ) -> &mut Self {
        self.start_call_raw(CallType::Create as u8, from, to, input, gas, value)
    }

    pub fn start_create2_call(
        &mut self,
        from: Address,
        to: Address,
        value: U256,
        gas: u64,
        input: Vec<u8>,
    ) -> &mut Self {
        self.start_call_raw(CallType::Create as u8, from, to, input, gas, value)
    }

    pub fn start_delegate_call(
        &mut self,
        from: Address,
        to: Address,
        value: U256,
        gas: u64,
        input: Vec<u8>,
    ) -> &mut Self {
        self.start_call_raw(CallType::DelegateCall as u8, from, to, input, gas, value)
    }

    pub fn start_call_code(
        &mut self,
        from: Address,
        to: Address,
        value: U256,
        gas: u64,
        input: Vec<u8>,
    ) -> &mut Self {
        self.start_call_raw(CallType::CallCode as u8, from, to, input, gas, value)
    }

    fn start_call_raw(
        &mut self,
        typ: u8,
        from: Address,
        to: Address,
        input: Vec<u8>,
        gas: u64,
        value: U256,
    ) -> &mut Self {
        self.tracer
            .on_call_enter(self.depth, typ, from, to, &input, gas, value);
        self.depth += 1;
        self
    }

    pub fn end_call(&mut self, output: Vec<u8>, gas_used: u64) -> &mut Self {
        self.depth -= 1;
        self.tracer
            .on_call_exit(self.depth, &output, gas_used, None, false);
        self
    }

    pub fn end_call_failed(
        &mut self,
        output: Vec<u8>,
        gas_used: u64,
        err: &dyn std::error::Error,
        reverted: bool,
    ) -> &mut Self {
        self.depth -= 1;
        self.tracer
            .on_call_exit(self.depth, &output, gas_used, Some(err), reverted);
        self
    }

    // ========================================================================
    // State Changes
    // ========================================================================

    pub fn balance_change(
        &mut self,
        addr: Address,
        old_balance: U256,
        new_balance: U256,
        reason: pbeth::balance_change::Reason,
    ) -> &mut Self {
        self.tracer
            .on_balance_change(addr, old_balance, new_balance, reason);
        self
    }

    pub fn nonce_change(&mut self, addr: Address, old_nonce: u64, new_nonce: u64) -> &mut Self {
        self.tracer.on_nonce_change(addr, old_nonce, new_nonce);
        self
    }

    pub fn code_change(
        &mut self,
        addr: Address,
        old_code_hash: B256,
        new_code_hash: B256,
        old_code: Vec<u8>,
        new_code: Vec<u8>,
    ) -> &mut Self {
        self.tracer
            .on_code_change(addr, old_code_hash, new_code_hash, &old_code, &new_code);
        self
    }

    pub fn storage_change(
        &mut self,
        addr: Address,
        slot: B256,
        old_value: B256,
        new_value: B256,
    ) -> &mut Self {
        self.tracer
            .on_storage_change(addr, slot, old_value, new_value);
        self
    }

    pub fn gas_change(
        &mut self,
        old_gas: u64,
        new_gas: u64,
        reason: pbeth::gas_change::Reason,
    ) -> &mut Self {
        self.tracer.on_gas_change(old_gas, new_gas, reason);
        self
    }

    // ========================================================================
    // Events & Operations
    // ========================================================================

    pub fn log(
        &mut self,
        addr: Address,
        topics: Vec<B256>,
        data: Vec<u8>,
        block_index: u32,
    ) -> &mut Self {
        self.tracer.on_log(addr, topics, &data, block_index);
        self.block_log_index += 1;
        self
    }

    pub fn opcode(&mut self, pc: u64, op: u8, gas: u64, cost: u64) -> &mut Self {
        let active_call_depth = self.depth - 1;
        self.tracer
            .on_opcode(pc, op, gas, cost, &[], active_call_depth, None);
        self
    }

    pub fn opcode_fault(
        &mut self,
        pc: u64,
        op: u8,
        gas: u64,
        cost: u64,
        err: &dyn std::error::Error,
    ) -> &mut Self {
        let active_call_depth = self.depth - 1;
        self.tracer
            .on_opcode_fault(pc, op, gas, cost, active_call_depth, err);
        self
    }

    pub fn keccak(&mut self, hash: B256, preimage: Vec<u8>) -> &mut Self {
        self.tracer.on_keccak_preimage(hash, &preimage);
        self
    }

    /// Simulates a SELFDESTRUCT opcode execution
    ///
    /// This method mimics the sequence of events when a contract self-destructs:
    /// 1. Calls OnOpcode(SELFDESTRUCT) to mark the active call as suicided
    /// 2. Calls OnCallEnter(SELFDESTRUCT) at depth+1 to set latestCallEnterSuicided flag
    /// 3. Emits SUICIDE_WITHDRAW balance change (contract balance → 0)
    /// 4. Emits SUICIDE_REFUND balance change (beneficiary receives balance)
    /// 5. Calls OnCallExit to clear the suicided flag
    ///
    /// # Arguments
    /// * `contract_addr` - Address of the contract being destroyed
    /// * `beneficiary_addr` - Address receiving the contract's balance
    /// * `contract_balance` - Current balance of the contract being transferred
    pub fn suicide(
        &mut self,
        contract_addr: Address,
        beneficiary_addr: Address,
        contract_balance: U256,
    ) -> &mut Self {
        // Step 1: Call OnOpcode(SELFDESTRUCT) - marks active call as suicided and executed
        let active_call_depth = self.depth - 1; // Depth of the active call
        self.tracer
            .on_opcode(0, 0xff, 0, 0, &[], active_call_depth, None); // 0xff is SELFDESTRUCT

        // Step 2: Trigger OnCallEnter(SELFDESTRUCT) at depth = active_call_depth + 1
        // This sets latestCallEnterSuicided flag
        let selfdestruct_depth = active_call_depth + 1;
        self.tracer.on_call_enter(
            selfdestruct_depth,
            0xff, // CallTypeSelfDestruct
            contract_addr,
            beneficiary_addr,
            &[],
            0,
            contract_balance,
        );

        // Step 3: Apply balance changes in the order Ethereum emits them
        // 1. SUICIDE_WITHDRAW: Contract balance goes to 0
        self.tracer.on_balance_change(
            contract_addr,
            contract_balance,
            U256::ZERO,
            pbeth::balance_change::Reason::SuicideWithdraw,
        );

        // 2. SUICIDE_REFUND: Beneficiary receives the balance
        let beneficiary_old_balance = if contract_addr == beneficiary_addr {
            // Special case: suicide to self (balance was just zeroed)
            U256::ZERO
        } else {
            // Normal case: assume beneficiary starts at 0 for simplicity
            U256::ZERO
        };

        self.tracer.on_balance_change(
            beneficiary_addr,
            beneficiary_old_balance,
            beneficiary_old_balance + contract_balance,
            pbeth::balance_change::Reason::SuicideRefund,
        );

        // Step 4: Call OnCallExit for SELFDESTRUCT at the same depth as OnCallEnter
        // This clears the latestCallEnterSuicided flag
        self.tracer
            .on_call_exit(selfdestruct_depth, &[], 0, None, false);

        self
    }

    // ========================================================================
    // System Calls
    // ========================================================================

    pub fn start_system_call(&mut self) -> &mut Self {
        self.tracer.on_system_call_start();
        self
    }

    pub fn end_system_call(&mut self) -> &mut Self {
        self.tracer.on_system_call_end();
        self
    }

    pub fn system_call(
        &mut self,
        from: Address,
        to: Address,
        input: Vec<u8>,
        gas: u64,
        output: Vec<u8>,
        gas_used: u64,
    ) -> &mut Self {
        self.tracer.on_system_call_start();
        self.tracer
            .on_call_enter(0, CallType::Call as u8, from, to, &input, gas, U256::ZERO);
        self.tracer.on_call_exit(0, &output, gas_used, None, false);
        self.tracer.on_system_call_end();
        self
    }

    // ========================================================================
    // Validation
    // ========================================================================

    pub fn validate<F>(&self, validate_func: F)
    where
        F: FnOnce(&pbeth::Block),
    {
        let block = self.parse_firehose_block();
        validate_func(&block);
    }

    pub fn validate_with_category<F>(&self, _category: &str, validate_func: F)
    where
        F: FnOnce(&pbeth::Block),
    {
        let block = self.parse_firehose_block();
        validate_func(&block);
    }

    /// Validate a block with custom BlockEvent (for testing specific block header fields)
    pub fn validate_with_custom_block<F>(
        &mut self,
        block_event: firehose::BlockEvent,
        validate_func: F,
    ) -> &mut Self
    where
        F: FnOnce(&pbeth::Block),
    {
        self.tracer.on_block_start(block_event);
        self.tracer.on_block_end(None);
        let block = self.parse_firehose_block();
        validate_func(&block);
        self
    }

    fn parse_firehose_block(&self) -> pbeth::Block {
        let output = self.output_buffer.get_bytes();
        let reader = BufReader::new(&output[..]);

        for line in reader.lines() {
            let line = line.expect("Failed to read line");
            if line.starts_with("FIRE BLOCK ") {
                // Format: FIRE BLOCK {num} {hash} {prev_num} {prev_hash} {lib_num} {timestamp} {base64}
                // Parts: [0]FIRE [1]BLOCK [2]num [3]hash [4]prev_num [5]prev_hash [6]lib_num [7]timestamp [8]base64
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 9 {
                    // The base64 protobuf is at index 8 (everything after the timestamp)
                    // We need to rejoin all parts from index 8 onwards in case the base64 contains whitespace
                    let base64_data = parts[8..].join(" ");
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(&base64_data)
                        .expect(&format!(
                            "Failed to decode base64 (len={}, data={})",
                            base64_data.len(),
                            &base64_data[..base64_data.len().min(100)]
                        ));
                    return pbeth::Block::decode(&decoded[..]).expect("Failed to decode protobuf");
                }
            }
        }

        panic!("No FIRE BLOCK found in output");
    }

    /// Parse all FIRE BLOCK lines from output buffer (for testing multiple blocks)
    pub fn parse_firehose_blocks(&self) -> Vec<pbeth::Block> {
        let output = self.output_buffer.get_bytes();
        let reader = BufReader::new(&output[..]);
        let mut blocks = Vec::new();

        for line in reader.lines() {
            let line = line.expect("Failed to read line");
            if line.starts_with("FIRE BLOCK ") {
                // Format: FIRE BLOCK {num} {hash} {prev_num} {prev_hash} {lib_num} {timestamp} {base64}
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 9 {
                    let base64_data = parts[8..].join(" ");
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(&base64_data)
                        .expect(&format!("Failed to decode base64"));
                    let block =
                        pbeth::Block::decode(&decoded[..]).expect("Failed to decode protobuf");
                    blocks.push(block);
                }
            }
        }

        blocks
    }

    /// Helper method to create a skipped block with default values
    pub fn skipped_block(&mut self, block_number: u64) -> &mut Self {
        use alloy_primitives::{Bloom, Bytes, B256, U256};
        use firehose::{BlockData, BlockEvent};
        use std::str::FromStr;

        let block_data = BlockData {
            number: block_number,
            hash: B256::from_str(
                "0xe74fcc728df762055c71a999736bb89dd47c541807c3021a1b94de6761afaf25",
            )
            .unwrap(),
            parent_hash: B256::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000063",
            )
            .unwrap(),
            uncle_hash: B256::ZERO,
            coinbase: miner_addr(),
            root: B256::ZERO,
            tx_hash: B256::ZERO,
            receipt_hash: B256::ZERO,
            bloom: Bloom::ZERO,
            difficulty: U256::ZERO,
            gas_limit: 30_000_000,
            gas_used: 0,
            time: 1704067200,
            extra: Bytes::new(),
            mix_digest: B256::ZERO,
            nonce: 0,
            base_fee: Some(U256::ZERO),
            uncles: vec![],
            size: 509,
            withdrawals: vec![],
            is_merge: true,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_root: None,
            requests_hash: None,
            tx_dependency: None,
        };

        let block_event = BlockEvent {
            block: block_data,
            finalized: None,
        };

        self.tracer.on_skipped_block(block_event);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracer_tester_creation() {
        let tester = TracerTester::new();
        assert_eq!(tester.depth, 0);
        assert_eq!(tester.block_log_index, 0);
    }

    #[test]
    fn test_test_block() {
        let block = test_block();
        assert_eq!(block.block.number, 100);
        assert_eq!(block.block.gas_limit, 30_000_000);
    }

    #[test]
    fn test_test_legacy_trx() {
        let trx = test_legacy_trx();
        assert_eq!(trx.tx_type, 0);
        assert_eq!(trx.from, alice_addr());
        assert_eq!(trx.to, Some(bob_addr()));
    }
}
