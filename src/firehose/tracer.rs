use alloy_consensus::{Transaction, TxType};
use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{Address, B256, Signature, U256};
use reth::primitives::TransactionSigned;

use super::{Config, HexView, finality::FinalityStatus, mapper, ordinal::Ordinal, printer};
use crate::firehose::PROTOCOL_VERSION;
use crate::pb::sf::ethereum::r#type::v2::{Block, TransactionTrace, transaction_trace};
use crate::{firehose_debug, firehose_info, prelude::*};
use std::sync::Arc;

pub struct Tracer<Node: FullNodeComponents> {
    pub config: Config,
    pub(super) chain_spec: Option<Arc<ChainSpec<Node>>>,

    // Block state
    pub(super) current_block: Option<Block>,
    block_ordinal: Ordinal,
    finality_status: FinalityStatus,
    block_is_genesis: bool,

    // Transaction state
    current_transaction: Option<TransactionTrace>,
    transaction_log_index: u32,
    in_system_call: bool,

    _phantom: std::marker::PhantomData<Node>,
}

impl<Node: FullNodeComponents> Tracer<Node> {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            chain_spec: None,
            current_block: None,
            block_ordinal: Ordinal::default(),
            finality_status: FinalityStatus::default(),
            block_is_genesis: false,
            current_transaction: None,
            transaction_log_index: 0,
            in_system_call: false,
            _phantom: std::marker::PhantomData,
        }
    }

    /// on_init initializes the tracer with chain configuration
    pub fn on_init(&mut self, spec: Arc<ChainSpec<Node>>) {
        self.chain_spec = Some(spec.clone());

        // Print Firehose init message to stdout
        printer::firehose_init_to_stdout(PROTOCOL_VERSION, "reth-firehose-tracer");

        info!(
            "Firehose tracer initialized: chain_id={}, protocol_version={}",
            spec.chain().id(),
            PROTOCOL_VERSION,
        );
    }

    /// on_genesis_block processes the genesis block and its state allocation
    pub fn on_genesis_block(&mut self, genesis: &Genesis) {
        self.ensure_not_in_block();
        self.ensure_init();

        // Set flag to indicate this is a genesis block, to be reset at block end
        self.block_is_genesis = true;

        // Get genesis hash from chain spec
        let chain_spec = self
            .chain_spec
            .as_ref()
            .expect("chain_spec is set after ensure_init");
        let genesis_hash = chain_spec.genesis_hash();

        firehose_info!(
            "genesis block (number={} hash={}, accounts={})",
            genesis.number.unwrap_or(0),
            HexView(genesis_hash),
            genesis.alloc.len()
        );

        let pb_block =
            mapper::block_header_to_protobuf(genesis_hash, chain_spec.genesis_header(), 0, vec![]);
        self.on_block_start_inner(pb_block);
        self.on_tx_start_inner(
            &TransactionSigned::new,
            B256::ZERO,
            Address::ZERO,
            Address::ZERO,
        );

        for (address, account) in &genesis.alloc {
            self.on_genesis_account_allocation(address, account);
        }

        firehose_info!(
            "completed processing genesis allocation with {} accounts",
            genesis.alloc.len()
        );
    }

    /// on_genesis_account_allocation processes a single account allocation in genesis
    /// This ports the behavior from Go's OnGenesisBlock where it processes each account
    fn on_genesis_account_allocation(&mut self, address: &Address, account: &GenesisAccount) {
        // TODO: Port from Go - need to add account balance change, nonce change, and code deployment
        // Go code does:
        // - Add balance change if balance > 0
        // - Add nonce change if nonce > 0
        // - Add code change if code is present
        // - Add storage changes if storage is present

        // Log account allocation for debugging
        firehose_debug!(
            "genesis account allocation: address={} balance={} nonce={} has_code={} storage_entries={}",
            HexView(address.as_slice()),
            account.balance,
            account.nonce.unwrap_or(0),
            account.code.is_some(),
            account.storage.as_ref().map(|s| s.len()).unwrap_or(0)
        );

        // Balance allocation
        if account.balance > U256::ZERO {
            // TODO: Add balance change tracking
        }

        // Nonce allocation
        if let Some(nonce) = account.nonce {
            if nonce > 0 {
                // TODO: Add nonce change tracking
            }
        }

        // Code allocation
        if let Some(code) = &account.code {
            if !code.is_empty() {
                // TODO: Add code change tracking
            }
        }

        // Storage allocation
        if let Some(storage) = &account.storage {
            for (_key, value) in storage {
                if value != &B256::ZERO {
                    // TODO: Add storage change tracking
                }
            }
        }
    }

    /// on_block_start prepares for block processing a new block altogether
    pub fn on_block_start(&mut self, block: &RecoveredBlock<Node>) {
        self.ensure_init();

        let pb_block = mapper::recovered_block_to_protobuf::<Node>(block);
        self.on_block_start_inner(pb_block);
    }

    /// on_block_start_inner contains the common block start logic used by both
    /// normal block processing and genesis block processing
    fn on_block_start_inner(&mut self, pb_block: Block) {
        self.current_block = Some(pb_block);
        self.block_ordinal.reset();
        self.finality_status.populate_from_chain(None);

        // Reset transaction state for new block
        self.reset_transaction();

        let block = self.current_block.as_ref().expect("current_block is set");

        debug!(
            "Processing block: number={}, hash={}",
            block.number,
            HexView(&block.hash),
        );
    }

    /// on_block_end finalizes block processing and outputs to stdout
    pub fn on_block_end(&mut self) {
        self.ensure_in_block();

        let current: Option<Block> = self.current_block.take();

        if let Some(block) = current {
            printer::firehose_block_to_stdout(block, self.finality_status);
        }

        // Reset block state
        self.reset_block();
    }

    /// reset_block resets the block state only, do not reset transaction or call state
    /// Ported from Go resetBlock() method
    pub fn reset_block(&mut self) {
        firehose_debug!("resetting block state");

        self.current_block = None;
        self.block_ordinal.reset();
        self.finality_status.reset();
        self.block_is_genesis = false;

        // TODO: Add other block state resets when implemented:
        // - block_base_fee reset
        // - block_is_precompiled_addr reset
        // - block_rules reset
    }

    /// reset_transaction resets the transaction state and the call state in one shot
    /// Ported from Go resetTransaction() method
    pub fn reset_transaction(&mut self) {
        firehose_debug!("resetting transaction state");

        // Reset transaction state
        self.current_transaction = None;
        self.transaction_log_index = 0;
        self.in_system_call = false;

        // TODO: Add other transaction state resets when implemented:
        // - evm reset

        // TODO: Add call state resets when implemented:
        // - call_stack.reset()
        // - latest_call_enter_suicided reset
        // - deferred_call_state.reset()
    }

    /// on_tx_start_inner is used internally in two places, in the normal "tracer" and in the "OnGenesisBlock",
    /// we manually pass some override to the `tx` because genesis block has a different way of creating
    /// the transaction that wraps the genesis block.
    /// Ported from Go onTxStart() method
    pub fn on_tx_start_inner<T>(
        &mut self,
        tx: &TransactionSigned,
        hash: B256,
        from: Address,
        to: Address,
    ) {
        firehose_debug!(
            "tx start inner (hash={} from={} to={})",
            HexView(hash.as_slice()),
            HexView(from.as_slice()),
            HexView(to.as_slice())
        );

        let signature = tx.signature();

        let trx = TransactionTrace {
            begin_ordinal: self.block_ordinal.next(),
            hash: hash.to_vec(),
            from: from.to_vec(),
            to: to.to_vec(),
            nonce: tx.nonce(),
            gas_limit: tx.gas_limit(),
            gas_price: self.create_gas_price_big_int(tx),
            value: self.create_big_int_from_u256(tx.value()),
            input: tx.input().to_vec(),
            v: vec![27 + signature.v() as u8],
            r: signature.r().to_be_bytes_vec(),
            s: signature.s().to_be_bytes_vec(),
            r#type: self.transaction_type_from_tx_type(tx.tx_type()) as i32,
            access_list: self.create_access_list(tx),
            max_fee_per_gas: self.create_max_fee_per_gas(tx),
            max_priority_fee_per_gas: self.create_max_priority_fee_per_gas(tx),

            // Initialize with defaults - these will be set by other methods
            index: 0,
            gas_used: 0,
            status: 0,
            receipt: None,
            calls: Vec::new(),
            return_data: Vec::new(),
            public_key: Vec::new(),
            end_ordinal: 0,

            // Optional fields that depend on transaction type
            blob_gas: self.create_blob_gas(tx),
            blob_gas_fee_cap: self.create_blob_gas_fee_cap(tx),
            blob_hashes: self.create_blob_hashes(tx),
            set_code_authorizations: self.create_set_code_authorizations(tx),
        };

        self.current_transaction = Some(trx);
    }
}

// Helper functions for transaction creation
impl<Node: FullNodeComponents> Tracer<Node> {
    fn create_gas_price_big_int<T>(
        &self,
        _tx: &T,
    ) -> Option<crate::pb::sf::ethereum::r#type::v2::BigInt>
    where
        T: Transaction,
    {
        // TODO: Implement gas price calculation similar to Go gasPrice() function
        // This should handle different transaction types and base fee calculation
        None
    }

    fn create_big_int_from_u256(
        &self,
        value: U256,
    ) -> Option<crate::pb::sf::ethereum::r#type::v2::BigInt> {
        Some(crate::pb::sf::ethereum::r#type::v2::BigInt {
            bytes: value.to_be_bytes_vec(),
        })
    }

    fn transaction_type_from_tx_type(&self, tx_type: TxType) -> transaction_trace::Type {
        match tx_type {
            TxType::Legacy => transaction_trace::Type::TrxTypeLegacy,
            TxType::Eip2930 => transaction_trace::Type::TrxTypeAccessList,
            TxType::Eip1559 => transaction_trace::Type::TrxTypeDynamicFee,
            TxType::Eip4844 => transaction_trace::Type::TrxTypeBlob,
            TxType::Eip7702 => transaction_trace::Type::TrxTypeSetCode,
        }
    }

    fn create_access_list<T>(
        &self,
        _tx: &T,
    ) -> Vec<crate::pb::sf::ethereum::r#type::v2::AccessTuple>
    where
        T: Transaction,
    {
        // TODO: Implement access list conversion from Reth transaction to protobuf
        Vec::new()
    }

    fn create_max_fee_per_gas<T>(
        &self,
        _tx: &T,
    ) -> Option<crate::pb::sf::ethereum::r#type::v2::BigInt>
    where
        T: Transaction,
    {
        // TODO: Implement max_fee_per_gas extraction for EIP-1559 transactions
        None
    }

    fn create_max_priority_fee_per_gas<T>(
        &self,
        _tx: &T,
    ) -> Option<crate::pb::sf::ethereum::r#type::v2::BigInt>
    where
        T: Transaction,
    {
        // TODO: Implement max_priority_fee_per_gas extraction for EIP-1559 transactions
        None
    }

    fn create_blob_gas<T>(&self, _tx: &T) -> Option<u64>
    where
        T: Transaction,
    {
        // TODO: Implement blob gas calculation for EIP-4844 transactions
        None
    }

    fn create_blob_gas_fee_cap<T>(
        &self,
        _tx: &T,
    ) -> Option<crate::pb::sf::ethereum::r#type::v2::BigInt>
    where
        T: Transaction,
    {
        // TODO: Implement blob gas fee cap for EIP-4844 transactions
        None
    }

    fn create_blob_hashes<T>(&self, _tx: &T) -> Vec<Vec<u8>>
    where
        T: Transaction,
    {
        // TODO: Implement blob hashes extraction for EIP-4844 transactions
        Vec::new()
    }

    fn create_set_code_authorizations<T>(
        &self,
        _tx: &T,
    ) -> Vec<crate::pb::sf::ethereum::r#type::v2::SetCodeAuthorization>
    where
        T: Transaction,
    {
        // TODO: Implement set code authorizations for EIP-7702 transactions
        Vec::new()
    }
}
