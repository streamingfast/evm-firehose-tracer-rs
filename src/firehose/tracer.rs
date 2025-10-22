use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Transaction, TxLegacy, TxType};
use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{Address, B256, Bytes, Log as AlloyLog, Signature, U256};
use reth::primitives::TransactionSigned;
use reth::primitives::transaction::SignedTransaction;
use reth::revm::revm::inspector::JournalExt;
use reth::revm::revm::interpreter::interpreter_types::Jumps;

use super::{Config, HexView, finality::FinalityStatus, mapper, ordinal::Ordinal, printer};
use crate::firehose::PROTOCOL_VERSION;
use crate::pb::sf::ethereum::r#type::v2::{Block, Call, TransactionTrace, transaction_trace};
use crate::prelude::SignedTx;
use crate::{firehose_debug, firehose_info, prelude::*};
use reth::core::primitives::Receipt;
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
    pub(super) current_transaction: Option<TransactionTrace>,
    transaction_log_index: u32,
    in_system_call: bool,
    previous_cumulative_gas_used: u64,

    // Call stack tracking
    call_stack: Vec<Call>,

    // Journal tracking for state changes
    last_journal_len: usize,

    // Opcode tracking for gas changes
    last_opcode: Option<u8>,
    last_gas_before_opcode: Option<u64>,

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
            previous_cumulative_gas_used: 0,
            call_stack: Vec::new(),
            last_journal_len: 0,
            last_opcode: None,
            last_gas_before_opcode: None,
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

        // Create a dummy legacy transaction to wrap genesis state allocation
        let genesis_tx = TransactionSigned::new_unhashed(
            TxLegacy::default().into(),
            Signature::test_signature(),
        );

        self.on_tx_start_inner(&genesis_tx, B256::ZERO, Address::ZERO, Address::ZERO);

        for (address, account) in &genesis.alloc {
            self.on_genesis_account_allocation(address, account);
        }

        // End the genesis transaction with a dummy receipt
        // Genesis transactions don't have real receipts, so we create a successful one
        let dummy_receipt = reth::primitives::Receipt {
            tx_type: alloy_consensus::TxType::Legacy,
            success: true,
            cumulative_gas_used: 0,
            logs: Vec::new(),
        };
        self.on_tx_end(&dummy_receipt);

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
        self.previous_cumulative_gas_used = 0;

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

        // Reset call stack
        self.call_stack.clear();

        // TODO: Add other transaction state resets when implemented:
        // - evm reset
        // - latest_call_enter_suicided reset
        // - deferred_call_state.reset()
    }

    /// on_tx_end finalizes the current transaction and adds it to the block
    pub fn on_tx_end<R>(&mut self, receipt: &R)
    where
        R: Receipt,
    {
        self.ensure_in_block();
        self.ensure_in_transaction();

        firehose_debug!("ending transaction");

        if let Some(mut trx) = self.current_transaction.take() {
            // Map receipt to protobuf
            trx.receipt = Some(mapper::receipt_to_protobuf(receipt));

            // Set transaction status 1: success, 0: failure
            trx.status = if receipt.status() { 1 } else { 0 };

            // Calculate gas used by transaction
            let cumulative_gas_used = receipt.cumulative_gas_used();
            trx.gas_used = cumulative_gas_used - self.previous_cumulative_gas_used;

            // Update gas for next transaction
            self.previous_cumulative_gas_used = cumulative_gas_used;

            trx.calls = std::mem::take(&mut self.call_stack);

            self.add_post_execution_state_changes(&mut trx);
            self.add_miner_reward(&mut trx);

            if let Some(root_call) = trx.calls.first() {
                trx.return_data = root_call.return_data.clone();
            }

            trx.end_ordinal = self.block_ordinal.next();

            // Get the current block and add the transaction to it
            if let Some(block) = &mut self.current_block {
                // Set the transaction index based on current count
                trx.index = block.transaction_traces.len() as u32;

                firehose_debug!(
                    "adding transaction to block (index={} hash={} status={} gas_used={} calls={})",
                    trx.index,
                    HexView(&trx.hash),
                    trx.status,
                    trx.gas_used,
                    trx.calls.len()
                );

                block.transaction_traces.push(trx);
            }
        }

        self.reset_transaction();
        firehose_debug!("transaction ended");
    }

    /// on_tx_start starts tracing a transaction from a signed transaction
    ///
    /// TODO Not sure what we should do here for other chains
    pub fn on_tx_start(&mut self, tx: &SignedTx<Node>)
    where
        SignedTx<Node>: SignedTransaction + Transaction + SignerRecoverable,
    {
        let hash = *tx.tx_hash();
        let from = tx.recover_signer().unwrap_or_default();
        let to = tx.to().unwrap_or_default();

        // We need to work with TransactionSigned for the inner implementation
        let tx_ref = unsafe { &*(tx as *const SignedTx<Node> as *const TransactionSigned) };
        self.on_tx_start_inner(tx_ref, hash, from, to);
    }

    /// on_tx_start_inner is used internally in two places, in the normal "tracer" and in the "OnGenesisBlock",
    /// we manually pass some override to the `tx` because genesis block has a different way of creating
    /// the transaction that wraps the genesis block.
    /// Ported from Go onTxStart() method
    pub fn on_tx_start_inner(
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

        // Public key recovery is not needed for Firehose 3.0
        let public_key = Vec::new();

        let trx = TransactionTrace {
            begin_ordinal: self.block_ordinal.next(),
            hash: hash.to_vec(),
            from: from.to_vec(),
            to: to.to_vec(),
            nonce: tx.nonce(),
            gas_limit: tx.gas_limit(),
            gas_price: self.create_gas_price_big_int(tx),
            value: if tx.value() > U256::ZERO {
                self.create_big_int_from_u256(tx.value())
            } else {
                None
            },
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
            public_key,
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
    /// Recover public key from transaction signature (unused in Firehose 3.0)
    #[allow(dead_code)]
    fn recover_public_key(
        &self,
        tx: &TransactionSigned,
        signature: &Signature,
        hash: B256,
    ) -> Vec<u8> {
        use alloy_consensus::transaction::SignableTransaction;

        // Get the signature hash for this transaction
        let sig_hash = tx.signature_hash();

        // Try to recover the public key
        match signature.recover_from_prehash(&sig_hash) {
            Ok(public_key) => {
                // Return the 64-byte uncompressed public key (without the 0x04 prefix)
                public_key.to_sec1_bytes()[1..].to_vec()
            }
            Err(_) => {
                firehose_debug!(
                    "failed to recover public key for transaction {}",
                    HexView(hash.as_slice())
                );
                Vec::new()
            }
        }
    }

    fn create_gas_price_big_int<T>(
        &self,
        tx: &T,
    ) -> Option<crate::pb::sf::ethereum::r#type::v2::BigInt>
    where
        T: Transaction,
    {
        // For legacy transactions, use gas_price directly
        // For EIP-1559+, this should be effective_gas_price = base_fee + min(max_priority_fee, max_fee - base_fee)
        if let Some(price) = tx.gas_price() {
            return Some(crate::pb::sf::ethereum::r#type::v2::BigInt {
                bytes: mapper::u256_trimmed_be_bytes(U256::from(price)),
            });
        }
        None
    }

    fn create_big_int_from_u256(
        &self,
        value: U256,
    ) -> Option<crate::pb::sf::ethereum::r#type::v2::BigInt> {
        Some(crate::pb::sf::ethereum::r#type::v2::BigInt {
            bytes: mapper::u256_trimmed_be_bytes(value),
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

// Inspector callback handlers
impl<Node: FullNodeComponents> Tracer<Node> {
    /// EVM step, called BEFORE each opcode execution
    pub fn on_step<CTX>(
        &mut self,
        interp: &mut reth::revm::revm::interpreter::Interpreter<
            reth::revm::revm::interpreter::interpreter::EthInterpreter,
        >,
        context: &mut CTX,
    ) where
        CTX: reth::revm::revm::context_interface::ContextTr,
        CTX::Journal: reth::revm::revm::inspector::JournalExt,
    {
        // Track journal for future state changes
        self.last_journal_len = context.journal_ref().journal().len();

        // Save gas BEFORE opcode executes (for gas tracking)
        if !self.call_stack.is_empty() {
            let opcode = interp.bytecode.opcode();
            use reth::revm::revm::bytecode::opcode;

            // Track opcodes that cause gas changes we need to record
            if opcode == opcode::CALLDATACOPY {
                self.last_opcode = Some(opcode);
                self.last_gas_before_opcode = Some(interp.gas.remaining());
            }
        }
    }

    /// EVM step end, called AFTER each opcode execution
    pub fn on_step_end<CTX>(
        &mut self,
        interp: &mut reth::revm::revm::interpreter::Interpreter<
            reth::revm::revm::interpreter::interpreter::EthInterpreter,
        >,
        _context: &mut CTX,
    ) where
        CTX: reth::revm::revm::context_interface::ContextTr,
    {
        // Record gas change if we tracked an opcode
        if let (Some(last_opcode), Some(old_gas)) = (self.last_opcode, self.last_gas_before_opcode)
        {
            let new_gas = interp.gas.remaining();
            let cost = old_gas.saturating_sub(new_gas);

            if cost > 0 {
                use crate::pb::sf::ethereum::r#type::v2::{GasChange, gas_change};
                use reth::revm::revm::bytecode::opcode;

                let reason = if last_opcode == opcode::CALLDATACOPY {
                    gas_change::Reason::CallDataCopy
                } else {
                    // Clear and return
                    self.last_opcode = None;
                    self.last_gas_before_opcode = None;
                    return;
                };

                // Add gas change to current call
                if let Some(root_call) = self.call_stack.last_mut() {
                    root_call.gas_changes.push(GasChange {
                        old_value: old_gas,
                        new_value: new_gas,
                        ordinal: self.block_ordinal.next(),
                        reason: reason as i32,
                    });
                }
            }

            // Clear tracking
            self.last_opcode = None;
            self.last_gas_before_opcode = None;
        }
    }

    /// CALL* operation starts
    pub fn on_call_enter(
        &mut self,
        caller: Address,
        to: Address,
        input: Bytes,
        gas_limit: u64,
        value: U256,
        call_type: i32,
    ) {
        let depth = self.call_stack.len() as u32;
        let parent_index = if depth > 0 {
            self.call_stack.len() as u32 - 1
        } else {
            0
        };

        // For root call (depth 0), we need to add transaction-level state changes
        let is_root_call = depth == 0;

        let mut call = Call {
            index: self.call_stack.len() as u32 + 1,
            parent_index,
            depth,
            call_type,
            caller: caller.to_vec(),
            address: to.to_vec(),
            value: if value > U256::ZERO {
                Some(mapper::big_int_from_u256(value))
            } else {
                None
            },
            gas_limit,
            input: input.to_vec(),
            gas_consumed: 0,
            return_data: Vec::new(),
            executed_code: !input.is_empty() || depth > 0,
            status_failed: false,
            address_delegates_to: None,
            suicide: false,
            keccak_preimages: Default::default(),
            storage_changes: Vec::new(),
            balance_changes: Vec::new(),
            nonce_changes: Vec::new(),
            logs: Vec::new(),
            code_changes: Vec::new(),
            gas_changes: Vec::new(),
            status_reverted: false,
            state_reverted: false,
            failure_reason: String::new(),
            begin_ordinal: 0,
            end_ordinal: 0,
            #[allow(deprecated)]
            account_creations: Vec::new(),
        };

        // Add transaction-level state changes for root call
        if is_root_call {
            self.populate_root_call_state_changes(&mut call, caller, to, value);
        }

        // Set begin_ordinal after state changes
        call.begin_ordinal = self.block_ordinal.next();

        // Add CALL_INITIAL_BALANCE for root call
        if is_root_call && gas_limit > 0 {
            use crate::pb::sf::ethereum::r#type::v2::{GasChange, gas_change};
            call.gas_changes.push(GasChange {
                old_value: 0,
                new_value: gas_limit,
                ordinal: self.block_ordinal.next(),
                reason: gas_change::Reason::CallInitialBalance as i32,
            });
        }

        self.call_stack.push(call);

        firehose_debug!(
            "call_enter: depth={} caller={} to={} gas={}",
            depth,
            HexView(caller.as_slice()),
            HexView(to.as_slice()),
            gas_limit
        );
    }

    // temporary
    fn calculate_intrinsic_gas(&self, input: &[u8]) -> u64 {
        let mut gas = 21000u64;
        for &byte in input {
            gas += if byte == 0 { 4 } else { 16 };
        }
        gas
    }

        // temporary
    fn calculate_tx_data_floor_gas(&self, input: &[u8]) -> Option<u64> {
        const TX_GAS: u64 = 21_000;
        const TOKENS_PER_NON_ZERO: u64 = 4;
        const COST_FLOOR_PER_TOKEN: u64 = 10;

        let zero_bytes = input.iter().filter(|&&b| b == 0).count() as u64;
        let non_zero_bytes = (input.len() as u64).saturating_sub(zero_bytes);

        let non_zero_tokens = non_zero_bytes.checked_mul(TOKENS_PER_NON_ZERO)?;
        let tokens = non_zero_tokens.checked_add(zero_bytes)?;
        let extra_cost = tokens.checked_mul(COST_FLOOR_PER_TOKEN)?;

        TX_GAS.checked_add(extra_cost)
    }

    // temporary  
    fn is_prague_active(&self) -> bool {
        true
    }

    fn populate_root_call_state_changes(
        &mut self,
        call: &mut Call,
        from: Address,
        _to: Address,
        _value: U256,
    ) {
        use crate::pb::sf::ethereum::r#type::v2::{
            BalanceChange, GasChange, NonceChange, balance_change, gas_change,
        };

        let trx = self
            .current_transaction
            .as_ref()
            .expect("transaction must be active");
        let gas_price = trx
            .gas_price
            .as_ref()
            .and_then(|gp| {
                if gp.bytes.is_empty() {
                    None
                } else {
                    Some(U256::try_from_be_slice(&gp.bytes).unwrap_or_default())
                }
            })
            .unwrap_or_default();
        let gas_limit = trx.gas_limit;

        call.gas_changes.push(GasChange {
            old_value: 0,
            new_value: gas_limit,
            ordinal: self.block_ordinal.next(),
            reason: gas_change::Reason::TxInitialBalance as i32,
        });

        let gas_cost = U256::from(gas_limit) * gas_price;
        if gas_cost > U256::ZERO {
            call.balance_changes.push(BalanceChange {
                address: from.to_vec(),
                old_value: Some(mapper::big_int_from_u256(gas_cost)),
                new_value: Some(mapper::big_int_from_u256(U256::ZERO)),
                ordinal: self.block_ordinal.next(),
                reason: balance_change::Reason::GasBuy as i32,
            });
        }

        let intrinsic_gas = self.calculate_intrinsic_gas(&call.input);
        call.gas_changes.push(GasChange {
            old_value: gas_limit,
            new_value: gas_limit - intrinsic_gas,
            ordinal: self.block_ordinal.next(),
            reason: gas_change::Reason::IntrinsicGas as i32,
        });

        call.nonce_changes.push(NonceChange {
            address: from.to_vec(),
            old_value: trx.nonce,
            new_value: trx.nonce + 1,
            ordinal: self.block_ordinal.next(),
        });
    }

    fn add_post_execution_state_changes(&mut self, trx: &mut TransactionTrace) {
        use crate::pb::sf::ethereum::r#type::v2::{
            BalanceChange, GasChange, balance_change, gas_change,
        };

        if let Some(root_call) = trx.calls.first_mut() {
            let from = Address::from_slice(&trx.from);
            let to = Address::from_slice(&root_call.address);
            let gas_price = trx
                .gas_price
                .as_ref()
                .and_then(|gp| {
                    if gp.bytes.is_empty() {
                        None
                    } else {
                        Some(U256::try_from_be_slice(&gp.bytes).unwrap_or_default())
                    }
                })
                .unwrap_or_default();

            let gas_limit = root_call.gas_limit;
            let gas_used = root_call.gas_consumed;

            if let Some(value_bigint) = &root_call.value {
                if !value_bigint.bytes.is_empty() {
                    let value = U256::try_from_be_slice(&value_bigint.bytes).unwrap_or_default();
                    if value > U256::ZERO {
                        root_call.balance_changes.push(BalanceChange {
                            address: from.to_vec(),
                            old_value: Some(mapper::big_int_from_u256(value)),
                            new_value: Some(mapper::big_int_from_u256(U256::ZERO)),
                            ordinal: self.block_ordinal.next(),
                            reason: balance_change::Reason::Transfer as i32,
                        });

                        root_call.balance_changes.push(BalanceChange {
                            address: to.to_vec(),
                            old_value: Some(mapper::big_int_from_u256(U256::ZERO)),
                            new_value: Some(mapper::big_int_from_u256(value)),
                            ordinal: self.block_ordinal.next(),
                            reason: balance_change::Reason::Transfer as i32,
                        });
                    }
                }
            }

            let is_precompiled = {
                let addr_u256 = U256::from_be_slice(to.as_slice());
                addr_u256 >= U256::from(1) && addr_u256 <= U256::from(10)
            };

            if is_precompiled && gas_used > 0 {
                root_call.gas_changes.push(GasChange {
                    old_value: gas_limit,
                    new_value: gas_limit - gas_used,
                    ordinal: self.block_ordinal.next(),
                    reason: gas_change::Reason::PrecompiledContract as i32,
                });
            }

            // Gas returned from call
            let call_gas_returned = if gas_limit > gas_used {
                gas_limit - gas_used
            } else {
                0
            };

            if call_gas_returned > 0 {
                root_call.gas_changes.push(GasChange {
                    old_value: call_gas_returned,
                    new_value: 0,
                    ordinal: self.block_ordinal.next(),
                    reason: gas_change::Reason::CallLeftOverReturned as i32,
                });
            }

            // Set endOrdinal after CALL_LEFT_OVER_RETURNED, before TX_DATA_FLOOR
            root_call.end_ordinal = self.block_ordinal.next();

            // EIP-7623: Data-heavy transactions pay the floor gas
            let mut final_gas_refund = call_gas_returned;

            if self.is_prague_active() {
                if let Some(floor_data_gas) = self.calculate_tx_data_floor_gas(&trx.input) {
                    if floor_data_gas <= trx.gas_limit {
                        let gas_used_before_floor = trx.gas_limit.saturating_sub(call_gas_returned);
                        if gas_used_before_floor < floor_data_gas {
                            let new_gas_remaining = trx.gas_limit - floor_data_gas;
                            if new_gas_remaining < final_gas_refund {
                                root_call.gas_changes.push(GasChange {
                                    old_value: final_gas_refund,
                                    new_value: new_gas_remaining,
                                    ordinal: self.block_ordinal.next(),
                                    reason: gas_change::Reason::TxDataFloor as i32,
                                });
                                final_gas_refund = new_gas_remaining;
                            }
                        }
                    }
                }
            }

            if final_gas_refund > 0 {
                let refund_value = U256::from(final_gas_refund) * gas_price;
                if refund_value > U256::ZERO {
                    root_call.balance_changes.push(BalanceChange {
                        address: from.to_vec(),
                        old_value: Some(mapper::big_int_from_u256(U256::ZERO)),
                        new_value: Some(mapper::big_int_from_u256(refund_value)),
                        ordinal: self.block_ordinal.next(),
                        reason: balance_change::Reason::GasRefund as i32,
                    });
                }

                root_call.gas_changes.push(GasChange {
                    old_value: final_gas_refund,
                    new_value: 0,
                    ordinal: self.block_ordinal.next(),
                    reason: gas_change::Reason::TxLeftOverReturned as i32,
                });
            }
        }
    }

    fn add_miner_reward(&mut self, trx: &mut TransactionTrace) {
        use crate::pb::sf::ethereum::r#type::v2::{BalanceChange, balance_change};

        if let Some(root_call) = trx.calls.first_mut() {
            let trx_gas_used = trx.gas_used;
            let gas_price = trx
                .gas_price
                .as_ref()
                .and_then(|gp| {
                    if gp.bytes.is_empty() {
                        None
                    } else {
                        Some(U256::try_from_be_slice(&gp.bytes).unwrap_or_default())
                    }
                })
                .unwrap_or_default();

            if let Some(block) = &self.current_block {
                if let Some(header) = &block.header {
                    let miner = Address::from_slice(&header.coinbase);
                    let tx_fee = U256::from(trx_gas_used) * gas_price;

                    if tx_fee > U256::ZERO {
                        root_call.balance_changes.push(BalanceChange {
                            address: miner.to_vec(),
                            old_value: Some(mapper::big_int_from_u256(U256::ZERO)),
                            new_value: Some(mapper::big_int_from_u256(tx_fee)),
                            ordinal: self.block_ordinal.next(),
                            reason: balance_change::Reason::RewardTransactionFee as i32,
                        });
                    }
                }
            }
        }
    }

    /// CALL* operation completes
    pub fn on_call_exit(&mut self, output: Bytes, gas_used: u64, success: bool) {
        if let Some(mut call) = self.call_stack.pop() {
            call.return_data = output.to_vec();
            call.gas_consumed = gas_used;
            call.status_failed = !success;

            if call.depth > 0 {
                call.end_ordinal = self.block_ordinal.next();
            }

            firehose_debug!(
                "call_exit: index={} gas_used={} success={}",
                call.index,
                gas_used,
                success
            );

            self.call_stack.push(call);
        }
    }

    /// CREATE* operation starts
    pub fn on_create_enter(
        &mut self,
        caller: Address,
        init_code: Bytes,
        gas_limit: u64,
        value: U256,
        call_type: i32,
    ) {
        let depth = self.call_stack.len() as u32;
        let parent_index = if depth > 0 {
            self.call_stack.len() as u32 - 1
        } else {
            0
        };

        let call = Call {
            index: self.call_stack.len() as u32 + 1, // Index starts from 1
            parent_index,
            depth,
            call_type,
            caller: caller.to_vec(),
            address: Vec::new(),
            value: Some(mapper::big_int_from_u256(value)),
            gas_limit,
            input: init_code.to_vec(),
            gas_consumed: 0,
            return_data: Vec::new(),
            executed_code: true,
            status_failed: false,
            address_delegates_to: None,
            suicide: false,
            keccak_preimages: Default::default(),
            storage_changes: Vec::new(),
            balance_changes: Vec::new(),
            nonce_changes: Vec::new(),
            logs: Vec::new(),
            code_changes: Vec::new(),
            gas_changes: Vec::new(),
            status_reverted: false,
            state_reverted: false,
            failure_reason: String::new(),
            begin_ordinal: self.block_ordinal.next(),
            end_ordinal: 0,
            #[allow(deprecated)]
            account_creations: Vec::new(),
        };

        self.call_stack.push(call);

        firehose_debug!(
            "create_enter: depth={} caller={} gas={}",
            depth,
            HexView(caller.as_slice()),
            gas_limit
        );
    }

    /// CREATE* operation completes
    pub fn on_create_exit(
        &mut self,
        output: Bytes,
        gas_used: u64,
        success: bool,
        created_address: Address,
    ) {
        if let Some(mut call) = self.call_stack.pop() {
            call.address = created_address.to_vec();
            call.return_data = output.to_vec();
            call.gas_consumed = gas_used;
            call.status_failed = !success;

            if call.depth > 0 {
                call.end_ordinal = self.block_ordinal.next();
            }

            firehose_debug!(
                "create_exit: index={} created={} gas_used={} success={}",
                call.index,
                HexView(created_address.as_slice()),
                gas_used,
                success
            );

            self.call_stack.push(call);
        }
    }

    /// LOG operation is executed
    pub fn on_log(&mut self, log: AlloyLog) {
        if let Some(call) = self.call_stack.last_mut() {
            let pb_log = crate::pb::sf::ethereum::r#type::v2::Log {
                address: log.address.to_vec(),
                topics: log.topics().iter().map(|t| t.to_vec()).collect(),
                data: log.data.data.to_vec(),
                index: self.transaction_log_index,
                block_index: 0, // Will be set at block level
                ordinal: self.block_ordinal.next(),
            };

            call.logs.push(pb_log);
            self.transaction_log_index += 1;

            firehose_debug!(
                "log: call_index={} log_index={} topics={}",
                call.index,
                self.transaction_log_index - 1,
                log.topics().len()
            );
        }
    }

    /// SELFDESTRUCT is executed
    pub fn on_selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        if let Some(call) = self.call_stack.last_mut() {
            call.suicide = true;

            firehose_debug!(
                "selfdestruct: contract={} target={} value={}",
                HexView(contract.as_slice()),
                HexView(target.as_slice()),
                value
            );
        }
    }
}
