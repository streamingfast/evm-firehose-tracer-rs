use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Transaction, TxLegacy, TxType};
use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{Address, B256, Bytes, Log as AlloyLog, Signature, U256};
use reth::primitives::TransactionSigned;
use reth::primitives::transaction::SignedTransaction;
use reth::revm::revm::inspector::JournalExt;
use reth::revm::revm::interpreter::interpreter_types::{Jumps, MemoryTr};

use super::{Config, HexView, finality::FinalityStatus, mapper, ordinal::Ordinal, printer};
use crate::{PROTOCOL_VERSION, SignedTx, ChainSpec, RecoveredBlock};
use pb::sf::ethereum::r#type::v2::{Block, Call, TransactionTrace, transaction_trace};
use crate::{firehose_debug, firehose_info};
use reth::api::FullNodeComponents;
use reth::chainspec::EthChainSpec;
use reth_tracing::tracing::{debug, info};
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
    block_log_index: u32,
    pub in_system_call: bool,
    previous_cumulative_gas_used: u64,

    // Call stack tracking
    pub call_stack: Vec<Call>,

    // Journal tracking for state changes
    last_journal_len: usize,

    // Opcode tracking for gas changes
    last_opcode: Option<u8>,
    last_gas_before_opcode: Option<u64>,
    pending_log_gas_change: Option<(u64, u64)>,

    // Keccak preimage tracking, stores potential preimages temporarily
    // Map of hash -> preimage, only saved to call if hash appears in event topics
    pending_keccak_preimages: std::collections::HashMap<String, Vec<u8>>,

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
            block_log_index: 0,
            in_system_call: false,
            previous_cumulative_gas_used: 0,
            call_stack: Vec::new(),
            last_journal_len: 0,
            last_opcode: None,
            last_gas_before_opcode: None,
            pending_log_gas_change: None,
            pending_keccak_preimages: std::collections::HashMap::new(),
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
        self.block_log_index = 0;
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

            // Check if root call reverted or failed to set transaction status
            let root_call_reverted = trx.calls.first()
                .map(|call| call.status_reverted)
                .unwrap_or(false);
            let root_call_failed = trx.calls.first()
                .map(|call| call.status_failed)
                .unwrap_or(false);

            // Set proper transaction status
            use crate::pb::sf::ethereum::r#type::v2::TransactionTraceStatus;
            if !receipt.status() {
                trx.status = if root_call_reverted {
                    TransactionTraceStatus::Reverted as i32
                } else {
                    TransactionTraceStatus::Failed as i32
                };
            } else {
                trx.status = TransactionTraceStatus::Succeeded as i32;
            }

            // Collect all logs from calls and add to receipt
            // According to Ethereum rules:
            // If the transaction failed (receipt.status=false), NO logs are included
            // If a sub-call reverted/failed, only that sub-call's logs (and descendants) are excluded
            if let Some(receipt_obj) = &mut trx.receipt {
                // If transaction failed, exclude ALL logs
                if !receipt.status() {
                    receipt_obj.logs = Vec::new();
                } else {
                    // Transaction succeeded - collect logs, excluding reverted/failed sub-calls
                    fn collect_logs_recursive(call: &Call, calls: &[Call], logs: &mut Vec<crate::pb::sf::ethereum::r#type::v2::Log>) {
                        // If this call reverted or failed, skip its logs and all child logs
                        if call.status_reverted || call.status_failed {
                            return;
                        }

                        // Add this call's logs
                        logs.extend(call.logs.iter().cloned());

                        // Recursively collect logs from child calls
                        for child_call in calls {
                            if child_call.parent_index == call.index {
                                collect_logs_recursive(child_call, calls, logs);
                            }
                        }
                    }

                    // Start from root call
                    if let Some(root_call) = trx.calls.first() {
                        let mut all_logs = Vec::new();
                        collect_logs_recursive(root_call, &trx.calls, &mut all_logs);
                        receipt_obj.logs = all_logs;
                    }
                }
            }

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

        // UNSAFE: This assumes SignedTx<Node> has the same memory layout as TransactionSigned
        // This works for Ethereum but may break for other chains
        // TODO: Find a safe way to do this
        let tx_ref = unsafe { &*(tx as *const SignedTx<Node> as *const TransactionSigned) };
        self.on_tx_start_inner(tx_ref, hash, from, to);
    }

    /// Starts capturing a system call
    pub fn on_system_call_start(&mut self) {
        firehose_debug!("starting system call");
        self.in_system_call = true;
        self.call_stack.clear();
    }

    /// Ends capturing a system call and adds it to the block's system_calls
    pub fn on_system_call_end(&mut self) {
        firehose_debug!("ending system call");

        if let Some(_block) = &mut self.current_block {
            // TEMPORARILY DISABLED: Move calls from the call stack to the block's system_calls
            let system_calls = std::mem::take(&mut self.call_stack);
            info!(target: "firehose:tracer", "Captured {} system calls (NOT adding to block to test)", system_calls.len());

            // TODO: Re-enable once we figure out the memory corruption issue
            // while let Some(call) = system_calls.pop() {
            //     block.system_calls.insert(0, call);
            // }

            info!(target: "firehose:tracer", "Dropping system_calls without adding them to block");
            drop(system_calls);
            info!(target: "firehose:tracer", "system_calls vec dropped successfully");
        }

        info!(target: "firehose:tracer", "Setting in_system_call = false");
        self.in_system_call = false;
        info!(target: "firehose:tracer", "Clearing call_stack");
        self.call_stack.clear();
        info!(target: "firehose:tracer", "on_system_call_end() about to return");
    }

    /// Manually create a system call entry from execution result
    /// This is needed because transact_system_call() doesn't trigger inspector hooks
    pub fn on_system_call_enter<H>(
        &mut self,
        caller: Address,
        address: Address,
        input: &[u8],
        result: &reth::revm::context::result::ResultAndState<H>,
    ) {
        use crate::pb::sf::ethereum::r#type::v2::{
            CallType, BigInt, GasChange, StorageChange, gas_change,
        };
        use reth::revm::context::result::ExecutionResult;

        // Extract gas + output + success from REVM result
        let (gas_used, output, is_success) = match &result.result {
            ExecutionResult::Success { gas_used, output, .. } => (*gas_used, output.data().to_vec(), true),
            ExecutionResult::Revert  { gas_used, output }     => (*gas_used, output.to_vec(), false),
            ExecutionResult::Halt    { gas_used, .. }         => (*gas_used, Vec::new(), false),
        };

        // We model system calls with a fixed 30M gas allowance
        let gas_limit: u64 = 30_000_000;
        let gas_left = gas_limit.saturating_sub(gas_used);

        // Build the Call, explicitly initialize ALL fields to avoid any Default issues (might change)
        let mut call = Call {
            index: 0,
            parent_index: 0,
            depth: 0,
            call_type: CallType::Call as i32,
            caller: caller.to_vec(),
            address: address.to_vec(),
            // Explicit
            address_delegates_to: None,
            value: Some(BigInt { bytes: Vec::new() }),
            gas_limit,
            gas_consumed: gas_used,
            return_data: output,
            input: input.to_vec(),
            executed_code: false,
            suicide: false,
            // Explicitl
            keccak_preimages: std::collections::HashMap::new(),
            // Explicit
            storage_changes: Vec::new(),
            // Explicitl
            balance_changes: Vec::new(),
            // Explicit
            nonce_changes: Vec::new(),
            // Explicit
            logs: Vec::new(),
            // Explicit
            code_changes: Vec::new(),
            // Explicit
            gas_changes: Vec::new(),
            status_failed: !is_success,
            status_reverted: matches!(result.result, ExecutionResult::Revert { .. }),
            failure_reason: String::new(),
            state_reverted: !is_success,
            begin_ordinal: self.block_ordinal.next(),
            end_ordinal: 0,
            // Explicit
            account_creations: Vec::new(),
        };

        call.gas_changes.push(GasChange {
            old_value: 0,
            new_value: gas_limit,
            ordinal: self.block_ordinal.next(),
            reason: gas_change::Reason::CallInitialBalance as i32,
        });

        if gas_left > 0 {
            call.gas_changes.push(GasChange {
                old_value: gas_left,
                new_value: 0,
                ordinal: self.block_ordinal.next(),
                reason: gas_change::Reason::CallLeftOverReturned as i32,
            });
        } else {
            call.gas_changes.push(GasChange {
                old_value: 0,
                new_value: 0,
                ordinal: self.block_ordinal.next(),
                reason: gas_change::Reason::CallLeftOverReturned as i32,
            });
        }

        // Extract real storage changes from result.state
        // result.state is a HashMap<Address, Account>, where Account.storage is HashMap<U256, EvmStorageSlot>
        // TODO: Fix U256 conversion - temporarily disabled to debug memory allocation bug
        // if let Some(account) = result.state.get(&address) {
        //     for (storage_key, storage_slot) in &account.storage {
        //         // Only record changes where original_value != present_value
        //         if storage_slot.is_changed() {
        //             call.storage_changes.push(StorageChange {
        //                 address: address.to_vec(),
        //                 key: Vec::new(),  // TODO
        //                 old_value: Vec::new(),  // TODO
        //                 new_value: Vec::new(),  // TODO
        //                 ordinal: self.block_ordinal.next(),
        //             });
        //         }
        //     }
        // }

        // close the call
        call.end_ordinal = self.block_ordinal.next();

        // push to the temporary stack; on_system_call_end() will flush to block.system_calls
        self.call_stack.push(call);
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
        info!(target: "firehose:tracer", "on_tx_start_inner: START");

        firehose_debug!(
            "tx start inner (hash={} from={} to={})",
            HexView(hash.as_slice()),
            HexView(from.as_slice()),
            HexView(to.as_slice())
        );

        let signature = tx.signature();

        info!(target: "firehose:tracer", "on_tx_start_inner: Creating public_key vec");
        // Public key recovery is not needed for Firehose 3.0
        let public_key = Vec::new();

        info!(target: "firehose:tracer", "on_tx_start_inner: Converting r to bytes, r={:?}", signature.r());
        let r_bytes = signature.r().to_be_bytes::<32>().to_vec();
        info!(target: "firehose:tracer", "on_tx_start_inner: r_bytes created with len={}", r_bytes.len());

        info!(target: "firehose:tracer", "on_tx_start_inner: Converting s to bytes, s={:?}", signature.s());
        let s_bytes = signature.s().to_be_bytes::<32>().to_vec();
        info!(target: "firehose:tracer", "on_tx_start_inner: s_bytes created with len={}", s_bytes.len());

        info!(target: "firehose:tracer", "on_tx_start_inner: Creating access_list");
        let access_list = self.create_access_list(tx);
        info!(target: "firehose:tracer", "on_tx_start_inner: Creating max_fee_per_gas");
        let max_fee_per_gas = self.create_max_fee_per_gas(tx);
        info!(target: "firehose:tracer", "on_tx_start_inner: Creating max_priority_fee_per_gas");
        let max_priority_fee_per_gas = self.create_max_priority_fee_per_gas(tx);

        info!(target: "firehose:tracer", "on_tx_start_inner: About to create TransactionTrace struct");

        // Pre-compute all fields to isolate which one causes the crash
        info!(target: "firehose:tracer", "Computing begin_ordinal");
        let begin_ordinal = self.block_ordinal.next();
        info!(target: "firehose:tracer", "Computing gas_price");
        let gas_price = self.create_gas_price_big_int(tx);
        info!(target: "firehose:tracer", "Computing value");
        let value = if tx.value() > U256::ZERO { self.create_big_int_from_u256(tx.value()) } else { None };
        info!(target: "firehose:tracer", "Computing blob_gas");
        let blob_gas = self.create_blob_gas(tx);
        info!(target: "firehose:tracer", "Computing blob_gas_fee_cap");
        let blob_gas_fee_cap = self.create_blob_gas_fee_cap(tx);
        info!(target: "firehose:tracer", "Computing blob_hashes");
        let blob_hashes = self.create_blob_hashes(tx);
        info!(target: "firehose:tracer", "Computing set_code_authorizations");
        let set_code_authorizations = self.create_set_code_authorizations(tx);

        info!(target: "firehose:tracer", "All fields computed, checking vector lengths");
        info!(target: "firehose:tracer", "r_bytes.len()={}, s_bytes.len()={}", r_bytes.len(), s_bytes.len());
        info!(target: "firehose:tracer", "access_list.len()={}", access_list.len());
        info!(target: "firehose:tracer", "blob_hashes.len()={}", blob_hashes.len());
        info!(target: "firehose:tracer", "set_code_authorizations.len()={}", set_code_authorizations.len());

        // Pre-compute all .to_vec() calls to isolate which one causes the crash
        info!(target: "firehose:tracer", "Converting hash to vec");
        let hash_vec = hash.to_vec();
        info!(target: "firehose:tracer", "Converting from to vec");
        let from_vec = from.to_vec();
        info!(target: "firehose:tracer", "Converting to to vec");
        let to_vec = to.to_vec();
        info!(target: "firehose:tracer", "Converting input to vec");
        let input_vec = tx.input().to_vec();
        info!(target: "firehose:tracer", "Creating v vec");
        let v_byte = 27 + signature.v() as u8;
        let v_vec = vec![v_byte];

        info!(target: "firehose:tracer", "Testing Default::default()");
        let _test = TransactionTrace::default();
        info!(target: "firehose:tracer", "Default worked, now creating actual struct");

        let trx = TransactionTrace {
            begin_ordinal,
            hash: hash_vec,
            from: from_vec,
            to: to_vec,
            nonce: tx.nonce(),
            gas_limit: tx.gas_limit(),
            gas_price,
            value,
            input: input_vec,
            v: v_vec,
            r: r_bytes,
            s: s_bytes,
            r#type: self.transaction_type_from_tx_type(tx.tx_type()) as i32,
            access_list,
            max_fee_per_gas,
            max_priority_fee_per_gas,

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
            blob_gas,
            blob_gas_fee_cap,
            blob_hashes,
            set_code_authorizations,
        };

        info!(target: "firehose:tracer", "on_tx_start_inner: TransactionTrace created, setting current_transaction");
        self.current_transaction = Some(trx);
        info!(target: "firehose:tracer", "on_tx_start_inner: COMPLETE");
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
            if opcode == opcode::CALLDATACOPY
                || opcode == opcode::CODECOPY
                || opcode == opcode::EXTCODECOPY
                || opcode == opcode::LOG0
                || opcode == opcode::LOG1
                || opcode == opcode::LOG2
                || opcode == opcode::LOG3
                || opcode == opcode::LOG4
            {
                self.last_opcode = Some(opcode);
                self.last_gas_before_opcode = Some(interp.gas.remaining());
            }

            // Track KECCAK256 to capture preimages for event topics
            if opcode == opcode::KECCAK256 {
                // Get the memory offset and size from the stack
                if let Ok(offset) = interp.stack.peek(0) {
                    if let Ok(size) = interp.stack.peek(1) {
                        let offset_usize = offset.saturating_to::<usize>();
                        let size_usize = size.saturating_to::<usize>();

                        // Read the data from memory that will be hashed
                        // Store ALL keccak preimages temporarily we'll only save the ones
                        // that appear in event topics when we process the LOG
                        if size_usize > 0 && size_usize <= 1024 * 1024 {
                            let memory = &interp.memory;
                            if offset_usize + size_usize <= memory.len() {
                                let data = memory.slice(offset_usize..offset_usize + size_usize);

                                // Calculate hash and store preimage temporarily
                                use alloy_primitives::keccak256;
                                let hash = keccak256(&*data);
                                let hash_hex = hex::encode(hash.as_slice());

                                self.pending_keccak_preimages.insert(hash_hex, (*data).to_vec());
                            }
                        }
                    }
                }
            }
        }
    }

    /// EVM step end, called AFTER each opcode execution
    pub fn on_step_end<CTX>(
        &mut self,
        interp: &mut reth::revm::revm::interpreter::Interpreter<
            reth::revm::revm::interpreter::interpreter::EthInterpreter,
        >,
        context: &mut CTX,
    ) where
        CTX: reth::revm::revm::context_interface::ContextTr,
        CTX::Journal: reth::revm::revm::inspector::JournalExt,
    {
        // Record gas change if we tracked an opcode
        if let (Some(last_opcode), Some(old_gas)) = (self.last_opcode, self.last_gas_before_opcode)
        {
            let new_gas = interp.gas.remaining();
            let cost = old_gas.saturating_sub(new_gas);

            if cost > 0 {
                use crate::pb::sf::ethereum::r#type::v2::{GasChange, gas_change};
                use reth::revm::revm::bytecode::opcode;

                let is_log_opcode = last_opcode == opcode::LOG0
                    || last_opcode == opcode::LOG1
                    || last_opcode == opcode::LOG2
                    || last_opcode == opcode::LOG3
                    || last_opcode == opcode::LOG4;

                if is_log_opcode {
                    // LOG opcodes are handled in on_log() where we have access to current gas
                    // Just keep the saved gas for on_log() to use, don't process here
                    return;
                }

                let reason = if last_opcode == opcode::CALLDATACOPY {
                    gas_change::Reason::CallDataCopy
                } else if last_opcode == opcode::CODECOPY {
                    gas_change::Reason::CodeCopy
                } else if last_opcode == opcode::EXTCODECOPY {
                    gas_change::Reason::ExtCodeCopy
                } else {
                    // Clear and return
                    self.last_opcode = None;
                    self.last_gas_before_opcode = None;
                    return;
                };

                // Add gas change to current call immediately for non-LOG opcodes
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

        // Extract state changes from journal entries added during this opcode
        self.extract_journal_entries(context);
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
        // parent_index should be the INDEX of the parent call (not stack position)
        // Root call has index=1, so first nested call has parent_index=1
        let parent_index = if depth > 0 {
            self.call_stack.last().map(|c| c.index).unwrap_or(0)
        } else {
            0
        };

        // For root call, we need to add transaction-level state changes
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

        // Add CALL_INITIAL_BALANCE for all calls (not just root)
        if gas_limit > 0 {
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
            new_value: gas_limit.saturating_sub(intrinsic_gas),
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

            // Check if transaction failed
            let tx_failed = root_call.status_failed && !root_call.status_reverted;

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
                    new_value: gas_limit.saturating_sub(gas_used),
                    ordinal: self.block_ordinal.next(),
                    reason: gas_change::Reason::PrecompiledContract as i32,
                });
            }

            // Gas returned from call or failed execution
            let call_gas_returned = gas_limit.saturating_sub(gas_used);

            if call_gas_returned > 0 {
                // For failed transactions
                let reason = if tx_failed {
                    gas_change::Reason::FailedExecution
                } else {
                    gas_change::Reason::CallLeftOverReturned
                };

                root_call.gas_changes.push(GasChange {
                    old_value: call_gas_returned,
                    new_value: 0,
                    ordinal: self.block_ordinal.next(),
                    reason: reason as i32,
                });
            }

            // Set endOrdinal after gas changes
            root_call.end_ordinal = self.block_ordinal.next();

            // Only process gas refunds for successful transactions (failed transactions consume all gas)
            if !tx_failed {
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
    pub fn on_call_exit(&mut self, output: Bytes, gas_used: u64, success: bool, is_revert: bool, failure_reason: String) {
        if let Some(mut call) = self.call_stack.pop() {
            call.return_data = output.to_vec();
            call.gas_consumed = gas_used;
            call.status_failed = !success;
            call.status_reverted = is_revert;
            // state_reverted: true when state was rolled back
            // This happens for ANY failure
            call.state_reverted = !success;

            firehose_debug!(
                "on_call_exit: success={} is_revert={} state_reverted={} status_reverted={}",
                success, is_revert, call.state_reverted, call.status_reverted
            );

            // Parse failure reason to human-readable format
            if !success {
                call.failure_reason = if is_revert {
                    // For reverts, try to decode the error message from return data
                    if output.len() >= 4 {
                        // Standard Solidity revert: Error(string)
                        "execution reverted".to_string()
                    } else {
                        "execution reverted".to_string()
                    }
                } else {
                    // Other failures
                    failure_reason
                };
            }

            // Add CALL_LEFT_OVER_RETURNED for nested calls
            if call.depth > 0 {
                let gas_left = call.gas_limit.saturating_sub(gas_used);
                if gas_left > 0 {
                    use crate::pb::sf::ethereum::r#type::v2::{GasChange, gas_change};
                    call.gas_changes.push(GasChange {
                        old_value: gas_left,
                        new_value: 0,
                        ordinal: self.block_ordinal.next(),
                        reason: gas_change::Reason::CallLeftOverReturned as i32,
                    });
                }

                call.end_ordinal = self.block_ordinal.next();
            }

            firehose_debug!(
                "call_exit: index={} gas_used={} success={} reverted={}",
                call.index,
                gas_used,
                success,
                is_revert
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
        // index of the parent call
        let parent_index = if depth > 0 {
            self.call_stack.last().map(|c| c.index).unwrap_or(0)
        } else {
            0
        };

        let call = Call {
             // Index starts at 1
            index: self.call_stack.len() as u32 + 1,
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
        is_revert: bool,
        failure_reason: String,
    ) {
        if let Some(mut call) = self.call_stack.pop() {
            call.address = created_address.to_vec();
            call.return_data = output.to_vec();
            call.gas_consumed = gas_used;
            call.status_failed = !success;
            call.status_reverted = is_revert;
            // state_reverted: true when state was rolled back (any failure)
            call.state_reverted = !success;

            if !success {
                call.failure_reason = if is_revert {
                    "execution reverted".to_string()
                } else {
                    failure_reason
                };
            }

            if call.depth > 0 {
                call.end_ordinal = self.block_ordinal.next();
            }

            firehose_debug!(
                "create_exit: index={} created={} gas_used={} success={} reverted={}",
                call.index,
                HexView(created_address.as_slice()),
                gas_used,
                success,
                is_revert
            );

            self.call_stack.push(call);
        }
    }

    /// LOG operation is executed
    pub fn on_log(&mut self, log: AlloyLog, current_gas: u64) {
        if let Some(call) = self.call_stack.last_mut() {
            // Record EVENT_LOG gas change BEFORE the log itself
            // Use the gas saved in on_step and current gas
            if let Some(old_gas) = self.last_gas_before_opcode {
                use crate::pb::sf::ethereum::r#type::v2::{GasChange, gas_change};

                let cost = old_gas.saturating_sub(current_gas);

                firehose_debug!(
                    "on_log: gas change old={} new={} cost={}",
                    old_gas,
                    current_gas,
                    cost
                );

                if cost > 0 {
                    call.gas_changes.push(GasChange {
                        old_value: old_gas,
                        new_value: current_gas,
                        ordinal: self.block_ordinal.next(),
                        reason: gas_change::Reason::EventLog as i32,
                    });
                }

                // Clear the saved gas
                self.last_gas_before_opcode = None;
                self.last_opcode = None;
            } else {
                firehose_debug!("on_log: NO saved gas before opcode!");
            }

            // save preimages to the call's keccak_preimages
            for topic in log.topics() {
                let topic_hex = hex::encode(topic.as_slice());
                if let Some(preimage) = self.pending_keccak_preimages.get(&topic_hex) {
                    call.keccak_preimages.insert(
                        topic_hex.clone(),
                        hex::encode(preimage),
                    );
                }
            }

            let pb_log = crate::pb::sf::ethereum::r#type::v2::Log {
                address: log.address.to_vec(),
                topics: log.topics().iter().map(|t| t.to_vec()).collect(),
                data: log.data.data.to_vec(),
                index: self.transaction_log_index,
                block_index: self.block_log_index,
                ordinal: self.block_ordinal.next(),
            };

            call.logs.push(pb_log);
            self.transaction_log_index += 1;
            self.block_log_index += 1;

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

    /// Extract state changes from journal entries
    fn extract_journal_entries<CTX>(&mut self, context: &mut CTX)
    where
        CTX: reth::revm::revm::context_interface::ContextTr,
        CTX::Journal: reth::revm::revm::inspector::JournalExt,
    {
        use crate::pb::sf::ethereum::r#type::v2::{BalanceChange, StorageChange, NonceChange, balance_change};
        use reth::revm::revm::context_interface::ContextTr as _;
        use reth::revm::revm::context_interface::JournalTr as _;

        // Collect journal entries to process
        let entries_to_process: Vec<_> = {
            let journal = context.journal_ref().journal();
            let current_len = journal.len();

            if current_len > self.last_journal_len {
                journal[self.last_journal_len..current_len].to_vec()
            } else {
                Vec::new()
            }
        };

        // Update journal length tracker
        let current_len = context.journal_ref().journal().len();
        self.last_journal_len = current_len;

        // Process collected entries
        if !entries_to_process.is_empty() {
            if let Some(call) = self.call_stack.last_mut() {
                for entry in entries_to_process {
                    match entry {
                        reth::revm::JournalEntry::BalanceChange { address, old_balance } => {
                            // Query current balance from state
                            let new_balance = context.balance(address)
                                .map(|load| load.data)
                                .unwrap_or(U256::ZERO);

                            call.balance_changes.push(BalanceChange {
                                address: address.to_vec(),
                                old_value: Some(mapper::big_int_from_u256(old_balance)),
                                new_value: Some(mapper::big_int_from_u256(new_balance)),
                                ordinal: self.block_ordinal.next(),
                                reason: balance_change::Reason::Transfer as i32,
                            });
                        }

                        reth::revm::JournalEntry::BalanceTransfer { balance, from, to } => {
                            // Query actual account balances
                            let from_balance = context.balance(from)
                                .map(|load| load.data)
                                .unwrap_or(U256::ZERO);
                            let to_balance = context.balance(to)
                                .map(|load| load.data)
                                .unwrap_or(U256::ZERO);

                            call.balance_changes.push(BalanceChange {
                                address: from.to_vec(),
                                old_value: Some(mapper::big_int_from_u256(from_balance + balance)),
                                new_value: Some(mapper::big_int_from_u256(from_balance)),
                                ordinal: self.block_ordinal.next(),
                                reason: balance_change::Reason::Transfer as i32,
                            });

                            call.balance_changes.push(BalanceChange {
                                address: to.to_vec(),
                                old_value: Some(mapper::big_int_from_u256(to_balance - balance)),
                                new_value: Some(mapper::big_int_from_u256(to_balance)),
                                ordinal: self.block_ordinal.next(),
                                reason: balance_change::Reason::Transfer as i32,
                            });
                        }

                        reth::revm::JournalEntry::StorageChanged { address, key, had_value } => {
                            // TODO: Fix U256 conversion - temporarily disabled to debug memory allocation bug
                            // key and had_value are U256 (StorageKey and StorageValue are type aliases)
                            // Get current value from state
                            // let current_value = context.sload(address, key)
                            //     .map(|load| load.data)
                            //     .unwrap_or(had_value);

                            // call.storage_changes.push(StorageChange {
                            //     address: address.to_vec(),
                            //     key: Vec::new(),  // TODO
                            //     old_value: Vec::new(),  // TODO
                            //     new_value: Vec::new(),  // TODO
                            //     ordinal: self.block_ordinal.next(),
                            // });
                        }

                        reth::revm::JournalEntry::NonceChange { address } => {
                            // Nonce was incremented by 1, load account to get current nonce
                            let new_nonce = context.journal_mut()
                                .load_account(address)
                                .map(|load| load.data.info.nonce)
                                .unwrap_or(0);
                            let old_nonce = new_nonce.saturating_sub(1);

                            call.nonce_changes.push(NonceChange {
                                address: address.to_vec(),
                                old_value: old_nonce,
                                new_value: new_nonce,
                                ordinal: self.block_ordinal.next(),
                            });
                        }

                        _ => {
                            // Other journal entries we may want to track later:
                            // - AccountCreated
                            // - AccountDestroyed
                            // - AccountWarmed (for gas tracking)
                            // - StorageWarmed (for gas tracking)
                            // whatever
                        }
                    }
                }
            }
        }
    }

}
