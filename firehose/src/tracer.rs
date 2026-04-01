use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};

use super::{
    callstack::CallStack,
    config,
    deferred_call_state::DeferredCallState,
    finality::FinalityStatus,
    open_callstack::{OpenCall, OpenCallStack},
    ordinal::Ordinal,
    Config,
};
use crate::types::{BlockEvent, ReceiptData, StateReader, TxEvent};
use crate::{
    firehose_debug, firehose_info, firehose_trace, utils, ChainConfig, Rules, PROTOCOL_VERSION,
};
use pb::sf::ethereum::r#type::v2::{Block, Call, TransactionTrace};

/// Tracer is the main Firehose tracer that captures EVM execution and produces
/// protobuf blocks for indexing.
///
/// Note: Parallel execution support (isolated tracer + coordinator) is excluded
/// from this Rust port as per requirements.
pub struct Tracer {
    // Global state
    output_writer: Box<dyn Write + Send>,
    init_sent: Arc<AtomicBool>,
    config: Config,
    chain_config: Option<ChainConfig>,

    // Block state
    block: Option<Block>,
    block_base_fee: Option<U256>,
    block_ordinal: Ordinal,
    block_finality: FinalityStatus,
    block_rules: Rules, // Fork rules for current block (computed once per block)
    block_is_genesis: bool,

    // Transaction state
    transaction: Option<TransactionTrace>,
    transaction_log_index: u32,
    transaction_state_reader: Option<Box<dyn StateReader + Send>>,
    in_system_call: bool,

    // Call state
    call_stack: CallStack,
    pub open_calls: OpenCallStack,
    deferred_call_state: DeferredCallState,
    latest_call_enter_suicided: bool,
    latest_call_enter_suicided_depth: i32, // Depth of the SELFDESTRUCT OnCallEnter
}

impl Tracer {
    /// Creates a new Firehose tracer with the given configuration.
    /// Output is written to stdout.
    pub fn new(config: Config) -> Self {
        Self::new_with_writer(config, Box::new(std::io::stdout()))
    }

    /// Creates a new Firehose tracer with a custom output writer.
    /// This is useful for testing where you want to capture output to a buffer.
    pub fn new_with_writer(config: Config, output_writer: Box<dyn Write + Send>) -> Self {
        Self {
            // Global state
            output_writer,
            init_sent: Arc::new(AtomicBool::new(false)),
            config,
            chain_config: None,

            // Block state
            block: None,
            block_base_fee: None,
            block_ordinal: Ordinal::default(),
            block_finality: FinalityStatus::default(),
            block_rules: Rules::default(),
            block_is_genesis: false,

            // Transaction state
            transaction: None,
            transaction_log_index: 0,
            transaction_state_reader: None,
            in_system_call: false,

            // Call state
            call_stack: CallStack::new(),
            open_calls: OpenCallStack::new(),
            deferred_call_state: DeferredCallState::new(),
            latest_call_enter_suicided: false,
            latest_call_enter_suicided_depth: 0,
        }
    }

    /// Resets the block state only (not transaction or call state)
    fn reset_block(&mut self) {
        self.block = None;
        self.block_base_fee = None;
        self.block_ordinal.reset();
        self.block_finality.reset();
        self.block_rules = Rules::default();
        self.block_is_genesis = false;
    }

    /// Resets the transaction state and call state in one shot
    fn reset_transaction(&mut self) {
        self.transaction = None;
        self.transaction_log_index = 0;
        self.transaction_state_reader = None;
        self.in_system_call = false;

        self.call_stack.reset();
        self.open_calls.reset();
        self.latest_call_enter_suicided = false;
        self.deferred_call_state.reset();
    }

    // ============================================================================
    // Lifecycle Hooks
    // ============================================================================

    /// OnBlockchainInit is called once when the blockchain is initialized
    pub fn on_blockchain_init(
        &mut self,
        node_name: &str,
        node_version: &str,
        chain_config: ChainConfig,
    ) {
        if self
            .init_sent
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            crate::printer::print_to_firehose(
                &mut self.output_writer,
                "FIRE INIT",
                PROTOCOL_VERSION,
                node_name,
                node_version,
            );
        } else {
            panic!("OnBlockchainInit was called more than once");
        }

        firehose_info!("tracer initialized (chain_id={})", chain_config.chain_id);
        self.chain_config = Some(chain_config);
    }

    /// OnGenesisBlock is called for the genesis block
    pub fn on_genesis_block(&mut self, event: BlockEvent, alloc: crate::types::GenesisAlloc) {
        if self.config.ignore_genesis_block {
            return;
        }

        firehose_info!(
            "genesis block (number={} hash={:?})",
            event.block.number,
            event.block.hash
        );
        self.ensure_blockchain_init();

        // Keep a reference to block root before moving event
        let block_root = event.block.root;

        // Going to be reset in OnBlockEnd
        self.block_is_genesis = true;

        // Start block
        self.on_block_start(event);

        // Create a synthetic transaction to hold all genesis changes
        // This matches the native tracer behavior (creating a synthetic empty transaction)
        let zero_addr = Address::ZERO;
        let zero_hash = B256::ZERO;

        let tx_event = TxEvent {
            tx_type: TxType::Legacy,
            hash: zero_hash,
            from: zero_addr,
            to: Some(zero_addr),
            input: Default::default(),
            value: U256::ZERO,
            gas: 0,
            gas_price: U256::ZERO,
            nonce: 0,
            index: 0,
            v: None,
            r: B256::ZERO,
            s: B256::ZERO,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: Vec::new(),
            blob_gas_fee_cap: None,
            blob_hashes: Vec::new(),
            set_code_authorizations: Vec::new(),
        };

        self.on_tx_start(tx_event, None);

        // Create a synthetic call to hold the changes
        // The CALL from zero address to zero address represents the genesis allocation
        self.on_call_enter(0, 0xf1, zero_addr, zero_addr, &[], 0, U256::ZERO);

        // Process genesis allocation in deterministic order (sorted by address)
        let mut sorted_addrs: Vec<_> = alloc.keys().copied().collect();
        sorted_addrs.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));

        for addr in sorted_addrs {
            if let Some(account) = alloc.get(&addr) {
                // Balance change (if non-zero)
                if let Some(balance) = &account.balance {
                    if !balance.is_zero() {
                        self.on_balance_change(
                            addr,
                            U256::ZERO,
                            *balance,
                            pb::sf::ethereum::r#type::v2::balance_change::Reason::GenesisBalance,
                        );
                    }
                }

                // Code change (if code exists)
                if let Some(code) = &account.code {
                    if !code.is_empty() {
                        let code_hash = utils::hash_bytes(code);
                        self.on_code_change(addr, B256::ZERO, code_hash, &[], code);
                    }
                }

                // Nonce change (if non-zero)
                if account.nonce > 0 {
                    self.on_nonce_change(addr, 0, account.nonce);
                }

                // Storage changes (sorted by key for determinism)
                let mut sorted_keys: Vec<_> = account.storage.keys().copied().collect();
                sorted_keys.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));

                for key in sorted_keys {
                    if let Some(value) = account.storage.get(&key) {
                        self.on_storage_change(addr, key, B256::ZERO, *value);
                    }
                }
            }
        }

        // End the synthetic call (output=empty, gasUsed=0, err=None, reverted=false)
        self.on_call_exit(0, &[], 0, None, false);

        // End the synthetic transaction with a successful receipt
        let receipt = ReceiptData {
            transaction_index: 0,
            gas_used: 0,
            status: 1, // Success
            logs: Vec::new(),
            logs_bloom: [0u8; 256],
            cumulative_gas_used: 0,
            blob_gas_used: 0,
            blob_gas_price: None,
            state_root: Some(block_root.0.to_vec().into()),
        };

        self.on_tx_end(Some(&receipt), None);

        // End the block
        self.on_block_end(None);
    }

    /// OnBlockStart is called at the beginning of block processing
    pub fn on_block_start(&mut self, event: BlockEvent) {
        self.ensure_blockchain_init();

        let block_data = &event.block;

        // Compute block rules for this block (block-scoped fork flags)
        self.block_rules = self.chain_config.as_ref().unwrap().rules(
            block_data.number,
            block_data.is_merge(),
            block_data.time,
        );

        firehose_info!(
            "block start (number={} hash={:?})",
            block_data.number,
            block_data.hash
        );

        // Create protobuf block
        self.block = Some(Block {
            hash: block_data.hash.0.to_vec(),
            number: block_data.number,
            header: Some(self.new_block_header_from_block_data(&event.block)),
            ver: 5, // Protocol version 5
            size: block_data.size,
            ..Default::default()
        });

        // Add uncles
        let uncle_headers: Vec<_> = block_data
            .uncles
            .iter()
            .map(|uncle| self.new_block_header_from_uncle_data(uncle))
            .collect();

        if let Some(block) = &mut self.block {
            block.uncles.extend(uncle_headers);
        }

        // Set base fee
        if let Some(base_fee) = block_data.base_fee {
            self.block_base_fee = Some(base_fee);
        }

        // Note: Block withdrawals (EIP-4895) are always recorded in v5 when present.
        // The protobuf Block does not yet have a withdrawals array field in this Rust version.
        // Withdrawals root hash is set in the block header (see new_block_header_from_block_data).

        // Populate finality status
        if let Some(finalized) = event.finalized {
            self.block_finality
                .set_last_finalized_block(finalized.number);
        }
    }

    /// OnBlockEnd is called at the end of block processing
    pub fn on_block_end(&mut self, err: Option<&dyn std::error::Error>) {
        firehose_info!("block ending (err={:?})", err);

        if err.is_none() {
            // Validate state: Must be in block and not in transaction
            self.ensure_in_block_and_not_in_trx();

            // Flush block to firehose
            if let Some(block) = self.block.take() {
                crate::printer::print_block_to_firehose(
                    &mut self.output_writer,
                    block,
                    &self.block_finality,
                );
            }
        } else {
            // An error occurred, could have happened in transaction/call context
            // We must not check if in trx/call, only check in block
            self.ensure_in_block();
        }

        self.reset_block();
        self.reset_transaction();

        firehose_info!("block end");
    }

    /// OnSkippedBlock is called for blocks that are skipped
    pub fn on_skipped_block(&mut self, event: BlockEvent) {
        // Validate we're not in a transaction (skipped blocks should never have transactions)
        if self.transaction.is_some() {
            panic!(
                "OnSkippedBlock called while in transaction state - skipped blocks must have 0 transactions"
            );
        }

        // Trace the block as normal, the Firehose system will discard it if needed
        self.on_block_start(event);
        self.on_block_end(None);
    }

    /// OnClose is called when the tracer is being shut down
    pub fn on_close(&mut self) {
        // No concurrent flush queue in this version, nothing to clean up
    }

    // ============================================================================
    // Transaction Lifecycle Hooks
    // ============================================================================

    /// OnTxStart is called at the beginning of transaction execution
    pub fn on_tx_start(
        &mut self,
        event: TxEvent,
        state_reader: Option<Box<dyn StateReader + Send>>,
    ) {
        firehose_info!("trx start (hash={:?} type={})", event.hash, event.tx_type);

        // Validate state: Must be in block, not in transaction, not in call
        self.ensure_in_block_and_not_in_trx_and_not_in_call();

        // Store state reader for this transaction
        self.transaction_state_reader = state_reader;

        // Convert transaction type to protobuf enum
        use pb::sf::ethereum::r#type::v2::transaction_trace::Type;
        let tx_type = match TxType::try_from(event.tx_type) {
            Ok(TxType::Legacy) => Type::TrxTypeLegacy as i32,
            Ok(TxType::AccessList) => Type::TrxTypeAccessList as i32,
            Ok(TxType::DynamicFee) => Type::TrxTypeDynamicFee as i32,
            Ok(TxType::Blob) => Type::TrxTypeBlob as i32,
            Ok(TxType::SetCode) => Type::TrxTypeSetCode as i32,
            _ => Type::TrxTypeLegacy as i32, // Default to legacy for unknown types
        };

        // Convert access list to protobuf format
        let access_list = event
            .access_list
            .iter()
            .map(|tuple| pb::sf::ethereum::r#type::v2::AccessTuple {
                address: tuple.address.0.to_vec(),
                storage_keys: tuple
                    .storage_keys
                    .iter()
                    .map(|key| key.0.to_vec())
                    .collect(),
            })
            .collect();

        // Convert set code authorizations to protobuf format
        let set_code_authorizations = event
            .set_code_authorizations
            .iter()
            .map(|auth| {
                // Trim leading zeros from chain_id (matches Go's big.Int.Bytes() behavior)
                let chain_id_u256 = U256::from_be_bytes(auth.chain_id.0);
                let chain_id_bytes = chain_id_u256.to_be_bytes_trimmed_vec();

                // Recover authority (signer address) from signature
                let authority = crate::eip7702::recover_authority(
                    auth.chain_id,
                    auth.address,
                    auth.nonce,
                    auth.v,
                    auth.r,
                    auth.s,
                )
                .map(|addr| addr.0.to_vec());

                pb::sf::ethereum::r#type::v2::SetCodeAuthorization {
                    chain_id: chain_id_bytes,
                    address: auth.address.0.to_vec(),
                    nonce: auth.nonce,
                    v: auth.v,
                    r: utils::normalize_signature_point(&auth.r.0).unwrap_or_default(),
                    s: utils::normalize_signature_point(&auth.s.0).unwrap_or_default(),
                    authority,
                    ..Default::default() // discarded will be set during validation
                }
            })
            .collect();

        // Convert blob hashes to protobuf format
        let blob_hashes = event
            .blob_hashes
            .iter()
            .map(|hash| hash.0.to_vec())
            .collect();

        // Compute effective gas price based on transaction type
        let effective_gas_price = compute_effective_gas_price(&event, self.block_base_fee);

        // Detect genesis synthetic transaction (hash=0, from=0, to=Some(0))
        // Genesis transactions have nil gas_price and value in protobuf (matching Golang)
        let is_genesis = self.block_is_genesis
            && event.hash == B256::ZERO
            && event.from == Address::ZERO
            && event.to == Some(Address::ZERO);

        // Create transaction trace (will be filled in as execution proceeds)
        let trx = TransactionTrace {
            begin_ordinal: self.block_ordinal.next(),
            r#type: tx_type,
            hash: event.hash.0.to_vec(),
            from: event.from.0.to_vec(),
            to: event.to.map(|a| a.0.to_vec()).unwrap_or_default(),
            nonce: event.nonce,
            gas_limit: event.gas,
            gas_price: if is_genesis {
                None
            } else {
                utils::u256_to_protobuf_always(effective_gas_price)
            },
            value: if is_genesis {
                None
            } else {
                utils::u256_to_protobuf(event.value)
            },
            input: event.input.to_vec(),
            v: event.v.map(|v| v.to_vec()).unwrap_or_default(),
            r: utils::normalize_signature_point(&event.r.0).unwrap_or_default(),
            s: utils::normalize_signature_point(&event.s.0).unwrap_or_default(),
            max_fee_per_gas: event.max_fee_per_gas.and_then(utils::u256_to_protobuf),
            max_priority_fee_per_gas: event
                .max_priority_fee_per_gas
                .and_then(utils::u256_to_protobuf),
            access_list,
            blob_gas_fee_cap: event.blob_gas_fee_cap.and_then(utils::u256_to_protobuf),
            blob_hashes,
            set_code_authorizations,
            index: event.index,
            ..Default::default()
        };

        self.transaction = Some(trx);
    }

    /// OnTxEnd is called at the end of transaction execution
    pub fn on_tx_end(
        &mut self,
        receipt: Option<&ReceiptData>,
        err: Option<&dyn std::error::Error>,
    ) {
        firehose_info!("trx ending (err={:?})", err);

        // Validate state: Must be in block and in transaction
        self.ensure_in_block_and_in_trx();

        // Complete the transaction
        if let Some(trx) = self.transaction.take() {
            let completed_trx = self.complete_transaction(trx, receipt, err);
            if let Some(block) = &mut self.block {
                block.transaction_traces.push(completed_trx);
            }
        }

        self.reset_transaction();

        firehose_info!("trx end");
    }

    /// Complete transaction processing (matching Golang completeTransaction)
    fn complete_transaction(
        &mut self,
        mut trx: TransactionTrace,
        receipt: Option<&ReceiptData>,
        _err: Option<&dyn std::error::Error>,
    ) -> TransactionTrace {
        firehose_info!("completing transaction (call_count={})", trx.calls.len());

        if trx.calls.is_empty() {
            // Bad block or misconfigured - terminate immediately
            trx.end_ordinal = self.block_ordinal.next();
            return trx;
        }

        // Step 1: Sort calls by index (MUST happen first)
        trx.calls.sort_by(|a, b| a.index.cmp(&b.index));

        // Step 2: Get root call for later operations
        let root_call_reverted = trx
            .calls
            .first()
            .map(|c| c.status_reverted)
            .unwrap_or(false);

        // Step 2.5: Discard SetCode authorizations that don't have corresponding nonce changes
        // (matching native tracer's discardUncommittedSetCodeAuthorization)
        // This MUST happen BEFORE deferred state is populated, since we need to check
        // the initial deferred state that was already transferred into the root call
        Self::discard_uncommitted_set_code_authorizations(&mut trx);

        // Step 3: Move any remaining deferred state to root call
        if !self.deferred_call_state.is_empty() {
            if let Some(root_call) = trx.calls.first_mut() {
                if let Err(e) = self
                    .deferred_call_state
                    .maybe_populate_call_and_reset("root", root_call)
                {
                    panic!("failed to populate deferred state on tx end: {}", e);
                }
            }
        }

        // Step 4: Populate receipt data (BEFORE state reverted)
        if let Some(receipt) = receipt {
            trx.index = receipt.transaction_index;
            trx.gas_used = receipt.gas_used;
            trx.receipt = Some(self.new_receipt_from_data(receipt, trx.r#type));

            // Set transaction status based on receipt
            if receipt.status == 1 {
                trx.status = pb::sf::ethereum::r#type::v2::TransactionTraceStatus::Succeeded as i32;
            } else {
                trx.status = pb::sf::ethereum::r#type::v2::TransactionTraceStatus::Failed as i32;
            }
        }

        // Step 4.5: Reth-specific reconciliation — revm's inspector `call_end` hook
        // may report the root call as successful even when the transaction actually
        // failed (e.g., out-of-gas). In Geth, `OnExit` receives the EVM-level error
        // directly, but revm determines failure at the executor level. When the receipt
        // says failure but the root call wasn't marked as failed, reconcile here.
        if self.config.chain_client == config::ChainClient::Reth {
            if let Some(receipt) = receipt {
                if receipt.status != 1 {
                    if let Some(root_call) = trx.calls.first_mut() {
                        if !root_call.status_failed {
                            root_call.status_failed = true;
                            root_call.failure_reason = "out of gas".to_string();
                        }
                    }
                }
            }
        }

        // Step 5: Check if root call reverted (overrides receipt status)
        if root_call_reverted {
            trx.status = pb::sf::ethereum::r#type::v2::TransactionTraceStatus::Reverted as i32;
        }

        // Step 6: Copy root call's return data to transaction
        if let Some(root_call) = trx.calls.first() {
            trx.return_data = root_call.return_data.clone();
        }

        // Step 7: Populate StateReverted for all calls
        Self::populate_state_reverted(&mut trx);

        // Step 8: Remove BlockIndex from logs in reverted calls
        Self::remove_log_block_index_on_state_reverted_calls(&mut trx);

        // Step 9: Assign ordinals and indexes to receipt logs from call logs
        Self::assign_ordinal_and_index_to_receipt_logs(&mut trx);

        // Step 10: Set end ordinal
        trx.end_ordinal = self.block_ordinal.next();

        trx
    }

    /// Assign ordinal and index from call logs to receipt logs
    /// (matching Golang assignOrdinalAndIndexToReceiptLogs)
    fn assign_ordinal_and_index_to_receipt_logs(trx: &mut TransactionTrace) {
        // Collect all logs from non-reverted calls
        let mut call_logs: Vec<&pb::sf::ethereum::r#type::v2::Log> = Vec::new();
        for call in &trx.calls {
            if call.state_reverted {
                continue;
            }
            call_logs.extend(call.logs.iter());
        }

        // Sort call logs by ordinal to ensure correct ordering
        call_logs.sort_by(|a, b| a.ordinal.cmp(&b.ordinal));

        // Get receipt logs (mutable)
        let receipt_logs = if let Some(receipt) = &mut trx.receipt {
            &mut receipt.logs
        } else {
            return; // No receipt, nothing to do
        };

        // Validate counts match
        if call_logs.len() != receipt_logs.len() {
            panic!(
                "mismatch between call logs and receipt logs: transaction has {} call logs but {} receipt logs",
                call_logs.len(),
                receipt_logs.len()
            );
        }

        // Copy ordinal and index from call logs to receipt logs
        for (i, call_log) in call_logs.iter().enumerate() {
            let receipt_log = &mut receipt_logs[i];

            // Validate BlockIndex matches
            if call_log.block_index != receipt_log.block_index {
                panic!(
                    "mismatch between call log and receipt log BlockIndex at index {}: call log has {} but receipt log has {}",
                    i, call_log.block_index, receipt_log.block_index
                );
            }

            // Assign ordinal and index
            receipt_log.ordinal = call_log.ordinal;
            receipt_log.index = call_log.index;
        }
    }

    /// Populate StateReverted field on all calls based on parent state and status
    /// (matching Golang populateStateReverted)
    fn populate_state_reverted(trx: &mut TransactionTrace) {
        // Match native tracer logic: StateReverted is set if parent is reverted OR call failed
        // Calls are ordered by index, so we see parents before children
        for i in 0..trx.calls.len() {
            let parent_reverted = if trx.calls[i].parent_index > 0 {
                let parent_idx = (trx.calls[i].parent_index - 1) as usize;
                trx.calls[parent_idx].state_reverted
            } else {
                false
            };

            let status_failed = trx.calls[i].status_failed;
            trx.calls[i].state_reverted = parent_reverted || status_failed;
        }
    }

    /// Remove BlockIndex from logs in reverted calls
    /// (matching Golang removeLogBlockIndexOnStateRevertedCalls)
    /// Logs in reverted calls should have BlockIndex set to 0 since they don't make it into the final state
    fn remove_log_block_index_on_state_reverted_calls(trx: &mut TransactionTrace) {
        for call in &mut trx.calls {
            if call.state_reverted {
                for log in &mut call.logs {
                    log.block_index = 0;
                }
            }
        }
    }

    /// Discard SetCode authorizations that don't have corresponding nonce changes
    /// (matching Golang discardUncommittedSetCodeAuthorizations)
    ///
    /// Per EIP-7702, when an authorization is applied, the authorizer's nonce is incremented.
    /// If we don't see this nonce change, it means the authorization was not actually applied
    /// (e.g., wrong nonce, already used, validation failed in EVM, etc.)
    fn discard_uncommitted_set_code_authorizations(trx: &mut TransactionTrace) {
        if trx.set_code_authorizations.is_empty() {
            return;
        }

        // Get root call (first call in sorted list)
        let root_call = match trx.calls.first() {
            Some(call) => call,
            None => return, // No calls, nothing to do
        };

        // Build a set to track which nonce changes we've used
        // (each nonce change can only match one authorization)
        use std::collections::HashSet;
        let mut used_nonce_change_indices: HashSet<usize> = HashSet::new();

        // Helper closure to find a matching nonce change for an authorization
        let find_nonce_change = |authority: &[u8], nonce: u64, used: &mut HashSet<usize>| -> bool {
            for (i, change) in root_call.nonce_changes.iter().enumerate() {
                if change.old_value == nonce
                    && change.new_value == nonce + 1
                    && change.address == authority
                    && !used.contains(&i)
                {
                    used.insert(i);
                    return true;
                }
            }
            false
        };

        // Check each authorization for a matching nonce change
        for auth in &mut trx.set_code_authorizations {
            // Check if authority is present
            let authority_bytes = match &auth.authority {
                Some(bytes) if !bytes.is_empty() => bytes.as_slice(),
                _ => {
                    // No authority (signature recovery failed) - mark as discarded
                    auth.discarded = true;
                    continue;
                }
            };

            // Look for nonce change matching this authorization
            if !find_nonce_change(authority_bytes, auth.nonce, &mut used_nonce_change_indices) {
                // No matching nonce change found - authorization was not applied
                firehose_debug!(
                    "discarded SetCode authorization: no matching nonce change (authority={} nonce={})",
                    hex::encode(authority_bytes),
                    auth.nonce
                );
                auth.discarded = true;
            }
        }
    }

    /// Create receipt from receipt data (matching Golang newReceiptFromData)
    fn new_receipt_from_data(
        &self,
        receipt: &ReceiptData,
        tx_type: i32,
    ) -> pb::sf::ethereum::r#type::v2::TransactionReceipt {
        use pb::sf::ethereum::r#type::v2::{Log, TransactionReceipt};

        let mut r = TransactionReceipt {
            cumulative_gas_used: receipt.cumulative_gas_used,
            logs_bloom: receipt.logs_bloom.to_vec(),
            state_root: receipt
                .state_root
                .as_ref()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
            logs: Vec::new(),
            blob_gas_used: None,
            blob_gas_price: None,
        };

        // Add EIP-4844 blob fields for blob transactions (type 3)
        use pb::sf::ethereum::r#type::v2::transaction_trace::Type;
        if tx_type == Type::TrxTypeBlob as i32 {
            r.blob_gas_used = Some(receipt.blob_gas_used);
            r.blob_gas_price = receipt
                .blob_gas_price
                .and_then(crate::utils::u256_to_protobuf);
        }

        // Add logs from receipt
        for log in &receipt.logs {
            let pb_log = Log {
                address: log.address.0.to_vec(),
                topics: log.topics.iter().map(|t| t.0.to_vec()).collect(),
                data: log.data.to_vec(),
                index: 0, // Will be assigned later
                block_index: log.block_index,
                ordinal: 0, // Will be assigned later
            };
            r.logs.push(pb_log);
        }

        r
    }

    // ============================================================================
    // Call Lifecycle Hooks
    // ============================================================================

    /// on_call records a complete call frame in one shot. The enter is processed
    /// immediately; the exit is deferred until the next call at the same or
    /// shallower depth arrives, or until flush_open_calls is called explicitly
    pub fn on_call(
        &mut self,
        depth: i32,
        opcode: u8,
        from: Address,
        to: Address,
        input: &[u8],
        gas: u64,
        value: U256,
        output: Vec<u8>,
        gas_used: u64,
        err: Option<super::StringError>,
        is_last: bool,
    ) {
        // Close any open calls at depth >= incoming depth before opening the new one
        let mut open_calls = std::mem::take(&mut self.open_calls);
        open_calls.flush_at_or_below(depth, self);
        self.open_calls = open_calls;

        self.on_call_enter(depth, opcode, from, to, input, gas, value);

        self.open_calls.push(OpenCall {
            depth,
            addr: to,
            call_type: self.opcode_to_call_type(opcode),
            output,
            gas_used,
            error: err,
        });

        if is_last {
            let mut open_calls = std::mem::take(&mut self.open_calls);
            open_calls.flush(0, self);
            self.open_calls = open_calls;
        }
    }

    /// OnCallEnter is called when entering a call
    pub fn on_call_enter(
        &mut self,
        depth: i32,
        typ: u8,
        from: Address,
        to: Address,
        input: &[u8],
        gas: u64,
        value: U256,
    ) {
        firehose_debug!(
            "call enter (depth={} type={} from={:?} to={:?})",
            depth,
            typ,
            from,
            to
        );

        // Handle SELFDESTRUCT specially
        if typ == Opcode::SelfDestruct as u8 {
            // SELFDESTRUCT opcode
            self.latest_call_enter_suicided = true;
            self.latest_call_enter_suicided_depth = depth;
            firehose_debug!("SELFDESTRUCT opcode: set latestCallEnterSuicided flag");
            return;
        }

        // Create call (will be pushed to stack)
        let mut call = Call {
            begin_ordinal: self.block_ordinal.next(),
            call_type: self.opcode_to_call_type(typ),
            caller: from.0.to_vec(),
            address: to.0.to_vec(),
            value: utils::u256_to_protobuf(value),
            gas_limit: gas,
            input: input.to_vec(),
            ..Default::default()
        };

        // Move deferred state to this call if it's the first call
        if depth == 0 {
            if let Err(e) = self
                .deferred_call_state
                .maybe_populate_call_and_reset("enter", &mut call)
            {
                panic!("failed to populate deferred state on call enter: {}", e);
            }
        }

        // EIP-7702: Detect delegation designators in account code (Prague fork)
        // Check if account code contains delegation bytecode (0xef0100 + address)
        if self.block_rules.is_prague
            && !self.in_system_call
            && !self.block_is_genesis
            && call.call_type != pb::sf::ethereum::r#type::v2::CallType::Create as i32
        {
            // Get code from state reader if available
            if let Some(state_reader) = &self.transaction_state_reader {
                let code: alloy_primitives::Bytes = state_reader.get_code(to);
                if !code.is_empty() {
                    // ParseDelegation returns (address, true) if valid delegation
                    if let Some(target) = Self::parse_delegation(&code) {
                        firehose_debug!(
                            "call resolved delegation (from={:?}, delegates_to={:?})",
                            from,
                            target
                        );
                        call.address_delegates_to = Some(target.0.to_vec());
                    }
                }
            }
        }

        self.call_stack.push(&mut call);
    }

    /// parse_delegation tries to parse a delegation designator from bytecode
    /// EIP-7702: Delegation format is 0xef0100 + 20-byte address (23 bytes total)
    fn parse_delegation(code: &[u8]) -> Option<Address> {
        const DELEGATION_PREFIX: [u8; 3] = [0xef, 0x01, 0x00];

        if code.len() != 23 || !code.starts_with(&DELEGATION_PREFIX) {
            return None;
        }

        // Extract address bytes (last 20 bytes)
        let addr_bytes = &code[DELEGATION_PREFIX.len()..];
        Some(Address::from_slice(addr_bytes))
    }

    /// OnCallExit is called when exiting a call
    pub fn on_call_exit(
        &mut self,
        depth: i32,
        output: &[u8],
        gas_used: u64,
        err: Option<&dyn std::error::Error>,
        reverted: bool,
    ) {
        // Handle SELFDESTRUCT exit
        if self.latest_call_enter_suicided {
            firehose_debug!("skipping OnCallExit for SELFDESTRUCT opcode");
            self.latest_call_enter_suicided = false;
            return;
        }

        // Ensure we're in a valid state
        self.ensure_in_block_and_in_trx_and_in_call();

        // Pop call from stack
        if let Some(mut call) = self.call_stack.pop() {
            firehose_debug!("call exit (depth={} gas_used={})", depth, gas_used);

            call.gas_consumed = gas_used;

            // For CREATE calls, don't set return data (matching Golang tracer line ~1437)
            // CREATE calls receive the contract code as output but it's NOT stored in ReturnData
            if call.call_type != pb::sf::ethereum::r#type::v2::CallType::Create as i32 {
                call.return_data = output.to_vec();
            }

            // Handle errors
            if reverted {
                let failure_reason = if let Some(e) = err {
                    e.to_string()
                } else {
                    String::new()
                };

                call.failure_reason = failure_reason;
                call.status_failed = true;

                // Match native tracer logic: We also treat ErrInsufficientBalance and
                // ErrDepth as reverted in Firehose model because they do not cost any gas.
                call.status_reverted = if let Some(e) = err {
                    utils::error_is_string(e, utils::TEXT_EXECUTION_REVERTED_ERR)
                        || utils::error_is_string(e, utils::TEXT_INSUFFICIENT_BALANCE_TRANSFER_ERR)
                        || utils::error_is_string(e, utils::TEXT_MAX_CALL_DEPTH_ERR)
                } else {
                    false
                };
            }

            call.end_ordinal = self.block_ordinal.next();

            // Append to transaction calls
            if let Some(trx) = &mut self.transaction {
                trx.calls.push(call);
            }
        }
    }

    // ============================================================================
    // State Change Hooks
    // ============================================================================

    /// OnBalanceChange is called when an account balance changes
    pub fn on_balance_change(
        &mut self,
        addr: Address,
        old_balance: U256,
        new_balance: U256,
        reason: pb::sf::ethereum::r#type::v2::balance_change::Reason,
    ) {
        firehose_trace!(
            "balance changed (address={:?} old_balance={} new_balance={} reason={:?})",
            addr,
            old_balance,
            new_balance,
            reason
        );

        // Ignore unspecified reasons
        if reason == pb::sf::ethereum::r#type::v2::balance_change::Reason::Unknown {
            return;
        }

        self.ensure_in_block_or_trx();

        let change = pb::sf::ethereum::r#type::v2::BalanceChange {
            ordinal: self.block_ordinal.next(),
            address: addr.0.to_vec(),
            old_value: utils::u256_to_protobuf(old_balance),
            new_value: utils::u256_to_protobuf(new_balance),
            reason: reason.into(),
        };

        // In transaction context - attach to call or defer
        if self.transaction.is_some() {
            if let Some(active_call) = self.call_stack.peek_mut() {
                active_call.balance_changes.push(change);
            } else {
                self.deferred_call_state.add_balance_change(change);
            }
        } else {
            // Block-level balance change
            if let Some(block) = &mut self.block {
                block.balance_changes.push(change);
            }
        }
    }

    /// OnNonceChange is called when an account nonce changes
    pub fn on_nonce_change(&mut self, addr: Address, old_nonce: u64, new_nonce: u64) {
        firehose_debug!(
            "nonce changed (address={:?} old_nonce={} new_nonce={})",
            addr,
            old_nonce,
            new_nonce
        );

        self.ensure_in_block_and_in_trx();

        let change = pb::sf::ethereum::r#type::v2::NonceChange {
            address: addr.0.to_vec(),
            old_value: old_nonce,
            new_value: new_nonce,
            ordinal: self.block_ordinal.next(),
        };

        if let Some(active_call) = self.call_stack.peek_mut() {
            active_call.nonce_changes.push(change);
        } else {
            self.deferred_call_state.add_nonce_change(change);
        }
    }

    /// OnCodeChange is called when contract code changes
    pub fn on_code_change(
        &mut self,
        addr: Address,
        prev_code_hash: B256,
        new_code_hash: B256,
        old_code: &[u8],
        new_code: &[u8],
    ) {
        firehose_debug!(
            "code changed (address={:?} prev_hash={:?} new_hash={:?})",
            addr,
            prev_code_hash,
            new_code_hash
        );

        self.ensure_in_block_or_trx();

        let change = pb::sf::ethereum::r#type::v2::CodeChange {
            address: addr.0.to_vec(),
            old_hash: prev_code_hash.0.to_vec(),
            old_code: old_code.to_vec(),
            new_hash: new_code_hash.0.to_vec(),
            new_code: new_code.to_vec(),
            ordinal: self.block_ordinal.next(),
        };

        // In transaction context - attach to call or defer
        if self.transaction.is_some() {
            if let Some(active_call) = self.call_stack.peek_mut() {
                // Ignore code changes from suicide if there was previous code
                if active_call.suicide && !old_code.is_empty() && new_code.is_empty() {
                    firehose_debug!("ignoring code change due to suicide");
                    return;
                }
                active_call.code_changes.push(change);
            } else {
                self.deferred_call_state.add_code_change(change);
            }
        } else {
            // Block-level code change
            if let Some(block) = &mut self.block {
                block.code_changes.push(change);
            }
        }
    }

    /// OnStorageChange is called when contract storage changes
    pub fn on_storage_change(
        &mut self,
        addr: Address,
        slot: B256,
        old_value: B256,
        new_value: B256,
    ) {
        firehose_trace!("storage changed (address={:?} key={:?})", addr, slot);

        self.ensure_in_block_and_in_trx();

        let change = pb::sf::ethereum::r#type::v2::StorageChange {
            address: addr.0.to_vec(),
            key: slot.0.to_vec(),
            old_value: old_value.0.to_vec(),
            new_value: new_value.0.to_vec(),
            ordinal: self.block_ordinal.next(),
        };

        if let Some(active_call) = self.call_stack.peek_mut() {
            active_call.storage_changes.push(change);
        } else {
            self.deferred_call_state.add_storage_change(change);
        }
    }

    // ============================================================================
    // Other Hooks
    // ============================================================================

    /// OnLog is called when a log event is emitted
    pub fn on_log(&mut self, addr: Address, topics: &[B256], data: &[u8], block_index: u32) {
        firehose_trace!(
            "log emitted (address={:?} topics={} data_len={})",
            addr,
            topics.len(),
            data.len()
        );

        self.ensure_in_block_and_in_trx();

        let pb_log = pb::sf::ethereum::r#type::v2::Log {
            address: addr.0.to_vec(),
            data: data.to_vec(),
            index: self.transaction_log_index,
            block_index,
            ordinal: self.block_ordinal.next(),
            topics: topics.iter().map(|t| t.0.to_vec()).collect(),
        };
        self.transaction_log_index += 1;

        if let Some(active_call) = self.call_stack.peek_mut() {
            active_call.logs.push(pb_log);
        } else {
            self.deferred_call_state.add_logs(pb_log);
        }
    }

    /// OnOpcode is called for each opcode executed
    pub fn on_opcode(
        &mut self,
        _pc: u64,
        op: u8,
        _gas: u64,
        _cost: u64,
        _data: &[u8],
        _depth: i32,
        err: Option<&dyn std::error::Error>,
    ) {
        if self.call_stack.peek().is_none() {
            return;
        }

        // Set ExecutedCode to true
        if let Some(active_call) = self.call_stack.peek_mut() {
            active_call.executed_code = true;
        }

        // The rest of the logic expects that a call succeeded
        if err.is_some() {
            return;
        }

        // Mark SELFDESTRUCT opcode
        if op == Opcode::SelfDestruct as u8 {
            if let Some(active_call) = self.call_stack.peek_mut() {
                active_call.suicide = true;
            }
        }
    }

    /// OnOpcodeFault is called when an opcode execution fails
    pub fn on_opcode_fault(
        &mut self,
        pc: u64,
        op: u8,
        _gas: u64,
        _cost: u64,
        _depth: i32,
        err: &dyn std::error::Error,
    ) {
        firehose_debug!("opcode fault (pc={} op={} err={})", pc, op, err);

        if let Some(active_call) = self.call_stack.peek_mut() {
            // Even faulted opcodes count as executed code
            active_call.executed_code = true;
        }
    }

    /// OnKeccakPreimage is called when a keccak256 preimage is available
    pub fn on_keccak_preimage(&mut self, hash: B256, preimage: &[u8]) {
        self.ensure_in_block_and_in_trx_and_in_call();

        if let Some(call) = self.call_stack.peek_mut() {
            // Store the preimage as hex-encoded string
            call.keccak_preimages
                .insert(hex::encode(hash.0), hex::encode(preimage));

            firehose_trace!(
                "keccak preimage (hash={:?} preimage_len={})",
                hash,
                preimage.len()
            );
        }
    }

    // ============================================================================
    // System Call Hooks
    // ============================================================================

    /// OnSystemCallStart is called when a system call starts (chain-specific)
    pub fn on_system_call_start(&mut self) {
        firehose_info!("system call start");
        self.ensure_in_block_and_not_in_trx();

        self.in_system_call = true;
        self.transaction = Some(TransactionTrace::default());
    }

    /// OnSystemCallEnd is called when a system call ends (chain-specific)
    pub fn on_system_call_end(&mut self) {
        firehose_info!("system call end");
        self.ensure_in_block_and_in_trx();
        self.ensure_in_system_call();

        // Move any calls created during system call to block's system calls list
        if let (Some(block), Some(trx)) = (&mut self.block, &mut self.transaction) {
            block.system_calls.append(&mut trx.calls);
        }

        self.reset_transaction();
    }

    // ============================================================================
    // Helper Methods
    // ============================================================================

    fn new_block_header_from_block_data(
        &self,
        block: &crate::types::BlockData,
    ) -> pb::sf::ethereum::r#type::v2::BlockHeader {
        pb::sf::ethereum::r#type::v2::BlockHeader {
            parent_hash: block.parent_hash.0.to_vec(),
            uncle_hash: block.uncle_hash.0.to_vec(),
            coinbase: block.coinbase.0.to_vec(),
            state_root: block.root.0.to_vec(),
            transactions_root: block.tx_hash.0.to_vec(),
            receipt_root: block.receipt_hash.0.to_vec(),
            logs_bloom: block.bloom.as_slice().to_vec(),
            difficulty: utils::u256_to_protobuf_always(block.difficulty),
            number: block.number,
            gas_limit: block.gas_limit,
            gas_used: block.gas_used,
            timestamp: Some(prost_types::Timestamp {
                seconds: block.time as i64,
                nanos: 0,
            }),
            extra_data: block.extra.to_vec(),
            mix_hash: block.mix_digest.0.to_vec(),
            nonce: block.nonce,
            hash: block.hash.0.to_vec(),
            base_fee_per_gas: block.base_fee.and_then(utils::u256_to_protobuf),
            // EIP-4895: Shanghai withdrawals root
            withdrawals_root: block
                .withdrawals_root
                .map(|root| root.0.to_vec())
                .unwrap_or_default(),
            // EIP-4844: Cancun blob gas tracking
            blob_gas_used: block.blob_gas_used,
            excess_blob_gas: block.excess_blob_gas,
            // EIP-4788: Cancun parent beacon block root
            parent_beacon_root: block
                .parent_beacon_root
                .map(|root| root.0.to_vec())
                .unwrap_or_default(),
            // EIP-7685: Prague execution requests hash
            requests_hash: block
                .requests_hash
                .map(|hash| hash.0.to_vec())
                .unwrap_or_default(),
            // Polygon-specific: Transaction dependency metadata
            tx_dependency: block.tx_dependency.as_ref().map(|deps| {
                pb::sf::ethereum::r#type::v2::Uint64NestedArray {
                    val: deps
                        .iter()
                        .map(|inner| pb::sf::ethereum::r#type::v2::Uint64Array {
                            val: inner.clone(),
                        })
                        .collect(),
                }
            }),
            ..Default::default()
        }
    }

    fn new_block_header_from_uncle_data(
        &self,
        uncle: &crate::types::UncleData,
    ) -> pb::sf::ethereum::r#type::v2::BlockHeader {
        pb::sf::ethereum::r#type::v2::BlockHeader {
            parent_hash: uncle.parent_hash.0.to_vec(),
            uncle_hash: uncle.uncle_hash.0.to_vec(),
            coinbase: uncle.coinbase.0.to_vec(),
            state_root: uncle.root.0.to_vec(),
            transactions_root: uncle.tx_hash.0.to_vec(),
            receipt_root: uncle.receipt_hash.0.to_vec(),
            logs_bloom: uncle.bloom.as_slice().to_vec(),
            difficulty: utils::u256_to_protobuf_always(uncle.difficulty),
            number: uncle.number,
            gas_limit: uncle.gas_limit,
            gas_used: uncle.gas_used,
            timestamp: Some(prost_types::Timestamp {
                seconds: uncle.time as i64,
                nanos: 0,
            }),
            extra_data: uncle.extra.to_vec(),
            mix_hash: uncle.mix_digest.0.to_vec(),
            nonce: uncle.nonce,
            hash: uncle.hash.0.to_vec(),
            base_fee_per_gas: uncle.base_fee.and_then(utils::u256_to_protobuf),
            ..Default::default()
        }
    }

    // ============================================================================
    // State Validation Methods
    // ============================================================================

    fn ensure_blockchain_init(&self) {
        if self.chain_config.is_none() {
            panic!("the OnBlockchainInit hook should have been called at this point");
        }
    }

    /// Converts an EVM opcode to a protobuf CallType enum value
    fn opcode_to_call_type(&self, opcode: u8) -> i32 {
        use pb::sf::ethereum::r#type::v2::CallType;

        match opcode.try_into() {
            Ok(Opcode::Create) => CallType::Create as i32,
            Ok(Opcode::Create2) => CallType::Create as i32, // CREATE2 maps to CREATE
            Ok(Opcode::Call) => CallType::Call as i32,
            Ok(Opcode::CallCode) => CallType::Callcode as i32,
            Ok(Opcode::DelegateCall) => CallType::Delegate as i32,
            Ok(Opcode::StaticCall) => CallType::Static as i32,
            _ => CallType::Unspecified as i32, // Unknown
        }
    }

    pub fn ensure_in_block(&self) {
        if self.block.is_none() {
            panic!("caller expected to be in block state but we were not");
        }
    }

    fn ensure_in_block_and_in_trx(&self) {
        self.ensure_in_block();
        if self.transaction.is_none() {
            panic!("caller expected to be in transaction state but we were not");
        }
    }

    fn ensure_in_block_and_not_in_trx(&self) {
        self.ensure_in_block();
        if self.transaction.is_some() {
            panic!("caller expected to not be in transaction state but we were");
        }
    }

    fn ensure_in_block_and_not_in_trx_and_not_in_call(&self) {
        self.ensure_in_block();
        if self.transaction.is_some() {
            panic!("caller expected to not be in transaction state but we were");
        }
        if self.call_stack.has_active_call() {
            panic!("caller expected to not be in call state but we were");
        }
    }

    fn ensure_in_block_or_trx(&self) {
        if self.transaction.is_none() && self.block.is_none() {
            panic!("caller expected to be in either block or transaction state but we were not");
        }
    }

    fn ensure_in_block_and_in_trx_and_in_call(&self) {
        if self.transaction.is_none() || self.block.is_none() {
            panic!("caller expected to be in block and in transaction but we were not");
        }
        if !self.call_stack.has_active_call() {
            panic!("caller expected to be in call state but we were not");
        }
    }

    fn ensure_in_system_call(&self) {
        if !self.in_system_call {
            panic!("caller expected to be in system call state but we were not");
        }
    }

    pub fn is_in_transaction(&self) -> bool {
        self.transaction.is_some()
    }

    pub fn is_in_call(&self) -> bool {
        self.call_stack.has_active_call()
    }

    pub fn is_in_system_call(&self) -> bool {
        self.in_system_call
    }

    pub fn is_in_block(&self) -> bool {
        self.block.is_some()
    }

    pub fn set_block_hash(&mut self, hash: alloy_primitives::B256) {
        if let Some(block) = &mut self.block {
            block.hash = hash.0.to_vec();
            if let Some(header) = &mut block.header {
                header.hash = hash.0.to_vec();
            }
        }
    }

    pub fn set_block_header_end_data(
        &mut self,
        state_root: alloy_primitives::B256,
        receipts_root: alloy_primitives::B256,
        logs_bloom: alloy_primitives::Bloom,
        gas_used: u64,
    ) {
        if let Some(block) = &mut self.block {
            if let Some(header) = &mut block.header {
                header.state_root = state_root.0.to_vec();
                header.receipt_root = receipts_root.0.to_vec();
                header.logs_bloom = logs_bloom.0.to_vec();
                header.gas_used = gas_used;
            }
        }
    }

    /// Sets the "to" address on the active transaction. Used for CREATE/CREATE2
    /// to patch the deployed contract address after it is known at depth 0
    pub fn set_transaction_to(&mut self, to: Address) {
        self.ensure_in_block_and_in_trx();
        self.transaction.as_mut().unwrap().to = to.0.to_vec();
    }
}

/// Computes the effective gas price for a transaction based on its type and block base fee.
/// Follows the same logic as go-ethereum's gasPrice function:
/// - For legacy/access list transactions (types 0, 1): use gas_price
/// - For EIP-1559 transactions (types 2, 3, 4: dynamic fee, blob, set code):
///   - If base_fee is None: use max_fee_per_gas (or fallback to gas_price)
///   - If base_fee is Some: use min(max_priority_fee_per_gas + base_fee, max_fee_per_gas)
// Transaction type constants (from Ethereum specification)
use crate::types::TxType;

use crate::types::Opcode;

fn compute_effective_gas_price(event: &TxEvent, base_fee: Option<U256>) -> U256 {
    match event.tx_type {
        TxType::Legacy | TxType::AccessList => {
            // Legacy, AccessList
            event.gas_price
        }
        _ => {
            // DynamicFee, Blob, SetCode (EIP-1559 transactions)
            if base_fee.is_none() {
                // If baseFee is nil, use MaxFeePerGas
                event.max_fee_per_gas.unwrap_or(event.gas_price)
            } else {
                let base_fee = base_fee.unwrap();
                // Compute: min(MaxPriorityFeePerGas + baseFee, MaxFeePerGas)
                if let (Some(max_priority), Some(max_fee)) =
                    (event.max_priority_fee_per_gas, event.max_fee_per_gas)
                {
                    let effective_price = max_priority.saturating_add(base_fee);
                    if effective_price > max_fee {
                        max_fee
                    } else {
                        effective_price
                    }
                } else {
                    // Fallback to GasPrice if EIP-1559 fields are not set
                    event.gas_price
                }
            }
        }
    }
}
