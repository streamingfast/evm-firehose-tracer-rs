//! Main Firehose tracer implementation

use crate::{MonadConsumer, FirehosePluginConfig, TRACER_NAME, TRACER_VERSION};
use alloy_primitives::B256;
use eyre::Result;
use firehose::{types::{AccessTuple, SetCodeAuthorization, TxType}, Opcode, Tracer};
use futures_util::StreamExt;
use monad_exec_events::ExecEvent;
use std::collections::HashMap;
use tracing::{error, info};

#[repr(u8)]
enum AccountAccessContext {
    BlockPrologue = 0,
    Transaction = 1,
    BlockEpilogue = 2,
}
fn evmc_status_to_error(evmc_status: i32) -> Option<firehose::StringError> {
    let msg = match evmc_status {
        0 => return None,
        1 => "execution failed",
        2 => "execution reverted",
        3 => "out of gas",
        4 => "invalid instruction",
        5 => "undefined instruction",
        6 => "stack overflow",
        7 => "stack underflow",
        8 => "bad jump destination",
        9 => "invalid memory access",
        10 => "call depth exceeded",
        11 => "static mode violation",
        12 => "precompile failure",
        13 => "contract validation failure",
        14 => "argument out of range",
        17 => "insufficient balance for transfer",
        _ => return Some(firehose::StringError(format!("unknown error (status {})", evmc_status))),
    };
    Some(firehose::StringError(msg.to_string()))
}

/// Main Firehose tracer for Monad
pub struct FirehosePlugin {
    config: FirehosePluginConfig,
    consumer: Option<MonadConsumer>,
    pub tracer: Tracer,
    tx_end_receipt: Option<monad_exec_events::ffi::monad_exec_txn_evm_output>,
    pending_tx_events: HashMap<usize, firehose::TxEvent>,
    // Logs buffered for receipt construction
    pending_receipt_logs: Vec<firehose::LogData>,
    block_txn_count: u64,
    last_finalized_block: u64,
    current_txn_index: u32,
    cumulative_gas_used: u64,
    system_call_account_access_count: u32,
}


impl FirehosePlugin {
    pub fn new(config: FirehosePluginConfig) -> Self {
        Self {
            config,
            consumer: None,
            tracer: Tracer::new(firehose::Config::new()),
            last_finalized_block: 0,
            tx_end_receipt: None,
            pending_tx_events: HashMap::new(),
            pending_receipt_logs: Vec::new(),
            block_txn_count: 0,
            current_txn_index: 0,
            cumulative_gas_used: 0,
            system_call_account_access_count: 0,
        }
    }

    pub fn new_with_writer(config: FirehosePluginConfig, writer: Box<dyn std::io::Write + Send>) -> Self {
        Self {
            config,
            consumer: None,
            tracer: Tracer::new_with_writer(firehose::Config::new(), writer),
            last_finalized_block: 0,
            tx_end_receipt: None,
            pending_tx_events: HashMap::new(),
            pending_receipt_logs: Vec::new(),
            block_txn_count: 0,
            current_txn_index: 0,
            cumulative_gas_used: 0,
            system_call_account_access_count: 0,
        }
    }

    fn ensure_in_block_and_in_pending(&self, txn_index: usize, event_name: &str) {
        self.tracer.ensure_in_block();
        if !self.pending_tx_events.contains_key(&txn_index) {
            panic!("{} for txn_index={} but no pending TxEvent", event_name, txn_index);
        }
    }

    fn ensure_system_call_account_access_count(&self, expected: u32) {
        if self.system_call_account_access_count != expected {
            panic!(
                "system call account access count mismatch: got {} expected {}",
                self.system_call_account_access_count,
                expected,
            );
        }
    }

    pub fn on_blockchain_init(&mut self, node_name: &str, node_version: &str) {
        let chain_config = firehose::ChainConfig::new(self.config.chain_id);
        self.tracer.on_blockchain_init(node_name, node_version, chain_config);
    }

    pub fn with_consumer(mut self, consumer: MonadConsumer) -> Self {
        self.consumer = Some(consumer);
        self
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Firehose tracer for network: {}", self.config.network_name);

        let chain_config = firehose::ChainConfig::new(self.config.chain_id);
        self.tracer.on_blockchain_init(TRACER_NAME, TRACER_VERSION, chain_config);

        let consumer = self
            .consumer
            .take()
            .ok_or_else(|| eyre::eyre!("No consumer configured"))?;

        let mut event_stream = consumer.start_consuming().await?;

        info!("Tracer started, processing events...");

        while let Some((_seqno, event)) = event_stream.next().await {
            if let Err(e) = self.process_event(event).await {
                error!("Failed to process event: {}", e);
                if !self.config.debug {
                    continue;
                }
            }
        }

        Ok(())
    }

    pub fn add_event(&mut self, event: ExecEvent) -> Result<()> {
        if !self.tracer.is_in_block() && !matches!(event, ExecEvent::BlockStart(_) | ExecEvent::BlockFinalized(_))
        {
            return Ok(());
        }

        match event {
            ExecEvent::BlockStart(block_start) => {
                tracing::debug!("block start (number={} txn_count={})", block_start.eth_block_input.number, block_start.eth_block_input.txn_count);

                self.block_txn_count = block_start.eth_block_input.txn_count;
                self.current_txn_index = 0;
                self.cumulative_gas_used = 0;

                let block_number = block_start.eth_block_input.number;
                let ei = &block_start.eth_block_input;
                let extra_data_len = ei.extra_data_length as usize;
                let base_fee = alloy_primitives::U256::from_limbs(ei.base_fee_per_gas.limbs);

                let block_data = firehose::BlockData{
                    number: block_number,
                    hash: B256::ZERO,
                    parent_hash: B256::from(block_start.parent_eth_hash.bytes),
                    uncle_hash: B256::from(ei.ommers_hash.bytes),
                    coinbase: alloy_primitives::Address::from(ei.beneficiary.bytes),
                    root: B256::ZERO,
                    tx_hash: B256::from(ei.transactions_root.bytes),
                    receipt_hash: B256::ZERO,
                    bloom: alloy_primitives::Bloom::ZERO,
                    difficulty: alloy_primitives::U256::from(ei.difficulty),
                    gas_limit: ei.gas_limit,
                    gas_used: 0,
                    time: ei.timestamp,
                    extra: alloy_primitives::Bytes::copy_from_slice(&ei.extra_data.bytes[..extra_data_len]),
                    mix_digest: B256::from(ei.prev_randao.bytes),
                    nonce: u64::from_le_bytes(ei.nonce.bytes),
                    base_fee: if base_fee.is_zero() { None } else { Some(base_fee) },
                    uncles: vec![],
                    size: 0,
                    withdrawals: vec![],
                    withdrawals_root: Some(B256::from(ei.withdrawals_root.bytes)),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    parent_beacon_root: Some(B256::ZERO),
                    requests_hash: Some(B256::ZERO),
                    tx_dependency: None,
                };

                self.tracer.on_block_start(firehose::BlockEvent { block: block_data, finalized: Some(firehose::FinalizedBlockRef{
                    number: self.last_finalized_block,
                    hash: None
                }) });
            }
            ExecEvent::BlockEnd(block_end) => {
                tracing::debug!("block end (hash={:?})", B256::from(block_end.eth_block_hash.bytes));

                self.tracer.set_block_hash(B256::from(block_end.eth_block_hash.bytes));
                let eo = &block_end.exec_output;
                self.tracer.set_block_header_end_data(
                    B256::from(eo.state_root.bytes),
                    B256::from(eo.receipts_root.bytes),
                    alloy_primitives::Bloom::from_slice(&eo.logs_bloom.bytes),
                    eo.gas_used,
                );
                self.tracer.on_block_end(None);
            }
            ExecEvent::TxnHeaderStart {
                txn_index,
                txn_header_start,
                data_bytes,
                blob_bytes,
            } => {
                tracing::debug!("txn header start (txn={} hash={:?})", txn_index, B256::from(txn_header_start.txn_hash.bytes));

                if self.tracer.is_in_system_call() {
                    self.tracer.on_system_call_end();
                }

                let h = &txn_header_start.txn_header;
                let blob_gas_fee_cap = alloy_primitives::U256::from_limbs(h.max_fee_per_blob_gas.limbs);
                let tx_type = TxType::try_from(h.txn_type as u8).unwrap_or(TxType::Legacy);
                // max_fee_per_gas and max_priority_fee_per_gas only apply to EIP-1559
                let is_eip1559 = h.txn_type >= 2;
                let tx_event = firehose::TxEvent {
                    tx_type,
                    hash: B256::from(txn_header_start.txn_hash.bytes),
                    from: alloy_primitives::Address::from(txn_header_start.sender.bytes),
                    to: if h.is_contract_creation { Some(alloy_primitives::Address::ZERO) } else { Some(alloy_primitives::Address::from(h.to.bytes)) },
                    input: alloy_primitives::Bytes::copy_from_slice(&data_bytes),
                    value: alloy_primitives::U256::from_limbs(h.value.limbs),
                    gas: h.gas_limit,
                    gas_price: alloy_primitives::U256::from_limbs(h.max_fee_per_gas.limbs),
                    max_fee_per_gas: if is_eip1559 { Some(alloy_primitives::U256::from_limbs(h.max_fee_per_gas.limbs)) } else { None },
                    max_priority_fee_per_gas: if is_eip1559 { Some(alloy_primitives::U256::from_limbs(h.max_priority_fee_per_gas.limbs)) } else { None },
                    nonce: h.nonce,
                    index: txn_index as u32,
                    v: Some(alloy_primitives::Bytes::copy_from_slice(&[h.y_parity as u8])),
                    r: B256::from(alloy_primitives::U256::from_limbs(h.r.limbs).to_be_bytes()),
                    s: B256::from(alloy_primitives::U256::from_limbs(h.s.limbs).to_be_bytes()),
                    blob_gas_fee_cap: if blob_gas_fee_cap.is_zero() { None } else { Some(blob_gas_fee_cap) },
                    blob_hashes: blob_bytes.chunks(32).map(|c| B256::from_slice(c)).collect(),
                    access_list: vec![],
                    set_code_authorizations: vec![],
                };
                self.pending_tx_events.insert(txn_index, tx_event);
            }
            ExecEvent::TxnAccessListEntry {
                txn_index,
                txn_access_list_entry,
                storage_key_bytes,
            } => {
                tracing::debug!("txn access list entry (txn={} addr={:?} keys={})", txn_index, alloy_primitives::Address::from(txn_access_list_entry.entry.address.bytes), txn_access_list_entry.entry.storage_key_count);

                self.ensure_in_block_and_in_pending(txn_index, "TxnAccessListEntry");

                if let Some(tx_event) = self.pending_tx_events.get_mut(&txn_index) {
                    let addr = alloy_primitives::Address::from(txn_access_list_entry.entry.address.bytes);
                    let storage_keys = storage_key_bytes
                        .chunks(32)
                        .map(|c| B256::from_slice(c))
                        .collect();
                    tx_event.access_list.push(AccessTuple { address: addr, storage_keys });
                }
            }
            ExecEvent::TxnAuthListEntry {
                txn_index,
                txn_auth_list_entry,
            } => {
                tracing::debug!("txn auth list entry (txn={} addr={:?})", txn_index, alloy_primitives::Address::from(txn_auth_list_entry.entry.address.bytes));

                self.ensure_in_block_and_in_pending(txn_index, "TxnAuthListEntry");

                if let Some(tx_event) = self.pending_tx_events.get_mut(&txn_index) {
                    let e = &txn_auth_list_entry.entry;
                    tx_event.set_code_authorizations.push(SetCodeAuthorization {
                        chain_id: B256::from(alloy_primitives::U256::from_limbs(e.chain_id.limbs).to_be_bytes()),
                        address: alloy_primitives::Address::from(e.address.bytes),
                        nonce: e.nonce,
                        v: e.y_parity as u32,
                        r: B256::from(alloy_primitives::U256::from_limbs(e.r.limbs).to_be_bytes()),
                        s: B256::from(alloy_primitives::U256::from_limbs(e.s.limbs).to_be_bytes()),
                    });
                }
            }
            ExecEvent::TxnEvmOutput { txn_index, output } => {
                tracing::debug!("txn evm output (txn={} gas_used={} status={} call_frame_count={})", txn_index, output.receipt.gas_used, output.receipt.status, output.call_frame_count);

                self.ensure_in_block_and_in_pending(txn_index, "TxnEvmOutput");
                self.current_txn_index = txn_index as u32;

                if let Some(tx_event) = self.pending_tx_events.remove(&txn_index) {
                    self.tracer.on_tx_start(tx_event, None);
                }
                self.tx_end_receipt = Some(output);
            }
            ExecEvent::TxnEnd => {
                tracing::info!("txn end");

                let mut open_calls = std::mem::take(&mut self.tracer.open_calls);
                open_calls.flush(0, &mut self.tracer);
                self.tracer.open_calls = open_calls;
                let receipt_logs = std::mem::take(&mut self.pending_receipt_logs);
                let mut bloom = alloy_primitives::Bloom::ZERO;
                for log in &receipt_logs {
                    bloom.accrue_raw_log(log.address, &log.topics);
                }
                let receipt = if let Some(output) = self.tx_end_receipt.take() {
                    self.cumulative_gas_used += output.receipt.gas_used;
                    firehose::ReceiptData{
                        transaction_index: self.current_txn_index,
                        gas_used: output.receipt.gas_used,
                        status: if output.receipt.status { 1 } else { 0 },
                        logs: receipt_logs,
                        logs_bloom: *bloom.0,
                        cumulative_gas_used: self.cumulative_gas_used,
                        blob_gas_used: 0,
                        blob_gas_price: None,
                        state_root: None,
                    }
                } else {
                    firehose::ReceiptData{
                        transaction_index: self.current_txn_index,
                        gas_used: 0,
                        status: 0,
                        logs: receipt_logs,
                        logs_bloom: *bloom.0,
                        cumulative_gas_used: self.cumulative_gas_used,
                        blob_gas_used: 0,
                        blob_gas_price: None,
                        state_root: None,
                    }
                };

                self.tracer.on_tx_end(Some(&receipt), None);
            }
            ExecEvent::TxnLog { txn_index, txn_log, topic_bytes, data_bytes } => {
                tracing::debug!("txn log (txn={} idx={} addr={:?} topics={} data_len={})", txn_index, txn_log.index, alloy_primitives::Address::from(txn_log.address.bytes), txn_log.topic_count, data_bytes.len());

                let mut topics: Vec<B256> = Vec::with_capacity(txn_log.topic_count as usize);
                for i in 0..txn_log.topic_count as usize {
                    let start = i * 32;
                    topics.push(B256::from_slice(&topic_bytes[start..start+32]));
                }
                let addr = alloy_primitives::Address::from(txn_log.address.bytes);
                if !self.tracer.is_in_transaction() {
                    panic!("TxnLog arrived but no transaction is active");
                }

                // Defer log into deferred call state
                self.tracer.on_log(addr, &topics, &data_bytes, txn_log.index);

                // also buffer for receipt construction
                self.pending_receipt_logs.push(firehose::LogData {
                    address: addr,
                    topics,
                    data: alloy_primitives::Bytes::copy_from_slice(&data_bytes),
                    block_index: txn_log.index,
                });
            }
            ExecEvent::TxnCallFrame { txn_index, txn_call_frame, input_bytes, return_bytes } => {
                tracing::debug!("txn call frame (txn={:?} depth={} opcode=0x{:02x} from={:?} to={:?} gas={} gas_used={} status={})", txn_index, txn_call_frame.depth, txn_call_frame.opcode, alloy_primitives::Address::from(txn_call_frame.caller.bytes), alloy_primitives::Address::from(txn_call_frame.call_target.bytes), txn_call_frame.gas, txn_call_frame.gas_used, txn_call_frame.evmc_status);

                if !self.tracer.is_in_transaction() {
                    self.tracer.on_system_call_start();
                }

                let depth = txn_call_frame.depth as i32;
                let from = alloy_primitives::Address::from(txn_call_frame.caller.bytes);
                let to = alloy_primitives::Address::from(txn_call_frame.call_target.bytes);
                let value = alloy_primitives::U256::from_limbs(txn_call_frame.value.limbs);
                let evmc_status = txn_call_frame.evmc_status as i32;
                let err = evmc_status_to_error(evmc_status);

                // For root-level, patch transaction's "to" with the
                // deployed address, for depth > 0, the deployed address is carried
                // via on_call_enter
                if depth == 0 && (txn_call_frame.opcode == Opcode::Create as u8 || txn_call_frame.opcode == Opcode::Create2 as u8) {
                    self.tracer.set_transaction_to(to);
                }

                // SELFDESTRUCT is atomic (enter + opcode + exit with no deferral)
                if txn_call_frame.opcode == Opcode::SelfDestruct as u8 {
                    let mut open_calls = std::mem::take(&mut self.tracer.open_calls);
                    open_calls.flush(depth, &mut self.tracer);
                    self.tracer.open_calls = open_calls;
                    self.tracer.on_call_enter(depth, Opcode::Call as u8, from, to, &input_bytes, txn_call_frame.gas, value);
                    self.tracer.on_opcode(0, Opcode::SelfDestruct as u8, txn_call_frame.gas, txn_call_frame.gas_used, &[], depth, None);
                    self.tracer.on_call_exit(depth, &return_bytes, txn_call_frame.gas_used, err.as_ref().map(|e| e as &dyn std::error::Error), evmc_status != 0);
                } else {
                    let opcode = txn_call_frame.opcode;
                    let gas = txn_call_frame.gas;
                    let gas_used = txn_call_frame.gas_used;
                    let return_bytes = return_bytes.into_vec();

                    self.tracer.on_call(depth, opcode, from, to, &input_bytes, gas, value, return_bytes.clone(), gas_used, err.clone(), false);

                    // Successful CREATE: emit code change (output is the deployed bytecode)
                    let is_create = opcode == Opcode::Create as u8 || opcode == Opcode::Create2 as u8;
                    if is_create && err.is_none() && !return_bytes.is_empty() {
                        let empty_hash = firehose::utils::hash_bytes(&[]);
                        let new_hash = firehose::utils::hash_bytes(&return_bytes);
                        self.tracer.on_code_change(to, empty_hash, new_hash, &[], &return_bytes);
                    }
                }
            }
            ExecEvent::AccountAccessListHeader(header) => {
                tracing::debug!("account access list header (ctx={} count={})", header.access_context, header.entry_count);

                if header.access_context == AccountAccessContext::Transaction as u8 {
                    // flush all sub-calls but keep the root call open
                    let mut open_calls = std::mem::take(&mut self.tracer.open_calls);
                    open_calls.flush(1, &mut self.tracer);
                    self.tracer.open_calls = open_calls;
                }
            }
            ExecEvent::AccountAccess(account_access) => {
                tracing::debug!("account access (addr={:?} balance_modified={} nonce_modified={})", alloy_primitives::Address::from(account_access.address.bytes), account_access.is_balance_modified, account_access.is_nonce_modified);

                if self.tracer.is_in_system_call() {
                    self.system_call_account_access_count += 1;
                }

                let addr = alloy_primitives::Address::from(account_access.address.bytes);
                if account_access.is_balance_modified {
                    use firehose::pb::sf::ethereum::r#type::v2::balance_change::Reason;
                    self.tracer.on_balance_change(addr, alloy_primitives::U256::from_limbs(account_access.prestate.balance.limbs), alloy_primitives::U256::from_limbs(account_access.modified_balance.limbs), Reason::MonadTxPostState);
                }
                if account_access.is_nonce_modified {
                    self.tracer.on_nonce_change(addr, account_access.prestate.nonce, account_access.modified_nonce);
                }
            }
            ExecEvent::StorageAccess(storage_access) => {
                tracing::debug!("storage access (addr={:?} modified={} transient={})", alloy_primitives::Address::from(storage_access.address.bytes), storage_access.modified, storage_access.transient);

                if storage_access.modified && !storage_access.transient {
                    let addr = alloy_primitives::Address::from(storage_access.address.bytes);
                    self.tracer.on_storage_change(addr, B256::from(storage_access.key.bytes), B256::from(storage_access.start_value.bytes), B256::from(storage_access.end_value.bytes));
                }
            }

            ExecEvent::BlockSystemCallStart { system_call_start, input_bytes } => {
                tracing::debug!("block system call start (from={:?} to={:?} opcode=0x{:02x} gas={})", alloy_primitives::Address::from(system_call_start.caller.bytes), alloy_primitives::Address::from(system_call_start.call_target.bytes), system_call_start.opcode, system_call_start.gas);

                self.system_call_account_access_count = 0;
                self.tracer.on_system_call_start();
                let from = alloy_primitives::Address::from(system_call_start.caller.bytes);
                let to = alloy_primitives::Address::from(system_call_start.call_target.bytes);
                self.tracer.on_call_enter(0, system_call_start.opcode, from, to, &input_bytes, system_call_start.gas, alloy_primitives::U256::ZERO);
            }
            ExecEvent::BlockSystemCallEnd { system_call_end, return_bytes } => {
                tracing::debug!("block system call end (gas_used={} status={} num_account_accesses={})", system_call_end.gas_used, system_call_end.evmc_status, system_call_end.num_account_accesses);

                self.ensure_system_call_account_access_count(system_call_end.num_account_accesses);
                let err = evmc_status_to_error(system_call_end.evmc_status as i32);
                self.tracer.on_call_exit(0, &return_bytes, system_call_end.gas_used, err.as_ref().map(|e| e as &dyn std::error::Error), system_call_end.evmc_status != 0);
                self.tracer.on_system_call_end();
            }

            ExecEvent::RecordError(e) => {
                tracing::warn!("record error ({:?})", e);
            }
            ExecEvent::BlockReject(e) => {
                tracing::warn!("block reject (code={:?})", e);
            }
            ExecEvent::BlockPerfEvmEnter => {
                tracing::debug!("block perf evm enter");
            }
            ExecEvent::BlockPerfEvmExit => {
                tracing::debug!("block perf evm exit");
            }
            ExecEvent::BlockFinalized(tag) => {
                tracing::info!("block finalized (block={} prev_last_finalized={})", tag.block_number, self.last_finalized_block);
                self.last_finalized_block = self.last_finalized_block.max(tag.block_number);
            }
            ExecEvent::BlockQC(e) => {
                tracing::info!("block qc (block={} round={} epoch={})", e.block_tag.block_number, e.round, e.epoch);
            }
            ExecEvent::BlockVerified(e) => {
                tracing::info!("block verified (block={})", e.block_number);
            }
            ExecEvent::TxnHeaderEnd => {
                tracing::debug!("txn header end");
            }
            ExecEvent::TxnReject { txn_index, reject } => {
                tracing::warn!("txn reject (txn={} code={:?})", txn_index, reject);
            }
            ExecEvent::TxnPerfEvmEnter => {
                tracing::debug!("txn perf evm enter");
            }
            ExecEvent::TxnPerfEvmExit => {
                tracing::debug!("txn perf evm exit");
            }
            ExecEvent::EvmError(e) => {
                tracing::warn!("evm error (domain={} status={})", e.domain_id, e.status_code);
            }
        }
        Ok(())
    }

    async fn process_event(&mut self, event: ExecEvent) -> Result<()> {
        if self.config.no_op {
            let block_num = if let ExecEvent::BlockStart(ref bs) = event {
                bs.eth_block_input.number
            } else {
                0
            };
            info!("NO-OP: block={}", block_num);
            return Ok(());
        }

        self.add_event(event)?;

        // TEMP
        // if let Some(block) = self.event_mapper.process_event(event).await? {
        //     let elapsed = start.elapsed();

        //     // Update HEAD block number
        //     self.current_head = block.number;

        //     // Calculate LIB
        //     let lib = if self.current_head > self.lib_delta {
        //         self.current_head - self.lib_delta
        //     } else {
        //         0
        //     };
        //     self.finality.set_last_finalized_block(lib);

        //     // Log block summary with metrics
        //     let hash_short = if block.hash.len() >= 6 {
        //         format!("{}..{}",
        //             hex::encode(&block.hash[..3]),
        //             hex::encode(&block.hash[block.hash.len()-3..]))
        //     } else {
        //         hex::encode(&block.hash)
        //     };

        //     let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
        //     let timestamp = block.header.as_ref()
        //         .and_then(|h| h.timestamp.as_ref())
        //         .map(|ts| ts.seconds)
        //         .unwrap_or(0);

        //     let total_calls: usize = block.transaction_traces.iter().map(|tx| tx.calls.len()).sum();
        //     let total_logs: usize = block.transaction_traces.iter()
        //         .filter_map(|tx| tx.receipt.as_ref())
        //         .map(|r| r.logs.len())
        //         .sum();

        //     info!(
        //         "Processed new block number={} hash={} lib={} size={} txs={} calls={} logs={} timestamp={} elapsed={:.2}ms",
        //         block.number,
        //         hash_short,
        //         lib,
        //         block.size,
        //         block.transaction_traces.len(),
        //         total_calls,
        //         total_logs,
        //         timestamp,
        //         elapsed_ms
        //     );

        //     // Print the completed block
        //     print_block_to_firehose(&mut stdout(), *block, &self.finality);
        // }

        Ok(())
    }
}
