//! Main Firehose tracer implementation

use crate::{EventMapper, MonadConsumer, FirehosePluginConfig, TRACER_NAME, TRACER_VERSION};
use alloy_primitives::B256;
use eyre::Result;
use firehose::{types::{AccessTuple, SetCodeAuthorization, TxType}, FinalityStatus, Tracer};
use firehose::printer::print_block_to_firehose;
use futures_util::StreamExt;
use monad_exec_events::ExecEvent;
use std::collections::HashMap;
use std::io::stdout;
use std::time::Instant;
use tracing::{error, info};

/// Main Firehose tracer for Monad
pub struct FirehosePlugin {
    config: FirehosePluginConfig,
    event_mapper: EventMapper,
    consumer: Option<MonadConsumer>,
    pub tracer: Tracer,
    tx_end_receipt: Option<monad_exec_events::ffi::monad_exec_txn_evm_output>,
    pending_tx_events: HashMap<usize, firehose::TxEvent>,
    block_txn_count: u64,
    txn_end_count: usize,
    // TODELETE
    finality: FinalityStatus,
    current_head: u64,
    lib_delta: u64,
}

impl FirehosePlugin {
    pub fn new(config: FirehosePluginConfig) -> Self {
        Self {
            config,
            event_mapper: EventMapper::new(),
            finality: FinalityStatus::default(),
            consumer: None,
            tracer: Tracer::new(firehose::Config::new()),
            current_head: 0,
            lib_delta: 10,
            tx_end_receipt: None,
            pending_tx_events: HashMap::new(),

            block_txn_count: 0,
            txn_end_count: 0,
        }
    }

    pub fn new_with_writer(config: FirehosePluginConfig, writer: Box<dyn std::io::Write + Send>) -> Self {
        Self {
            config,
            event_mapper: EventMapper::new(),
            finality: FinalityStatus::default(),
            consumer: None,
            tracer: Tracer::new_with_writer(firehose::Config::new(), writer),
            current_head: 0,
            lib_delta: 10,
            tx_end_receipt: None,
            pending_tx_events: HashMap::new(),

            block_txn_count: 0,
            txn_end_count: 0,
        }
    }

    pub fn is_epilogue(&self) -> bool {
        self.block_txn_count > 0 && self.txn_end_count >= self.block_txn_count as usize
    }

    fn ensure_in_block_and_in_pending(&self, txn_index: usize, event_name: &str) {
        self.tracer.ensure_in_block();
        if !self.pending_tx_events.contains_key(&txn_index) {
            panic!("{} for txn_index={} but no pending TxEvent", event_name, txn_index);
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
        match event {
            ExecEvent::BlockStart(block_start) => {
                // self.current_txn_idx = None;
                self.block_txn_count = block_start.eth_block_input.txn_count;
                self.txn_end_count = 0;

                let block_number = block_start.eth_block_input.number;
                // Signal for finalized
                let lib = if block_number > self.lib_delta {
                    block_number - self.lib_delta
                } else {
                    0
                };

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
                    blob_gas_used: None,
                    excess_blob_gas: None,
                    parent_beacon_root: None,
                    requests_hash: None,
                    tx_dependency: None,
                };

                self.tracer.on_block_start(firehose::BlockEvent { block: block_data, finalized: Some(firehose::FinalizedBlockRef{
                    number: lib,
                    hash: None
                }) });
            }
            ExecEvent::BlockEnd(block_end) => {
                self.tracer.on_block_end(None);
            }
            ExecEvent::TxnHeaderStart {
                txn_index,
                txn_header_start,
                data_bytes,
                blob_bytes,
            } => {

                let h = &txn_header_start.txn_header;
                let blob_gas_fee_cap = alloy_primitives::U256::from_limbs(h.max_fee_per_blob_gas.limbs);
                let tx_event = firehose::TxEvent {
                    tx_type: TxType::try_from(h.txn_type as u8).unwrap_or(TxType::Legacy),
                    hash: B256::from(txn_header_start.txn_hash.bytes),
                    from: alloy_primitives::Address::from(txn_header_start.sender.bytes),
                    to: if h.is_contract_creation { None } else { Some(alloy_primitives::Address::from(h.to.bytes)) },
                    input: alloy_primitives::Bytes::copy_from_slice(&data_bytes),
                    value: alloy_primitives::U256::from_limbs(h.value.limbs),
                    gas: h.gas_limit,
                    gas_price: alloy_primitives::U256::from_limbs(h.max_fee_per_gas.limbs),
                    max_fee_per_gas: Some(alloy_primitives::U256::from_limbs(h.max_fee_per_gas.limbs)),
                    max_priority_fee_per_gas: Some(alloy_primitives::U256::from_limbs(h.max_priority_fee_per_gas.limbs)),
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

                self.ensure_in_block_and_in_pending(txn_index, "TxnEvmOutput");

                if let Some(tx_event) = self.pending_tx_events.remove(&txn_index) {
                    self.tracer.on_tx_start(tx_event, None);
                }
                self.tx_end_receipt = Some(output);
            }
            ExecEvent::TxnEnd => {
                self.txn_end_count += 1;

                let receipt = if let Some(output) = self.tx_end_receipt.take() {
                    firehose::ReceiptData{
                        transaction_index: 0,
                        gas_used: output.receipt.gas_used,
                        status: if output.receipt.status { 1 } else { 0 },
                        logs: vec![],
                        logs_bloom: [0u8; 256],
                        cumulative_gas_used: output.receipt.gas_used,
                        blob_gas_used: 0,
                        blob_gas_price: None,
                        state_root: None,
                    }
                } else {
                    firehose::ReceiptData{
                        transaction_index: 0,
                        gas_used: 0,
                        status: 0,
                        logs: vec![],
                        logs_bloom: [0u8; 256],
                        cumulative_gas_used: 0,
                        blob_gas_used: 0,
                        blob_gas_price: None,
                        state_root: None,
                    }
                };

                self.tracer.on_tx_end(Some(&receipt), None);
            }
            ExecEvent::TxnLog { txn_index, txn_log, topic_bytes, data_bytes } => {
                let mut topics: Vec<B256> = Vec::with_capacity(txn_log.topic_count as usize);
                for i in 0..txn_log.topic_count as usize {
                    let start = i * 32;
                    topics.push(B256::from_slice(&topic_bytes[start..start+32]));
                }
                let addr = alloy_primitives::Address::from(txn_log.address.bytes);
                if !self.tracer.is_in_transaction() {
                    panic!("TxnLog arrived but no transaction is active");
                }
                if self.tracer.is_in_call() {
                    self.tracer.on_log(addr, &topics, &data_bytes, txn_log.index);
                }
            }
            ExecEvent::TxnCallFrame { txn_index, txn_call_frame, input_bytes, return_bytes } => {

                // if !self.tracer.is_in_transaction() {
                //     self.tracer.on_system_call_start();
                // }

                let from = alloy_primitives::Address::from(txn_call_frame.caller.bytes);
                let to = alloy_primitives::Address::from(txn_call_frame.call_target.bytes);
                let value = alloy_primitives::U256::from_limbs(txn_call_frame.value.limbs);

                self.tracer.on_call_enter(txn_call_frame.depth as i32, txn_call_frame.opcode, from, to, &input_bytes, txn_call_frame.gas, value);
                self.tracer.on_call_exit(txn_call_frame.depth as i32, &return_bytes, txn_call_frame.gas_used, None, txn_call_frame.evmc_status == 2);
            }
            ExecEvent::AccountAccessListHeader(header) => {

                // self.tracer.on_system_call_end();
            }
            ExecEvent::AccountAccess(account_access) => {
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
                if storage_access.modified && !storage_access.transient {
                    let addr = alloy_primitives::Address::from(storage_access.address.bytes);
                    self.tracer.on_storage_change(addr, B256::from(storage_access.key.bytes), B256::from(storage_access.start_value.bytes), B256::from(storage_access.end_value.bytes));
                }
            }

            ExecEvent::BlockSystemCallStart { system_call_start, input_bytes } => {
                self.tracer.on_system_call_start();
                let from = alloy_primitives::Address::from(system_call_start.caller.bytes);
                let to = alloy_primitives::Address::from(system_call_start.call_target.bytes);
                self.tracer.on_call_enter(0, system_call_start.opcode, from, to, &input_bytes, system_call_start.gas, alloy_primitives::U256::ZERO);
            }
            ExecEvent::BlockSystemCallEnd { system_call_end, return_bytes } => {
                self.tracer.on_call_exit(0, &return_bytes, system_call_end.gas_used, None, system_call_end.evmc_status == 2);
                self.tracer.on_system_call_end();
            }

            ExecEvent::RecordError(monad_event_record_error) => todo!(),
            ExecEvent::BlockReject(_) => todo!(),
            ExecEvent::BlockPerfEvmEnter => {}
            ExecEvent::BlockPerfEvmExit => {}
            ExecEvent::BlockQC(monad_exec_block_qc) => todo!(),

            // Consensus level finalized
            ExecEvent::BlockFinalized(monad_exec_block_tag) => todo!(),
            ExecEvent::BlockVerified(monad_exec_block_verified) => todo!(),
            ExecEvent::TxnHeaderEnd => {}
            ExecEvent::TxnReject { txn_index, reject } => {}
            ExecEvent::TxnPerfEvmEnter => {}
            ExecEvent::TxnPerfEvmExit => {}
            ExecEvent::EvmError(monad_exec_evm_error) => todo!(),
        }
        Ok(())
    }

    async fn process_event(&mut self, event: ExecEvent) -> Result<()> {
        if self.config.no_op {
            let block_num = if let ExecEvent::BlockStart(ref bs) = event {
                bs.eth_block_input.number
            } else {
                self.current_head
            };
            info!("NO-OP: block={}", block_num);
            return Ok(());
        }

        // Handle mid-stream panic, we wait for the next BlockStart
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.add_event(event)
        }));

        match res {
            Ok(inner) => inner?,
            Err(panic_payload) => {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| panic_payload.downcast_ref::<String>().map(|s| s.as_str()))
                    .unwrap_or("unknown panic");
                error!("tracer panicked, resetting state: {}", msg);
                self.tracer.reset();
                self.tx_end_receipt = None;
                self.pending_tx_events.clear();
                self.block_txn_count = 0;
                self.txn_end_count = 0;
            }
        }

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
