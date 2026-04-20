//! Main Firehose tracer implementation

use crate::{MonadConsumer, MonadConsumerPlugin, TRACER_NAME, TRACER_VERSION};
use alloy_primitives::{Address, Bytes, B256};
use eyre::Result;
use firehose::{
    types::{AccessTuple, SetCodeAuthorization, StateReader, TxType},
    Tracer,
};
use futures_util::StreamExt;
use monad_exec_events::ExecEvent;
use std::collections::HashMap;
use tracing::{error, info};

struct DelegationStateReader {
    delegation_code: HashMap<Address, Bytes>,
}

impl DelegationStateReader {
    fn new() -> Self {
        Self {
            delegation_code: HashMap::new(),
        }
    }

    fn set_code(&mut self, addr: Address, code: Vec<u8>) {
        if code.is_empty() {
            self.delegation_code.remove(&addr);
        } else {
            self.delegation_code.insert(addr, Bytes::from(code));
        }
    }

    fn snapshot(&self) -> SnapshotStateReader {
        SnapshotStateReader {
            delegation_code: self.delegation_code.clone(),
        }
    }
}

/// An owned snapshot of DelegationStateReader suitable for passing to on_tx_start.
struct SnapshotStateReader {
    delegation_code: HashMap<Address, Bytes>,
}

impl StateReader for SnapshotStateReader {
    fn get_nonce(&self, _address: Address) -> u64 {
        0
    }

    fn get_code(&self, address: Address) -> Bytes {
        self.delegation_code
            .get(&address)
            .cloned()
            .unwrap_or_default()
    }

    fn exists(&self, _address: Address) -> bool {
        false
    }
}

/// Monad is a Prague-era chain (EIP-7702 active from genesis).
fn monad_chain_config(chain_id: u64) -> firehose::ChainConfig {
    firehose::ChainConfig {
        chain_id,
        shanghai_time: Some(0),
        cancun_time: Some(0),
        prague_time: Some(0),
        verkle_time: None,
    }
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
        _ => {
            return Some(firehose::StringError(format!(
                "unknown error (status {})",
                evmc_status
            )))
        }
    };
    Some(firehose::StringError(msg.to_string()))
}

/// Main Firehose tracer for Monad
pub struct FirehosePlugin {
    config: MonadConsumerPlugin,
    consumer: Option<MonadConsumer>,
    pub tracer: Tracer,
    tx_end_receipt: Option<monad_exec_events::ffi::monad_exec_txn_evm_output>,
    pending_tx_events: HashMap<usize, firehose::TxEvent>,
    // Logs buffered for receipt construction
    // This duplication could be avoided by reading the logs back from the Firehose tracer
    // internal call state instead of buffering them separately here
    pending_receipt_logs: Vec<firehose::LogData>,
    // EIP-7702: delegation code changes buffered from TxnAuthListEntry (is_valid_authority=true),
    // emitted as on_code_change when the corresponding AccountAccess arrives (is_nonce_modified=true)
    pending_delegation_code_changes: HashMap<Address, Vec<Vec<u8>>>,
    delegation_state: DelegationStateReader,
    block_txn_count: u64,
    last_finalized_block: u64,
    current_txn_index: u32,
    cumulative_gas_used: u64,
    system_call_account_access_count: u32,
    expected_call_frames: u32,
    current_call_frame_index: u32,
}

impl FirehosePlugin {
    pub fn new(config: MonadConsumerPlugin) -> Self {
        Self {
            config,
            consumer: None,
            tracer: Tracer::new(firehose::Config::new()),
            last_finalized_block: 0,
            tx_end_receipt: None,
            pending_tx_events: HashMap::new(),
            pending_receipt_logs: Vec::new(),
            pending_delegation_code_changes: HashMap::new(),
            delegation_state: DelegationStateReader::new(),
            block_txn_count: 0,
            current_txn_index: 0,
            cumulative_gas_used: 0,
            system_call_account_access_count: 0,
            expected_call_frames: 0,
            current_call_frame_index: 0,
        }
    }

    pub fn new_with_writer(
        config: MonadConsumerPlugin,
        writer: Box<dyn std::io::Write + Send>,
    ) -> Self {
        Self {
            config,
            consumer: None,
            tracer: Tracer::new_with_writer(firehose::Config::new(), writer),
            last_finalized_block: 0,
            tx_end_receipt: None,
            pending_tx_events: HashMap::new(),
            pending_receipt_logs: Vec::new(),
            pending_delegation_code_changes: HashMap::new(),
            delegation_state: DelegationStateReader::new(),
            block_txn_count: 0,
            current_txn_index: 0,
            cumulative_gas_used: 0,
            system_call_account_access_count: 0,
            expected_call_frames: 0,
            current_call_frame_index: 0,
        }
    }

    fn ensure_in_block_and_in_pending(&self, txn_index: usize, event_name: &str) {
        self.tracer.ensure_in_block();
        if !self.pending_tx_events.contains_key(&txn_index) {
            panic!(
                "{} for txn_index={} but no pending TxEvent",
                event_name, txn_index
            );
        }
    }

    fn ensure_system_call_account_access_count(&self, expected: u32) {
        if self.system_call_account_access_count != expected {
            panic!(
                "system call account access count mismatch: got {} expected {}",
                self.system_call_account_access_count, expected,
            );
        }
    }

    pub fn on_blockchain_init(&mut self, node_name: &str, node_version: &str) {
        let chain_config = monad_chain_config(self.config.chain_id);
        self.tracer
            .on_blockchain_init(node_name, node_version, chain_config);
    }

    pub fn with_consumer(mut self, consumer: MonadConsumer) -> Self {
        self.consumer = Some(consumer);
        self
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Firehose tracer");

        let chain_config = monad_chain_config(self.config.chain_id);
        self.tracer
            .on_blockchain_init(TRACER_NAME, TRACER_VERSION, chain_config);

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
        // Drop events until we see the first BlockStart. This handles two cases:
        // 1. The ring replay starts mid-block (oldest buffered event is not a BlockStart)
        // 2. A Gap was encountered and the reader reset to the current tail mid-block
        if !self.tracer.is_in_block()
            && !matches!(
                event,
                ExecEvent::BlockStart(_) | ExecEvent::BlockFinalized(_)
            )
        {
            return Ok(());
        }

        match event {
            ExecEvent::BlockStart(block_start) => {
                tracing::info!(
                    "block start (number={} timestamp={} txn_count={})",
                    block_start.eth_block_input.number,
                    block_start.eth_block_input.timestamp,
                    block_start.eth_block_input.txn_count
                );

                self.block_txn_count = block_start.eth_block_input.txn_count;
                self.current_txn_index = 0;
                self.cumulative_gas_used = 0;

                let block_number = block_start.eth_block_input.number;
                let ei = &block_start.eth_block_input;
                let extra_data_len = ei.extra_data_length as usize;
                let base_fee = alloy_primitives::U256::from_limbs(ei.base_fee_per_gas.limbs);

                let block_data = firehose::BlockData {
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
                    extra: alloy_primitives::Bytes::copy_from_slice(
                        &ei.extra_data.bytes[..extra_data_len],
                    ),
                    mix_digest: B256::from(ei.prev_randao.bytes),
                    nonce: u64::from_le_bytes(ei.nonce.bytes),
                    base_fee: if base_fee.is_zero() {
                        None
                    } else {
                        Some(base_fee)
                    },
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

                self.tracer.on_block_start(firehose::BlockEvent {
                    block: block_data,
                    finalized: Some(firehose::FinalizedBlockRef {
                        number: self.last_finalized_block,
                        hash: None,
                    }),
                });
            }
            ExecEvent::BlockEnd(block_end) => {
                tracing::debug!(
                    "block end (hash={:?})",
                    B256::from(block_end.eth_block_hash.bytes)
                );

                self.tracer
                    .set_block_hash(B256::from(block_end.eth_block_hash.bytes));
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
                tracing::debug!(
                    "txn header start (txn={} hash={:?})",
                    txn_index,
                    B256::from(txn_header_start.txn_hash.bytes)
                );

                let h = &txn_header_start.txn_header;
                let blob_gas_fee_cap =
                    alloy_primitives::U256::from_limbs(h.max_fee_per_blob_gas.limbs);
                let tx_type = TxType::try_from(h.txn_type as u8).unwrap_or(TxType::Legacy);
                // max_fee_per_gas and max_priority_fee_per_gas only apply to EIP-1559
                let is_eip1559 = h.txn_type >= firehose::TxType::DynamicFee as u8;
                let tx_event = firehose::TxEvent {
                    tx_type,
                    hash: B256::from(txn_header_start.txn_hash.bytes),
                    from: alloy_primitives::Address::from(txn_header_start.sender.bytes),
                    to: if h.is_contract_creation {
                        None
                    } else {
                        Some(alloy_primitives::Address::from(h.to.bytes))
                    },
                    input: alloy_primitives::Bytes::copy_from_slice(&data_bytes),
                    value: alloy_primitives::U256::from_limbs(h.value.limbs),
                    gas: h.gas_limit,
                    gas_price: alloy_primitives::U256::from_limbs(h.max_fee_per_gas.limbs),
                    max_fee_per_gas: if is_eip1559 {
                        Some(alloy_primitives::U256::from_limbs(h.max_fee_per_gas.limbs))
                    } else {
                        None
                    },
                    max_priority_fee_per_gas: if is_eip1559 {
                        Some(alloy_primitives::U256::from_limbs(
                            h.max_priority_fee_per_gas.limbs,
                        ))
                    } else {
                        None
                    },
                    nonce: h.nonce,
                    index: txn_index as u32,
                    v: Some(alloy_primitives::Bytes::copy_from_slice(
                        &[h.y_parity as u8],
                    )),
                    r: B256::from(alloy_primitives::U256::from_limbs(h.r.limbs).to_be_bytes()),
                    s: B256::from(alloy_primitives::U256::from_limbs(h.s.limbs).to_be_bytes()),
                    blob_gas_fee_cap: if blob_gas_fee_cap.is_zero() {
                        None
                    } else {
                        Some(blob_gas_fee_cap)
                    },
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
                tracing::debug!(
                    "txn access list entry (txn={} addr={:?} keys={})",
                    txn_index,
                    alloy_primitives::Address::from(txn_access_list_entry.entry.address.bytes),
                    txn_access_list_entry.entry.storage_key_count
                );

                self.ensure_in_block_and_in_pending(txn_index, "TxnAccessListEntry");

                if let Some(tx_event) = self.pending_tx_events.get_mut(&txn_index) {
                    let addr =
                        alloy_primitives::Address::from(txn_access_list_entry.entry.address.bytes);
                    let storage_keys = storage_key_bytes
                        .chunks(32)
                        .map(|c| B256::from_slice(c))
                        .collect();
                    tx_event.access_list.push(AccessTuple {
                        address: addr,
                        storage_keys,
                    });
                }
            }
            ExecEvent::TxnAuthListEntry {
                txn_index,
                txn_auth_list_entry,
            } => {
                tracing::debug!(
                    "txn auth list entry (txn={} addr={:?})",
                    txn_index,
                    alloy_primitives::Address::from(txn_auth_list_entry.entry.address.bytes)
                );

                self.ensure_in_block_and_in_pending(txn_index, "TxnAuthListEntry");

                if let Some(tx_event) = self.pending_tx_events.get_mut(&txn_index) {
                    let e = &txn_auth_list_entry.entry;
                    tx_event.set_code_authorizations.push(SetCodeAuthorization {
                        chain_id: B256::from(
                            alloy_primitives::U256::from_limbs(e.chain_id.limbs).to_be_bytes(),
                        ),
                        address: alloy_primitives::Address::from(e.address.bytes),
                        nonce: e.nonce,
                        v: e.y_parity as u32,
                        r: B256::from(alloy_primitives::U256::from_limbs(e.r.limbs).to_be_bytes()),
                        s: B256::from(alloy_primitives::U256::from_limbs(e.s.limbs).to_be_bytes()),
                    });
                }

                // EIP-7702: buffer delegation code change for valid authorities.
                // AccountAccess (is_nonce_modified=true) will confirm the auth was applied.
                if txn_auth_list_entry.is_valid_authority {
                    let authority =
                        alloy_primitives::Address::from(txn_auth_list_entry.authority.bytes);
                    let target =
                        alloy_primitives::Address::from(txn_auth_list_entry.entry.address.bytes);
                    let new_code = if target.is_zero() {
                        vec![]
                    } else {
                        let mut code = vec![0xef, 0x01, 0x00];
                        code.extend_from_slice(target.as_slice());
                        code
                    };
                    self.pending_delegation_code_changes
                        .entry(authority)
                        .or_default()
                        .push(new_code);
                }
            }
            ExecEvent::TxnEvmOutput { txn_index, output } => {
                tracing::debug!(
                    "txn evm output (txn={} gas_used={} status={} call_frame_count={})",
                    txn_index,
                    output.receipt.gas_used,
                    output.receipt.status,
                    output.call_frame_count
                );

                self.ensure_in_block_and_in_pending(txn_index, "TxnEvmOutput");
                self.current_txn_index = txn_index as u32;
                self.expected_call_frames = output.call_frame_count;
                self.current_call_frame_index = 0;

                if let Some(tx_event) = self.pending_tx_events.remove(&txn_index) {
                    // EIP-7702: pass current delegation state so the shared tracer can
                    // populate addressDelegatesTo on calls to already-delegated EOAs.
                    let state_reader = Box::new(self.delegation_state.snapshot());
                    self.tracer.on_tx_start(tx_event, Some(state_reader));
                }
                self.tx_end_receipt = Some(output);
            }
            ExecEvent::TxnEnd => {
                tracing::debug!("txn end");

                let receipt_logs = std::mem::take(&mut self.pending_receipt_logs);
                let mut bloom = alloy_primitives::Bloom::ZERO;
                for log in &receipt_logs {
                    bloom.accrue_raw_log(log.address, &log.topics);
                }
                let receipt = if let Some(output) = self.tx_end_receipt.take() {
                    self.cumulative_gas_used += output.receipt.gas_used;
                    firehose::ReceiptData {
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
                    firehose::ReceiptData {
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

                // EIP-7702: discard unconfirmed delegations (tx reverted or auth never applied)
                self.pending_delegation_code_changes.clear();
                self.tracer.on_tx_end(Some(&receipt), None);
            }
            ExecEvent::TxnLog {
                txn_index,
                txn_log,
                topic_bytes,
                data_bytes,
            } => {
                tracing::debug!(
                    "txn log (txn={} idx={} addr={:?} topics={} data_len={})",
                    txn_index,
                    txn_log.index,
                    alloy_primitives::Address::from(txn_log.address.bytes),
                    txn_log.topic_count,
                    data_bytes.len()
                );

                let mut topics: Vec<B256> = Vec::with_capacity(txn_log.topic_count as usize);
                for i in 0..txn_log.topic_count as usize {
                    let start = i * 32;
                    topics.push(B256::from_slice(&topic_bytes[start..start + 32]));
                }
                let addr = alloy_primitives::Address::from(txn_log.address.bytes);
                if !self.tracer.is_in_transaction() {
                    panic!("TxnLog arrived but no transaction is active");
                }

                // Defer log into deferred call state
                self.tracer
                    .on_log(addr, &topics, &data_bytes, txn_log.index);

                // also buffer for receipt construction
                self.pending_receipt_logs.push(firehose::LogData {
                    address: addr,
                    topics,
                    data: alloy_primitives::Bytes::copy_from_slice(&data_bytes),
                    block_index: txn_log.index,
                });
            }
            ExecEvent::TxnCallFrame {
                txn_index,
                txn_call_frame,
                input_bytes,
                return_bytes,
            } => {
                tracing::debug!("txn call frame (txn={:?} depth={} opcode=0x{:02x} from={:?} to={:?} gas={} gas_used={} status={})", txn_index, txn_call_frame.depth, txn_call_frame.opcode, alloy_primitives::Address::from(txn_call_frame.caller.bytes), alloy_primitives::Address::from(txn_call_frame.call_target.bytes), txn_call_frame.gas, txn_call_frame.gas_used, txn_call_frame.evmc_status);

                let depth = txn_call_frame.depth as i32;
                let from = alloy_primitives::Address::from(txn_call_frame.caller.bytes);
                let to = alloy_primitives::Address::from(txn_call_frame.call_target.bytes);
                let value = alloy_primitives::U256::from_limbs(txn_call_frame.value.limbs);
                let evmc_status = txn_call_frame.evmc_status as i32;
                let err = evmc_status_to_error(evmc_status);

                self.current_call_frame_index += 1;
                let is_last = self.current_call_frame_index == self.expected_call_frames;

                let opcode = txn_call_frame.opcode;
                let gas = txn_call_frame.gas;
                let gas_used = txn_call_frame.gas_used;
                let return_bytes = return_bytes.into_vec();

                self.tracer.on_call(
                    depth,
                    opcode,
                    from,
                    to,
                    &input_bytes,
                    gas,
                    value,
                    return_bytes,
                    gas_used,
                    err,
                    is_last,
                );
            }
            ExecEvent::AccountAccessListHeader(header) => {
                tracing::debug!(
                    "account access list header (ctx={} count={})",
                    header.access_context,
                    header.entry_count
                );
            }
            ExecEvent::AccountAccess(account_access) => {
                tracing::debug!(
                    "account access (addr={:?} balance_modified={} nonce_modified={})",
                    alloy_primitives::Address::from(account_access.address.bytes),
                    account_access.is_balance_modified,
                    account_access.is_nonce_modified
                );

                if self.tracer.is_in_system_call() {
                    self.system_call_account_access_count += 1;
                }

                let addr = alloy_primitives::Address::from(account_access.address.bytes);
                if account_access.is_balance_modified {
                    use firehose::pb::sf::ethereum::r#type::v2::balance_change::Reason;
                    self.tracer.on_balance_change(
                        addr,
                        alloy_primitives::U256::from_limbs(account_access.prestate.balance.limbs),
                        alloy_primitives::U256::from_limbs(account_access.modified_balance.limbs),
                        Reason::MonadTxPostState,
                    );
                }
                if account_access.is_nonce_modified {
                    if let Some(new_codes) = self.pending_delegation_code_changes.remove(&addr) {
                        // EIP-7702: one synthetic nonce+code change per applied auth entry.
                        let mut current_nonce = account_access.prestate.nonce;
                        let old_hash = B256::from(account_access.prestate.code_hash.bytes);
                        for new_code in new_codes {
                            self.tracer
                                .on_nonce_change(addr, current_nonce, current_nonce + 1);
                            let new_hash = firehose::utils::hash_bytes(&new_code);
                            self.tracer
                                .on_code_change(addr, old_hash, new_hash, &[], &new_code);
                            self.delegation_state.set_code(addr, new_code);
                            current_nonce += 1;
                        }
                        // remaining bump if addr was also the tx sender
                        if current_nonce < account_access.modified_nonce {
                            self.tracer.on_nonce_change(
                                addr,
                                current_nonce,
                                account_access.modified_nonce,
                            );
                        }
                    } else {
                        self.tracer.on_nonce_change(
                            addr,
                            account_access.prestate.nonce,
                            account_access.modified_nonce,
                        );
                    }
                }
            }
            ExecEvent::StorageAccess(storage_access) => {
                tracing::debug!(
                    "storage access (addr={:?} modified={} transient={})",
                    alloy_primitives::Address::from(storage_access.address.bytes),
                    storage_access.modified,
                    storage_access.transient
                );

                if storage_access.modified && !storage_access.transient {
                    let addr = alloy_primitives::Address::from(storage_access.address.bytes);
                    self.tracer.on_storage_change(
                        addr,
                        B256::from(storage_access.key.bytes),
                        B256::from(storage_access.start_value.bytes),
                        B256::from(storage_access.end_value.bytes),
                    );
                }
            }

            ExecEvent::BlockSystemCallStart {
                system_call_start,
                input_bytes,
            } => {
                tracing::debug!(
                    "block system call start (from={:?} to={:?} opcode=0x{:02x} gas={})",
                    alloy_primitives::Address::from(system_call_start.caller.bytes),
                    alloy_primitives::Address::from(system_call_start.call_target.bytes),
                    system_call_start.opcode,
                    system_call_start.gas
                );

                self.system_call_account_access_count = 0;
                self.tracer.on_system_call_start();
                let from = alloy_primitives::Address::from(system_call_start.caller.bytes);
                let to = alloy_primitives::Address::from(system_call_start.call_target.bytes);
                self.tracer.on_call_enter(
                    0,
                    system_call_start.opcode,
                    from,
                    to,
                    &input_bytes,
                    system_call_start.gas,
                    alloy_primitives::U256::ZERO,
                );
            }
            ExecEvent::BlockSystemCallEnd {
                system_call_end,
                return_bytes,
            } => {
                tracing::debug!(
                    "block system call end (gas_used={} status={} num_account_accesses={})",
                    system_call_end.gas_used,
                    system_call_end.evmc_status,
                    system_call_end.num_account_accesses
                );

                self.ensure_system_call_account_access_count(system_call_end.num_account_accesses);
                let err = evmc_status_to_error(system_call_end.evmc_status as i32);
                self.tracer.on_call_exit(
                    0,
                    &return_bytes,
                    system_call_end.gas_used,
                    err.as_ref().map(|e| e as &dyn std::error::Error),
                    system_call_end.evmc_status != 0,
                );
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
                tracing::debug!(
                    "block finalized (block={} prev_last_finalized={})",
                    tag.block_number,
                    self.last_finalized_block
                );
                self.last_finalized_block = self.last_finalized_block.max(tag.block_number);
            }
            ExecEvent::BlockQC(e) => {
                tracing::info!(
                    "block qc (block={} round={} epoch={})",
                    e.block_tag.block_number,
                    e.round,
                    e.epoch
                );
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
                tracing::warn!(
                    "evm error (domain={} status={})",
                    e.domain_id,
                    e.status_code
                );
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

        Ok(())
    }
}
