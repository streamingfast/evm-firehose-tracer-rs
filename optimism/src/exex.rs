use crate::prelude::*;
use firehose;
use reth::chainspec::{EthChainSpec, EthereumHardforks};
use futures_util::StreamExt;
use url::Url;
use tokio_tungstenite::connect_async;
use alloy_primitives::{Address, Bloom, Bytes, B256, U256};
use alloy_rpc_types_engine::PayloadId;
use alloy_eips::eip4895::Withdrawal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use reth_optimism_primitives::OpTransactionSigned;
use alloy_consensus::Transaction as _;
use alloy_consensus::transaction::SignerRecoverable;

/// Custom FlashBlock struct that handles receipt deserialization flexibly
#[derive(Debug, Clone, Deserialize, Serialize)]
struct FlashBlock {
    pub payload_id: PayloadId,
    pub index: u64,
    pub base: Option<ExecutionPayloadBaseV1>,
    pub diff: ExecutionPayloadFlashblockDeltaV1,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Metadata {
    pub block_number: u64,
    pub new_account_balances: BTreeMap<Address, U256>,
    /// Use flexible JSON Value for receipts to avoid deserialization issues
    #[serde(default)]
    pub receipts: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExecutionPayloadBaseV1 {
    pub parent_beacon_block_root: B256,
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub prev_randao: B256,
    #[serde(with = "alloy_serde::quantity")]
    pub block_number: u64,
    #[serde(with = "alloy_serde::quantity")]
    pub gas_limit: u64,
    #[serde(with = "alloy_serde::quantity")]
    pub timestamp: u64,
    pub extra_data: Bytes,
    pub base_fee_per_gas: U256,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExecutionPayloadFlashblockDeltaV1 {
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bloom,
    #[serde(with = "alloy_serde::quantity")]
    pub gas_used: u64,
    pub block_hash: B256,
    pub transactions: Vec<Bytes>,
    pub withdrawals: Vec<Withdrawal>,
    pub withdrawals_root: B256,
}

/// OP-Reth-specific firehose tracer
///
/// This tracer can operate in two modes:
/// 1. Flashblocks mode: Consumes flashblocks from a WebSocket stream (e.g., Base's flashblocks endpoint)
/// 2. Canonical mode: Processes canonical blocks from the local op-reth node
pub async fn firehose_tracer<Node: FullNodeComponents>(
    mut ctx: ExExContext<Node>,
    mut tracer: firehose::Tracer<Node>,
    flashblocks_url: Option<String>,
) -> eyre::Result<()>
where
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
{
    // If flashblocks URL is provided, consume flashblocks instead of canonical blocks
    if let Some(url_str) = flashblocks_url {
        info!(target: "firehose:tracer", url = %url_str, "Launching flashblocks consumer mode");

        // Initialize tracer with chain spec
        tracer.on_init(ctx.config.chain.clone());

        let url = Url::parse(&url_str)?;

        // Connect to WebSocket
        info!(target: "firehose:tracer", "Connecting to flashblocks WebSocket...");
        let (ws_stream, _) = connect_async(url.as_str()).await?;
        info!(target: "firehose:tracer", "Connected to flashblocks WebSocket");

        let (_, mut read) = ws_stream.split();

        // Track current flashblock accumulation
        let mut current_flashblocks: Vec<FlashBlock> = Vec::new();
        let mut current_block_num: Option<u64> = None;

        while let Some(msg) = read.next().await {
            match msg {
                Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                    // Deserialize JSON to FlashBlock
                    match serde_json::from_str::<FlashBlock>(&text) {
                        Ok(flashblock) => {
                            let block_num = flashblock.metadata.block_number;

                            info!(target: "firehose:tracer",
                                flashblock_index = flashblock.index,
                                block_number = block_num,
                                tx_count = flashblock.diff.transactions.len(),
                                gas_used = flashblock.diff.gas_used,
                                "Received flashblock"
                            );

                            // If this is index 0 or a new block number, output previous block and start new one
                            if flashblock.index == 0 || current_block_num != Some(block_num) {
                                // Output the previous accumulated block if any
                                if !current_flashblocks.is_empty() {
                                    output_flashblock_as_fire_block(&mut tracer, &current_flashblocks);
                                }

                                // Start accumulating new block
                                current_flashblocks.clear();
                                current_block_num = Some(block_num);
                            }

                            // Add this flashblock to accumulation
                            current_flashblocks.push(flashblock);
                        }
                        Err(e) => {
                            info!(target: "firehose:tracer", error = ?e, "Failed to deserialize flashblock");
                        }
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Binary(bytes)) => {
                    // Decompress brotli-encoded flashblock
                    let mut decompressed = Vec::new();
                    if let Err(e) = brotli::BrotliDecompress(&mut &bytes[..], &mut decompressed) {
                        info!(target: "firehose:tracer", error = ?e, "Failed to decompress flashblock");
                        continue;
                    }

                    // Deserialize JSON to FlashBlock
                    match serde_json::from_slice::<FlashBlock>(&decompressed) {
                        Ok(flashblock) => {
                            let block_num = flashblock.metadata.block_number;

                            info!(target: "firehose:tracer",
                                flashblock_index = flashblock.index,
                                block_number = block_num,
                                tx_count = flashblock.diff.transactions.len(),
                                gas_used = flashblock.diff.gas_used,
                                "Received flashblock (compressed)"
                            );

                            // If this is index 0 or a new block number, output previous block and start new one
                            if flashblock.index == 0 || current_block_num != Some(block_num) {
                                // Output the previous accumulated block if any
                                if !current_flashblocks.is_empty() {
                                    output_flashblock_as_fire_block(&mut tracer, &current_flashblocks);
                                }

                                // Start accumulating new block
                                current_flashblocks.clear();
                                current_block_num = Some(block_num);
                            }

                            // Add this flashblock to accumulation
                            current_flashblocks.push(flashblock);
                        }
                        Err(e) => {
                            info!(target: "firehose:tracer", error = ?e, "Failed to deserialize flashblock");
                        }
                    }
                }
                Ok(msg) => {
                    info!(target: "firehose:tracer", "Unexpected websocket message type: {:?}", msg);
                }
                Err(e) => {
                    info!(target: "firehose:tracer", error = ?e, "Flashblock stream error");
                    break;
                }
            }
        }

        info!(target: "firehose:tracer", "Flashblock stream ended");
        return Ok(());
    }

    // Canonical block mode - process blocks from local op-reth node
    info!(target: "firehose:tracer", config = ?tracer.config, "Launching canonical block mode");

    // Initialize tracer with chain spec
    tracer.on_init(ctx.config.chain.clone());

    // Get EVM config from components for transaction re-execution
    let evm_config = ctx.components.evm_config().clone();

    while let Some(notification) = ctx.notifications.try_next().await? {
        match &notification {
            ExExNotification::ChainCommitted { new } => {
                // Iterate through blocks with their receipts
                for (block, receipts) in new.blocks_and_receipts() {
                    if block.number() == 1 {
                        tracer.on_genesis_block(ctx.config.chain.genesis());
                    } else {
                        tracer.on_block_start(block);

                        // Get state provider for the parent block to re-execute transactions
                        let parent_hash = block.parent_hash();
                        let state_provider = match ctx.provider().state_by_block_hash(parent_hash) {
                            Ok(provider) => provider,
                            Err(e) => {
                                info!(target: "firehose:tracer", "Failed to get state provider for block {}: {}", block.number(), e);
                                continue;
                            }
                        };

                        // COMPLETELY DISABLED FOR TESTING: Execute system calls using shared helper
                        info!(target: "firehose:tracer", "Skipping execute_system_calls_with_tracing entirely for testing");
                        // if let Err(e) = shared::exex::execute_system_calls_with_tracing(
                        //     &mut tracer,
                        //     block,
                        //     &state_provider,
                        //     &evm_config,
                        //     &ctx.config.chain,
                        // ) {
                        //     info!(target: "firehose:tracer", "Failed to execute system calls: {}", e);
                        // }

                        let tx_count = receipts.len();
                        info!(target: "firehose:tracer", "Processing {} transactions", tx_count);

                        // Process each transaction
                        for (tx_index, receipt) in receipts.iter().enumerate() {
                            info!(target: "firehose:tracer", "Transaction {}", tx_index);

                            // TODO: Check if it's a deposit transaction and skip
                            // TODO: Re-enable transaction tracing once we fix the signature issue
                            info!(target: "firehose:tracer", "Would process transaction {} (currently disabled)", tx_index);
                        }

                        // Finalize and output the block
                        tracer.on_block_end();
                    }
                }
            }
            ExExNotification::ChainReorged { old, new } => {
                info!(from_chain = ?old.range(), to_chain = ?new.range(), "Received reorg");
            }
            ExExNotification::ChainReverted { old } => {
                info!(reverted_chain = ?old.range(), "Received revert");
            }
        };

        if let Some(committed_chain) = notification.committed_chain() {
            ctx.events
                .send(ExExEvent::FinishedHeight(committed_chain.tip().num_hash()))?;
        }
    }

    Ok(())
}

/// Helper function to convert U256 to trimmed big-endian bytes
fn u256_to_bytes(v: U256) -> Vec<u8> {
    let mut bytes = v.to_be_bytes_vec();
    // Trim leading zeros
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    bytes
}

/// Decode transaction bytes to extract transaction fields
fn decode_transaction(tx_bytes: &[u8]) -> eyre::Result<OpTransactionSigned> {
    use alloy_rlp::Decodable;

    // Try to decode as OpTransactionSigned
    let mut buf = tx_bytes;
    OpTransactionSigned::decode(&mut buf).map_err(|e| eyre::eyre!("Failed to decode transaction: {}", e))
}

/// Convert accumulated flashblocks into a FIRE BLOCK output
fn output_flashblock_as_fire_block<Node: FullNodeComponents>(
    tracer: &mut firehose::Tracer<Node>,
    flashblocks: &[FlashBlock],
) where
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
{
    use pb::sf::ethereum::r#type::v2::{
        Block, BlockHeader, BigInt, block::DetailLevel,
        TransactionTrace, transaction_trace::Type as TxType,
        BalanceChange, balance_change::Reason as BalanceReason,
    };
    use alloy_primitives::FixedBytes;
    use prost_types::Timestamp;

    if flashblocks.is_empty() {
        return;
    }

    // Get the last flashblock which has the final state
    let last_fb = flashblocks.last().unwrap();

    // Use the base if available (index 0), otherwise use diff data
    let base_opt = flashblocks.iter().find_map(|fb| fb.base.as_ref());

    if base_opt.is_none() {
        info!(target: "firehose:tracer", block_number = last_fb.metadata.block_number, "Skipping block without base payload");
        return;
    }

    let base = base_opt.unwrap();
     // Use last flashblock for final state
    let diff = &last_fb.diff;

    info!(target: "firehose:tracer",
        block_number = base.block_number,
        flashblock_count = flashblocks.len(),
        tx_count = diff.transactions.len(),
        "Outputting complete block from flashblocks"
    );

    // Process transactions from all flashblocks
    let mut transaction_traces = Vec::new();
    let mut tx_index = 0u64;

    for flashblock in flashblocks {
        for tx_bytes in &flashblock.diff.transactions {
            // Try to decode the transaction to extract proper fields
            let tx_trace = match decode_transaction(tx_bytes) {
                Ok(decoded_tx) => {
                    // Extract transaction hash
                    let tx_hash = decoded_tx.hash();

                    // Get sender address (recover from signature)
                    let from = decoded_tx.recover_signer()
                        .unwrap_or_else(|_| Address::ZERO);

                    // Get recipient address
                    let to = decoded_tx.to().map(|addr| addr.to_vec()).unwrap_or_default();

                    // Determine transaction type, OpTransactionSigned returns OpTxType
                    use reth_optimism_primitives::OpTxType;
                    let tx_type = match decoded_tx.tx_type() {
                        OpTxType::Legacy => TxType::TrxTypeLegacy,
                        OpTxType::Eip2930 => TxType::TrxTypeAccessList,
                        OpTxType::Eip1559 => TxType::TrxTypeDynamicFee,
                         // Map EIP-7702 to DynamicFee for now
                        OpTxType::Eip7702 => TxType::TrxTypeDynamicFee,
                        OpTxType::Deposit => TxType::TrxTypeOptimismDeposit,
                    } as i32;

                    // Get signature components, OpTxEnvelope is an enum so we need to match
                    use op_alloy_consensus::{OpTxEnvelope, TxDeposit};
                    let (v_bytes, r_bytes, s_bytes) = match &decoded_tx {
                        OpTxEnvelope::Legacy(signed) => {
                            let sig = signed.signature();
                            // v() returns bool (y_parity), convert to bytes
                            let v = if sig.v() { 1u8 } else { 0u8 };
                            (vec![v], sig.r().to_be_bytes_vec(), sig.s().to_be_bytes_vec())
                        }
                        OpTxEnvelope::Eip2930(signed) => {
                            let sig = signed.signature();
                            let v = if sig.v() { 1u8 } else { 0u8 };
                            (vec![v], sig.r().to_be_bytes_vec(), sig.s().to_be_bytes_vec())
                        }
                        OpTxEnvelope::Eip1559(signed) => {
                            let sig = signed.signature();
                            let v = if sig.v() { 1u8 } else { 0u8 };
                            (vec![v], sig.r().to_be_bytes_vec(), sig.s().to_be_bytes_vec())
                        }
                        OpTxEnvelope::Eip7702(signed) => {
                            let sig = signed.signature();
                            let v = if sig.v() { 1u8 } else { 0u8 };
                            (vec![v], sig.r().to_be_bytes_vec(), sig.s().to_be_bytes_vec())
                        }
                        OpTxEnvelope::Deposit(_) => {
                            // Deposit transactions dont have signatures
                            let sig = TxDeposit::signature();
                            let v = if sig.v() { 1u8 } else { 0u8 };
                            (vec![v], sig.r().to_be_bytes_vec(), sig.s().to_be_bytes_vec())
                        }
                    };

                    TransactionTrace {
                        to,
                        nonce: decoded_tx.nonce(),
                        gas_price: Some(BigInt {
                            bytes: u256_to_bytes(U256::from(decoded_tx.max_fee_per_gas())),
                        }),
                        gas_limit: decoded_tx.gas_limit(),
                        // We dont have execution data
                        gas_used: 0,
                        value: Some(BigInt {
                            bytes: u256_to_bytes(decoded_tx.value()),
                        }),
                        input: decoded_tx.input().to_vec(),
                        v: v_bytes,
                        r: r_bytes,
                        s: s_bytes,
                        hash: tx_hash.to_vec(),
                        from: from.to_vec(),
                        status: pb::sf::ethereum::r#type::v2::TransactionTraceStatus::Succeeded as i32,
                        return_data: Vec::new(),
                        public_key: Vec::new(),
                        begin_ordinal: tx_index,
                        end_ordinal: tx_index + 1,
                        r#type: tx_type,
                        // TODO: Extract access list if present
                        access_list: Vec::new(),
                        max_fee_per_gas: Some(BigInt {
                            bytes: u256_to_bytes(U256::from(decoded_tx.max_fee_per_gas())),
                        }),
                        max_priority_fee_per_gas: decoded_tx.max_priority_fee_per_gas().map(|v| BigInt {
                            bytes: u256_to_bytes(U256::from(v)),
                        }),
                        index: tx_index as u32,
                        receipt: None,
                        calls: Vec::new(),
                        blob_gas: None,
                        blob_gas_fee_cap: None,
                        blob_hashes: Vec::new(),
                        set_code_authorizations: Vec::new(),
                    }
                }
                Err(e) => {
                    // If decoding fails fall back to raw bytes only
                    info!(target: "firehose:tracer", error = ?e, "Failed to decode transaction, using raw bytes");
                    TransactionTrace {
                        to: Vec::new(),
                        nonce: 0,
                        gas_price: None,
                        gas_limit: 0,
                        gas_used: 0,
                        value: None,
                        input: tx_bytes.to_vec(),
                        v: Vec::new(),
                        r: Vec::new(),
                        s: Vec::new(),
                        hash: Vec::new(),
                        from: Vec::new(),
                        status: pb::sf::ethereum::r#type::v2::TransactionTraceStatus::Succeeded as i32,
                        return_data: Vec::new(),
                        public_key: Vec::new(),
                        begin_ordinal: tx_index,
                        end_ordinal: tx_index + 1,
                        r#type: TxType::TrxTypeOptimismDeposit as i32,
                        access_list: Vec::new(),
                        max_fee_per_gas: None,
                        max_priority_fee_per_gas: None,
                        index: tx_index as u32,
                        receipt: None,
                        calls: Vec::new(),
                        blob_gas: None,
                        blob_gas_fee_cap: None,
                        blob_hashes: Vec::new(),
                        set_code_authorizations: Vec::new(),
                    }
                }
            };

            transaction_traces.push(tx_trace);
            tx_index += 1;
        }
    }

    // Extract balance changes from the last flashblock's metadata
    let mut balance_changes = Vec::new();
    for (address, new_balance) in &last_fb.metadata.new_account_balances {
        let balance_change = BalanceChange {
            address: address.to_vec(),
            old_value: None,
            new_value: Some(BigInt {
                bytes: u256_to_bytes(*new_balance),
            }),
            reason: BalanceReason::Unknown as i32,
            ordinal: 0,
        };
        balance_changes.push(balance_change);
    }

    info!(target: "firehose:tracer",
        block_number = base.block_number,
        tx_traces = transaction_traces.len(),
        balance_changes = balance_changes.len(),
        "Extracted data from flashblocks"
    );

    // Build Block protobuf from flashblock data
    let pb_header = BlockHeader {
        parent_hash: base.parent_hash.to_vec(),
        // OP Stack has no uncles
        uncle_hash: FixedBytes::<32>::ZERO.to_vec(),
        coinbase: base.fee_recipient.to_vec(),
        state_root: diff.state_root.to_vec(),
        // TODO: compute if needed
        transactions_root: FixedBytes::<32>::ZERO.to_vec(),
        receipt_root: diff.receipts_root.to_vec(),
        logs_bloom: diff.logs_bloom.as_slice().to_vec(),
         // PoS has no difficulty
        difficulty: Some(BigInt { bytes: vec![0] }),
        #[allow(deprecated)]
        total_difficulty: Some(BigInt { bytes: vec![0] }),
        number: base.block_number,
        gas_limit: base.gas_limit,
        gas_used: diff.gas_used,
        timestamp: Some(Timestamp {
            seconds: base.timestamp as i64,
            nanos: 0,
        }),
        extra_data: base.extra_data.to_vec(),
        // prevRandao in PoS
        mix_hash: base.prev_randao.to_vec(),
        // No nonce in PoS
        nonce: 0,
        hash: diff.block_hash.to_vec(),
        base_fee_per_gas: Some(BigInt {
            bytes: u256_to_bytes(base.base_fee_per_gas),
        }),
        withdrawals_root: diff.withdrawals_root.to_vec(),
        tx_dependency: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_root: base.parent_beacon_block_root.to_vec(),
        // EIP-7685 requests not used in OP Stack yet
        requests_hash: Vec::new(),
    };

    let pb_block = Block {
        hash: diff.block_hash.to_vec(),
        number: base.block_number,
        // We don't have raw block size from flashblocks
        size: 0,
        header: Some(pb_header),
         // OP Stack has no uncles
        uncles: Vec::new(),
        transaction_traces,
        balance_changes,
        code_changes: Vec::new(),
        system_calls: Vec::new(),
        ver: firehose::BLOCK_VERSION,
        detail_level: DetailLevel::DetaillevelExtended as i32,
    };

    // Use the tracer's internal API by calling on_block_start_inner which sets current_block
    // Then call on_block_end to output
    // Since we can't access current_block directly, we need to use the public API
    // For now, just manually print the FIRE BLOCK format
    use firehose::printer;
    use firehose::finality::FinalityStatus;

    printer::firehose_block_to_stdout(pb_block, FinalityStatus::default());

    info!(target: "firehose:tracer", block_number = base.block_number, "FIRE BLOCK output complete");
}
