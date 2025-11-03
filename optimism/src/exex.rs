use crate::prelude::*;
use firehose;
use reth::chainspec::{EthChainSpec, EthereumHardforks};
use reth_optimism_flashblocks::FlashBlock;
use futures_util::StreamExt;
use url::Url;
use tokio_tungstenite::connect_async;

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

        while let Some(msg) = read.next().await {
            match msg {
                Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                    // Deserialize JSON to FlashBlock
                    match serde_json::from_str::<FlashBlock>(&text) {
                        Ok(flashblock) => {
                            info!(target: "firehose:tracer",
                                flashblock_index = flashblock.index,
                                block_number = flashblock.metadata.block_number,
                                tx_count = flashblock.diff.transactions.len(),
                                gas_used = flashblock.diff.gas_used,
                                "Processing flashblock"
                            );

                            // TODO: Convert flashblock to traced block and output FIRE BLOCK format
                            // 1. Converting flashblock metadata to block header
                            // 2. Processing transactions from flashblock.diff.transactions
                            // 3. Using flashblock.metadata.receipts for receipt data
                            // 4. Calling tracer.on_block_start(), process txs, tracer.on_block_end()
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
                            info!(target: "firehose:tracer",
                                flashblock_index = flashblock.index,
                                block_number = flashblock.metadata.block_number,
                                tx_count = flashblock.diff.transactions.len(),
                                gas_used = flashblock.diff.gas_used,
                                "Processing flashblock (compressed)"
                            );

                            // TODO: Convert flashblock to traced block and output FIRE BLOCK format
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
