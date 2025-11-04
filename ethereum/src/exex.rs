use crate::prelude::*;
use firehose;
use reth::chainspec::{EthChainSpec, EthereumHardforks};

/// Ethereum-specific firehose tracer
pub async fn firehose_tracer<Node: FullNodeComponents>(
    mut ctx: ExExContext<Node>,
    mut tracer: firehose::Tracer<Node>,
) -> eyre::Result<()>
where
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
{
    info!(target: "firehose:tracer", config = ?tracer.config, "Launching Ethereum tracer");

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

                        // Execute system calls using shared helper
                        if let Err(e) = shared::exex::execute_system_calls_with_tracing(
                            &mut tracer,
                            block,
                            &state_provider,
                            &evm_config,
                            &ctx.config.chain,
                        ) {
                            info!(target: "firehose:tracer", "Failed to execute system calls: {}", e);
                        }

                        // Process each transaction in the block with re-execution
                        let recovered_txs: Vec<_> = block.transactions_recovered().collect();

                        for (tx_index, (recovered_tx, receipt)) in
                            recovered_txs.iter().zip(receipts.iter()).enumerate()
                        {
                            let tx: &SignedTx<Node> = &**recovered_tx;
                            tracer.on_tx_start(tx);

                            // Re-execute the transaction using shared helper
                            if let Err(e) = shared::exex::execute_transaction_with_tracing(
                                &mut tracer,
                                block,
                                tx_index,
                                &state_provider,
                                &evm_config,
                            ) {
                                info!(target: "firehose:tracer", "Failed to execute transaction: {}", e);
                            }

                            tracer.on_tx_end(receipt);
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
