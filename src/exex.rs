use crate::firehose;
use crate::prelude::*;
use reth::api::{BlockBody, ConfigureEvm};
use reth::providers::StateProviderFactory;
use reth::revm::db::CacheDB;
use reth::revm::db::EmptyDB;
use reth_exex::{ExExContext, ExExEvent, ExExNotification};

pub async fn firehose_tracer<Node: FullNodeComponents>(
    mut ctx: ExExContext<Node>,
    mut tracer: firehose::Tracer<Node>,
) -> eyre::Result<()> {
    info!(target: "firehose:tracer", config = ?tracer.config, "Launching tracer");

    // TODO: Should we load the tracer here instead? Unsure about the exec flow, maybe it's better
    // to prepare it in advance like we have right now. But it poses questions with the flow as `on_init`
    // needs to be called, which for now we do here.
    tracer.on_init(ctx.config.chain.clone());

    while let Some(notification) = ctx.notifications.try_next().await? {
        match &notification {
            ExExNotification::ChainCommitted { new } => {
                // Iterate through blocks with their receipts
                for (block, receipts) in new.blocks_and_receipts() {
                    if block.number() == 1 {
                        tracer.on_genesis_block(ctx.config.chain.genesis());
                    } else {
                        tracer.on_block_start(block);

                        // Process each transaction in the block with its receipt
                        let transactions = block.body().transactions();
                        for (tx, receipt) in transactions.iter().zip(receipts.iter()) {
                            tracer.on_tx_start(tx);
                            // TODO: Execute transaction and capture execution traces
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

// TODO: This function will be used to trace individual transactions within blocks
#[allow(dead_code)]
fn trace_block<Node: FullNodeComponents>(
    block: &RecoveredBlock<Node>,
    provider: Node::Provider,
    evm_config: &Node::Evm,
) -> eyre::Result<()> {
    let _state_at = provider.state_by_block_hash(block.hash())?;
    let _exec_ctx = evm_config.context_for_block(block);
    let mut _db = CacheDB::new(EmptyDB::default());
    // Use the evm_for_block method to construct the EVM instance
    // let evm = evm_config.evm_for_block(&mut db, block.header());
    // let mut executor = evm_config.create_executor(evm, exec_ctx);

    Ok(())
}
