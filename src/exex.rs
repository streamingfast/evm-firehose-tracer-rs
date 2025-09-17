use crate::firehose;
use crate::prelude::*;
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
                new.blocks().iter().for_each(|(_, block)| {
                    tracer.on_block_start(block);
                    tracer.on_block_end();
                });
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
