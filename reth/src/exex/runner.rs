use crate::{exex::inspector, exex::mapper, prelude::*};
use eyre::Context;
use firehose;
use reth::chainspec::{EthChainSpec, EthereumHardforks};
use reth_evm::execute::BlockExecutor;
use reth_provider::BlockIdReader;

/// Ethereum-specific firehose tracer
pub async fn run_loop<Node: FullNodeComponents>(
    mut ctx: ExExContext<Node>,
    mut tracer: firehose::Tracer,
) -> eyre::Result<()>
where
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
    SignedTx<Node>: mapper::SignatureFields,
{
    info!(target: "firehose:tracer", "Launching Ethereum tracer");

    // Initialize tracer with chain spec
    // FIXME: Pull version from cargo
    tracer.on_blockchain_init(
        "reth/ethereum",
        "1.11.3",
        firehose::ChainConfig {
            // FIXME: use ctx.config.chain to populate these fields instead of hardcoding, the ChainSpec is fully
            // generic and don't seem to have any trait bounds, unclear how we will extract the fields.
            ..Default::default()
        },
    );

    // Get EVM config from components for transaction re-execution
    let evm_config = ctx.components.evm_config().clone();

    while let Some(notification) = ctx.notifications.try_next().await? {
        match &notification {
            ExExNotification::ChainCommitted { new } => {
                for (block, receipts) in new.blocks_and_receipts() {
                    trace_block(&ctx, &mut tracer, &evm_config, block, receipts)
                        .wrap_err("Firehose trace block")?;
                }
            }
            ExExNotification::ChainReorged { old, new } => {
                error!(from_chain = ?old.range(), to_chain = ?new.range(), "Received reorg");
            }
            ExExNotification::ChainReverted { old } => {
                error!(reverted_chain = ?old.range(), "Received revert");
            }
        };

        if let Some(committed_chain) = notification.committed_chain() {
            ctx.events
                .send(ExExEvent::FinishedHeight(committed_chain.tip().num_hash()))?;
        }
    }

    Ok(())
}

pub fn trace_block<Node: FullNodeComponents>(
    ctx: &ExExContext<Node>,
    tracer: &mut firehose::Tracer,
    evm_config: &Node::Evm,
    block: &RecoveredBlock<Node>,
    receipts: &Vec<Receipt<Node>>,
) -> eyre::Result<()>
where
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
    SignedTx<Node>: mapper::SignatureFields,
{
    use alloy_consensus::TxReceipt;

    if block.number() == 1 {
        tracer.on_genesis_block(
            firehose::BlockEvent {
                block: mapper::to_block_data::<Node>(block),
                finalized: None,
            },
            mapper::to_genesis_alloc(ctx.config.chain.genesis()),
        );
        return Ok(());
    }

    tracer.on_block_start(firehose::BlockEvent {
        block: mapper::to_block_data::<Node>(block),
        finalized: mapper::to_finalized_ref(ctx.provider().finalized_block_num_hash()),
    });

    let parent_hash = block.parent_hash();
    let state_provider = ctx
        .provider()
        .state_by_block_hash(parent_hash)
        .wrap_err_with(|| format!("Failed to get state provider for block {}", block.number()))?;

    // Use State<DB> (required by create_executor) instead of CacheDB
    let mut state = reth_revm::State::builder()
        .with_database(StateProviderDatabase::new(state_provider))
        .with_bundle_update()
        .build();

    let evm_env = evm_config.evm_env(block.header())?;
    // context_for_block type-checks because FullNodeComponents bounds Node::Evm:
    // ConfigureEvm<Primitives = <Node::Types as NodeTypes>::Primitives>
    let exec_ctx = evm_config.context_for_block(block.sealed_block())?;

    // Inspector borrows tracer mutably for the duration of the block execution.
    // All tracer lifecycle calls (on_tx_start, on_tx_end, etc.) go through
    // executor.evm_mut().inspector_mut().tracer_mut() while the inspector is live.
    let inspector = inspector::Firehose::<Node>::new(tracer);
    let evm = evm_config.evm_with_env_and_inspector(&mut state, evm_env, inspector);
    let mut executor = evm_config.create_executor(evm, exec_ctx);

    // System calls (EIP-4788, EIP-2935, etc.) — handled by apply_pre_execution_changes
    executor.evm_mut().inspector_mut().tracer_mut().on_system_call_start();
    executor
        .apply_pre_execution_changes()
        .wrap_err("Failed to apply pre-execution changes")?;
    executor.evm_mut().inspector_mut().tracer_mut().on_system_call_end();

    let mut prev_cumulative_gas: u64 = 0;
    let mut log_index: u32 = 0;

    for (tx_index, (recovered_tx, receipt)) in block
        .transactions_recovered()
        .zip(receipts.iter())
        .enumerate()
    {
        let tx: &SignedTx<Node> = &**recovered_tx;
        let tx_event = mapper::signed_tx_to_tx_event(tx, recovered_tx.signer(), tx_index);

        // Fresh state reader per transaction (cheap lazy DB access) for on_tx_start StateReader
        let state_reader_provider = ctx
            .provider()
            .state_by_block_hash(parent_hash)
            .wrap_err_with(|| format!("Failed to get state reader for transaction {tx_index}"))?;
        let state_reader = Box::new(mapper::StateReaderAdapter(state_reader_provider));

        executor
            .evm_mut()
            .inspector_mut()
            .tracer_mut()
            .on_tx_start(tx_event, Some(state_reader));

        // execute_transaction accepts Recovered<&SignedTx<Node>> directly (ExecutableTx impl)
        // Inspector hooks (on_call_enter, on_call_exit, on_opcode, etc.) fire automatically
        executor
            .execute_transaction(recovered_tx)
            .wrap_err_with(|| format!("Failed to execute transaction {tx_index}"))?;

        let cumulative_gas = receipt.cumulative_gas_used();
        let gas_used = cumulative_gas - prev_cumulative_gas;
        let log_count = receipt.logs().len() as u32;
        let receipt_data =
            mapper::to_receipt_data(receipt, tx_index as u32, gas_used, log_index);
        prev_cumulative_gas = cumulative_gas;
        log_index += log_count;

        executor
            .evm_mut()
            .inspector_mut()
            .tracer_mut()
            .on_tx_end(Some(&receipt_data), None);
    }

    // Post-execution changes (block rewards, withdrawals, etc.)
    // This consumes the executor, dropping the inspector and releasing the tracer borrow
    executor
        .apply_post_execution_changes()
        .wrap_err("Failed to apply post-execution changes")?;

    // Tracer borrow released — can call directly again
    tracer.on_block_end(None);

    Ok(())
}
