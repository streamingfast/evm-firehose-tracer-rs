use crate::firehose;
use crate::prelude::*;
use alloy_consensus::Transaction;
use alloy_primitives::B256;
use std::sync::Arc;
use reth::api::ConfigureEvm;
use reth::providers::{StateProviderBox, StateProviderFactory};
use reth_evm::{evm::Evm, system_calls::SystemCaller};
use reth_exex::{ExExContext, ExExEvent, ExExNotification};

pub async fn firehose_tracer<Node: FullNodeComponents>(
    mut ctx: ExExContext<Node>,
    mut tracer: firehose::Tracer<Node>,
) -> eyre::Result<()>
where
    ChainSpec<Node>: reth::chainspec::EthereumHardforks,
{
    info!(target: "firehose:tracer", config = ?tracer.config, "Launching tracer");

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

                        // Execute system calls (EIP-4788 Beacon Root, EIP-2935 Block Hashes) before transactions
                        if let Err(e) = execute_system_calls_with_tracing(
                            &mut tracer,
                            block,
                            &state_provider,
                            &evm_config,
                            &ctx.config.chain,
                        ) {
                            info!(target: "firehose:tracer", "Failed to execute system calls: {}", e);
                        }

                        // Process each transaction in the block with re-execution
                        // Collect recovered transactions with their indices
                        let recovered_txs: Vec<_> = block.transactions_recovered().collect();

                        for (tx_index, (recovered_tx, receipt)) in
                            recovered_txs.iter().zip(receipts.iter()).enumerate()
                        {
                            // Recovered<&T> derefs to &T via the Deref trait
                            let tx: &SignedTx<Node> = &**recovered_tx;
                            tracer.on_tx_start(tx);

                            // Re-execute the transaction with FirehoseInspector to capture call traces
                            if let Err(e) = execute_transaction_with_tracing(
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

/// Execute a single transaction with the FirehoseInspector to capture call traces
///
/// This function replays all transactions in the block up to the target transaction,
/// then executes the target transaction with the inspector to capture its execution trace.
fn execute_transaction_with_tracing<Node: FullNodeComponents>(
    tracer: &mut firehose::Tracer<Node>,
    block: &RecoveredBlock<Node>,
    target_tx_index: usize,
    state_provider: &StateProviderBox,
    evm_config: &Node::Evm,
) -> eyre::Result<()> {
    use reth::revm::db::CacheDB;
    use reth_revm::database::StateProviderDatabase;

    // Create database from state provider
    let mut db = CacheDB::new(StateProviderDatabase::new(state_provider));
    let evm_env = evm_config.evm_env(block.header());

    // First pass: replay all transactions BEFORE our target without inspector to build state
    {
        let mut evm = evm_config.evm_with_env(&mut db, evm_env.clone());

        for (index, recovered_tx) in block.transactions_recovered().enumerate() {
            if index == target_tx_index {
                break;
            }

            // Execute and commit previous transactions to build correct state
            let tx_env = evm_config.tx_env(recovered_tx);
            evm.transact_commit(tx_env)?;
        }
    }

    // Second pass: execute the target transaction with inspector
    let mut inspector = firehose::FirehoseInspector::new(tracer);
    let mut evm = evm_config.evm_with_env_and_inspector(&mut db, evm_env, &mut inspector);

    for (index, recovered_tx) in block.transactions_recovered().enumerate() {
        if index == target_tx_index {
            let tx_env = evm_config.tx_env(recovered_tx);
            let _result = evm.transact(tx_env)?;
            break;
        }
    }

    Ok(())
}

/// Execute system calls (EIP-4788, EIP-2935) with tracing
///
/// System calls are special calls that execute before transactions in a block.
/// They update beacon roots and block hashes in special system contracts.
fn execute_system_calls_with_tracing<Node: FullNodeComponents>(
    tracer: &mut firehose::Tracer<Node>,
    block: &RecoveredBlock<Node>,
    state_provider: &StateProviderBox,
    evm_config: &Node::Evm,
    chain_spec: &Arc<ChainSpec<Node>>,
) -> eyre::Result<()>
where
    ChainSpec<Node>: reth::chainspec::EthereumHardforks,
{
    use reth::revm::db::CacheDB;
    use reth_revm::database::StateProviderDatabase;

    // Create database from state provider
    let mut db = CacheDB::new(StateProviderDatabase::new(state_provider));
    let evm_env = evm_config.evm_env(block.header());

    // Mark that we're entering system call execution
    tracer.on_system_call_start();

    use reth::chainspec::EthereumHardforks;
    use alloy_consensus::BlockHeader as _;
    let is_cancun = chain_spec.is_cancun_active_at_timestamp(block.timestamp());
    let is_prague = chain_spec.is_prague_active_at_timestamp(block.timestamp());
    let has_beacon_root = block.header().parent_beacon_block_root().is_some();
    let parent_hash = block.parent_hash();

    info!(target: "firehose:tracer",
        block_number = block.number(),
        block_timestamp = block.timestamp(),
        is_cancun = is_cancun,
        is_prague = is_prague,
        has_beacon_root = has_beacon_root,
        parent_hash = ?parent_hash,
        "Executing system calls"
    );

    // Execute system calls and manually create Call objects
    // NOTE: transact_system_call() doesn't trigger inspector hooks, so we must manually
    // construct the Call objects after execution, similar to how Geth uses OnSystemCallStart/End hooks
    {
        use alloy_consensus::BlockHeader as _;
        use alloy_eips::{eip2935::HISTORY_STORAGE_ADDRESS, eip4788::{BEACON_ROOTS_ADDRESS, SYSTEM_ADDRESS}};

        // EIP-4788: Beacon root system call
        if is_cancun && block.number() > 0 {
            if let Some(parent_beacon_root) = block.header().parent_beacon_block_root() {
                info!(target: "firehose:tracer", "Executing EIP-4788 beacon root system call");

                // Execute without inspector
                let mut evm = evm_config.evm_with_env(&mut db, evm_env.clone());
                let result = evm.transact_system_call(
                    SYSTEM_ADDRESS,
                    BEACON_ROOTS_ADDRESS,
                    parent_beacon_root.0.into(),
                )?;

                // Manually create a Call object for this system call
                tracer.on_system_call_enter(
                    SYSTEM_ADDRESS,
                    BEACON_ROOTS_ADDRESS,
                    parent_beacon_root.as_slice(),
                    &result,
                );
            }
        }

        // EIP-2935: Block hash system call
        if is_prague && block.number() > 0 {
            info!(target: "firehose:tracer", "Executing EIP-2935 block hash system call");

            let parent_hash = block.parent_hash();

            // Execute without inspector
            let mut evm = evm_config.evm_with_env(&mut db, evm_env.clone());
            let result = evm.transact_system_call(
                SYSTEM_ADDRESS,
                HISTORY_STORAGE_ADDRESS,
                parent_hash.0.into(),
            )?;

            // Manually create a Call object for this system call
            tracer.on_system_call_enter(
                SYSTEM_ADDRESS,
                HISTORY_STORAGE_ADDRESS,
                parent_hash.as_slice(),
                &result,
            );
        }
    }

    info!(target: "firehose:tracer", block_number = block.number(), call_stack_len = tracer.call_stack.len(), "System calls executed");

    // Mark that system calls are complete
    tracer.on_system_call_end();

    Ok(())
}
