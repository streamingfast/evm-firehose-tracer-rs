use std::collections::HashMap;

use crate::{exex::inspector, prelude::*};
use firehose;
use reth::chainspec::{EthChainSpec, EthereumHardforks};

/// Ethereum-specific firehose tracer
pub async fn run_loop<Node: FullNodeComponents>(
    mut ctx: ExExContext<Node>,
    mut tracer: firehose::Tracer,
) -> eyre::Result<()>
where
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
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
                // Iterate through blocks with their receipts
                for (block, receipts) in new.blocks_and_receipts() {
                    if block.number() == 1 {
                        // FIXME: Re-implement using `ctx.config.chain.genesis()`
                        tracer.on_genesis_block(
                            firehose::BlockEvent {
                                ..Default::default()
                            },
                            HashMap::new(),
                        );
                    } else {
                        // FIXME: Implement correct population of BlockEvent fields from the block header and any other sources as needed
                        // FIXME: Implement finality correctly (does ExEx have a way to query/report that?)
                        tracer.on_block_start(firehose::BlockEvent {
                            ..Default::default()
                        });

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
                        if let Err(e) = execute_system_calls_with_tracing::<Node>(
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

                        // FIXME: Receipt would need to be reported up back
                        for (tx_index, (recovered_tx, _receipt)) in
                            recovered_txs.iter().zip(receipts.iter()).enumerate()
                        {
                            let _tx: &SignedTx<Node> = &**recovered_tx;
                            // FIXME: Implement correct population of TxEvent fields from the transaction and any other sources as needed
                            // FIXME: Check how we can add support for StateReader implementation, normally we should be able to use
                            // state_provider from above but maybe we will need to deal with some form of locking as we need to share it
                            tracer.on_tx_start(
                                firehose::TxEvent {
                                    ..Default::default()
                                },
                                None,
                            );

                            // Re-execute the transaction using shared helper
                            if let Err(e) = execute_transaction_with_tracing::<Node>(
                                &mut tracer,
                                block,
                                tx_index,
                                &state_provider,
                                &evm_config,
                            ) {
                                // FIXME: This should be a hard error, all transactions should be replayable since they come
                                // from a know block.
                                info!(target: "firehose:tracer", "Failed to execute transaction: {}", e);
                            }

                            // FIXME: Fill in correct receipt information, probably that execute_transaction_with_tracing should return the receipt
                            tracer.on_tx_end(None, None);
                        }

                        // Finalize and output the block
                        tracer.on_block_end(None);
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
pub fn execute_transaction_with_tracing<Node: FullNodeComponents>(
    tracer: &mut firehose::Tracer,
    block: &RecoveredBlock<Node>,
    target_tx_index: usize,
    state_provider: &StateProviderBox,
    evm_config: &Node::Evm,
) -> eyre::Result<()> {
    use reth::revm::db::CacheDB;

    // Create database from state provider
    let mut db = CacheDB::new(StateProviderDatabase::new(state_provider));
    let evm_env = evm_config.evm_env(block.header())?;

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
    let mut inspector = inspector::Firehose::<Node>::new(tracer);
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
///
/// This function is generic and works with any chain that implements EthereumHardforks.
pub fn execute_system_calls_with_tracing<Node: FullNodeComponents>(
    tracer: &mut firehose::Tracer,
    block: &RecoveredBlock<Node>,
    state_provider: &StateProviderBox,
    evm_config: &Node::Evm,
    chain_spec: &Arc<ChainSpec<Node>>,
) -> eyre::Result<()>
where
    ChainSpec<Node>: reth::chainspec::EthereumHardforks,
{
    use reth::revm::db::CacheDB;

    // Create database from state provider
    let db = CacheDB::new(StateProviderDatabase::new(state_provider));
    let evm_env = evm_config.evm_env(block.header());

    // FIXME: We need to fully revisit this an check if Reth don't offer some helper ro run system calls. We will
    // need at some point to decide how we could deal with Ethereum vs Optimism here.
    let _ = (db, evm_env);

    // Mark that we're entering system call execution
    tracer.on_system_call_start();

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
        // use alloy_eips::{
        //     eip2935::HISTORY_STORAGE_ADDRESS,
        //     eip4788::{BEACON_ROOTS_ADDRESS, SYSTEM_ADDRESS},
        // };

        // FULLY DISABLED FOR TESTING: EIP-4788: Beacon root system call
        if is_cancun && block.number() > 0 {
            if let Some(_parent_beacon_root) = block.header().parent_beacon_block_root() {
                info!(target: "firehose:tracer", "Skipping EIP-4788 beacon root system call (DISABLED for testing)");

                // DISABLED: Execute without inspector
                // let mut evm = evm_config.evm_with_env(&mut db, evm_env.clone());
                // let _result = evm.transact_system_call(
                //     SYSTEM_ADDRESS,
                //     BEACON_ROOTS_ADDRESS,
                //     parent_beacon_root.0.into(),
                // )?;
            }
        }

        // FULLY DISABLED FOR TESTING: EIP-2935: Block hash system call
        if is_prague && block.number() > 0 {
            info!(target: "firehose:tracer", "Skipping EIP-2935 block hash system call (DISABLED for testing)");

            // DISABLED: Execute without inspector
            // let _parent_hash = block.parent_hash();
            // let mut evm = evm_config.evm_with_env(&mut db, evm_env.clone());
            // let _result = evm.transact_system_call(
            //     SYSTEM_ADDRESS,
            //     HISTORY_STORAGE_ADDRESS,
            //     parent_hash.0.into(),
            // )?;
        }
    }

    // info!(target: "firehose:tracer", block_number = block.number(), call_stack_len = tracer.call_stack.len(), "System calls executed");

    // Mark that system calls are complete
    tracer.on_system_call_end();

    info!(target: "firehose:tracer", "on_system_call_end() returned successfully");

    Ok(())
}
