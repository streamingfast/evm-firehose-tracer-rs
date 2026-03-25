use crate::{exex::inspector, exex::mapper, prelude::*};
use eyre::Context;
use firehose;
use reth::chainspec::{EthChainSpec, EthereumHardforks};
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
    mut tracer: &mut firehose::Tracer,
    evm_config: &Node::Evm,
    block: &RecoveredBlock<Node>,
    receipts: &Vec<Receipt<Node>>,
) -> eyre::Result<()>
where
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
    SignedTx<Node>: mapper::SignatureFields,
{
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

    // Get state provider for the parent block to re-execute transactions
    let parent_hash = block.parent_hash();
    let state_provider = ctx
        .provider()
        .state_by_block_hash(parent_hash)
        .wrap_err(format!(
            "Failed to get state provider for block {}",
            block.number()
        ))?;

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

    let mut prev_cumulative_gas: u64 = 0;
    let mut log_index: u32 = 0;
    for (tx_index, (recovered_tx, receipt)) in block
        .transactions_recovered()
        .zip(receipts.iter())
        .enumerate()
    {
        // Create a fresh state provider for the StateReader on each transaction.
        // This is cheap (lazy DB access) and gives on_tx_start an owned Send + 'static value.
        let state_reader_provider = ctx
            .provider()
            .state_by_block_hash(parent_hash)
            .wrap_err_with(|| format!("Failed to get state reader for transaction {tx_index}"))?;

        trace_transaction::<Node>(
            &mut tracer,
            block,
            tx_index,
            recovered_tx,
            receipt,
            &state_provider,
            state_reader_provider,
            &evm_config,
            &mut prev_cumulative_gas,
            &mut log_index,
        )
        .wrap_err_with(|| format!("Firehose trace transaction {tx_index}"))?;
    }

    // Finalize and output the block
    tracer.on_block_end(None);

    Ok(())
}

pub fn trace_transaction<Node: FullNodeComponents>(
    tracer: &mut firehose::Tracer,
    block: &RecoveredBlock<Node>,
    tx_index: usize,
    recovered_tx: reth::primitives::Recovered<&SignedTx<Node>>,
    receipt: &Receipt<Node>,
    state_provider: &StateProviderBox,
    state_reader_provider: StateProviderBox,
    evm_config: &Node::Evm,
    prev_cumulative_gas: &mut u64,
    log_index: &mut u32,
) -> eyre::Result<()>
where
    SignedTx<Node>: mapper::SignatureFields,
{
    use alloy_consensus::TxReceipt;

    let tx: &SignedTx<Node> = &**recovered_tx;
    let tx_event = mapper::signed_tx_to_tx_event(tx, recovered_tx.signer(), tx_index);
    let state_reader = Box::new(mapper::StateReaderAdapter(state_reader_provider));
    tracer.on_tx_start(tx_event, Some(state_reader));

    execute_transaction_with_tracing::<Node>(tracer, block, tx_index, state_provider, evm_config)
        .wrap_err_with(|| format!("Failed to execute transaction {tx_index}"))?;

    let cumulative_gas = receipt.cumulative_gas_used();
    let gas_used = cumulative_gas - *prev_cumulative_gas;
    let log_count = receipt.logs().len() as u32;
    let receipt_data = mapper::to_receipt_data(receipt, tx_index as u32, gas_used, *log_index);
    *prev_cumulative_gas = cumulative_gas;
    *log_index += log_count;

    tracer.on_tx_end(Some(&receipt_data), None);

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

    // FIXME: That is very poor creating an exponential series of states. Instead, we should
    // execute + tracer + commit each transaction one after the other, enabling building
    // up the state as we good avoid the two pass approach below.

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
