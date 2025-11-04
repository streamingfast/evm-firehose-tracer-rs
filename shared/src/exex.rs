use crate::prelude::*;
use firehose;
use reth::chainspec::{EthChainSpec, EthereumHardforks};

/// Execute a single transaction with the FirehoseInspector to capture call traces
///
/// This function replays all transactions in the block up to the target transaction,
/// then executes the target transaction with the inspector to capture its execution trace.
pub fn execute_transaction_with_tracing<Node: FullNodeComponents>(
    tracer: &mut firehose::Tracer<Node>,
    block: &RecoveredBlock<Node>,
    target_tx_index: usize,
    state_provider: &StateProviderBox,
    evm_config: &Node::Evm,
) -> eyre::Result<()> {
    use reth::revm::db::CacheDB;

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
///
/// This function is generic and works with any chain that implements EthereumHardforks.
pub fn execute_system_calls_with_tracing<Node: FullNodeComponents>(
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

    // Create database from state provider
    let mut db = CacheDB::new(StateProviderDatabase::new(state_provider));
    let evm_env = evm_config.evm_env(block.header());

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
        use alloy_eips::{eip2935::HISTORY_STORAGE_ADDRESS, eip4788::{BEACON_ROOTS_ADDRESS, SYSTEM_ADDRESS}};

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

    info!(target: "firehose:tracer", block_number = block.number(), call_stack_len = tracer.call_stack.len(), "System calls executed");

    // Mark that system calls are complete
    tracer.on_system_call_end();

    info!(target: "firehose:tracer", "on_system_call_end() returned successfully");

    Ok(())
}

