use crate::{exex::inspector, exex::mapper, prelude::*};
use alloy_consensus::transaction::TxHashRef as _;
use alloy_primitives::Bytes;
use eyre::Context;
use firehose;
use reth::chainspec::{EthChainSpec, EthereumHardforks};
use reth::revm::revm::Database as _;
use reth_evm::block::TxResult as _;
use reth_evm::execute::BlockExecutor;
use reth_provider::BlockIdReader;

/// Ethereum-specific firehose tracer
pub async fn run_loop<Node: FullNodeComponents, F>(
    mut ctx: ExExContext<Node>,
    mut tracer: firehose::Tracer,
    get_signature: F,
) -> eyre::Result<()>
where
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
    F: Fn(&SignedTx<Node>) -> (B256, B256, Bytes) + Send + Sync + 'static,
{
    info!(target: "firehose", "Launching Ethereum tracer");

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
                info!(target: "firehose", chain = ?new.range(), "Chain committed, tracing {} blocks", new.len());

                let skip_failed = std::env::var("SKIP_FAILED_BLOCKS")
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);

                let chain_start = std::time::Instant::now();
                for (block, receipts) in new.blocks_and_receipts() {
                    let result = trace_block(
                        &ctx,
                        &mut tracer,
                        &evm_config,
                        block,
                        receipts,
                        &get_signature,
                    );
                    if let Err(err) = result {
                        error!(target: "firehose", block = block.number(), error = ?err, "trace_block failed");
                        if skip_failed {
                            warn!(target: "firehose", block = block.number(), "SKIP_FAILED_BLOCKS=true, skipping block");
                            continue;
                        }
                        return Err(err.wrap_err("Firehose trace block"));
                    }
                }

                let elapsed = chain_start.elapsed();
                info!(target: "firehose", elapsed = ?chain_start.elapsed(), by_block = ?(elapsed / new.len() as u32),  "Traced chain");
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

pub fn trace_block<Node: FullNodeComponents, F>(
    ctx: &ExExContext<Node>,
    tracer: &mut firehose::Tracer,
    evm_config: &Node::Evm,
    block: &RecoveredBlock<Node>,
    receipts: &Vec<Receipt<Node>>,
    get_signature: &F,
) -> eyre::Result<()>
where
    ChainSpec<Node>: EthereumHardforks + EthChainSpec,
    F: Fn(&SignedTx<Node>) -> (B256, B256, Bytes),
{
    use alloy_consensus::TxReceipt;

    if block.number() == 1 {
        tracer.on_genesis_block(
            firehose::BlockEvent {
                block: mapper::to_block_data::<Node>(block),
                finalized: None,
                flash_block: None,
            },
            mapper::to_genesis_alloc(ctx.config.chain.genesis()),
        );
        return Ok(());
    }

    tracer.on_block_start(firehose::BlockEvent {
        block: mapper::to_block_data::<Node>(block),
        finalized: mapper::to_finalized_ref(ctx.provider().finalized_block_num_hash()),
        flash_block: None,
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

    let evm_env = evm_config
        .evm_env(block.header())
        .wrap_err_with(|| format!("Failed to build EVM env for block {}", block.number()))?;
    // context_for_block type-checks because FullNodeComponents bounds Node::Evm:
    // ConfigureEvm<Primitives = <Node::Types as NodeTypes>::Primitives>
    let exec_ctx = evm_config
        .context_for_block(block.sealed_block())
        .wrap_err_with(|| format!("Failed to build EVM context for block {}", block.number()))?;

    // Inspector borrows tracer mutably for the duration of the block execution.
    // All tracer lifecycle calls (on_tx_start, on_tx_end, etc.) go through
    // executor.evm_mut().inspector_mut().tracer_mut() while the inspector is live.
    let inspector = inspector::FirehoseInspector::<Node>::new(tracer);
    let evm = evm_config.evm_with_env_and_inspector(&mut state, evm_env, inspector);
    let mut executor = evm_config.create_executor(evm, exec_ctx);

    // Set state hook to log EvmState changes after each transaction and system call
    executor.set_state_hook(Some(Box::new(
        |source: reth_evm::block::StateChangeSource, state: &reth::revm::revm::state::EvmState| {
            inspector::log_evm_state(&format!("state_hook({source:?})"), state);
        },
    )));

    // System calls (EIP-4788, EIP-2935, etc.) — handled by apply_pre_execution_changes
    executor
        .evm_mut()
        .inspector_mut()
        .tracer_mut()
        .on_system_call_start();
    executor.apply_pre_execution_changes().wrap_err_with(|| {
        format!(
            "Failed to apply pre-execution changes for block {}",
            block.number()
        )
    })?;
    executor
        .evm_mut()
        .inspector_mut()
        .tracer_mut()
        .on_system_call_end();

    let mut prev_cumulative_gas: u64 = 0;
    let mut log_index: u32 = 0;

    for (tx_index, (recovered_tx, receipt)) in block
        .transactions_recovered()
        .zip(receipts.iter())
        .enumerate()
    {
        let tx: &SignedTx<Node> = &**recovered_tx;
        let (r, s, v) = get_signature(tx);
        let tx_event = mapper::signed_tx_to_tx_event(tx, recovered_tx.signer(), tx_index, r, s, v);

        // Fresh state reader per transaction (cheap lazy DB access) for on_tx_start StateReader
        let state_reader_provider = ctx
            .provider()
            .state_by_block_hash(parent_hash)
            .wrap_err_with(|| {
                format!(
                    "Failed to get state reader for block {} tx_index={tx_index} tx_hash={}",
                    block.number(),
                    recovered_tx.tx_hash()
                )
            })?;
        let state_reader = Box::new(mapper::StateReaderAdapter(state_reader_provider));

        executor
            .evm_mut()
            .inspector_mut()
            .tracer_mut()
            .on_tx_start(tx_event, Some(state_reader));

        let caller_nonce = executor
            .evm_mut()
            .db_mut()
            .basic(recovered_tx.signer())?
            .ok_or_else(|| {
                eyre::eyre!(
                    "Failed to get caller account info for block {} tx_index={tx_index} tx_hash={}",
                    block.number(),
                    recovered_tx.tx_hash()
                )
            })?
            .nonce;
        info!(target: "firehose", block = block.number(), tx_index, tx_hash = ?recovered_tx.tx_hash(), caller_nonce, "Executing transaction");

        // execute_transaction_without_commit runs the full EVM execution (including post-execution
        // gas refund and miner fee) and returns the final EvmState without committing to DB.
        // Inspector hooks (on_call_enter, on_call_exit, on_opcode, etc.) fire during transact().
        let tx_result = executor
            .execute_transaction_without_commit(recovered_tx)
            .wrap_err_with(|| {
                format!(
                    "Failed to execute transaction block={} tx_index={tx_index} tx_hash={}",
                    block.number(),
                    recovered_tx.tx_hash()
                )
            })?;

        // Emit post-execution balance changes (gas refund to sender, miner fee to coinbase).
        // revm's post_execution runs reimburse_caller and reward_beneficiary after the last
        // inspector hook, so we explicitly compute and emit them using Ethereum gas rules.
        {
            let result_gas_used = tx_result.result().result.gas_used();
            let sender = recovered_tx.signer();
            let coinbase = block.header().beneficiary();
            let gas_limit = tx.gas_limit();
            let base_fee = block.header().base_fee_per_gas().unwrap_or(0);
            let effective_gas_price: u128 = if tx.is_dynamic_fee() {
                std::cmp::min(
                    tx.max_fee_per_gas(),
                    base_fee as u128 + tx.max_priority_fee_per_gas().unwrap_or(0),
                )
            } else {
                tx.gas_price().unwrap_or(0)
            };

            let (db, inspector, _) = executor.evm_mut().components_mut();
            inspector.process_post_tx_balance_changes(
                sender,
                coinbase,
                gas_limit,
                result_gas_used,
                effective_gas_price,
                base_fee,
                |addr| {
                    db.basic(addr)
                        .ok()
                        .flatten()
                        .map(|info| info.balance)
                        .unwrap_or(U256::ZERO)
                },
            );
        }

        executor.commit_transaction(tx_result).wrap_err_with(|| {
            format!(
                "Failed to commit transaction block={} tx_index={tx_index} tx_hash={}",
                block.number(),
                recovered_tx.tx_hash()
            )
        })?;

        let cumulative_gas = receipt.cumulative_gas_used();
        let gas_used = cumulative_gas - prev_cumulative_gas;
        let log_count = receipt.logs().len() as u32;
        let receipt_data = mapper::to_receipt_data(receipt, tx_index as u32, gas_used, log_index);
        prev_cumulative_gas = cumulative_gas;
        log_index += log_count;

        executor
            .evm_mut()
            .inspector_mut()
            .tracer_mut()
            .on_tx_end(Some(&receipt_data), None);
    }

    executor
        .evm_mut()
        .inspector_mut()
        .tracer_mut()
        .on_system_call_start();

    // Post-execution changes (block rewards, withdrawals, etc.)
    // This consumes the executor, dropping the inspector and releasing the tracer borrow
    executor.apply_post_execution_changes().wrap_err_with(|| {
        format!(
            "Failed to apply post-execution changes for block {}",
            block.number()
        )
    })?;

    // Tracer borrow released — can call directly again
    tracer.on_system_call_end();

    tracer.on_block_end(None);

    Ok(())
}
