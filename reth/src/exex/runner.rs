use crate::{exex::inspector, exex::mapper, prelude::*};
use alloy_consensus::transaction::TxHashRef as _;
use alloy_primitives::{Address, Bytes};
use eyre::Context;
use firehose;
use reth::chainspec::{EthChainSpec, EthereumHardforks};
use reth::revm::revm::Database as _;
use reth_evm::block::TxResult as _;
use reth_evm::execute::BlockExecutor;
use reth_provider::{AccountReader, BlockIdReader, BlockNumReader, StateProviderBox};
use reth_revm::database::StateProviderDatabase;
use reth_revm::State;

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

                // === DIAGNOSTIC PROBE: node-level state at notification receipt ===
                //
                // We log the provider's view of the chain at the moment we receive this
                // ChainCommitted notification. This helps diagnose "wrong state" symptoms by
                // making the in-memory canonical head, the database/static-file tip, and the
                // range of the just-committed chain directly comparable.
                //
                //   best_block_number   — BlockchainProvider returns the canonical in-memory
                //                         head (`CanonicalInMemoryState::get_canonical_block_number`).
                //   last_block_number   — static-files tip (static_file_provider.last_block_number()).
                //                         On a storage_v2 node this also reflects the Execution
                //                         stage frontier because execution receipts/changesets live
                //                         in static files.
                //
                // If the ChainCommitted notification's range is far behind `best`, that's a
                // backfill; if it equals `best`, it's live. A wide gap between `best` and `last`
                // can indicate the in-memory chain and the persisted state disagree.
                let provider = ctx.provider();
                let best = provider.best_block_number().ok();
                let last = provider.last_block_number().ok();
                info!(
                    target: "firehose",
                    chain_range = ?new.range(),
                    best_block_number = ?best,
                    last_block_number = ?last,
                    "ChainCommitted diagnostic probe",
                );

                // Build one `State<StateProviderDatabase>` anchored at the chain's fork block
                // and reuse it for every block in this notification.
                //
                // `reth_revm::State` keeps a `CacheDB` that retains every account touched by a
                // transaction and updates it on each `commit_transaction`. Reusing the same
                // `State` across every block in the chain means:
                //
                // 1. The state handed to the EVM for block N+1 already reflects every
                //    transaction committed in blocks N, N-1, ... within the same notification.
                //    The historical state provider is only consulted for an account on its
                //    first access within the notification; subsequent reads hit the cache.
                //
                // 2. The historical provider is only queried at the chain's fork block
                //    (`chain.fork_block()`) rather than each block's parent hash. This reduces
                //    pressure on the provider and limits the number of opportunities to hit
                //    whatever provider-level bug might return the wrong state.
                //
                // NOTE: this change alone does not fix the root cause of a wrong-state bug.
                // If `state_by_block_hash(fork_block.hash)` itself returns incorrect state
                // (e.g. because `fork_block.hash` resolves to `best_block_number ==
                // last_block_number`, triggering the `LatestStateProviderRef::new` branch in
                // `DatabaseProvider::history_by_block_hash`), every block in the notification
                // will be wrong together. The diagnostic probe below flags that case.
                let fork_block = new.fork_block();

                // === DIAGNOSTIC PROBE: fork-block resolution ===
                //
                // `BlockchainProvider::state_by_block_hash` paths:
                //   - If `fork_block.hash` is in the canonical in-memory chain, returns an
                //     in-memory overlay (correct).
                //   - Otherwise calls `DatabaseProvider::history_by_block_hash(hash)`, which:
                //       1. resolves hash → block_number via HeaderNumbers table,
                //       2. if `block_number == best == last`, returns a LatestStateProviderRef
                //          (reads the latest plain-state, NOT a historical snapshot),
                //       3. else returns `HistoricalStateProviderRef::new(self, block_number+1)`.
                //
                // So the "latest fallback" only triggers when the resolved block number equals
                // both the Finish stage checkpoint AND the static-files tip. For any block
                // strictly behind those, we take the historical path. Log all three numbers
                // and their equality so we can tell from production logs which branch fired.
                let resolved_fork_number = provider.block_number(fork_block.hash).ok().flatten();
                info!(
                    target: "firehose",
                    fork_block_number = fork_block.number,
                    fork_block_hash = %fork_block.hash,
                    resolved_block_number = ?resolved_fork_number,
                    best_block_number = ?best,
                    last_block_number = ?last,
                    "Resolving state provider for fork block",
                );

                let state_provider = ctx
                    .provider()
                    .state_by_block_hash(fork_block.hash)
                    .wrap_err_with(|| {
                        format!(
                            "Failed to get state provider for chain fork block {} ({})",
                            fork_block.number, fork_block.hash,
                        )
                    })?;

                // === DIAGNOSTIC PROBE: first-tx sender nonce from the state provider ===
                //
                // Pre-read the nonce of the first transaction's signer from the state provider
                // we just constructed, BEFORE wrapping it in `State<DB>`. Compare it against
                // the tx's declared nonce.
                //
                // Invariant: for a tx that landed in the first block of this notification,
                // the state provider anchored at `fork_block` (= `block.parent_hash()`) must
                // report `nonce == tx.nonce` for that signer. If it reports something else,
                // the state provider is lying about historical state, and we know it before
                // the EVM even sees the transaction.
                //
                // We skip this check for deposits (no signer / nonce semantics) and for
                // notifications whose first block has no transactions.
                if let Some((first_block, _)) = new.blocks_and_receipts().next() {
                    for (tx_index, recovered_tx) in
                        first_block.transactions_recovered().enumerate().take(1)
                    {
                        let signer: Address = recovered_tx.signer();
                        let tx_nonce = recovered_tx.nonce();
                        let tx_hash = recovered_tx.tx_hash();
                        let state_nonce = state_provider
                            .basic_account(&signer)
                            .ok()
                            .flatten()
                            .map(|a| a.nonce);
                        let matches = state_nonce == Some(tx_nonce);
                        info!(
                            target: "firehose",
                            first_block_number = first_block.number(),
                            tx_index,
                            tx_hash = %tx_hash,
                            signer = %signer,
                            tx_nonce,
                            state_nonce = ?state_nonce,
                            matches,
                            "First-tx nonce probe (pre-execution)",
                        );
                    }
                }

                let mut shared_state: State<StateProviderDatabase<StateProviderBox>> =
                    State::builder()
                        .with_database(StateProviderDatabase::new(state_provider))
                        .with_bundle_update()
                        .build();

                let chain_start = std::time::Instant::now();
                for (block, receipts) in new.blocks_and_receipts() {
                    let result = trace_block(
                        &ctx,
                        &mut tracer,
                        &evm_config,
                        block,
                        receipts,
                        &get_signature,
                        &mut shared_state,
                    );
                    if let Err(err) = result {
                        error!(target: "firehose", block = block.number(), error = ?err, "trace_block failed");
                        if skip_failed {
                            warn!(target: "firehose", block = block.number(), "SKIP_FAILED_BLOCKS=true, skipping block");
                            tracer.on_block_end(Some(&*Box::<dyn std::error::Error>::from(
                                "some error",
                            )));
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
    shared_state: &mut State<StateProviderDatabase<StateProviderBox>>,
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

    // === DIAGNOSTIC PROBE: per-block pre-execution state snapshot ===
    //
    // At this point `shared_state` holds the cumulative cache from all prior blocks in the
    // notification. We read the first tx's signer nonce directly from the cached `State<DB>`
    // (which is what the EVM will see on execution) and compare against the tx's declared
    // nonce. This catches cross-block drift: if block N-1's commit in `shared_state`
    // corrupted or failed to update the cache, block N's pre-state will disagree with the
    // tx's expectations.
    //
    // `Database::basic` populates the cache on miss (via the underlying StateProviderDatabase
    // → StateProviderBox → BlockchainProvider at the fork block), so the first call for a
    // given address here IS the historical state read, and subsequent calls hit the cache.
    if let Some(recovered_tx) = block.transactions_recovered().next() {
        let signer: Address = recovered_tx.signer();
        let tx_nonce = recovered_tx.nonce();
        let tx_hash = recovered_tx.tx_hash();
        let cached_nonce = shared_state
            .basic(signer)
            .ok()
            .flatten()
            .map(|info| info.nonce);
        let matches = cached_nonce == Some(tx_nonce);
        info!(
            target: "firehose",
            block = block.number(),
            tx_hash = %tx_hash,
            signer = %signer,
            tx_nonce,
            cached_nonce = ?cached_nonce,
            matches,
            "Per-block first-tx nonce probe (from shared_state cache)",
        );
    }

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
    // The EVM borrows `shared_state` mutably for the duration of this block. Bundle updates
    // from prior blocks in the same ChainCommitted notification are already reflected in its
    // cache via earlier `commit_transaction` calls, so nonce / balance reads here see the
    // correct pre-block state without re-querying the historical provider.
    let evm = evm_config.evm_with_env_and_inspector(&mut *shared_state, evm_env, inspector);
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

        // Fresh state reader per transaction for on_tx_start StateReader.
        //
        // KNOWN LIMITATION: this reader is resolved from the provider at `parent_hash`, not
        // from the live `shared_state`. The firehose StateReader observations it produces are
        // pre-block, not pre-tx. EVM-level nonce validation is unaffected (that uses the
        // shared_state cache, not this reader).
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
    // This consumes the executor, dropping the inspector and releasing the tracer borrow.
    // State mutations (pre-execution changes, tx commits, post-execution changes) remain in
    // `shared_state`, ready for the next block in this chain notification.
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
