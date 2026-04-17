// Tests ported from go-ethereum's eth/tracers/firehose_test.go (TestFirehose_FlashBlock* tests).
//
// Flash blocks are a mechanism used by Optimism/Katana where a single canonical block is
// built incrementally across multiple "flash" iterations. Each iteration adds more transactions,
// emits a partial block, and a snapshot captures the point where the next iteration should start.
//
// The tests verify:
//  1. Transaction traces are accumulated correctly across flash block iterations
//  2. Snapshot captures state at a specific point (not including post-snapshot traces)
//  3. Sequence validation: same or lower flash block index panics
//  4. New block number clears the snapshot
//  5. Regular blocks do not affect the flash block snapshot or last flash block index
//  6. System calls are included in snapshots
//  7. Balance changes and code changes are included in snapshots

use alloy_primitives::{Bloom, Bytes, U256, B256};
use firehose::{BlockData, BlockEvent, FlashBlockData, Opcode, TxEvent, TxType};
use firehose_test::{
    alice_addr, big_int, bob_addr, charlie_addr, hash32, miner_addr, success_receipt,
    test_block, beacon_roots_address, history_storage_address,
    system_address, TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

/// newFlashBlockEvent builds a BlockEvent with FlashBlock metadata using test_block's block data.
fn new_flash_block_event(idx: u64) -> BlockEvent {
    let mut event = test_block();
    event.flash_block = Some(FlashBlockData { idx, is_final: false });
    event
}

/// newFlashBlockEventFromBlock builds a flash BlockEvent using custom block data.
fn new_flash_block_event_from_block(block: BlockData, idx: u64) -> BlockEvent {
    BlockEvent {
        block,
        finalized: None,
        flash_block: Some(FlashBlockData { idx, is_final: false }),
    }
}

/// Flash transaction helpers with unique nonces for identification.
fn flash_tx(nonce: u64, hash_byte: u8) -> TxEvent {
    TxEvent {
        tx_type: TxType::Legacy,
        hash: B256::from({
            let mut b = [0u8; 32];
            b[0] = hash_byte;
            b[1] = hash_byte;
            b
        }),
        from: alice_addr(),
        to: Some(bob_addr()),
        input: Bytes::new(),
        value: big_int(nonce as i64 * 1000),
        gas: 21000,
        gas_price: big_int(1),
        nonce,
        index: 0,
        v: None,
        r: B256::ZERO,
        s: B256::ZERO,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: vec![],
        blob_gas_fee_cap: None,
        blob_hashes: vec![],
        set_code_authorizations: vec![],
    }
}

fn flash_tx1() -> TxEvent { flash_tx(1, 0x11) }
fn flash_tx2() -> TxEvent { flash_tx(2, 0x22) }
fn flash_tx3() -> TxEvent { flash_tx(3, 0x33) }
fn flash_tx4() -> TxEvent { flash_tx(4, 0x44) }

/// Executes a simple send transaction within the tester.
fn exec_flash_tx(tester: &mut TracerTester, tx: TxEvent) {
    tester
        .start_trx(tx)
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_trx(Some(success_receipt(21000)), None);
}

fn block2_data() -> BlockData {
    let b1 = test_block().block;
    BlockData {
        number: b1.number + 1,
        hash: hash32(9999),
        parent_hash: b1.hash,
        uncle_hash: b1.uncle_hash,
        coinbase: b1.coinbase,
        root: b1.root,
        tx_hash: b1.tx_hash,
        receipt_hash: b1.receipt_hash,
        bloom: Bloom::ZERO,
        difficulty: U256::ZERO,
        gas_limit: b1.gas_limit,
        time: b1.time + 1,
        size: b1.size,
        ..Default::default()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[test]
fn test_flash_block_basic_handling() {
    let mut tester = TracerTester::new();

    // --- Flash block iteration 1 ---
    tester.tracer.on_block_start(new_flash_block_event(1));
    exec_flash_tx(&mut tester, flash_tx1());
    exec_flash_tx(&mut tester, flash_tx2());

    // Snapshot before ending, so the next iteration picks up tx1+tx2.
    tester.tracer.snapshot_flash_block_for_next_iteration();
    tester.tracer.on_block_end(None);

    // --- Flash block iteration 2 (Idx=3, indices can skip) ---
    tester.tracer.on_block_start(new_flash_block_event(3));
    exec_flash_tx(&mut tester, flash_tx3());
    exec_flash_tx(&mut tester, flash_tx4());
    tester.tracer.on_block_end(None);

    // Two blocks were emitted; parse both.
    let blocks = tester.parse_firehose_blocks();
    assert_eq!(blocks.len(), 2, "two blocks should have been emitted");

    // First flash block: only tx1 and tx2
    assert_eq!(blocks[0].transaction_traces.len(), 2);
    assert_eq!(blocks[0].transaction_traces[0].nonce, 1);
    assert_eq!(blocks[0].transaction_traces[1].nonce, 2);

    // Second flash block: tx1, tx2 (from snapshot) + tx3, tx4 (new)
    assert_eq!(blocks[1].transaction_traces.len(), 4, "second flash block should have 4 transactions");
    assert_eq!(blocks[1].transaction_traces[0].nonce, 1);
    assert_eq!(blocks[1].transaction_traces[1].nonce, 2);
    assert_eq!(blocks[1].transaction_traces[2].nonce, 3);
    assert_eq!(blocks[1].transaction_traces[3].nonce, 4);
}

#[test]
fn test_flash_block_sequence_validation_same_index_panics() {
    let mut tester = TracerTester::new();
    let block1_data = test_block().block;

    tester.tracer.on_block_start(new_flash_block_event_from_block(block1_data.clone(), 1));
    tester.tracer.snapshot_flash_block_for_next_iteration();
    tester.tracer.on_block_end(None);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tester.tracer.on_block_start(new_flash_block_event_from_block(block1_data, 1));
    }));
    assert!(result.is_err(), "same index should panic");
}

#[test]
fn test_flash_block_sequence_validation_backwards_index_panics() {
    let mut tester = TracerTester::new();
    let block1_data = test_block().block;

    tester.tracer.on_block_start(new_flash_block_event_from_block(block1_data.clone(), 1));
    tester.tracer.snapshot_flash_block_for_next_iteration();
    tester.tracer.on_block_end(None);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tester.tracer.on_block_start(new_flash_block_event_from_block(block1_data, 0));
    }));
    assert!(result.is_err(), "backwards index should panic");
}

#[test]
fn test_flash_block_sequence_validation_new_block_number_no_panic() {
    let mut tester = TracerTester::new();
    let block1_data = test_block().block;
    let block2 = block2_data();

    tester.tracer.on_block_start(new_flash_block_event_from_block(block1_data, 1));
    tester.tracer.snapshot_flash_block_for_next_iteration();
    tester.tracer.on_block_end(None);

    // Should NOT panic: different block number clears snapshot
    tester.tracer.on_block_start(new_flash_block_event_from_block(block2, 0));
    tester.tracer.on_block_end(None);
}

#[test]
fn test_flash_block_sequence_validation_non_sequential_but_higher() {
    let mut tester = TracerTester::new();
    let block1_data = test_block().block;

    tester.tracer.on_block_start(new_flash_block_event_from_block(block1_data.clone(), 1));
    tester.tracer.snapshot_flash_block_for_next_iteration();
    tester.tracer.on_block_end(None);

    // Skipped indices 2 and 3, but Idx=4 is still strictly higher than 1.
    tester.tracer.on_block_start(new_flash_block_event_from_block(block1_data, 4));
    tester.tracer.on_block_end(None);
}

#[test]
fn test_flash_block_persists_on_regular_block() {
    let block1_data = test_block().block;
    let block2 = block2_data();

    let mut tester = TracerTester::new();

    // Start flash block with Idx=1
    tester.tracer.on_block_start(new_flash_block_event_from_block(block1_data, 1));
    assert!(tester.tracer.is_flash_block());

    tester.tracer.snapshot_flash_block_for_next_iteration();
    tester.tracer.on_block_end(None);

    // Snapshot is set; IsFlashBlock is false between blocks
    assert!(tester.tracer.has_flash_block_snapshot());
    assert!(!tester.tracer.is_flash_block());

    // Start regular (non-flash) block
    tester.tracer.on_block_start(BlockEvent::new(block2));
    assert!(!tester.tracer.is_flash_block());

    // Snapshot must NOT be cleared by a regular block
    assert!(tester.tracer.has_flash_block_snapshot(), "snapshot should persist through regular block");

    tester.tracer.on_block_end(None);
}

#[test]
fn test_flash_block_snapshot_basic_usage() {
    let mut tester = TracerTester::new();

    // --- Flash block iteration 1 ---
    tester.tracer.on_block_start(new_flash_block_event(1));

    // Add two regular transactions
    exec_flash_tx(&mut tester, flash_tx1());
    exec_flash_tx(&mut tester, flash_tx2());

    // Add first system call BEFORE snapshot (should be included)
    tester.tracer.on_system_call_start();
    tester.tracer.on_call_enter(0, Opcode::Call as u8, system_address(), beacon_roots_address(), &[], 30_000_000, U256::ZERO);
    tester.tracer.on_call_exit(0, &[], 50_000, None, false);
    tester.tracer.on_system_call_end();

    // Take snapshot: captures 2 txs + 1 system call
    tester.tracer.snapshot_flash_block_for_next_iteration();

    // Add second system call AFTER snapshot (should NOT be in next iteration)
    tester.tracer.on_system_call_start();
    tester.tracer.on_call_enter(0, Opcode::Call as u8, system_address(), history_storage_address(), &[], 30_000_000, U256::ZERO);
    tester.tracer.on_call_exit(0, &[], 45_000, None, false);
    tester.tracer.on_system_call_end();

    tester.tracer.on_block_end(None);

    // --- Flash block iteration 2 ---
    tester.tracer.on_block_start(new_flash_block_event(2));

    // Should have 2 txs + 1 system call (from snapshot, NOT the post-snapshot system call)
    exec_flash_tx(&mut tester, flash_tx4());
    tester.tracer.on_block_end(None);

    let blocks = tester.parse_firehose_blocks();
    assert_eq!(blocks.len(), 2);

    // First block: 2 txs + 2 system calls
    assert_eq!(blocks[0].transaction_traces.len(), 2);
    assert_eq!(blocks[0].system_calls.len(), 2);

    // Second block (from snapshot): 2 txs + 1 system call (NOT 2), plus tx4
    assert_eq!(blocks[1].transaction_traces.len(), 3, "second block should have tx1+tx2 (from snapshot) + tx4 (new)");
    assert_eq!(blocks[1].transaction_traces[0].nonce, 1);
    assert_eq!(blocks[1].transaction_traces[1].nonce, 2);
    assert_eq!(blocks[1].transaction_traces[2].nonce, 4);
    assert_eq!(blocks[1].system_calls.len(), 1, "second block should have only 1 system call from snapshot");
}

#[test]
fn test_flash_block_snapshot_without_snapshot() {
    let mut tester = TracerTester::new();

    // --- Flash block iteration 1: add 2 transactions, no snapshot ---
    tester.tracer.on_block_start(new_flash_block_event(1));
    exec_flash_tx(&mut tester, flash_tx1());
    exec_flash_tx(&mut tester, flash_tx2());
    // Intentionally NOT calling snapshot_flash_block_for_next_iteration()
    tester.tracer.on_block_end(None);

    // --- Flash block iteration 2: should start completely fresh ---
    tester.tracer.on_block_start(new_flash_block_event(2));
    tester.tracer.on_block_end(None);

    let blocks = tester.parse_firehose_blocks();
    assert_eq!(blocks.len(), 2);

    assert_eq!(blocks[0].transaction_traces.len(), 2);
    assert_eq!(blocks[1].transaction_traces.len(), 0, "second block should start fresh with no transactions");
}

#[test]
fn test_flash_block_snapshot_cleared_on_new_block() {
    let block1_data = test_block().block;
    let block2 = BlockData {
        number: block1_data.number + 1,
        hash: hash32(8888),
        parent_hash: block1_data.hash,
        uncle_hash: block1_data.uncle_hash,
        coinbase: block1_data.coinbase,
        root: block1_data.root,
        tx_hash: block1_data.tx_hash,
        receipt_hash: block1_data.receipt_hash,
        bloom: Bloom::ZERO,
        difficulty: U256::ZERO,
        gas_limit: block1_data.gas_limit,
        time: block1_data.time + 1,
        size: block1_data.size,
        ..Default::default()
    };

    let mut tester = TracerTester::new();

    // --- Flash block on block 1 ---
    tester.tracer.on_block_start(new_flash_block_event_from_block(block1_data, 1));
    exec_flash_tx(&mut tester, flash_tx1());
    tester.tracer.snapshot_flash_block_for_next_iteration();
    assert!(tester.tracer.has_flash_block_snapshot());
    tester.tracer.on_block_end(None);

    // --- Flash block on block 2 (different number): snapshot must be cleared ---
    tester.tracer.on_block_start(new_flash_block_event_from_block(block2, 1));

    // Snapshot should have been cleared because the block number changed
    assert!(!tester.tracer.has_flash_block_snapshot(), "snapshot should be cleared on new block number");

    tester.tracer.on_block_end(None);

    let blocks = tester.parse_firehose_blocks();
    assert_eq!(blocks.len(), 2);

    // Second block should have started fresh (no transactions from the cleared snapshot)
    assert_eq!(blocks[1].transaction_traces.len(), 0, "second block should start fresh after snapshot is cleared");
}

#[test]
fn test_flash_block_snapshot_multiple_iterations() {
    let mut tester = TracerTester::new();

    // --- Iteration 1: snapshot after tx1, then add tx2 after snapshot ---
    tester.tracer.on_block_start(new_flash_block_event(1));
    exec_flash_tx(&mut tester, flash_tx1());
    tester.tracer.snapshot_flash_block_for_next_iteration(); // snapshot: 1 tx
    exec_flash_tx(&mut tester, flash_tx2());                 // added after snapshot
    tester.tracer.on_block_end(None);

    // --- Iteration 2: starts with 1 tx (from snapshot), adds tx3, snapshot after tx3, tx4 after snapshot ---
    tester.tracer.on_block_start(new_flash_block_event(2));
    exec_flash_tx(&mut tester, flash_tx3());
    tester.tracer.snapshot_flash_block_for_next_iteration(); // snapshot: 2 txs (tx1+tx3)
    exec_flash_tx(&mut tester, flash_tx4());                 // added after snapshot
    tester.tracer.on_block_end(None);

    // --- Iteration 3: starts with 2 txs (from snapshot: tx1+tx3), no more txs added ---
    tester.tracer.on_block_start(new_flash_block_event(3));
    tester.tracer.on_block_end(None);

    let blocks = tester.parse_firehose_blocks();
    assert_eq!(blocks.len(), 3);

    // First block: tx1 + tx2
    assert_eq!(blocks[0].transaction_traces.len(), 2);
    assert_eq!(blocks[0].transaction_traces[0].nonce, 1);
    assert_eq!(blocks[0].transaction_traces[1].nonce, 2);

    // Second block: tx1 (snapshot) + tx3 (new) + tx4 (post-snapshot)
    assert_eq!(blocks[1].transaction_traces.len(), 3);
    assert_eq!(blocks[1].transaction_traces[0].nonce, 1);
    assert_eq!(blocks[1].transaction_traces[1].nonce, 3);
    assert_eq!(blocks[1].transaction_traces[2].nonce, 4);

    // Third block: tx1 + tx3 (from snapshot, tx4 excluded)
    assert_eq!(blocks[2].transaction_traces.len(), 2);
    assert_eq!(blocks[2].transaction_traces[0].nonce, 1);
    assert_eq!(blocks[2].transaction_traces[1].nonce, 3);
}

#[test]
fn test_flash_block_snapshot_system_calls_included() {
    let mut tester = TracerTester::new();

    // --- Flash block iteration 1 ---
    tester.tracer.on_block_start(new_flash_block_event(1));

    // Regular transaction
    exec_flash_tx(&mut tester, flash_tx1());

    // System call 1 (before snapshot)
    tester.tracer.on_system_call_start();
    tester.tracer.on_call_enter(0, Opcode::Call as u8, system_address(), beacon_roots_address(), &[], 30_000_000, U256::ZERO);
    tester.tracer.on_call_exit(0, &[], 50_000, None, false);
    tester.tracer.on_system_call_end();

    // System call 2 (before snapshot)
    tester.tracer.on_system_call_start();
    tester.tracer.on_call_enter(0, Opcode::Call as u8, system_address(), history_storage_address(), &[], 30_000_000, U256::ZERO);
    tester.tracer.on_call_exit(0, &[], 45_000, None, false);
    tester.tracer.on_system_call_end();

    // Snapshot: 1 tx + 2 system calls
    tester.tracer.snapshot_flash_block_for_next_iteration();

    // System call 3 (after snapshot - should NOT appear in next iteration)
    tester.tracer.on_system_call_start();
    tester.tracer.on_call_enter(0, Opcode::Call as u8, system_address(), charlie_addr(), &[], 30_000_000, U256::ZERO);
    tester.tracer.on_call_exit(0, &[], 40_000, None, false);
    tester.tracer.on_system_call_end();

    tester.tracer.on_block_end(None);

    // --- Flash block iteration 2 ---
    tester.tracer.on_block_start(new_flash_block_event(2));
    exec_flash_tx(&mut tester, flash_tx2());
    tester.tracer.on_block_end(None);

    let blocks = tester.parse_firehose_blocks();
    assert_eq!(blocks.len(), 2);

    // First block: 1 tx + 3 system calls
    assert_eq!(blocks[0].transaction_traces.len(), 1);
    assert_eq!(blocks[0].system_calls.len(), 3);

    // Second block: 1 tx (from snapshot) + 2 system calls (from snapshot, NOT 3) + tx2 (new)
    assert_eq!(blocks[1].transaction_traces.len(), 2);
    assert_eq!(blocks[1].transaction_traces[0].nonce, 1);
    assert_eq!(blocks[1].transaction_traces[1].nonce, 2);
    assert_eq!(blocks[1].system_calls.len(), 2, "only system calls before the snapshot should appear");
}

#[test]
fn test_flash_block_snapshot_balance_changes_included() {
    let mut tester = TracerTester::new();

    // --- Flash block iteration 1 ---
    tester.tracer.on_block_start(new_flash_block_event(1));

    // Transaction with balance changes
    exec_flash_tx(&mut tester, flash_tx1());
    // Balance change before snapshot (block-level, outside transaction)
    tester.balance_change(
        miner_addr(),
        U256::ZERO,
        big_int(1_000_000_000_000_000_000),
        pbeth::balance_change::Reason::RewardMineBlock,
    );

    // Snapshot: includes tx1 + block-level balance change
    tester.tracer.snapshot_flash_block_for_next_iteration();

    // Balance change AFTER snapshot (should NOT appear in next iteration)
    tester.balance_change(
        alice_addr(),
        U256::ZERO,
        big_int(500_000_000_000_000_000),
        pbeth::balance_change::Reason::RewardMineUncle,
    );

    tester.tracer.on_block_end(None);

    // --- Flash block iteration 2 ---
    tester.tracer.on_block_start(new_flash_block_event(2));
    tester.tracer.on_block_end(None);

    let blocks = tester.parse_firehose_blocks();
    assert_eq!(blocks.len(), 2);

    // First block: 1 tx + 2 balance changes
    assert_eq!(blocks[0].balance_changes.len(), 2);

    // Second block: 1 balance change (from snapshot only, not the post-snapshot one)
    assert_eq!(blocks[1].transaction_traces.len(), 1, "tx1 from snapshot");
    assert_eq!(blocks[1].balance_changes.len(), 1, "only balance change before snapshot");
    assert_eq!(blocks[1].balance_changes[0].address, miner_addr().as_slice());
}

#[test]
fn test_flash_block_snapshot_code_changes_included() {
    let empty_hash = B256::ZERO;

    let mut tester = TracerTester::new();

    // --- Flash block iteration 1 ---
    tester.tracer.on_block_start(new_flash_block_event(1));

    // Transaction
    exec_flash_tx(&mut tester, flash_tx1());

    // Code change before snapshot
    tester.code_change(
        beacon_roots_address(),
        empty_hash,
        hash32(100),
        vec![],
        vec![0x60, 0x01],
    );

    // Snapshot: includes tx1 + code change
    tester.tracer.snapshot_flash_block_for_next_iteration();

    // Code change AFTER snapshot (should NOT appear in next iteration)
    tester.code_change(
        history_storage_address(),
        empty_hash,
        hash32(200),
        vec![],
        vec![0x60, 0x02],
    );

    tester.tracer.on_block_end(None);

    // --- Flash block iteration 2 ---
    tester.tracer.on_block_start(new_flash_block_event(2));
    tester.tracer.on_block_end(None);

    let blocks = tester.parse_firehose_blocks();
    assert_eq!(blocks.len(), 2);

    // First block: 1 tx + 2 code changes
    assert_eq!(blocks[0].code_changes.len(), 2);

    // Second block: 1 tx + only 1 code change (from snapshot, not the post-snapshot one)
    assert_eq!(blocks[1].transaction_traces.len(), 1);
    assert_eq!(blocks[1].code_changes.len(), 1, "only code change before snapshot");
    assert_eq!(blocks[1].code_changes[0].address, beacon_roots_address().as_slice());
}

#[test]
fn test_flash_block_snapshot_on_non_flash_block_is_noop() {
    let mut tester = TracerTester::new();

    // Regular block (no FlashBlock field)
    tester.start_block();
    exec_flash_tx(&mut tester, flash_tx1());

    // Snapshot on a non-flash block should be a no-op
    tester.tracer.snapshot_flash_block_for_next_iteration();
    assert!(!tester.tracer.has_flash_block_snapshot(), "no snapshot should be created for non-flash blocks");

    tester.end_block(None);
}

#[test]
fn test_flash_block_ordinal_restored_from_snapshot() {
    let mut tester = TracerTester::new();

    // --- Flash block iteration 1 ---
    tester.tracer.on_block_start(new_flash_block_event(1));
    exec_flash_tx(&mut tester, flash_tx1());
    exec_flash_tx(&mut tester, flash_tx2());

    // Snapshot the ordinal after 2 transactions
    tester.tracer.snapshot_flash_block_for_next_iteration();

    // Add more transactions after the snapshot (should not affect ordinals in next iteration)
    exec_flash_tx(&mut tester, flash_tx3());
    tester.tracer.on_block_end(None);

    // --- Flash block iteration 2 ---
    tester.tracer.on_block_start(new_flash_block_event(2));
    exec_flash_tx(&mut tester, flash_tx4());
    tester.tracer.on_block_end(None);

    let blocks = tester.parse_firehose_blocks();
    assert_eq!(blocks.len(), 2);

    let second = &blocks[1];
    assert_eq!(second.transaction_traces.len(), 3); // tx1, tx2 (snapshot), tx4 (new)

    // tx4 (new in iteration 2) should have a BeginOrdinal that continues from where
    // tx2 left off, not from where tx3 would have been.
    let tx2_end_ordinal = second.transaction_traces[1].end_ordinal;
    let tx4_begin_ordinal = second.transaction_traces[2].begin_ordinal;
    assert!(
        tx4_begin_ordinal > tx2_end_ordinal,
        "tx4 begin ordinal ({}) should be after tx2 end ordinal ({})",
        tx4_begin_ordinal,
        tx2_end_ordinal
    );
}
