use firehose_tracer::pb::sf::ethereum::r#type::v2 as pbeth;
use firehose_tracer_test::{
    alice_addr, beacon_roots_address, bob_addr, hash32, history_storage_address, success_receipt,
    system_address, test_legacy_trx, TracerTester,
};

// =============================================================================
// System Call Tests
// =============================================================================
// System calls are protocol-level calls executed outside regular transactions
// Examples: Beacon root updates (EIP-4788), parent hash storage (EIP-2935)

#[test]
fn test_beacon_root_system_call() {
    // EIP-4788: Beacon block root stored in contract
    let beacon_root = hash32(12345); // Simulated beacon root

    let mut tester = TracerTester::new();
    tester
        .start_block()
        // System call happens before any transactions
        .system_call(
            system_address(),
            beacon_roots_address(),
            beacon_root.0.to_vec(),
            30_000_000,
            vec![],
            50_000,
        )
        // Then regular transaction
        .start_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("systemcall", |block| {
            // Verify system call was recorded
            assert_eq!(1, block.system_calls.len(), "Should have 1 system call");
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have 1 transaction"
            );

            // Verify system call details
            let sys_call = &block.system_calls[0];
            assert_eq!(system_address().as_slice(), sys_call.caller.as_slice());
            assert_eq!(
                beacon_roots_address().as_slice(),
                sys_call.address.as_slice()
            );
            assert_eq!(beacon_root.as_slice(), sys_call.input.as_slice());
            assert_eq!(30_000_000, sys_call.gas_limit);
            assert_eq!(50_000, sys_call.gas_consumed);
            assert_eq!(pbeth::CallType::Call as i32, sys_call.call_type);

            // Verify ordinals are assigned
            assert!(sys_call.begin_ordinal > 0, "BeginOrdinal should be set");
            assert!(sys_call.end_ordinal > 0, "EndOrdinal should be set");
            assert!(
                sys_call.begin_ordinal < sys_call.end_ordinal,
                "BeginOrdinal should be less than EndOrdinal"
            );
        });
}

#[test]
fn test_parent_hash_system_call() {
    // EIP-2935/7709: Parent block hash storage
    let parent_hash = hash32(99999);

    let mut tester = TracerTester::new();
    tester
        .start_block()
        .system_call(
            system_address(),
            history_storage_address(),
            parent_hash.0.to_vec(),
            30_000_000,
            vec![],
            45_000,
        )
        .start_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("systemcall", |block| {
            assert_eq!(1, block.system_calls.len());
            let sys_call = &block.system_calls[0];
            assert_eq!(
                history_storage_address().as_slice(),
                sys_call.address.as_slice()
            );
            assert_eq!(parent_hash.as_slice(), sys_call.input.as_slice());
        });
}

#[test]
fn test_multiple_system_calls() {
    // Multiple system calls in same block
    let beacon_root = hash32(1111);
    let parent_hash = hash32(2222);

    let mut tester = TracerTester::new();
    tester
        .start_block()
        // First system call: beacon root
        .system_call(
            system_address(),
            beacon_roots_address(),
            beacon_root.0.to_vec(),
            30_000_000,
            vec![],
            50_000,
        )
        // Second system call: parent hash
        .system_call(
            system_address(),
            history_storage_address(),
            parent_hash.0.to_vec(),
            30_000_000,
            vec![],
            45_000,
        )
        // Then regular transaction
        .start_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("systemcall", |block| {
            // Should have 2 system calls and 1 transaction
            assert_eq!(2, block.system_calls.len(), "Should have 2 system calls");
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have 1 transaction"
            );

            // Verify first system call (beacon root)
            let sys_call1 = &block.system_calls[0];
            assert_eq!(
                beacon_roots_address().as_slice(),
                sys_call1.address.as_slice()
            );
            assert_eq!(beacon_root.as_slice(), sys_call1.input.as_slice());
            assert_eq!(50_000, sys_call1.gas_consumed);

            // Verify second system call (parent hash)
            let sys_call2 = &block.system_calls[1];
            assert_eq!(
                history_storage_address().as_slice(),
                sys_call2.address.as_slice()
            );
            assert_eq!(parent_hash.as_slice(), sys_call2.input.as_slice());
            assert_eq!(45_000, sys_call2.gas_consumed);

            // Verify ordinals are sequential
            assert!(
                sys_call1.end_ordinal < sys_call2.begin_ordinal,
                "System calls should have sequential ordinals"
            );
        });
}

#[test]
fn test_system_call_with_storage_changes() {
    use firehose_tracer_test::big_int;
    // System call that makes storage changes
    let beacon_root = hash32(5555);
    let storage_key = hash32(1);
    let storage_value = hash32(12345);
    let zero_val = hash32(0);

    let mut tester = TracerTester::new();
    tester
        .start_block()
        .start_system_call()
        .start_call(
            system_address(),
            beacon_roots_address(),
            big_int(0),
            30_000_000,
            beacon_root.0.to_vec(),
        )
        // System call modifies storage
        .storage_change(beacon_roots_address(), storage_key, zero_val, storage_value)
        .end_call(vec![], 50_000)
        .end_system_call()
        .start_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("systemcall", |block| {
            assert_eq!(1, block.system_calls.len());
            let sys_call = &block.system_calls[0];

            // Verify storage change was recorded
            assert_eq!(1, sys_call.storage_changes.len());
            assert_eq!(
                beacon_roots_address().as_slice(),
                sys_call.storage_changes[0].address.as_slice()
            );
            assert_eq!(
                storage_key.as_slice(),
                sys_call.storage_changes[0].key.as_slice()
            );
            assert_eq!(
                storage_value.as_slice(),
                sys_call.storage_changes[0].new_value.as_slice()
            );
        });
}

#[test]
fn test_system_call_before_transactions() {
    use firehose_tracer_test::{big_int, charlie_addr, miner_addr};
    // System call happens before any transactions (most common case)
    let beacon_root = hash32(7777);

    let mut tester = TracerTester::new();
    tester
        .start_block()
        .system_call(
            system_address(),
            beacon_roots_address(),
            beacon_root.0.to_vec(),
            30_000_000,
            vec![],
            50_000,
        )
        // First transaction
        .start_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_trx(Some(success_receipt(21000)), None)
        // Second transaction
        .start_trx(test_legacy_trx())
        .start_call(charlie_addr(), miner_addr(), big_int(200), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("systemcall", |block| {
            assert_eq!(1, block.system_calls.len());
            assert_eq!(2, block.transaction_traces.len());

            // System call ordinals should be before transaction ordinals
            let sys_call = &block.system_calls[0];
            let first_trx = &block.transaction_traces[0];
            assert!(
                sys_call.end_ordinal < first_trx.begin_ordinal,
                "System call should complete before first transaction"
            );
        });
}

#[test]
fn test_system_call_ordinal_assignment() {
    // Verify ordinals are correctly assigned for system calls
    let beacon_root = hash32(8888);

    let mut tester = TracerTester::new();
    tester
        .start_block()
        .system_call(
            system_address(),
            beacon_roots_address(),
            beacon_root.0.to_vec(),
            30_000_000,
            vec![],
            50_000,
        )
        .start_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("systemcall", |block| {
            let sys_call = &block.system_calls[0];

            // System call should have non-zero ordinals
            assert!(
                sys_call.begin_ordinal > 0,
                "BeginOrdinal should be non-zero"
            );
            assert!(sys_call.end_ordinal > 0, "EndOrdinal should be non-zero");

            // BeginOrdinal < EndOrdinal
            assert!(sys_call.begin_ordinal < sys_call.end_ordinal);
        });
}

#[test]
fn test_system_call_no_transactions() {
    // Block with only system calls, no transactions
    let beacon_root = hash32(9999);

    let mut tester = TracerTester::new();
    tester
        .start_block()
        .system_call(
            system_address(),
            beacon_roots_address(),
            beacon_root.0.to_vec(),
            30_000_000,
            vec![],
            50_000,
        )
        .end_block(None)
        .validate_with_category("systemcall", |block| {
            assert_eq!(1, block.system_calls.len());
            assert_eq!(0, block.transaction_traces.len());

            let sys_call = &block.system_calls[0];
            assert_eq!(
                beacon_roots_address().as_slice(),
                sys_call.address.as_slice()
            );
        });
}

#[test]
fn test_system_call_before_and_after_transaction() {
    use firehose_tracer_test::big_int;
    // System call → Transaction → System call
    // Tests ordinal sequencing: sys1(1-2) → trx(3-6) → sys2(7-8)
    let beacon_root1 = hash32(1111);
    let beacon_root2 = hash32(2222);

    let mut tester = TracerTester::new();
    tester
        .start_block()
        // First system call
        .system_call(
            system_address(),
            beacon_roots_address(),
            beacon_root1.0.to_vec(),
            30_000_000,
            vec![],
            50_000,
        )
        // Transaction
        .start_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_trx(Some(success_receipt(21000)), None)
        // Second system call
        .system_call(
            system_address(),
            beacon_roots_address(),
            beacon_root2.0.to_vec(),
            30_000_000,
            vec![],
            50_000,
        )
        .end_block(None)
        .validate_with_category("systemcall", |block| {
            assert_eq!(2, block.system_calls.len(), "Should have 2 system calls");
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have 1 transaction"
            );

            // First system call
            let sys_call1 = &block.system_calls[0];
            assert_eq!(beacon_root1.as_slice(), sys_call1.input.as_slice());
            assert_eq!(1, sys_call1.begin_ordinal);
            assert_eq!(2, sys_call1.end_ordinal);

            // Transaction (ordinals continue from first system call)
            let trx = &block.transaction_traces[0];
            assert_eq!(3, trx.begin_ordinal);
            assert_eq!(6, trx.end_ordinal);

            // Second system call (ordinals continue from transaction)
            let sys_call2 = &block.system_calls[1];
            assert_eq!(beacon_root2.as_slice(), sys_call2.input.as_slice());
            assert_eq!(7, sys_call2.begin_ordinal);
            assert_eq!(8, sys_call2.end_ordinal);

            // Verify ordinal ordering across all elements
            assert!(
                sys_call1.end_ordinal < trx.begin_ordinal,
                "First system call should complete before transaction"
            );
            assert!(
                trx.end_ordinal < sys_call2.begin_ordinal,
                "Transaction should complete before second system call"
            );
        });
}

/// reth/alloy-evm wraps `apply_pre_execution_changes` (which runs EIP-2935 then EIP-4788)
/// in ONE `OnSystemCallStart`/`OnSystemCallEnd` pair. Geth's firehose tracer wraps each
/// EIP separately and applies them in the opposite order (EIP-4788 then EIP-2935), so each
/// system call lands in `block.system_calls` with `call.index = 1`.
///
/// `on_system_call_end` reverses the accumulated calls and stamps `index = 1` on every
/// entry to match the geth shape regardless of how many system calls share a single window.
#[test]
fn test_two_system_calls_in_one_window_are_reversed_and_indexed_at_1() {
    use firehose_tracer::types::Opcode;

    let beacon_root = hash32(7777);
    let parent_hash = hash32(8888);

    let mut tester = TracerTester::new();
    tester.start_block().start_system_call();

    // Mimic alloy-evm's apply order inside a single system-call window:
    //   1. EIP-2935: blockhash history (parent_hash → history_storage_address)
    //   2. EIP-4788: beacon root (beacon_root → beacon_roots_address)
    tester
        .tracer
        .on_call_enter(
            0,
            Opcode::Call as u8,
            system_address(),
            history_storage_address(),
            &parent_hash.0,
            30_000_000,
            alloy_primitives::U256::ZERO,
        );
    tester
        .tracer
        .on_call_exit(0, &[], 45_000, None, false);
    tester
        .tracer
        .on_call_enter(
            0,
            Opcode::Call as u8,
            system_address(),
            beacon_roots_address(),
            &beacon_root.0,
            30_000_000,
            alloy_primitives::U256::ZERO,
        );
    tester
        .tracer
        .on_call_exit(0, &[], 50_000, None, false);

    tester
        .end_system_call()
        .start_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), alloy_primitives::U256::ZERO, 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate(|block| {
            assert_eq!(2, block.system_calls.len(), "two system calls");

            // Reversed: beacon comes BEFORE blockhash even though execution order was
            // (blockhash, beacon) — matching geth's spec-canonical order.
            let first = &block.system_calls[0];
            let second = &block.system_calls[1];
            assert_eq!(
                beacon_roots_address().as_slice(),
                first.address.as_slice(),
                "first system call after reversal must be beacon root (EIP-4788)",
            );
            assert_eq!(
                history_storage_address().as_slice(),
                second.address.as_slice(),
                "second system call after reversal must be blockhash history (EIP-2935)",
            );

            // Both stamped to index = 1 — geth wraps each system call separately so neither
            // ever sees a sibling in its own window, leaving the call_stack reset between.
            assert_eq!(
                1, first.index,
                "every system call's index is forced to 1 to match geth"
            );
            assert_eq!(1, second.index, "every system call's index is forced to 1");

            // Ordinals must follow array order: the canonical-first call (beacon) carries
            // the LOWER ordinal range, even though it executed second in alloy-evm. Without
            // ordinal swapping the trace would have first.begin_ordinal > second.begin_ordinal,
            // which contradicts geth's per-window emission and the firehose ordinal contract.
            assert!(
                first.begin_ordinal < second.begin_ordinal,
                "canonical-first call must carry lower begin_ordinal than canonical-second \
                 (got first={}, second={})",
                first.begin_ordinal,
                second.begin_ordinal,
            );
            assert!(
                first.end_ordinal < second.begin_ordinal,
                "canonical-first call must end before canonical-second starts \
                 (got first.end={}, second.begin={})",
                first.end_ordinal,
                second.begin_ordinal,
            );
        });
}

/// Mirror of a real base-mainnet pre-execution window: alloy-evm runs
/// EIP-2935 (HISTORY_STORAGE — 1 storage write, 3 ordinals) followed by
/// EIP-4788 (BEACON_ROOTS — 2 storage writes, 4 ordinals). The two groups have
/// different ordinal widths.
///
/// The earlier ordinal-swap implementation matched groups by sort-by-min on a
/// pre-sort snapshot AND then refused to rewrite when widths disagreed — so on
/// real blocks it bailed out, leaving a trace with the canonical-first call
/// (beacon) carrying ordinals 4..7 above the canonical-second (history) at 1..3.
/// This test exercises that exact shape: the canonical-first group must end up
/// with the lowest ordinals despite being the *wider* of the two.
#[test]
fn test_ordinal_swap_handles_groups_of_unequal_width() {
    use firehose_tracer::pb::sf::ethereum::r#type::v2 as pbeth;
    use firehose_tracer::types::Opcode;

    let beacon_root = hash32(0xAA);
    let parent_hash = hash32(0xBB);
    // Storage keys/values for the writes — the actual values don't matter, we
    // just need them to occupy ordinal slots inside each call.
    let h_key = hash32(0x14CC);
    let h_old = hash32(0x1001);
    let h_new = hash32(0x1002);
    let b_key1 = hash32(0x0AEA);
    let b_old1 = hash32(0x2001);
    let b_new1 = hash32(0x2002);
    let b_key2 = hash32(0x2AE9);
    let b_old2 = hash32(0x3001);
    let b_new2 = hash32(0x3002);

    let mut tester = TracerTester::new();
    tester.start_block().start_system_call();

    // Group 1 (execution order): EIP-2935 with ONE storage write.
    tester.tracer.on_call_enter(
        0,
        Opcode::Call as u8,
        system_address(),
        history_storage_address(),
        &parent_hash.0,
        30_000_000,
        alloy_primitives::U256::ZERO,
    );
    tester.tracer.on_storage_change(history_storage_address(), h_key, h_old, h_new);
    tester.tracer.on_call_exit(0, &[], 5_000, None, false);

    // Group 2 (execution order): EIP-4788 with TWO storage writes — wider group.
    tester.tracer.on_call_enter(
        0,
        Opcode::Call as u8,
        system_address(),
        beacon_roots_address(),
        &beacon_root.0,
        30_000_000,
        alloy_primitives::U256::ZERO,
    );
    tester.tracer.on_storage_change(beacon_roots_address(), b_key1, b_old1, b_new1);
    tester.tracer.on_storage_change(beacon_roots_address(), b_key2, b_old2, b_new2);
    tester.tracer.on_call_exit(0, &[], 10_000, None, false);

    tester
        .end_system_call()
        .start_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), alloy_primitives::U256::ZERO, 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate(|block| {
            assert_eq!(2, block.system_calls.len(), "two system calls");

            let beacon = &block.system_calls[0];
            let history = &block.system_calls[1];
            assert_eq!(
                beacon_roots_address().as_slice(),
                beacon.address.as_slice(),
                "canonical-first must be beacon root (EIP-4788)",
            );
            assert_eq!(
                history_storage_address().as_slice(),
                history.address.as_slice(),
                "canonical-second must be blockhash history (EIP-2935)",
            );

            // Beacon window: begin, 2 storages, end → 4 contiguous ordinals.
            // History window: begin, 1 storage, end → 3 contiguous ordinals.
            // Together they must span [overall_min, overall_min + 7) without gaps.
            let beacon_ords = collect_ordinals(beacon);
            let history_ords = collect_ordinals(history);
            assert_eq!(
                4,
                beacon_ords.len(),
                "beacon emits 4 ordinals (begin + 2 storage + end)"
            );
            assert_eq!(
                3,
                history_ords.len(),
                "history emits 3 ordinals (begin + 1 storage + end)"
            );

            // Inter-group: every beacon ordinal precedes every history ordinal —
            // the canonical-first group occupies the LOWER ordinal range.
            let beacon_max = *beacon_ords.iter().max().unwrap();
            let history_min = *history_ords.iter().min().unwrap();
            assert!(
                beacon_max < history_min,
                "every beacon ordinal must precede every history ordinal \
                 (got beacon_max={}, history_min={})",
                beacon_max,
                history_min,
            );

            // Intra-group: each group's ordinals are contiguous and in the same
            // relative order as emitted (begin < storage1 < … < end).
            assert_eq!(beacon.begin_ordinal + 1, beacon.storage_changes[0].ordinal);
            assert_eq!(beacon.begin_ordinal + 2, beacon.storage_changes[1].ordinal);
            assert_eq!(beacon.begin_ordinal + 3, beacon.end_ordinal);
            assert_eq!(history.begin_ordinal + 1, history.storage_changes[0].ordinal);
            assert_eq!(history.begin_ordinal + 2, history.end_ordinal);

            // The two groups together must occupy a contiguous range starting at
            // the window's lowest ordinal — no gaps, no overlap.
            assert_eq!(
                beacon.end_ordinal + 1,
                history.begin_ordinal,
                "history must start one ordinal after beacon ends",
            );

            // Sanity: indices are still per-group reset to 1.
            assert_eq!(1, beacon.index);
            assert_eq!(1, history.index);

            // Sanity: every ordinal-bearing field collected from the call.
            fn collect_ordinals(c: &pbeth::Call) -> Vec<u64> {
                let mut v = vec![c.begin_ordinal, c.end_ordinal];
                v.extend(c.storage_changes.iter().map(|s| s.ordinal));
                v.extend(c.balance_changes.iter().map(|b| b.ordinal));
                v.extend(c.nonce_changes.iter().map(|n| n.ordinal));
                v.extend(c.code_changes.iter().map(|cc| cc.ordinal));
                v.extend(c.gas_changes.iter().map(|g| g.ordinal));
                v.extend(c.logs.iter().map(|l| l.ordinal));
                v.sort_unstable();
                v
            }
        });
}

/// Safeguard: when a system-call window contains a root whose address isn't in the
/// canonical predeploy list, leave the window in execution order. We still renumber
/// each group's root to `index = 1` (that matches geth's per-window model regardless
/// of which EIP the call belongs to).
///
/// This prevents an "always reverse" rule from silently rearranging chain-specific or
/// not-yet-known system calls when alloy-evm emits something we haven't catalogued.
#[test]
fn test_unknown_system_call_address_disables_reordering() {
    use firehose_tracer::types::Opcode;

    let parent_hash = hash32(8888);
    // 20-byte address that is NOT a known system predeploy.
    let unknown = alloy_primitives::Address::repeat_byte(0xAB);

    let mut tester = TracerTester::new();
    tester.start_block().start_system_call();

    // Execution order inside the window: known EIP-2935 first, then an unknown call.
    // If the tracer were applying canonical-order reorder unconditionally it might
    // float the unknown anywhere; with the safeguard it must stay where execution
    // put it.
    tester.tracer.on_call_enter(
        0,
        Opcode::Call as u8,
        system_address(),
        history_storage_address(),
        &parent_hash.0,
        30_000_000,
        alloy_primitives::U256::ZERO,
    );
    tester.tracer.on_call_exit(0, &[], 45_000, None, false);
    tester.tracer.on_call_enter(
        0,
        Opcode::Call as u8,
        system_address(),
        unknown,
        &[],
        30_000_000,
        alloy_primitives::U256::ZERO,
    );
    tester.tracer.on_call_exit(0, &[], 30_000, None, false);

    tester
        .end_system_call()
        .start_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), alloy_primitives::U256::ZERO, 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate(|block| {
            assert_eq!(2, block.system_calls.len(), "two system calls");

            // Order preserved (NOT reordered) because the second root is unknown.
            assert_eq!(
                history_storage_address().as_slice(),
                block.system_calls[0].address.as_slice(),
                "execution-order first call (known EIP-2935) must remain first when \
                 a sibling root is unknown",
            );
            assert_eq!(
                unknown.as_slice(),
                block.system_calls[1].address.as_slice(),
                "unknown system call must keep its execution-order position",
            );

            // Renumbering still applies — geth's per-window reset is independent of
            // which EIP the call is for.
            assert_eq!(1, block.system_calls[0].index);
            assert_eq!(1, block.system_calls[1].index);
        });
}

/// Safeguard: a system call with a NESTED child must keep its parent/child link
/// intact after renumbering. In our shared window the root might have a
/// non-1 index (because earlier calls used up indices). We shift `index` and
/// `parent_index` by a uniform offset per group, so a nested child still points to
/// its renumbered parent.
///
/// EIP-4788 / EIP-2935 don't have nested children today (they're SLOAD/SSTORE
/// precompile-style contracts). This test guards the path so that a future system
/// call with an internal CALL doesn't silently produce dangling parent_index pointers.
#[test]
fn test_renumber_preserves_parent_child_within_group() {
    use firehose_tracer::types::Opcode;

    let beacon_root = hash32(1234);
    let parent_hash = hash32(5678);
    let inner_target = alloy_primitives::Address::repeat_byte(0xCD);

    let mut tester = TracerTester::new();
    tester.start_block().start_system_call();

    // Group 1 (execution order): EIP-2935 root + a nested inner call inside it.
    //   on_call_enter (root, depth=0)  → index=1
    //     on_call_enter (inner, depth=1) → index=2, parent_index=1
    //     on_call_exit  (inner)
    //   on_call_exit (root)
    tester.tracer.on_call_enter(
        0,
        Opcode::Call as u8,
        system_address(),
        history_storage_address(),
        &parent_hash.0,
        30_000_000,
        alloy_primitives::U256::ZERO,
    );
    tester.tracer.on_call_enter(
        1,
        Opcode::Call as u8,
        history_storage_address(),
        inner_target,
        &[],
        25_000,
        alloy_primitives::U256::ZERO,
    );
    tester.tracer.on_call_exit(1, &[], 5_000, None, false);
    tester.tracer.on_call_exit(0, &[], 45_000, None, false);

    // Group 2 (execution order): EIP-4788 root, no nested children.
    //   on_call_enter (root, depth=0)  → index=3 in our shared window
    //   on_call_exit  (root)
    tester.tracer.on_call_enter(
        0,
        Opcode::Call as u8,
        system_address(),
        beacon_roots_address(),
        &beacon_root.0,
        30_000_000,
        alloy_primitives::U256::ZERO,
    );
    tester.tracer.on_call_exit(0, &[], 50_000, None, false);

    tester
        .end_system_call()
        .start_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), alloy_primitives::U256::ZERO, 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate(|block| {
            // Two known system calls → reorder applies (beacon before blockhash).
            // Within each group calls are emitted in index order (root first, descendants
            // after) — `partition_into_call_groups` sorts by index. Group 1 (beacon) has
            // a single root; group 2 (EIP-2935) has root + one inner child.
            assert_eq!(3, block.system_calls.len(), "two roots + one nested child");

            // [0] = beacon root (canonical position 0), renumbered to index 1.
            assert_eq!(
                beacon_roots_address().as_slice(),
                block.system_calls[0].address.as_slice(),
                "beacon (EIP-4788) reordered to first",
            );
            assert_eq!(1, block.system_calls[0].index);
            assert_eq!(0, block.system_calls[0].parent_index);

            // [1] = EIP-2935 root, renumbered to index 1 within its group (was index 1
            // in our shared window pre-reorder, offset = 0, unchanged).
            assert_eq!(
                history_storage_address().as_slice(),
                block.system_calls[1].address.as_slice(),
                "EIP-2935 root after canonical reordering",
            );
            assert_eq!(1, block.system_calls[1].index, "root re-indexed to 1");
            assert_eq!(0, block.system_calls[1].parent_index);

            // [2] = nested inner child of EIP-2935. Its `parent_index` must point at the
            // renumbered root (index 1 within the group), NOT the original index from
            // the shared window. This is the safeguard the test exists to verify.
            assert_eq!(
                inner_target.as_slice(),
                block.system_calls[2].address.as_slice(),
                "EIP-2935 inner child stays in its group",
            );
            assert_eq!(2, block.system_calls[2].index, "inner re-indexed to 2");
            assert_eq!(
                1, block.system_calls[2].parent_index,
                "inner.parent_index remapped to renumbered root (1), not dangling",
            );
        });
}
