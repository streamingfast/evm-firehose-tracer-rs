use firehose_test::{
    alice_addr, beacon_roots_address, bob_addr, hash32, history_storage_address, success_receipt,
    system_address, test_legacy_trx, TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

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
    use firehose_test::big_int;
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
    use firehose_test::{big_int, charlie_addr, miner_addr};
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
    use firehose_test::big_int;
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
