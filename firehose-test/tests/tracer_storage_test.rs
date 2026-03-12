use firehose_test::{alice_addr, bob_addr, hash32, success_receipt, test_legacy_trx, TracerTester};

#[test]
fn test_basic_storage_change() {
    // Basic storage change during call execution
    let key = hash32(1);
    let old_val = hash32(100);
    let new_val = hash32(200);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        .storage_change(bob_addr(), key, old_val, new_val)
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("onstoragechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                1,
                call.storage_changes.len(),
                "Should have 1 storage change"
            );
            let sc = &call.storage_changes[0];
            assert_eq!(bob_addr().as_slice(), sc.address.as_slice());
            assert_eq!(key.as_slice(), sc.key.as_slice());
            assert_eq!(old_val.as_slice(), sc.old_value.as_slice());
            assert_eq!(new_val.as_slice(), sc.new_value.as_slice());
        });
}

#[test]
fn test_multiple_storage_changes_in_call() {
    // Multiple storage changes in same call
    let key1 = hash32(1);
    let key2 = hash32(2);
    let key3 = hash32(3);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        .storage_change(bob_addr(), key1, hash32(100), hash32(200))
        .storage_change(bob_addr(), key2, hash32(300), hash32(400))
        .storage_change(bob_addr(), key3, hash32(500), hash32(600))
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("onstoragechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                3,
                call.storage_changes.len(),
                "Should have 3 storage changes"
            );

            // Verify ordering (ordinals should be increasing)
            assert!(
                call.storage_changes[0].ordinal < call.storage_changes[1].ordinal,
                "First storage change ordinal should be less than second"
            );
            assert!(
                call.storage_changes[1].ordinal < call.storage_changes[2].ordinal,
                "Second storage change ordinal should be less than third"
            );

            // Verify each storage change
            assert_eq!(key1.as_slice(), call.storage_changes[0].key.as_slice());
            assert_eq!(key2.as_slice(), call.storage_changes[1].key.as_slice());
            assert_eq!(key3.as_slice(), call.storage_changes[2].key.as_slice());
        });
}

#[test]
fn test_multiple_calls_with_storage_changes() {
    // Multiple calls, each with storage changes
    let key1 = hash32(1);
    let key2 = hash32(2);
    let key10 = hash32(10);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            100000,
            vec![],
        )
        .storage_change(bob_addr(), key1, hash32(100), hash32(200))
        .start_call(
            bob_addr(),
            alice_addr(),
            alloy_primitives::U256::ZERO,
            50000,
            vec![],
        )
        .storage_change(alice_addr(), key10, hash32(1000), hash32(2000))
        .end_call(vec![], 50000)
        .storage_change(bob_addr(), key2, hash32(300), hash32(400))
        .end_call(vec![], 100000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("onstoragechange", |block| {
            let trx = &block.transaction_traces[0];

            // Root call should have 2 storage changes
            let root_call = &trx.calls[0];
            assert_eq!(
                2,
                root_call.storage_changes.len(),
                "Root call should have 2 storage changes"
            );
            assert_eq!(key1.as_slice(), root_call.storage_changes[0].key.as_slice());
            assert_eq!(key2.as_slice(), root_call.storage_changes[1].key.as_slice());

            // Nested call should have 1 storage change
            let nested_call = &trx.calls[1];
            assert_eq!(
                1,
                nested_call.storage_changes.len(),
                "Nested call should have 1 storage change"
            );
            assert_eq!(
                key10.as_slice(),
                nested_call.storage_changes[0].key.as_slice()
            );
        });
}

#[test]
fn test_storage_change_full_32_bytes() {
    // Test full 32-byte key and value handling
    let mut key = [0u8; 32];
    let mut old_val = [0u8; 32];
    let mut new_val = [0u8; 32];

    // Fill with patterns to verify all bytes are preserved
    for i in 0..32 {
        key[i] = i as u8;
        old_val[i] = (i * 2) as u8;
        new_val[i] = (i * 3) as u8;
    }

    let key = alloy_primitives::B256::from(key);
    let old_val = alloy_primitives::B256::from(old_val);
    let new_val = alloy_primitives::B256::from(new_val);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        .storage_change(bob_addr(), key, old_val, new_val)
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("onstoragechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                1,
                call.storage_changes.len(),
                "Should have 1 storage change"
            );
            let sc = &call.storage_changes[0];
            assert_eq!(key.as_slice(), sc.key.as_slice());
            assert_eq!(old_val.as_slice(), sc.old_value.as_slice());
            assert_eq!(new_val.as_slice(), sc.new_value.as_slice());
        });
}
