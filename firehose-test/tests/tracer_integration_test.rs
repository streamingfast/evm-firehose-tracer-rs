use firehose_test::{
    alice_addr, big_int, bob_addr, charlie_addr, hash32, log1, receipt_with_logs, success_receipt,
    test_legacy_trx, TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

// =============================================================================
// Integration Tests - Multiple State Changes
// =============================================================================
// Tests combinations of different state change types in realistic scenarios

#[test]
fn test_create_with_value_transfer() {
    // CONTRACT CREATE with value transfer combines:
    // - Balance change (value transfer from caller to contract)
    // - Code change (contract deployment)

    let deployed_code = vec![0x60, 0x80, 0x60, 0x40, 0x52]; // Simple contract bytecode
    let code_hash = hash32(123);
    let prev_hash = hash32(0);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(1000000), 200000, vec![]) // 1 ETH value transfer
        // Balance changes during value transfer
        .balance_change(
            alice_addr(),
            big_int(10000000),
            big_int(9000000),
            pbeth::balance_change::Reason::Transfer,
        )
        .balance_change(
            bob_addr(),
            big_int(0),
            big_int(1000000),
            pbeth::balance_change::Reason::Transfer,
        )
        // Code deployment
        .code_change(
            bob_addr(),
            prev_hash,
            code_hash,
            vec![],
            deployed_code.clone(),
        )
        .end_call(vec![], 150000)
        .end_block_trx(Some(success_receipt(200000)), None, None)
        .validate_with_category("multiplestatechanges", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Verify all state changes are recorded
            assert_eq!(
                2,
                call.balance_changes.len(),
                "Should have 2 balance changes"
            );
            assert_eq!(1, call.code_changes.len(), "Should have 1 code change");

            // Verify ordinals are all increasing
            assert!(call.balance_changes[0].ordinal < call.balance_changes[1].ordinal);
            assert!(call.balance_changes[1].ordinal < call.code_changes[0].ordinal);
        });
}

#[test]
fn test_contract_initialization_with_storage_and_logs() {
    // Contract constructor execution combines:
    // - Code change (deployment)
    // - Storage initialization
    // - Log emission (initialization events)

    let deployed_code = vec![0x60, 0x01];
    let code_hash = hash32(456);
    let prev_hash = hash32(0);

    let storage_key = hash32(1);
    let zero_val = hash32(0);
    let storage_val = hash32(100);

    let log_data = vec![0x01, 0x02];
    let log_topics = vec![hash32(200)];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 200000, vec![])
        .code_change(bob_addr(), prev_hash, code_hash, vec![], deployed_code)
        .storage_change(bob_addr(), storage_key, zero_val, storage_val)
        .log(bob_addr(), log_topics, log_data.clone(), 0)
        .end_call(vec![], 180000)
        .end_block_trx(
            Some(receipt_with_logs(
                200000,
                vec![log1(bob_addr(), hash32(200), log_data)],
            )),
            None,
            None,
        )
        .validate_with_category("multiplestatechanges", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Verify all state changes are recorded
            assert_eq!(1, call.code_changes.len(), "Should have code change");
            assert_eq!(1, call.storage_changes.len(), "Should have storage change");
            assert_eq!(1, call.logs.len(), "Should have log");

            // Verify ordinals are increasing
            assert!(call.code_changes[0].ordinal < call.storage_changes[0].ordinal);
            assert!(call.storage_changes[0].ordinal < call.logs[0].ordinal);

            // Verify receipt logs match
            let receipt = trx.receipt.as_ref().unwrap();
            assert_eq!(1, receipt.logs.len());
            assert_eq!(call.logs[0].ordinal, receipt.logs[0].ordinal);
        });
}

#[test]
fn test_comprehensive_transaction_all_state_types() {
    // Comprehensive test with ALL state change types in one transaction:
    // - Balance changes
    // - Nonce change
    // - Code change
    // - Storage change
    // - Log emission

    let deployed_code = vec![0x60, 0x02];
    let code_hash = hash32(789);
    let prev_hash = hash32(0);

    let storage_key = hash32(2);
    let zero_val = hash32(0);
    let storage_val = hash32(200);

    let log_data = vec![0x03, 0x04];
    let log_topics = vec![hash32(300)];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(500000), 300000, vec![])
        // All state change types
        .balance_change(
            alice_addr(),
            big_int(10000000),
            big_int(9500000),
            pbeth::balance_change::Reason::Transfer,
        )
        .nonce_change(alice_addr(), 5, 6)
        .code_change(bob_addr(), prev_hash, code_hash, vec![], deployed_code)
        .storage_change(bob_addr(), storage_key, zero_val, storage_val)
        .log(bob_addr(), log_topics, log_data.clone(), 0)
        .end_call(vec![], 250000)
        .end_block_trx(
            Some(receipt_with_logs(
                300000,
                vec![log1(bob_addr(), hash32(300), log_data)],
            )),
            None,
            None,
        )
        .validate_with_category("multiplestatechanges", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Verify ALL state change types are present
            assert_eq!(1, call.balance_changes.len(), "Should have balance change");
            assert_eq!(1, call.nonce_changes.len(), "Should have nonce change");
            assert_eq!(1, call.code_changes.len(), "Should have code change");
            assert_eq!(1, call.storage_changes.len(), "Should have storage change");
            assert_eq!(1, call.logs.len(), "Should have log");

            // Verify ordinals are strictly increasing across ALL types
            let mut ordinals = Vec::new();
            ordinals.push(call.balance_changes[0].ordinal);
            ordinals.push(call.nonce_changes[0].ordinal);
            ordinals.push(call.code_changes[0].ordinal);
            ordinals.push(call.storage_changes[0].ordinal);
            ordinals.push(call.logs[0].ordinal);

            // Check strict ordering
            for i in 1..ordinals.len() {
                assert!(
                    ordinals[i - 1] < ordinals[i],
                    "Ordinals should be strictly increasing across all state change types"
                );
            }
        });
}

#[test]
fn test_nested_calls_with_different_state_changes() {
    // Multiple nested calls, each with different state change types
    // Root call: balance change
    // Nested call: storage + log

    let storage_key = hash32(3);
    let zero_val = hash32(0);
    let storage_val = hash32(300);

    let log_data = vec![0x05];
    let log_topics = vec![hash32(400)];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 300000, vec![])
        // Root call: balance change
        .balance_change(
            alice_addr(),
            big_int(10000000),
            big_int(9900000),
            pbeth::balance_change::Reason::Transfer,
        )
        // Nested call
        .start_call(bob_addr(), charlie_addr(), big_int(0), 100000, vec![])
        .storage_change(charlie_addr(), storage_key, zero_val, storage_val)
        .log(charlie_addr(), log_topics, log_data.clone(), 0)
        .end_call(vec![], 90000)
        .end_call(vec![], 280000)
        .end_block_trx(
            Some(receipt_with_logs(
                300000,
                vec![log1(charlie_addr(), hash32(400), log_data)],
            )),
            None,
            None,
        )
        .validate_with_category("multiplestatechanges", |block| {
            let trx = &block.transaction_traces[0];

            // Root call has balance change
            assert_eq!(1, trx.calls[0].balance_changes.len());
            assert_eq!(0, trx.calls[0].storage_changes.len());
            assert_eq!(0, trx.calls[0].logs.len());

            // Nested call has storage + log
            assert_eq!(0, trx.calls[1].balance_changes.len());
            assert_eq!(1, trx.calls[1].storage_changes.len());
            assert_eq!(1, trx.calls[1].logs.len());

            // Verify ordinals across both calls
            let balance_ordinal = trx.calls[0].balance_changes[0].ordinal;
            let storage_ordinal = trx.calls[1].storage_changes[0].ordinal;
            let log_ordinal = trx.calls[1].logs[0].ordinal;

            assert!(balance_ordinal < storage_ordinal);
            assert!(storage_ordinal < log_ordinal);
        });
}
