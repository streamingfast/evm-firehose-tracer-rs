use alloy_primitives::Address;
use firehose_test::{
    alice_addr, big_int, bob_addr, charlie_addr, failed_receipt_with_logs, log0, log1, log2,
    receipt_at, receipt_with_logs, test_legacy_trx, topic, TracerTester, ERR_EXECUTION_REVERTED,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

// =============================================================================
// Receipt Assignment Tests
// =============================================================================

#[test]
fn test_receipt_fields_assigned() {
    // Receipt fields should be properly assigned to transaction trace
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![0x01])
        .end_call(vec![0x42], 20000)
        .end_block_trx(Some(receipt_at(5, 1, 21000, 100000, vec![])), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];

            assert_eq!(5, trx.index, "Transaction index should match receipt");
            assert_eq!(21000, trx.gas_used, "Gas used should match receipt");
            assert_eq!(
                pbeth::TransactionTraceStatus::Succeeded as i32,
                trx.status,
                "Status should be SUCCEEDED for status=1"
            );

            assert!(trx.receipt.is_some(), "Receipt should be populated");
            let receipt = trx.receipt.as_ref().unwrap();
            assert_eq!(
                100000, receipt.cumulative_gas_used,
                "Cumulative gas should match receipt"
            );
        });
}

#[test]
fn test_receipt_status_failed() {
    // Receipt status 0 should mark transaction as FAILED
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![0x01])
        .end_call(vec![], 21000)
        .end_block_trx(Some(receipt_at(0, 0, 21000, 21000, vec![])), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(
                pbeth::TransactionTraceStatus::Failed as i32,
                trx.status,
                "Status should be FAILED for status=0"
            );
        });
}

#[test]
fn test_receipt_status_reverted_overrides_success() {
    // Even if receipt says succeeded (status=1), if root call reverted, transaction is REVERTED
    let err = std::io::Error::new(std::io::ErrorKind::Other, ERR_EXECUTION_REVERTED);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![0x01])
        .end_call_failed(b"reverted".to_vec(), 21000, &err, true)
        .end_block_trx(Some(receipt_at(0, 1, 21000, 21000, vec![])), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(
                pbeth::TransactionTraceStatus::Reverted as i32,
                trx.status,
                "Status should be REVERTED when root call reverts"
            );
        });
}

// =============================================================================
// Log Ordinals and Indexes Tests
// =============================================================================

#[test]
fn test_logs_from_successful_call_assigned_to_receipt() {
    // Scenario: Single call with 3 logs
    let receipt_logs = vec![
        log1(bob_addr(), topic("Transfer"), vec![0x01]),
        log2(bob_addr(), topic("Approval"), topic("Spender"), vec![0x02]),
        log0(bob_addr(), vec![0x03]),
    ];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .log(bob_addr(), vec![topic("Transfer")], vec![0x01], 0)
        .log(
            bob_addr(),
            vec![topic("Approval"), topic("Spender")],
            vec![0x02],
            1,
        )
        .log(bob_addr(), vec![], vec![0x03], 2)
        .end_call(vec![], 95000)
        .end_block_trx(Some(receipt_with_logs(100000, receipt_logs)), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Call should have 3 logs with ordinals and indexes
            assert_eq!(3, call.logs.len(), "Call should have 3 logs");
            assert!(call.logs[0].ordinal > 0, "Log 0 should have ordinal");
            assert!(call.logs[1].ordinal > 0, "Log 1 should have ordinal");
            assert!(call.logs[2].ordinal > 0, "Log 2 should have ordinal");
            assert_eq!(0, call.logs[0].index, "Log 0 should have index 0");
            assert_eq!(1, call.logs[1].index, "Log 1 should have index 1");
            assert_eq!(2, call.logs[2].index, "Log 2 should have index 2");

            // Receipt should have 3 logs with same ordinals and indexes
            assert!(trx.receipt.is_some(), "Receipt should exist");
            let receipt = trx.receipt.as_ref().unwrap();
            assert_eq!(3, receipt.logs.len(), "Receipt should have 3 logs");

            for i in 0..3 {
                assert_eq!(
                    call.logs[i].ordinal, receipt.logs[i].ordinal,
                    "Receipt log {} ordinal should match call log",
                    i
                );
                assert_eq!(
                    call.logs[i].index, receipt.logs[i].index,
                    "Receipt log {} index should match call log",
                    i
                );
                assert_eq!(
                    call.logs[i].block_index, receipt.logs[i].block_index,
                    "Receipt log {} block index should match call log",
                    i
                );
            }
        });
}

#[test]
fn test_logs_across_multiple_successful_calls() {
    // Scenario: Root call logs 2, nested call logs 1, root call logs 1 more
    // Receipt should have all 4 logs in ordinal order
    let receipt_logs = vec![
        log1(bob_addr(), topic("Event1"), vec![0x01]),
        log1(bob_addr(), topic("Event2"), vec![0x02]),
        log1(charlie_addr(), topic("Event3"), vec![0x03]),
        log1(bob_addr(), topic("Event4"), vec![0x04]),
    ];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .log(bob_addr(), vec![topic("Event1")], vec![0x01], 0)
        .log(bob_addr(), vec![topic("Event2")], vec![0x02], 1)
        .start_call(bob_addr(), charlie_addr(), big_int(0), 50000, vec![0x02])
        .log(charlie_addr(), vec![topic("Event3")], vec![0x03], 2)
        .end_call(vec![], 45000)
        .log(bob_addr(), vec![topic("Event4")], vec![0x04], 3)
        .end_call(vec![], 90000)
        .end_block_trx(Some(receipt_with_logs(100000, receipt_logs)), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];

            // Collect all call logs
            let mut all_call_logs: Vec<&pbeth::Log> = Vec::new();
            for call in &trx.calls {
                all_call_logs.extend(&call.logs);
            }

            assert_eq!(4, all_call_logs.len(), "Should have 4 call logs total");
            let receipt = trx.receipt.as_ref().unwrap();
            assert_eq!(4, receipt.logs.len(), "Should have 4 receipt logs");

            // Verify ordinals are in order
            for i in 1..receipt.logs.len() {
                assert!(
                    receipt.logs[i].ordinal > receipt.logs[i - 1].ordinal,
                    "Receipt log ordinals should be in order"
                );
            }

            // Verify indexes are sequential
            for (i, log) in receipt.logs.iter().enumerate() {
                assert_eq!(
                    i as u32, log.index,
                    "Receipt log {} should have index {}",
                    i, i
                );
            }
        });
}

#[test]
fn test_logs_in_reverted_call_not_in_receipt() {
    // Scenario: Root call succeeds with 1 log, nested call reverts with 1 log
    // Receipt should only have the 1 log from root call
    let receipt_logs = vec![log1(bob_addr(), topic("Success"), vec![0x01])];

    let err = std::io::Error::new(std::io::ErrorKind::Other, ERR_EXECUTION_REVERTED);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .log(bob_addr(), vec![topic("Success")], vec![0x01], 0)
        .start_call(bob_addr(), charlie_addr(), big_int(0), 50000, vec![0x02])
        .log(charlie_addr(), vec![topic("Reverted")], vec![0x02], 1)
        .end_call_failed(b"error".to_vec(), 45000, &err, true)
        .end_call(vec![], 90000)
        .end_block_trx(Some(receipt_with_logs(100000, receipt_logs)), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];
            let reverted_call = &trx.calls[1];

            // Root call should have 1 log
            assert_eq!(1, root_call.logs.len(), "Root call should have 1 log");

            // Reverted call should have 1 log (logs are tracked even in reverted calls)
            assert_eq!(
                1,
                reverted_call.logs.len(),
                "Reverted call should have 1 log"
            );

            // Receipt should only have 1 log (from successful root call)
            let receipt = trx.receipt.as_ref().unwrap();
            assert_eq!(
                1,
                receipt.logs.len(),
                "Receipt should only have 1 log from successful call"
            );
        });
}

#[test]
fn test_all_logs_removed_when_root_call_reverts() {
    // Scenario: Root call reverts - no logs should be in receipt
    let err = std::io::Error::new(std::io::ErrorKind::Other, ERR_EXECUTION_REVERTED);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .log(bob_addr(), vec![topic("Event1")], vec![0x01], 0)
        .start_call(bob_addr(), charlie_addr(), big_int(0), 50000, vec![0x02])
        .log(charlie_addr(), vec![topic("Event2")], vec![0x02], 1)
        .end_call(vec![], 45000)
        .log(bob_addr(), vec![topic("Event3")], vec![0x03], 2)
        .end_call_failed(b"root reverted".to_vec(), 90000, &err, true)
        .end_block_trx(Some(receipt_with_logs(100000, vec![])), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            assert_eq!(
                pbeth::TransactionTraceStatus::Reverted as i32,
                trx.status,
                "Transaction should be reverted"
            );
            assert!(root_call.state_reverted, "Root call should be reverted");

            // All calls should have StateReverted=true
            for (i, call) in trx.calls.iter().enumerate() {
                assert!(call.state_reverted, "Call {} should be reverted", i);
                // All logs should have BlockIndex=0
                for (j, log) in call.logs.iter().enumerate() {
                    assert_eq!(
                        0, log.block_index,
                        "Call {} log {} should have BlockIndex=0",
                        i, j
                    );
                }
            }

            // Receipt should have no logs
            let receipt = trx.receipt.as_ref().unwrap();
            assert_eq!(0, receipt.logs.len(), "Receipt should have no logs");
        });
}

#[test]
fn test_deeply_nested_reverted_calls() {
    // Scenario: Root -> A (success, 1 log) -> B (reverted, 1 log) -> C (reverted, 1 log)
    // Receipt should only have 1 log from A
    let addr_dead = Address::from([
        0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let addr_beef = Address::from([
        0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    let receipt_logs = vec![log1(charlie_addr(), topic("Success"), vec![0x01])];

    let err = std::io::Error::new(std::io::ErrorKind::Other, ERR_EXECUTION_REVERTED);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        // Call A succeeds
        .start_call(bob_addr(), charlie_addr(), big_int(0), 80000, vec![0x02])
        .log(charlie_addr(), vec![topic("Success")], vec![0x01], 0)
        // Call B reverts
        .start_call(charlie_addr(), addr_dead, big_int(0), 60000, vec![0x03])
        .log(addr_dead, vec![topic("Reverted1")], vec![0x02], 1)
        // Call C reverts (child of B)
        .start_call(addr_dead, addr_beef, big_int(0), 40000, vec![0x04])
        .log(addr_beef, vec![topic("Reverted2")], vec![0x03], 2)
        .end_call_failed(b"C error".to_vec(), 35000, &err, true)
        .end_call_failed(b"B error".to_vec(), 55000, &err, true)
        .end_call(vec![], 70000) // A succeeds
        .end_call(vec![], 85000) // Root succeeds
        .end_block_trx(Some(receipt_with_logs(100000, receipt_logs)), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(4, trx.calls.len(), "Should have 4 calls");

            let call_a = &trx.calls[1];
            let call_b = &trx.calls[2];
            let call_c = &trx.calls[3];

            // A should not be reverted
            assert!(!call_a.state_reverted, "Call A should not be reverted");
            assert_eq!(
                0, call_a.logs[0].block_index,
                "Call A log should keep original BlockIndex=0"
            );

            // B and C should be reverted
            assert!(call_b.state_reverted, "Call B should be reverted");
            assert!(call_c.state_reverted, "Call C should be reverted");
            assert_eq!(
                0, call_b.logs[0].block_index,
                "Call B log should have BlockIndex=0"
            );
            assert_eq!(
                0, call_c.logs[0].block_index,
                "Call C log should have BlockIndex=0"
            );

            // Receipt should only have 1 log from A
            let receipt = trx.receipt.as_ref().unwrap();
            assert_eq!(1, receipt.logs.len(), "Receipt should have 1 log");
            assert_eq!(
                call_a.logs[0].ordinal, receipt.logs[0].ordinal,
                "Receipt log should match call A log"
            );
        });
}

#[test]
fn test_failed_transaction_with_logs() {
    // Scenario: Transaction fails (receipt status=0) but didn't revert
    // Logs should still appear in receipt
    let receipt_logs = vec![log1(bob_addr(), topic("FailedEvent"), vec![0x01])];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .log(bob_addr(), vec![topic("FailedEvent")], vec![0x01], 0)
        .end_call(vec![], 95000) // Call succeeds (no revert)
        .end_block_trx(
            Some(failed_receipt_with_logs(100000, receipt_logs)),
            None,
            None,
        ) // But receipt status=0
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            assert_eq!(
                pbeth::TransactionTraceStatus::Failed as i32,
                trx.status,
                "Transaction should be FAILED (receipt status=0)"
            );
            assert!(
                !root_call.state_reverted,
                "Root call should not be state reverted"
            );

            // Log should still be in receipt
            let receipt = trx.receipt.as_ref().unwrap();
            assert_eq!(1, receipt.logs.len(), "Receipt should have 1 log");
            assert_eq!(
                root_call.logs[0].ordinal, receipt.logs[0].ordinal,
                "Receipt log should match call log"
            );
        });
}

// =============================================================================
// Receipt LogsBloom Tests
// =============================================================================

#[test]
fn test_empty_bloom_for_transaction_without_logs() {
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![0x01])
        .end_call(vec![], 20000)
        .end_block_trx(Some(receipt_at(0, 1, 21000, 21000, vec![])), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            let receipt = trx.receipt.as_ref().expect("Receipt should exist");

            assert!(
                !receipt.logs_bloom.is_empty(),
                "LogsBloom should not be empty"
            );
            assert_eq!(
                256,
                receipt.logs_bloom.len(),
                "LogsBloom should be 256 bytes"
            );

            // Verify all bytes are zero (empty bloom)
            for (i, &b) in receipt.logs_bloom.iter().enumerate() {
                assert_eq!(0, b, "LogsBloom byte {} should be 0", i);
            }
        });
}

#[test]
fn test_non_empty_bloom_for_transaction_with_logs() {
    // Create a non-empty bloom (simulated)
    let mut logs_bloom = [0u8; 256];
    logs_bloom[0] = 0x01;
    logs_bloom[100] = 0x42;
    logs_bloom[255] = 0xff;

    let receipt_logs = vec![log1(bob_addr(), topic("Transfer"), vec![0x01])];

    let receipt = firehose::ReceiptData {
        transaction_index: 0,
        status: 1,
        gas_used: 30000,
        logs_bloom,
        cumulative_gas_used: 30000,
        logs: receipt_logs,
        blob_gas_used: 0,
        blob_gas_price: None,
        state_root: None,
    };

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .log(bob_addr(), vec![topic("Transfer")], vec![0x01], 0)
        .end_call(vec![], 95000)
        .end_block_trx(Some(receipt), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            let pb_receipt = trx.receipt.as_ref().expect("Receipt should exist");

            assert!(
                !pb_receipt.logs_bloom.is_empty(),
                "LogsBloom should not be empty"
            );
            assert_eq!(
                256,
                pb_receipt.logs_bloom.len(),
                "LogsBloom should be 256 bytes"
            );

            // Verify bloom data matches what we passed in
            assert_eq!(
                0x01, pb_receipt.logs_bloom[0],
                "LogsBloom[0] should be 0x01"
            );
            assert_eq!(
                0x42, pb_receipt.logs_bloom[100],
                "LogsBloom[100] should be 0x42"
            );
            assert_eq!(
                0xff, pb_receipt.logs_bloom[255],
                "LogsBloom[255] should be 0xff"
            );
        });
}

#[test]
fn test_bloom_preserved_from_receipt_input() {
    // Verify that bloom filter is faithfully copied from ReceiptData
    let mut logs_bloom = [0u8; 256];
    logs_bloom[0] = 0xaa;
    logs_bloom[1] = 0xbb;
    logs_bloom[50] = 0x12;
    logs_bloom[100] = 0x34;
    logs_bloom[200] = 0x56;
    logs_bloom[254] = 0x78;
    logs_bloom[255] = 0x9a;

    let receipt = firehose::ReceiptData {
        transaction_index: 3, // Non-zero index to test that too
        status: 1,
        gas_used: 50000,
        logs_bloom,
        cumulative_gas_used: 150000,
        logs: vec![],
        blob_gas_used: 0,
        blob_gas_price: None,
        state_root: None,
    };

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .end_call(vec![], 95000)
        .end_block_trx(Some(receipt), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            let pb_receipt = trx.receipt.as_ref().expect("Receipt should exist");

            assert!(
                !pb_receipt.logs_bloom.is_empty(),
                "LogsBloom should not be empty"
            );
            assert_eq!(
                256,
                pb_receipt.logs_bloom.len(),
                "LogsBloom should be 256 bytes"
            );

            // Verify every byte we set is preserved exactly
            assert_eq!(0xaa, pb_receipt.logs_bloom[0], "LogsBloom[0] not preserved");
            assert_eq!(0xbb, pb_receipt.logs_bloom[1], "LogsBloom[1] not preserved");
            assert_eq!(
                0x12, pb_receipt.logs_bloom[50],
                "LogsBloom[50] not preserved"
            );
            assert_eq!(
                0x34, pb_receipt.logs_bloom[100],
                "LogsBloom[100] not preserved"
            );
            assert_eq!(
                0x56, pb_receipt.logs_bloom[200],
                "LogsBloom[200] not preserved"
            );
            assert_eq!(
                0x78, pb_receipt.logs_bloom[254],
                "LogsBloom[254] not preserved"
            );
            assert_eq!(
                0x9a, pb_receipt.logs_bloom[255],
                "LogsBloom[255] not preserved"
            );

            // Verify unset bytes remain zero
            assert_eq!(
                0x00, pb_receipt.logs_bloom[2],
                "Unset bloom byte should be 0"
            );
            assert_eq!(
                0x00, pb_receipt.logs_bloom[99],
                "Unset bloom byte should be 0"
            );
        });
}

// =============================================================================
// Log BlockIndex Tests
// =============================================================================

#[test]
fn test_successful_logs_have_block_index() {
    let receipt_logs = vec![log1(bob_addr(), topic("Event"), vec![0x01])];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .log(bob_addr(), vec![topic("Event")], vec![0x01], 0)
        .end_call(vec![], 95000)
        .end_block_trx(Some(receipt_with_logs(100000, receipt_logs)), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Call log should have BlockIndex set
            assert_eq!(1, call.logs.len(), "Should have 1 log");
            assert_eq!(
                0, call.logs[0].block_index,
                "First log in block should have BlockIndex=0"
            );

            // Receipt log should have same BlockIndex
            let receipt = trx.receipt.as_ref().unwrap();
            assert_eq!(
                call.logs[0].block_index, receipt.logs[0].block_index,
                "Receipt log BlockIndex should match call log"
            );
        });
}

#[test]
fn test_reverted_logs_have_zero_block_index() {
    let err = std::io::Error::new(std::io::ErrorKind::Other, ERR_EXECUTION_REVERTED);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .log(bob_addr(), vec![topic("Event")], vec![0x01], 0)
        .end_call_failed(b"error".to_vec(), 95000, &err, true)
        .end_block_trx(Some(receipt_with_logs(100000, vec![])), None, None)
        .validate_with_category("receiptassignment", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Call log should have BlockIndex=0
            assert_eq!(1, call.logs.len(), "Should have 1 log");
            assert_eq!(
                0, call.logs[0].block_index,
                "Reverted log should have BlockIndex=0"
            );
        });
}
