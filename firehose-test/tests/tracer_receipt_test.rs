use firehose_test::{
    alice_addr, bob_addr, log0, log1, log2, receipt_at, receipt_with_logs, test_legacy_trx, topic,
    TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

#[test]
fn test_receipt_fields_assigned() {
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![0x01],
        )
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
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![0x01],
        )
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
    let err = std::io::Error::new(std::io::ErrorKind::Other, "execution reverted");

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![0x01],
        )
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
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![0x01],
        )
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
