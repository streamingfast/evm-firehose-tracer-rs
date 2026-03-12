use firehose_test::{success_receipt, test_legacy_trx, TracerTester};

// =============================================================================
// Transaction Tests
// =============================================================================
// Tests basic transaction handling without calls

#[test]
fn test_simple_transaction() {
    // Simple transaction without any calls (should still create a block)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .end_block_trx(Some(success_receipt(0)), None, None)
        .validate_with_category("transaction", |block| {
            assert_eq!(100, block.number, "Block number should match test block");
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
        });
}
