use alloy_primitives::U256;
use firehose_test::{alice_addr, bob_addr, failed_receipt, test_legacy_trx, TracerTester};
use pb::sf::ethereum::r#type::v2::TransactionTraceStatus;

/// Reth-specific: revm's inspector `call_end` hook reports the root call as
/// successful even when the transaction ran out of gas. The failure is only
/// visible via the receipt (status=0). The tracer's `complete_transaction`
/// reconciliation step must detect this and mark the root call as failed.
#[test]
fn test_reth_root_call_out_of_gas_reconciliation() {
    let mut tester = TracerTester::new_reth();
    tester
        .start_block_trx(test_legacy_trx())
        // Simulate Reth behavior: root call ends successfully (no error)
        // even though all gas was consumed
        .start_call(alice_addr(), bob_addr(), U256::ZERO, 648, vec![0x01])
        .end_call(vec![], 648)
        // Receipt says failure (status=0)
        .end_block_trx(Some(failed_receipt(648)), None, None)
        .validate_with_category("reth", |block| {
            assert_eq!(1, block.transaction_traces.len());
            let trx = &block.transaction_traces[0];

            assert_eq!(
                TransactionTraceStatus::Failed as i32,
                trx.status,
                "Transaction status should be Failed from receipt"
            );

            assert_eq!(1, trx.calls.len());
            let root_call = &trx.calls[0];

            assert!(
                root_call.status_failed,
                "Root call should be marked as failed (reconciled from receipt)"
            );
            assert_eq!(
                "out of gas", root_call.failure_reason,
                "Failure reason should be 'out of gas'"
            );
            assert!(
                root_call.state_reverted,
                "Root call should have state_reverted (status_failed propagates)"
            );
            assert!(
                !root_call.status_reverted,
                "Root call should NOT be status_reverted (out-of-gas is not a revert)"
            );
        });
}

/// Verify that without ChainClient::Reth, the same scenario does NOT reconcile
/// (default/Geth behavior where the inspector correctly reports failures).
#[test]
fn test_default_client_no_reconciliation() {
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // Same scenario: call ends successfully but receipt says failure
        .start_call(alice_addr(), bob_addr(), U256::ZERO, 648, vec![0x01])
        .end_call(vec![], 648)
        .end_block_trx(Some(failed_receipt(648)), None, None)
        .validate_with_category("reth", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            assert!(
                !root_call.status_failed,
                "Without Reth client, root call should NOT be reconciled"
            );
            assert!(
                root_call.failure_reason.is_empty(),
                "Without Reth client, failure_reason should remain empty"
            );
        });
}

/// Reth-specific: when the inspector already correctly reports the failure
/// (e.g., via end_call_failed), the reconciliation should not overwrite it.
#[test]
fn test_reth_reconciliation_does_not_overwrite_existing_failure() {
    let err = firehose::StringError("execution reverted".to_string());
    let mut tester = TracerTester::new_reth();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), U256::ZERO, 100000, vec![0x01])
        .end_call_failed(vec![], 95000, &err, true)
        .end_block_trx(Some(failed_receipt(100000)), None, None)
        .validate_with_category("reth", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            assert!(root_call.status_failed);
            assert_eq!(
                "execution reverted", root_call.failure_reason,
                "Should keep original failure reason, not overwrite with 'out of gas'"
            );
            assert!(
                root_call.status_reverted,
                "Should keep original status_reverted from the revert error"
            );
        });
}
