use firehose_test::{alice_addr, bob_addr, success_receipt, test_legacy_trx, TracerTester};
use pb::sf::ethereum::r#type::v2 as pbeth;

#[test]
fn test_gas_change_no_change_ignored() {
    // Gas changes where old == new should be ignored
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .gas_change(100000, 100000, pbeth::gas_change::Reason::IntrinsicGas)
        .end_call(vec![], 100000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("ongaschange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // No-change gas changes should be filtered out
            assert_eq!(
                0,
                call.gas_changes.len(),
                "No-change gas changes should be ignored"
            );
        });
}

#[test]
fn test_gas_change_with_active_call() {
    // Normal gas change during active call
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .gas_change(100000, 90000, pbeth::gas_change::Reason::IntrinsicGas)
        .end_call(vec![], 90000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("ongaschange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.gas_changes.len());
            let gc = &call.gas_changes[0];
            assert_eq!(100000, gc.old_value);
            assert_eq!(90000, gc.new_value);
            assert_eq!(pbeth::gas_change::Reason::IntrinsicGas as i32, gc.reason);
            assert_ne!(0, gc.ordinal);
        });
}

#[test]
fn test_gas_change_deferred_state() {
    // Gas change before call stack initialization (deferred state)
    // This happens for initial gas balance
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .gas_change(0, 21000, pbeth::gas_change::Reason::TxInitialBalance)
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("ongaschange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Deferred gas change should be applied to root call
            assert_eq!(1, call.gas_changes.len());
            let gc = &call.gas_changes[0];
            assert_eq!(0, gc.old_value);
            assert_eq!(21000, gc.new_value);
            assert_eq!(
                pbeth::gas_change::Reason::TxInitialBalance as i32,
                gc.reason
            );
        });
}

#[test]
fn test_gas_change_multiple_changes() {
    // Multiple gas changes in same call
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .gas_change(100000, 90000, pbeth::gas_change::Reason::IntrinsicGas)
        .gas_change(90000, 85000, pbeth::gas_change::Reason::CallDataCopy)
        .gas_change(85000, 80000, pbeth::gas_change::Reason::ContractCreation)
        .end_call(vec![], 80000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("ongaschange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(3, call.gas_changes.len());

            // First change
            assert_eq!(100000, call.gas_changes[0].old_value);
            assert_eq!(90000, call.gas_changes[0].new_value);
            assert_eq!(
                pbeth::gas_change::Reason::IntrinsicGas as i32,
                call.gas_changes[0].reason
            );

            // Second change
            assert_eq!(90000, call.gas_changes[1].old_value);
            assert_eq!(85000, call.gas_changes[1].new_value);
            assert_eq!(
                pbeth::gas_change::Reason::CallDataCopy as i32,
                call.gas_changes[1].reason
            );

            // Third change
            assert_eq!(85000, call.gas_changes[2].old_value);
            assert_eq!(80000, call.gas_changes[2].new_value);
            assert_eq!(
                pbeth::gas_change::Reason::ContractCreation as i32,
                call.gas_changes[2].reason
            );
        });
}
