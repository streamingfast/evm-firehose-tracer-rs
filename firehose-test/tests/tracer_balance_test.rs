use firehose_test::{success_receipt, test_legacy_trx, TracerTester};
use pb::sf::ethereum::r#type::v2::balance_change::Reason;

#[test]
fn test_balance_change_with_active_call() {
    // Balance change during active call execution
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            test_legacy_trx().from,
            test_legacy_trx().to.unwrap(),
            test_legacy_trx().value,
            21000,
            vec![],
        )
        .balance_change(
            test_legacy_trx().from,
            alloy_primitives::U256::from(1000),
            alloy_primitives::U256::from(900),
            Reason::Transfer,
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("onbalancechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                1,
                call.balance_changes.len(),
                "Should have 1 balance change"
            );
            let bc = &call.balance_changes[0];
            assert_eq!(test_legacy_trx().from.as_slice(), bc.address.as_slice());
            assert_eq!(Reason::Transfer as i32, bc.reason);
        });
}

#[test]
fn test_balance_change_deferred_state() {
    // Balance change before call stack initialization (deferred)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // Balance change BEFORE call starts
        .balance_change(
            test_legacy_trx().from,
            alloy_primitives::U256::from(1000),
            alloy_primitives::U256::from(790),
            Reason::GasBuy,
        )
        .start_call(
            test_legacy_trx().from,
            test_legacy_trx().to.unwrap(),
            test_legacy_trx().value,
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("onbalancechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Deferred balance change should be applied to root call
            assert_eq!(
                1,
                call.balance_changes.len(),
                "Should have 1 balance change"
            );
            let bc = &call.balance_changes[0];
            assert_eq!(test_legacy_trx().from.as_slice(), bc.address.as_slice());
            assert_eq!(Reason::GasBuy as i32, bc.reason);
        });
}

#[test]
fn test_multiple_balance_changes_in_call() {
    // Multiple balance changes in same call
    use firehose_test::{alice_addr, bob_addr};
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
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(1000),
            alloy_primitives::U256::from(900),
            Reason::Transfer,
        )
        .balance_change(
            bob_addr(),
            alloy_primitives::U256::from(500),
            alloy_primitives::U256::from(600),
            Reason::Transfer,
        )
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(900),
            alloy_primitives::U256::from(800),
            Reason::GasRefund,
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("onbalancechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                3,
                call.balance_changes.len(),
                "Should have 3 balance changes"
            );

            // Verify ordering (ordinals should be increasing)
            assert!(
                call.balance_changes[0].ordinal < call.balance_changes[1].ordinal,
                "First balance change ordinal should be less than second"
            );
            assert!(
                call.balance_changes[1].ordinal < call.balance_changes[2].ordinal,
                "Second balance change ordinal should be less than third"
            );
        });
}

#[test]
fn test_block_level_balance_change() {
    // Balance change at block level (no transaction)
    use firehose_test::miner_addr;
    let mut tester = TracerTester::new();
    tester
        .start_block()
        // Block-level balance change (e.g., mining reward)
        .balance_change(
            miner_addr(),
            alloy_primitives::U256::ZERO,
            alloy_primitives::U256::from(2000000000000000000_u64),
            Reason::RewardMineBlock,
        )
        .end_block(None)
        .validate_with_category("onbalancechange", |block| {
            // Block-level balance changes
            assert_eq!(
                1,
                block.balance_changes.len(),
                "Should have 1 block-level balance change"
            );
            let bc = &block.balance_changes[0];
            assert_eq!(miner_addr().as_slice(), bc.address.as_slice());
            assert_eq!(Reason::RewardMineBlock as i32, bc.reason);
        });
}
