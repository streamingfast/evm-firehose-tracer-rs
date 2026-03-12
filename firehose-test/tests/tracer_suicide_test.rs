use alloy_primitives::Bytes;
use firehose::LogData;
use firehose_test::{
    alice_addr, big_int, bob_addr, charlie_addr, hash32, miner_addr, receipt_with_logs,
    success_receipt, test_legacy_trx, TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

// =============================================================================
// SELFDESTRUCT / Suicide Tests
// =============================================================================

#[test]
fn test_normal_suicide_different_beneficiary() {
    // Contract suicides, sending balance to different address
    let contract_balance = alloy_primitives::U256::from(500);

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
        // Bob (contract) self-destructs, sending balance to Charlie
        .suicide(bob_addr(), charlie_addr(), contract_balance)
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("suicide", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            // Verify call is marked as suicided
            assert!(root_call.suicide, "Call should be marked as suicided");
            assert!(
                root_call.executed_code,
                "Call should have ExecutedCode=true"
            );

            // Verify balance changes (should have 2: SUICIDE_WITHDRAW + SUICIDE_REFUND)
            let balance_changes = &root_call.balance_changes;
            assert_eq!(2, balance_changes.len(), "Should have 2 balance changes");

            // First: Contract balance withdrawn
            let withdraw = &balance_changes[0];
            assert_eq!(bob_addr().as_slice(), withdraw.address.as_slice());
            assert_eq!(
                pbeth::balance_change::Reason::SuicideWithdraw as i32,
                withdraw.reason
            );

            // Second: Beneficiary receives balance
            let refund = &balance_changes[1];
            assert_eq!(charlie_addr().as_slice(), refund.address.as_slice());
            assert_eq!(
                pbeth::balance_change::Reason::SuicideRefund as i32,
                refund.reason
            );
        });
}

#[test]
fn test_suicide_to_self() {
    // Contract suicides to itself (edge case)
    let contract_balance = alloy_primitives::U256::from(1000);

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
        // Bob self-destructs to itself
        .suicide(bob_addr(), bob_addr(), contract_balance)
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("suicide", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            // Verify suicide flag
            assert!(root_call.suicide);
            assert!(root_call.executed_code);

            // Balance changes for suicide-to-self
            let balance_changes = &root_call.balance_changes;
            assert_eq!(2, balance_changes.len());

            // Withdraw from contract
            let withdraw = &balance_changes[0];
            assert_eq!(bob_addr().as_slice(), withdraw.address.as_slice());
            assert_eq!(
                pbeth::balance_change::Reason::SuicideWithdraw as i32,
                withdraw.reason
            );

            // Refund to same address (beneficiary == contract)
            let refund = &balance_changes[1];
            assert_eq!(bob_addr().as_slice(), refund.address.as_slice());
            assert_eq!(
                pbeth::balance_change::Reason::SuicideRefund as i32,
                refund.reason
            );
        });
}

#[test]
fn test_suicide_with_zero_balance() {
    // Contract with zero balance suicides
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
        // Bob has zero balance
        .suicide(bob_addr(), charlie_addr(), alloy_primitives::U256::ZERO)
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("suicide", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            // Still marked as suicide even with zero balance
            assert!(root_call.suicide);
            assert!(root_call.executed_code);

            // Should still have balance changes
            let balance_changes = &root_call.balance_changes;
            assert_eq!(2, balance_changes.len());

            let withdraw = &balance_changes[0];
            assert_eq!(
                pbeth::balance_change::Reason::SuicideWithdraw as i32,
                withdraw.reason
            );

            let refund = &balance_changes[1];
            assert_eq!(
                pbeth::balance_change::Reason::SuicideRefund as i32,
                refund.reason
            );
        });
}

#[test]
fn test_suicide_ordinal_assignment() {
    // Verify ordinals are properly assigned for suicide balance changes
    let contract_balance = alloy_primitives::U256::from(500);

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
        .suicide(bob_addr(), charlie_addr(), contract_balance)
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("suicide", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            let balance_changes = &root_call.balance_changes;
            assert_eq!(2, balance_changes.len());

            // Ordinals should be assigned and sequential
            let withdraw = &balance_changes[0];
            let refund = &balance_changes[1];

            assert!(withdraw.ordinal > 0, "Withdraw should have ordinal");
            assert!(refund.ordinal > 0, "Refund should have ordinal");
            assert!(
                withdraw.ordinal < refund.ordinal,
                "Withdraw ordinal should be before refund"
            );
        });
}

#[test]
fn test_suicide_in_nested_call() {
    // Suicide happens in a nested call, not root
    let contract_balance = big_int(750);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            200000,
            vec![],
        )
        // Bob calls Charlie
        .start_call(
            bob_addr(),
            charlie_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        // Charlie self-destructs
        .suicide(charlie_addr(), miner_addr(), contract_balance)
        .end_call(vec![], 50000) // Charlie returns
        .end_call(vec![], 150000) // Bob returns
        .end_block_trx(Some(success_receipt(200000)), None, None)
        .validate_with_category("suicide", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(2, trx.calls.len(), "Should have 2 calls");

            // Root call (Bob) - NOT suicided
            let root_call = &trx.calls[0];
            assert!(!root_call.suicide, "Root call should not be suicided");

            // Nested call (Charlie) - IS suicided
            let nested_call = &trx.calls[1];
            assert!(nested_call.suicide, "Nested call should be suicided");
            assert!(nested_call.executed_code);

            // Balance changes on the nested call
            let balance_changes = &nested_call.balance_changes;
            assert_eq!(2, balance_changes.len());

            let withdraw = &balance_changes[0];
            assert_eq!(charlie_addr().as_slice(), withdraw.address.as_slice());
            assert_eq!(
                pbeth::balance_change::Reason::SuicideWithdraw as i32,
                withdraw.reason
            );

            let refund = &balance_changes[1];
            assert_eq!(miner_addr().as_slice(), refund.address.as_slice());
            assert_eq!(
                pbeth::balance_change::Reason::SuicideRefund as i32,
                refund.reason
            );
        });
}

#[test]
fn test_multiple_suicides_in_transaction() {
    // Multiple contracts suicide in same transaction
    let balance1 = big_int(100);
    let balance2 = big_int(200);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            300000,
            vec![],
        )
        // First suicide: Bob → Charlie
        .suicide(bob_addr(), charlie_addr(), balance1)
        // Bob calls Miner
        .start_call(
            bob_addr(),
            miner_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        // Second suicide: Miner → Alice
        .suicide(miner_addr(), alice_addr(), balance2)
        .end_call(vec![], 50000) // Miner returns
        .end_call(vec![], 250000) // Bob returns
        .end_block_trx(Some(success_receipt(300000)), None, None)
        .validate_with_category("suicide", |block| {
            let trx = &block.transaction_traces[0];

            // Root call - first suicide
            let root_call = &trx.calls[0];
            assert!(root_call.suicide);
            assert_eq!(2, root_call.balance_changes.len());

            // Nested call - second suicide
            let nested_call = &trx.calls[1];
            assert!(nested_call.suicide);
            assert_eq!(2, nested_call.balance_changes.len());

            // Verify different beneficiaries
            assert_eq!(
                charlie_addr().as_slice(),
                root_call.balance_changes[1].address.as_slice()
            );
            assert_eq!(
                alice_addr().as_slice(),
                nested_call.balance_changes[1].address.as_slice()
            );
        });
}

#[test]
fn test_suicide_with_storage_and_logs() {
    // Suicide combined with storage changes and logs
    let contract_balance = big_int(300);
    let storage_key = hash32(1);
    let storage_value = hash32(42);
    let zero_val = hash32(0);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            200000,
            vec![],
        )
        // Storage change before suicide
        .storage_change(bob_addr(), storage_key, zero_val, storage_value)
        // Log event
        .log(bob_addr(), vec![hash32(100)], vec![0x01, 0x02], 0)
        // Then suicide
        .suicide(bob_addr(), charlie_addr(), contract_balance)
        .end_call(vec![], 150000)
        .end_block_trx(
            Some(receipt_with_logs(
                200000,
                vec![LogData {
                    address: bob_addr(),
                    topics: vec![hash32(100)],
                    data: Bytes::from(vec![0x01, 0x02]),
                    block_index: 0,
                }],
            )),
            None,
            None,
        )
        .validate_with_category("suicide", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            // Verify suicide
            assert!(root_call.suicide);

            // Verify storage change exists
            assert_eq!(1, root_call.storage_changes.len());
            assert_eq!(
                storage_key.as_slice(),
                root_call.storage_changes[0].key.as_slice()
            );

            // Verify log exists
            assert_eq!(1, root_call.logs.len());
            assert_eq!(bob_addr().as_slice(), root_call.logs[0].address.as_slice());

            // Verify balance changes (suicide)
            assert_eq!(2, root_call.balance_changes.len());
            assert_eq!(
                pbeth::balance_change::Reason::SuicideWithdraw as i32,
                root_call.balance_changes[0].reason
            );
            assert_eq!(
                pbeth::balance_change::Reason::SuicideRefund as i32,
                root_call.balance_changes[1].reason
            );
        });
}
