use firehose_test::{
    alice_addr, bob_addr, charlie_addr, success_receipt, test_legacy_trx, TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

/// Helper to compute keccak256 of bytes
fn hash_bytes(data: &[u8]) -> alloy_primitives::B256 {
    alloy_primitives::keccak256(data)
}

// =============================================================================
// Balance Changes - Deferred State
// =============================================================================

#[test]
fn test_balance_change_before_root_call() {
    // Balance change occurs before root call starts (deferred to root call)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(1000),
            alloy_primitives::U256::from(790),
            pbeth::balance_change::Reason::GasBuy,
        )
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.balance_changes.len());
            let bc = &call.balance_changes[0];
            assert_eq!(alice_addr().as_slice(), bc.address.as_slice());
            assert_eq!(pbeth::balance_change::Reason::GasBuy as i32, bc.reason);
        });
}

#[test]
fn test_balance_change_after_root_call() {
    // Balance change occurs after root call ends (deferred to root call)
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
        .end_call(vec![], 21000)
        // Balance change AFTER call ends but before transaction ends
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(790),
            alloy_primitives::U256::from(800),
            pbeth::balance_change::Reason::GasRefund,
        )
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.balance_changes.len());
            let bc = &call.balance_changes[0];
            assert_eq!(alice_addr().as_slice(), bc.address.as_slice());
            assert_eq!(pbeth::balance_change::Reason::GasRefund as i32, bc.reason);
        });
}

#[test]
fn test_balance_changes_mixed_before_during_after() {
    // Balance changes: before call, during call, after call
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // BEFORE: Gas buy
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(1000),
            alloy_primitives::U256::from(790),
            pbeth::balance_change::Reason::GasBuy,
        )
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        // DURING: Transfer
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(790),
            alloy_primitives::U256::from(690),
            pbeth::balance_change::Reason::Transfer,
        )
        .balance_change(
            bob_addr(),
            alloy_primitives::U256::from(500),
            alloy_primitives::U256::from(600),
            pbeth::balance_change::Reason::Transfer,
        )
        .end_call(vec![], 21000)
        // AFTER: Gas refund
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(690),
            alloy_primitives::U256::from(700),
            pbeth::balance_change::Reason::GasRefund,
        )
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // All changes should be in root call, ordered chronologically
            assert_eq!(4, call.balance_changes.len());

            // Before call (deferred)
            assert_eq!(
                alice_addr().as_slice(),
                call.balance_changes[0].address.as_slice()
            );
            assert_eq!(
                pbeth::balance_change::Reason::GasBuy as i32,
                call.balance_changes[0].reason
            );

            // During call
            assert_eq!(
                alice_addr().as_slice(),
                call.balance_changes[1].address.as_slice()
            );
            assert_eq!(
                pbeth::balance_change::Reason::Transfer as i32,
                call.balance_changes[1].reason
            );

            assert_eq!(
                bob_addr().as_slice(),
                call.balance_changes[2].address.as_slice()
            );
            assert_eq!(
                pbeth::balance_change::Reason::Transfer as i32,
                call.balance_changes[2].reason
            );

            // After call (deferred)
            assert_eq!(
                alice_addr().as_slice(),
                call.balance_changes[3].address.as_slice()
            );
            assert_eq!(
                pbeth::balance_change::Reason::GasRefund as i32,
                call.balance_changes[3].reason
            );
        });
}

// =============================================================================
// Nonce Changes - Deferred State
// =============================================================================

#[test]
fn test_nonce_change_before_root_call() {
    // Nonce change before call starts (e.g., EIP-7702 SetCode)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .nonce_change(alice_addr(), 0, 1)
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.nonce_changes.len());
            let nc = &call.nonce_changes[0];
            assert_eq!(alice_addr().as_slice(), nc.address.as_slice());
            assert_eq!(0, nc.old_value);
            assert_eq!(1, nc.new_value);
        });
}

#[test]
fn test_nonce_change_after_root_call() {
    // Nonce change after call ends
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
        .end_call(vec![], 21000)
        .nonce_change(alice_addr(), 5, 6)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.nonce_changes.len());
            let nc = &call.nonce_changes[0];
            assert_eq!(alice_addr().as_slice(), nc.address.as_slice());
            assert_eq!(5, nc.old_value);
            assert_eq!(6, nc.new_value);
        });
}

#[test]
fn test_nonce_changes_mixed_before_during_after() {
    // Nonce changes: before, during, after call
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // BEFORE: EIP-7702 SetCode nonce increment
        .nonce_change(alice_addr(), 0, 1)
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        // DURING: Contract creation increments nonce
        .nonce_change(bob_addr(), 0, 1)
        .end_call(vec![], 21000)
        // AFTER: Some post-execution nonce change
        .nonce_change(charlie_addr(), 10, 11)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(3, call.nonce_changes.len());

            // Before (deferred)
            assert_eq!(
                alice_addr().as_slice(),
                call.nonce_changes[0].address.as_slice()
            );
            assert_eq!(0, call.nonce_changes[0].old_value);
            assert_eq!(1, call.nonce_changes[0].new_value);

            // During
            assert_eq!(
                bob_addr().as_slice(),
                call.nonce_changes[1].address.as_slice()
            );

            // After (deferred)
            assert_eq!(
                charlie_addr().as_slice(),
                call.nonce_changes[2].address.as_slice()
            );
        });
}

// =============================================================================
// Code Changes - Deferred State
// =============================================================================

#[test]
fn test_code_change_before_root_call() {
    // Code change before call starts (e.g., EIP-7702 SetCode)
    let old_code = vec![0x60, 0x00];
    let new_code = vec![0x60, 0x01, 0x60, 0x02];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .code_change(
            alice_addr(),
            hash_bytes(&old_code),
            hash_bytes(&new_code),
            old_code.clone(),
            new_code.clone(),
        )
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.code_changes.len());
            let cc = &call.code_changes[0];
            assert_eq!(alice_addr().as_slice(), cc.address.as_slice());
            assert_eq!(old_code, cc.old_code);
            assert_eq!(new_code, cc.new_code);
        });
}

#[test]
fn test_code_change_after_root_call() {
    // Code change after call ends
    let old_code = vec![];
    let new_code = vec![0x60, 0x03];

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
        .end_call(vec![], 21000)
        .code_change(
            charlie_addr(),
            hash_bytes(&old_code),
            hash_bytes(&new_code),
            old_code.clone(),
            new_code.clone(),
        )
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.code_changes.len());
            let cc = &call.code_changes[0];
            assert_eq!(charlie_addr().as_slice(), cc.address.as_slice());
            assert_eq!(old_code, cc.old_code);
            assert_eq!(new_code, cc.new_code);
        });
}

// =============================================================================
// Storage Changes - Deferred State
// =============================================================================

#[test]
fn test_storage_change_before_root_call() {
    // Storage change before call starts
    let slot = alloy_primitives::B256::from([1u8; 32]);
    let old_value = alloy_primitives::B256::from([0u8; 32]);
    let new_value = alloy_primitives::B256::from([2u8; 32]);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .storage_change(alice_addr(), slot, old_value, new_value)
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.storage_changes.len());
            let sc = &call.storage_changes[0];
            assert_eq!(alice_addr().as_slice(), sc.address.as_slice());
            assert_eq!(slot.as_slice(), sc.key.as_slice());
            assert_eq!(old_value.as_slice(), sc.old_value.as_slice());
            assert_eq!(new_value.as_slice(), sc.new_value.as_slice());
        });
}

#[test]
fn test_storage_change_after_root_call() {
    // Storage change after call ends
    let slot = alloy_primitives::B256::from([3u8; 32]);
    let old_value = alloy_primitives::B256::from([4u8; 32]);
    let new_value = alloy_primitives::B256::from([5u8; 32]);

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
        .end_call(vec![], 21000)
        .storage_change(bob_addr(), slot, old_value, new_value)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.storage_changes.len());
            let sc = &call.storage_changes[0];
            assert_eq!(bob_addr().as_slice(), sc.address.as_slice());
        });
}

// =============================================================================
// Gas Changes - Deferred State
// =============================================================================

#[test]
fn test_gas_change_before_root_call() {
    // Gas change before call starts (intrinsic gas)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .gas_change(21000, 0, pbeth::gas_change::Reason::IntrinsicGas)
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.gas_changes.len());
            let gc = &call.gas_changes[0];
            assert_eq!(21000, gc.old_value);
            assert_eq!(0, gc.new_value);
            assert_eq!(pbeth::gas_change::Reason::IntrinsicGas as i32, gc.reason);
        });
}

#[test]
fn test_gas_change_after_root_call() {
    // Gas change after call ends (gas refund)
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
        .end_call(vec![], 21000)
        .gas_change(0, 5000, pbeth::gas_change::Reason::RefundAfterExecution)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.gas_changes.len());
            let gc = &call.gas_changes[0];
            assert_eq!(0, gc.old_value);
            assert_eq!(5000, gc.new_value);
            assert_eq!(
                pbeth::gas_change::Reason::RefundAfterExecution as i32,
                gc.reason
            );
        });
}

#[test]
fn test_code_changes_mixed_before_during_after() {
    // Code changes: before, during, after call
    let code1_old = vec![0x60, 0x00];
    let code1_new = vec![0x60, 0x01];
    let code2_old = vec![];
    let code2_new = vec![0x60, 0x02];
    let code3_old = vec![0x60, 0x03];
    let code3_new = vec![0x60, 0x04];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // BEFORE: EIP-7702 SetCode
        .code_change(
            alice_addr(),
            hash_bytes(&code1_old),
            hash_bytes(&code1_new),
            code1_old.clone(),
            code1_new.clone(),
        )
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        // DURING: Contract deployment
        .code_change(
            bob_addr(),
            hash_bytes(&code2_old),
            hash_bytes(&code2_new),
            code2_old.clone(),
            code2_new.clone(),
        )
        .end_call(vec![], 21000)
        // AFTER: Another code change
        .code_change(
            charlie_addr(),
            hash_bytes(&code3_old),
            hash_bytes(&code3_new),
            code3_old.clone(),
            code3_new.clone(),
        )
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(3, call.code_changes.len());

            // Before (deferred)
            assert_eq!(
                alice_addr().as_slice(),
                call.code_changes[0].address.as_slice()
            );

            // During
            assert_eq!(
                bob_addr().as_slice(),
                call.code_changes[1].address.as_slice()
            );

            // After (deferred)
            assert_eq!(
                charlie_addr().as_slice(),
                call.code_changes[2].address.as_slice()
            );
        });
}

#[test]
fn test_gas_changes_mixed_before_during_after() {
    // Gas changes: before, during, after call
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // BEFORE: Intrinsic gas
        .gas_change(50000, 29000, pbeth::gas_change::Reason::IntrinsicGas)
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            50000,
            vec![],
        )
        // DURING: Call execution (using STATE_COLD_ACCESS as example of gas consumed during call)
        .gas_change(29000, 8000, pbeth::gas_change::Reason::StateColdAccess)
        .end_call(vec![], 8000)
        // AFTER: Gas refund
        .gas_change(8000, 13000, pbeth::gas_change::Reason::RefundAfterExecution)
        .end_block_trx(Some(success_receipt(37000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(3, call.gas_changes.len());

            // Before (deferred)
            assert_eq!(
                pbeth::gas_change::Reason::IntrinsicGas as i32,
                call.gas_changes[0].reason
            );

            // During
            assert_eq!(
                pbeth::gas_change::Reason::StateColdAccess as i32,
                call.gas_changes[1].reason
            );

            // After (deferred)
            assert_eq!(
                pbeth::gas_change::Reason::RefundAfterExecution as i32,
                call.gas_changes[2].reason
            );
        });
}

// =============================================================================
// Mixed State Changes - Complex Scenarios
// =============================================================================

#[test]
fn test_all_state_types_before_root_call() {
    // All types of state changes before root call
    let old_code = vec![];
    let new_code = vec![0x60, 0x00];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(1000),
            alloy_primitives::U256::from(790),
            pbeth::balance_change::Reason::GasBuy,
        )
        .nonce_change(alice_addr(), 0, 1)
        .code_change(
            alice_addr(),
            hash_bytes(&old_code),
            hash_bytes(&new_code),
            old_code.clone(),
            new_code.clone(),
        )
        .gas_change(50000, 29000, pbeth::gas_change::Reason::IntrinsicGas)
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            29000,
            vec![],
        )
        .end_call(vec![], 29000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // All deferred state should be in root call
            assert_eq!(1, call.balance_changes.len());
            assert_eq!(1, call.nonce_changes.len());
            assert_eq!(1, call.code_changes.len());
            assert_eq!(1, call.gas_changes.len());
        });
}

#[test]
fn test_all_state_types_after_root_call() {
    // All types of state changes after root call
    let old_code = vec![0x60, 0x01];
    let new_code = vec![0x60, 0x02];

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
        .end_call(vec![], 21000)
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(790),
            alloy_primitives::U256::from(800),
            pbeth::balance_change::Reason::GasRefund,
        )
        .nonce_change(charlie_addr(), 5, 6)
        .code_change(
            charlie_addr(),
            hash_bytes(&old_code),
            hash_bytes(&new_code),
            old_code.clone(),
            new_code.clone(),
        )
        .gas_change(0, 5000, pbeth::gas_change::Reason::RefundAfterExecution)
        .end_block_trx(Some(success_receipt(16000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // All deferred state should be in root call
            assert_eq!(1, call.balance_changes.len());
            assert_eq!(1, call.nonce_changes.len());
            assert_eq!(1, call.code_changes.len());
            assert_eq!(1, call.gas_changes.len());
        });
}

#[test]
fn test_all_state_types_mixed_before_during_after() {
    // Complex scenario: all state types before, during, and after root call
    let code1_old = vec![];
    let code1_new = vec![0x60, 0x00];
    let code2_old = vec![];
    let code2_new = vec![0x60, 0x01];
    let code3_old = vec![0x60, 0x02];
    let code3_new = vec![0x60, 0x03];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // === BEFORE ROOT CALL ===
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(1000),
            alloy_primitives::U256::from(790),
            pbeth::balance_change::Reason::GasBuy,
        )
        .nonce_change(alice_addr(), 0, 1)
        .code_change(
            alice_addr(),
            hash_bytes(&code1_old),
            hash_bytes(&code1_new),
            code1_old.clone(),
            code1_new.clone(),
        )
        .gas_change(50000, 29000, pbeth::gas_change::Reason::IntrinsicGas)
        // === DURING ROOT CALL ===
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            29000,
            vec![],
        )
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(790),
            alloy_primitives::U256::from(690),
            pbeth::balance_change::Reason::Transfer,
        )
        .balance_change(
            bob_addr(),
            alloy_primitives::U256::from(500),
            alloy_primitives::U256::from(600),
            pbeth::balance_change::Reason::Transfer,
        )
        .nonce_change(bob_addr(), 0, 1)
        .code_change(
            bob_addr(),
            hash_bytes(&code2_old),
            hash_bytes(&code2_new),
            code2_old.clone(),
            code2_new.clone(),
        )
        .gas_change(29000, 8000, pbeth::gas_change::Reason::StateColdAccess)
        .end_call(vec![], 8000)
        // === AFTER ROOT CALL ===
        .balance_change(
            alice_addr(),
            alloy_primitives::U256::from(690),
            alloy_primitives::U256::from(700),
            pbeth::balance_change::Reason::GasRefund,
        )
        .nonce_change(charlie_addr(), 10, 11)
        .code_change(
            charlie_addr(),
            hash_bytes(&code3_old),
            hash_bytes(&code3_new),
            code3_old.clone(),
            code3_new.clone(),
        )
        .gas_change(8000, 13000, pbeth::gas_change::Reason::RefundAfterExecution)
        .end_block_trx(Some(success_receipt(37000)), None, None)
        .validate_with_category("deferredcallstate", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // All state changes should be in root call, properly ordered
            assert_eq!(
                4,
                call.balance_changes.len(),
                "Should have 4 balance changes"
            );
            assert_eq!(3, call.nonce_changes.len(), "Should have 3 nonce changes");
            assert_eq!(3, call.code_changes.len(), "Should have 3 code changes");
            assert_eq!(3, call.gas_changes.len(), "Should have 3 gas changes");

            // Verify ordering: before (deferred) -> during -> after (deferred)
            // Balance changes
            assert_eq!(
                pbeth::balance_change::Reason::GasBuy as i32,
                call.balance_changes[0].reason,
                "First balance change should be gas buy (before)"
            );
            assert_eq!(
                pbeth::balance_change::Reason::Transfer as i32,
                call.balance_changes[1].reason,
                "Second balance change should be transfer (during)"
            );
            assert_eq!(
                pbeth::balance_change::Reason::Transfer as i32,
                call.balance_changes[2].reason,
                "Third balance change should be transfer (during)"
            );
            assert_eq!(
                pbeth::balance_change::Reason::GasRefund as i32,
                call.balance_changes[3].reason,
                "Fourth balance change should be gas refund (after)"
            );

            // Nonce changes
            assert_eq!(
                alice_addr().as_slice(),
                call.nonce_changes[0].address.as_slice(),
                "First nonce change should be Alice (before)"
            );
            assert_eq!(
                bob_addr().as_slice(),
                call.nonce_changes[1].address.as_slice(),
                "Second nonce change should be Bob (during)"
            );
            assert_eq!(
                charlie_addr().as_slice(),
                call.nonce_changes[2].address.as_slice(),
                "Third nonce change should be Charlie (after)"
            );

            // Code changes
            assert_eq!(
                alice_addr().as_slice(),
                call.code_changes[0].address.as_slice(),
                "First code change should be Alice (before)"
            );
            assert_eq!(
                bob_addr().as_slice(),
                call.code_changes[1].address.as_slice(),
                "Second code change should be Bob (during)"
            );
            assert_eq!(
                charlie_addr().as_slice(),
                call.code_changes[2].address.as_slice(),
                "Third code change should be Charlie (after)"
            );

            // Gas changes
            assert_eq!(
                pbeth::gas_change::Reason::IntrinsicGas as i32,
                call.gas_changes[0].reason,
                "First gas change should be intrinsic (before)"
            );
            assert_eq!(
                pbeth::gas_change::Reason::StateColdAccess as i32,
                call.gas_changes[1].reason,
                "Second gas change should be call (during)"
            );
            assert_eq!(
                pbeth::gas_change::Reason::RefundAfterExecution as i32,
                call.gas_changes[2].reason,
                "Third gas change should be refund (after)"
            );
        });
}
