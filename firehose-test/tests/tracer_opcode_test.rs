use firehose_test::{
    alice_addr, big_int, bob_addr, charlie_addr, failed_receipt, success_receipt, test_legacy_trx,
    TracerTester, ERR_OUT_OF_GAS,
};

// =============================================================================
// Opcode Fault Tests
// =============================================================================

#[test]
fn test_invalid_opcode_fault() {
    // Test that OnOpcodeFault sets ExecutedCode but doesn't directly set StatusFailed
    // The failure is handled by OnCallExit
    // Invalid opcode is a failure but NOT a revert (like out of gas)
    let err = std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid opcode: opcode 0xfe not defined",
    );

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![0xff, 0xfe],
        )
        // Simulate an invalid opcode fault
        .opcode_fault(1, 0xfe, 21000, 0, &err)
        // Call fails due to the fault (propagates to OnCallExit)
        // Invalid opcode is a failure (reverted=true) but not a StatusReverted (not execution reverted)
        .end_call_failed(vec![], 0, &err, true)
        .end_block_trx(Some(failed_receipt(21000)), None, None)
        .validate_with_category("onopcodefault", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // ExecutedCode should be set by OnOpcodeFault
            assert_eq!(
                call.executed_code,
                Some(true),
                "ExecutedCode should be set even for faulted opcodes"
            );

            // StatusFailed is set by OnCallExit, not OnOpcodeFault
            assert!(call.status_failed, "Call should be marked as failed");
            // Invalid opcode is not a "StatusReverted" (not ErrExecutionReverted)
            assert!(
                !call.status_reverted,
                "Invalid opcode is failed but not reverted"
            );
            assert!(call.failure_reason.contains("invalid opcode"));
        });
}

#[test]
fn test_stack_underflow_fault() {
    // Stack underflow is a common fault condition
    let err = std::io::Error::new(std::io::ErrorKind::InvalidData, "stack underflow");

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![0x01],
        ) // ADD without stack items
        .opcode_fault(0, 0x01, 21000, 0, &err)
        .end_call_failed(vec![], 0, &err, true)
        .end_block_trx(Some(failed_receipt(21000)), None, None)
        .validate_with_category("onopcodefault", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(call.executed_code, Some(true), "ExecutedCode should be set");
            assert!(call.status_failed, "Call should fail");
            assert!(call.failure_reason.contains("stack underflow"));
        });
}

#[test]
fn test_stack_overflow_fault() {
    // Stack overflow (exceeding 1024 items)
    let err = std::io::Error::new(std::io::ErrorKind::InvalidData, "stack limit reached 1024");

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            100000,
            vec![0x60, 0x00],
        ) // PUSH1 0
        .opcode_fault(1000, 0x60, 50000, 3, &err)
        .end_call_failed(vec![], 50000, &err, true)
        .end_block_trx(Some(failed_receipt(100000)), None, None)
        .validate_with_category("onopcodefault", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(call.executed_code, Some(true));
            assert!(call.status_failed);
            assert!(call.failure_reason.contains("stack limit"));
        });
}

#[test]
fn test_out_of_gas_fault() {
    // Out of gas during opcode execution
    let err = std::io::Error::new(std::io::ErrorKind::Other, ERR_OUT_OF_GAS);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![0x5b],
        ) // JUMPDEST
        .opcode_fault(0, 0x5b, 10, 5, &err)
        .end_call_failed(vec![], 21000, &err, true)
        .end_block_trx(Some(failed_receipt(21000)), None, None)
        .validate_with_category("onopcodefault", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(call.executed_code, Some(true));
            assert!(call.status_failed);
            // Out of gas is not a revert, it's a failure
            assert!(!call.status_reverted, "Out of gas should not be reverted");
            assert_eq!("out of gas", call.failure_reason);
        });
}

#[test]
fn test_nested_call_opcode_fault() {
    // Opcode fault in a nested call
    let err = std::io::Error::new(std::io::ErrorKind::Other, "invalid opcode: 0xfe");

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 100000, vec![])
        // Bob executes some code
        .opcode(0, 0x60, 100000, 3) // PUSH1
        // Bob calls Charlie
        .start_call(bob_addr(), charlie_addr(), big_int(50), 50000, vec![0xfe])
        // Charlie executes invalid opcode
        .opcode_fault(0, 0xfe, 50000, 0, &err)
        .end_call_failed(vec![], 0, &err, true)
        // Bob succeeds (handles the revert)
        .end_call(vec![], 90000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("onopcodefault", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(2, trx.calls.len(), "Should have 2 calls");

            let root_call = &trx.calls[0];
            let nested_call = &trx.calls[1];

            // Nested call should have ExecutedCode set and be failed
            assert_eq!(
                nested_call.executed_code,
                Some(true),
                "Nested call should have ExecutedCode"
            );
            assert!(nested_call.status_failed, "Nested call should fail");
            assert!(nested_call.failure_reason.contains("invalid opcode"));

            // Root call should succeed and have ExecutedCode (from OpCode call)
            assert!(!root_call.status_failed, "Root call should succeed");
            assert_eq!(
                root_call.executed_code,
                Some(true),
                "Root call should have ExecutedCode"
            );
        });
}

#[test]
fn test_multiple_opcode_faults_before_exit() {
    // Multiple opcode faults before call exit (last fault's error is what matters)
    let err1 = std::io::Error::new(std::io::ErrorKind::Other, "fault 1");
    let err2 = std::io::Error::new(std::io::ErrorKind::Other, "invalid opcode: final fault");

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            big_int(100),
            21000,
            vec![0x60, 0x01, 0xfe],
        )
        .opcode_fault(0, 0x60, 21000, 3, &err1)
        .opcode_fault(2, 0xfe, 20997, 0, &err2)
        .end_call_failed(vec![], 0, &err2, true)
        .end_block_trx(Some(failed_receipt(21000)), None, None)
        .validate_with_category("onopcodefault", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(call.executed_code, Some(true));
            assert!(call.status_failed);
            // The final error is what's recorded
            assert!(call.failure_reason.contains("final fault"));
        });
}
