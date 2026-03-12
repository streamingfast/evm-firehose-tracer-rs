use firehose_test::{
    addr_from_hex, alice_addr, big_int, bob_addr, charlie_addr, failed_receipt, hash32, log1,
    miner_addr, must_big_int, receipt_with_logs, success_receipt, test_legacy_trx, TracerTester,
    ERR_EXECUTION_REVERTED, ERR_INSUFFICIENT_BALANCE_TRANSFER, ERR_MAX_CALL_DEPTH, ERR_OUT_OF_GAS,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

// Test error types matching VM errors
#[derive(Debug)]
struct ExecutionRevertedError;

impl std::fmt::Display for ExecutionRevertedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", ERR_EXECUTION_REVERTED)
    }
}

impl std::error::Error for ExecutionRevertedError {}

#[derive(Debug)]
struct InsufficientBalanceError;

impl std::fmt::Display for InsufficientBalanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", ERR_INSUFFICIENT_BALANCE_TRANSFER)
    }
}

impl std::error::Error for InsufficientBalanceError {}

#[derive(Debug)]
struct MaxCallDepthError;

impl std::fmt::Display for MaxCallDepthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", ERR_MAX_CALL_DEPTH)
    }
}

impl std::error::Error for MaxCallDepthError {}

#[derive(Debug)]
struct OutOfGasError;

impl std::fmt::Display for OutOfGasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", ERR_OUT_OF_GAS)
    }
}

impl std::error::Error for OutOfGasError {}

// Wrapped error type for testing error chains
#[derive(Debug)]
struct WrappedError {
    message: String,
    source: Box<dyn std::error::Error>,
}

impl std::fmt::Display for WrappedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for WrappedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[test]
fn test_simple_nested_call() {
    // Alice calls Bob, Bob calls Charlie
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            100000,
            vec![0x01],
        )
        // Bob makes a nested call to Charlie
        .start_call(
            bob_addr(),
            charlie_addr(),
            alloy_primitives::U256::from(50),
            50000,
            vec![0x02],
        )
        .end_call(vec![0x03], 45000) // Charlie returns
        .end_call(vec![0x04], 90000) // Bob returns
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(2, trx.calls.len(), "Should have 2 calls (root + nested)");

            let root_call = &trx.calls[0];
            assert_eq!(pbeth::CallType::Call as i32, root_call.call_type);
            assert_eq!(alice_addr().as_slice(), root_call.caller.as_slice());
            assert_eq!(bob_addr().as_slice(), root_call.address.as_slice());
            assert_eq!(0, root_call.depth);
            assert_eq!(0, root_call.parent_index, "Root call has no parent");

            let nested_call = &trx.calls[1];
            assert_eq!(pbeth::CallType::Call as i32, nested_call.call_type);
            assert_eq!(bob_addr().as_slice(), nested_call.caller.as_slice());
            assert_eq!(charlie_addr().as_slice(), nested_call.address.as_slice());
            assert_eq!(1, nested_call.depth);
            assert_eq!(1, nested_call.parent_index, "Nested call parent is root");
        });
}

#[test]
fn test_deep_nested_calls() {
    // Alice -> Bob -> Charlie -> Miner (depth 0, 1, 2, 3)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            200000,
            vec![],
        )
        .start_call(
            bob_addr(),
            charlie_addr(),
            alloy_primitives::U256::from(50),
            150000,
            vec![],
        )
        .start_call(
            charlie_addr(),
            miner_addr(),
            alloy_primitives::U256::from(25),
            100000,
            vec![],
        )
        .end_call(vec![], 95000) // Miner returns
        .end_call(vec![], 140000) // Charlie returns
        .end_call(vec![], 180000) // Bob returns
        .end_block_trx(Some(success_receipt(200000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(3, trx.calls.len(), "Should have 3 nested calls");

            // Verify depth progression
            let expected_depths = [0, 1, 2];
            for (i, expected_depth) in expected_depths.iter().enumerate() {
                assert_eq!(*expected_depth, trx.calls[i].depth);
            }

            // Verify parent relationships
            assert_eq!(0, trx.calls[0].parent_index); // Root has no parent
            assert_eq!(1, trx.calls[1].parent_index); // Child of call 1 (index=1)
            assert_eq!(2, trx.calls[2].parent_index); // Child of call 2 (index=2)
        });
}

#[test]
fn test_nested_with_failure() {
    // Alice calls Bob, Bob calls Charlie (fails), Bob continues and succeeds
    let mut tester = TracerTester::new();
    // Wrap the error to match Golang's fmt.Errorf("revert: %w", err)
    let inner_err = ExecutionRevertedError;
    let err = WrappedError {
        message: format!("revert: {}", ERR_EXECUTION_REVERTED),
        source: Box::new(inner_err),
    };

    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            100000,
            vec![],
        )
        // Bob calls Charlie, which reverts
        .start_call(
            bob_addr(),
            charlie_addr(),
            alloy_primitives::U256::from(50),
            50000,
            vec![],
        )
        .end_call_failed(vec![], 10000, &err, true)
        // Bob continues and succeeds
        .end_call(vec![0x05], 80000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(2, trx.calls.len());

            let root_call = &trx.calls[0];
            assert!(!root_call.status_failed, "Root call should succeed");
            assert!(!root_call.status_reverted);

            let nested_call = &trx.calls[1];
            assert!(nested_call.status_failed, "Nested call should fail");
            assert!(nested_call.status_reverted);
            assert_eq!("revert: execution reverted", nested_call.failure_reason);
        });
}

#[test]
fn test_nested_all_revert() {
    // Alice calls Bob, Bob calls Charlie (fails), Bob also reverts
    let mut tester = TracerTester::new();
    // Wrap errors to match Golang's fmt.Errorf("nested revert: %w", err) and fmt.Errorf("parent revert: %w", err)
    let nested_inner = ExecutionRevertedError;
    let nested_err = WrappedError {
        message: format!("nested revert: {}", ERR_EXECUTION_REVERTED),
        source: Box::new(nested_inner),
    };
    let parent_inner = ExecutionRevertedError;
    let parent_err = WrappedError {
        message: format!("parent revert: {}", ERR_EXECUTION_REVERTED),
        source: Box::new(parent_inner),
    };

    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            100000,
            vec![],
        )
        // Bob calls Charlie, which reverts
        .start_call(
            bob_addr(),
            charlie_addr(),
            alloy_primitives::U256::from(50),
            50000,
            vec![],
        )
        .end_call_failed(vec![], 10000, &nested_err, true)
        // Bob also reverts
        .end_call_failed(vec![], 20000, &parent_err, true)
        .end_block_trx(Some(failed_receipt(100000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(2, trx.calls.len());

            // Both calls should be reverted
            assert!(trx.calls[0].status_failed);
            assert!(trx.calls[0].status_reverted);
            assert!(trx.calls[1].status_failed);
            assert!(trx.calls[1].status_reverted);
        });
}
// =============================================================================
// Call Types Tests
// =============================================================================

#[test]
fn test_call_type_basic() {
    // Basic CALL type
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
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            assert_eq!(1, block.transaction_traces.len());
            let trx = &block.transaction_traces[0];
            assert_eq!(1, trx.calls.len());

            let call = &trx.calls[0];
            assert_eq!(pbeth::CallType::Call as i32, call.call_type);
            assert_eq!(alice_addr().as_slice(), call.caller.as_slice());
            assert_eq!(bob_addr().as_slice(), call.address.as_slice());
            // Value is stored as big-endian bytes, last byte contains small values
            let value = call
                .value
                .as_ref()
                .unwrap()
                .bytes
                .last()
                .copied()
                .unwrap_or(0);
            assert_eq!(100, value, "Value should be 100");
            assert_eq!(21000, call.gas_limit);
            assert_eq!(21000, call.gas_consumed);
            assert!(!call.status_failed);
            assert!(!call.status_reverted);
        });
}

#[test]
fn test_call_type_staticcall() {
    // STATICCALL can only happen as a nested call from a contract
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            50000,
            vec![],
        )
        // Bob makes a STATICCALL to Charlie
        .start_static_call(bob_addr(), charlie_addr(), 21000, vec![0x01, 0x02])
        .end_call(vec![0x03, 0x04], 20000)
        .end_call(vec![], 45000)
        .end_block_trx(Some(success_receipt(50000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(
                2,
                trx.calls.len(),
                "Should have root call + nested STATICCALL"
            );

            let nested_call = &trx.calls[1];
            assert_eq!(pbeth::CallType::Static as i32, nested_call.call_type);
            assert!(
                nested_call.value.is_none(),
                "STATICCALL should have nil value"
            );
            assert_eq!(&[0x01, 0x02], nested_call.input.as_slice());
            assert_eq!(&[0x03, 0x04], nested_call.return_data.as_slice());
        });
}

#[test]
fn test_call_type_delegatecall() {
    // DELEGATECALL can only happen as a nested call from a contract
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            50000,
            vec![],
        )
        // Bob makes a DELEGATECALL to Charlie
        .start_delegate_call(
            bob_addr(),
            charlie_addr(),
            alloy_primitives::U256::ZERO,
            21000,
            vec![0x05],
        )
        .end_call(vec![0x06], 20000)
        .end_call(vec![], 45000)
        .end_block_trx(Some(success_receipt(50000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(
                2,
                trx.calls.len(),
                "Should have root call + nested DELEGATECALL"
            );

            let nested_call = &trx.calls[1];
            assert_eq!(pbeth::CallType::Delegate as i32, nested_call.call_type);
            assert!(
                nested_call.value.is_none(),
                "DELEGATECALL should have nil value"
            );
        });
}

#[test]
fn test_call_type_callcode() {
    // CALLCODE can only happen as a nested call from a contract
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            50000,
            vec![],
        )
        // Bob makes a CALLCODE to Charlie
        .start_call_code(
            bob_addr(),
            charlie_addr(),
            alloy_primitives::U256::from(50),
            21000,
            vec![],
        )
        .end_call(vec![], 20000)
        .end_call(vec![], 45000)
        .end_block_trx(Some(success_receipt(50000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(
                2,
                trx.calls.len(),
                "Should have root call + nested CALLCODE"
            );

            let nested_call = &trx.calls[1];
            assert_eq!(pbeth::CallType::Callcode as i32, nested_call.call_type);
            let value = nested_call
                .value
                .as_ref()
                .unwrap()
                .bytes
                .last()
                .copied()
                .unwrap_or(0);
            assert_eq!(50, value, "Value should be 50");
        });
}

#[test]
fn test_call_type_create() {
    let contract_code = vec![0x60, 0x80, 0x60, 0x40];
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_create_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            53000,
            contract_code.clone(),
        )
        .end_call(contract_code.clone(), 50000)
        .end_block_trx(Some(success_receipt(53000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(pbeth::CallType::Create as i32, call.call_type);
            assert_eq!(&contract_code, &call.input);
            // CREATE calls don't return the code in ReturnData
            assert!(
                call.return_data.is_empty(),
                "CREATE call should have empty return data"
            );
        });
}

#[test]
fn test_call_type_create2() {
    // CREATE2 can only happen as a nested call from a contract
    let contract_code = vec![0x60, 0x80, 0x60, 0x40];
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            100000,
            vec![],
        )
        // Bob deploys a contract using CREATE2
        .start_create2_call(
            bob_addr(),
            charlie_addr(),
            alloy_primitives::U256::ZERO,
            53000,
            contract_code.clone(),
        )
        .end_call(contract_code, 50000)
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(2, trx.calls.len(), "Should have root call + nested CREATE2");

            let nested_call = &trx.calls[1];
            assert_eq!(pbeth::CallType::Create as i32, nested_call.call_type);
            // CREATE2 uses same firehose.CallType as CREATE
            assert!(
                nested_call.return_data.is_empty(),
                "CREATE2 call should have empty return data"
            );
        });
}

// =============================================================================
// Call Failures Tests
// =============================================================================

#[test]
fn test_call_failure_reverted() {
    // Create wrapped error matching Golang's fmt.Errorf("revert: %w", err)
    let inner_err = ExecutionRevertedError;
    let err = WrappedError {
        message: format!("revert: {}", ERR_EXECUTION_REVERTED),
        source: Box::new(inner_err),
    };

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
        .end_call_failed(vec![], 5000, &err, true)
        .end_block_trx(Some(failed_receipt(21000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert!(call.status_failed, "Call should be marked as failed");
            assert!(call.status_reverted, "Call should be marked as reverted");
            assert_eq!("revert: execution reverted", call.failure_reason);
            assert_eq!(5000, call.gas_consumed);
        });
}

#[test]
fn test_call_failure_out_of_gas() {
    let err = std::io::Error::new(std::io::ErrorKind::Other, "out of gas");

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
        .end_call_failed(vec![], 21000, &err, true)
        .end_block_trx(Some(failed_receipt(21000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert!(call.status_failed);
            assert!(
                !call.status_reverted,
                "Out of gas is failed but not reverted"
            );
            assert_eq!("out of gas", call.failure_reason);
            assert_eq!(21000, call.gas_consumed, "Should consume all gas");
        });
}

#[test]
fn test_call_failure_invalid_opcode() {
    let err = std::io::Error::new(std::io::ErrorKind::Other, "invalid opcode");

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![0xff],
        )
        .end_call_failed(vec![], 10000, &err, true)
        .end_block_trx(Some(failed_receipt(21000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert!(call.status_failed);
            assert_eq!("invalid opcode", call.failure_reason);
        });
}

#[test]
fn test_call_failure_pre_homestead_code_store_oog() {
    // Pre-Homestead quirk: ErrCodeStoreOutOfGas with reverted=false
    // In Frontier (pre-Homestead), code storage running out of gas was not treated
    // as a state revert - the call returns an error but reverted=false means no state rollback.
    // Since reverted=false, the Firehose model treats this as a successful call:
    // - StatusFailed: false (no state revert)
    // - StatusReverted: false (no revert)
    // - StateReverted: false (state is kept)
    // - FailureReason: empty (no failure from Firehose perspective)
    let err = std::io::Error::new(std::io::ErrorKind::Other, "code store out of gas");

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_create_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            53000,
            vec![0x60, 0x80],
        )
        // Contract deployment fails at EVM level but reverted=false means state is kept
        .end_call_failed(vec![], 0, &err, false)
        .end_block_trx(Some(success_receipt(53000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // In Firehose model, reverted=false means successful state transition
            assert!(!call.status_failed, "reverted=false means no state failure");
            assert!(!call.status_reverted, "reverted=false means no revert");
            assert!(
                !call.state_reverted,
                "State is NOT reverted in pre-Homestead"
            );
            assert_eq!(
                "", call.failure_reason,
                "No failure reason when reverted=false"
            );

            // Gas consumption
            assert_eq!(0, call.gas_consumed, "Code store OOG consumes no gas");
        });
}

#[test]
fn test_nested_multiple_siblings() {
    // Alice calls Bob, Bob calls Charlie and Miner (sibling calls)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            200000,
            vec![],
        )
        // First sibling: Bob calls Charlie
        .start_call(
            bob_addr(),
            charlie_addr(),
            alloy_primitives::U256::from(30),
            80000,
            vec![],
        )
        .end_call(vec![0x01], 75000)
        // Second sibling: Bob calls Miner
        .start_call(
            bob_addr(),
            miner_addr(),
            alloy_primitives::U256::from(20),
            80000,
            vec![],
        )
        .end_call(vec![0x02], 75000)
        .end_call(vec![0x03], 150000) // Bob returns
        .end_block_trx(Some(success_receipt(200000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(
                3,
                trx.calls.len(),
                "Should have 3 calls (root + 2 siblings)"
            );

            let first_sibling = &trx.calls[1];
            let second_sibling = &trx.calls[2];

            // Both siblings should have same parent (root=1) and same depth
            assert_eq!(1, first_sibling.parent_index);
            assert_eq!(1, second_sibling.parent_index);
            assert_eq!(1, first_sibling.depth);
            assert_eq!(1, second_sibling.depth);

            // Verify addresses
            assert_eq!(charlie_addr().as_slice(), first_sibling.address.as_slice());
            assert_eq!(miner_addr().as_slice(), second_sibling.address.as_slice());
        });
}

// =============================================================================
// Call Data And Gas Tests
// =============================================================================

#[test]
fn test_call_with_large_input() {
    let mut large_input = vec![0u8; 1024];
    for (i, byte) in large_input.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            50000,
            large_input.clone(),
        )
        .end_call(vec![0x01], 45000)
        .end_block_trx(Some(success_receipt(50000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(&large_input, &call.input);
            assert_eq!(50000, call.gas_limit);
            assert_eq!(45000, call.gas_consumed);
        });
}

#[test]
fn test_call_with_large_output() {
    let mut large_output = vec![0u8; 2048];
    for (i, byte) in large_output.iter_mut().enumerate() {
        *byte = ((i * 3) % 256) as u8;
    }

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
        .end_call(large_output.clone(), 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(&large_output, &call.return_data);
        });
}

#[test]
fn test_call_with_zero_value() {
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            21000,
            vec![],
        )
        .end_call(vec![], 20000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Zero value is represented as nil in protobuf
            assert!(call.value.is_none(), "Zero value should be None");
        });
}

#[test]
fn test_call_gas_fully_consumed() {
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
        .end_call(vec![], 21000) // All gas consumed
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                call.gas_limit, call.gas_consumed,
                "All gas should be consumed"
            );
        });
}

// ============================================================================

// ============================================================================
// TestTracer_MixedCallTypes - Test combinations of different call types
// ============================================================================

#[test]
fn test_call_then_staticcall() {
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 100000, vec![])
        .start_static_call(bob_addr(), charlie_addr(), 50000, vec![])
        .end_call(vec![0x01], 45000)
        .end_call(vec![0x02], 90000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(2, trx.calls.len());

            assert_eq!(pbeth::CallType::Call as i32, trx.calls[0].call_type);
            assert_eq!(pbeth::CallType::Static as i32, trx.calls[1].call_type);
        });
}

#[test]
fn test_call_then_delegatecall() {
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 100000, vec![])
        .start_delegate_call(bob_addr(), charlie_addr(), big_int(0), 50000, vec![])
        .end_call(vec![0x01], 45000)
        .end_call(vec![0x02], 90000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(2, trx.calls.len());

            assert_eq!(pbeth::CallType::Call as i32, trx.calls[0].call_type);
            assert_eq!(pbeth::CallType::Delegate as i32, trx.calls[1].call_type);
        });
}

#[test]
fn test_create_then_call() {
    let contract_code = vec![0x60, 0x80];
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_create_call(
            alice_addr(),
            bob_addr(),
            big_int(0),
            100000,
            contract_code.clone(),
        )
        // New contract makes a call to Charlie
        .start_call(bob_addr(), charlie_addr(), big_int(0), 50000, vec![])
        .end_call(vec![0x01], 45000)
        .end_call(contract_code.clone(), 90000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(2, trx.calls.len());

            assert_eq!(pbeth::CallType::Create as i32, trx.calls[0].call_type);
            assert_eq!(pbeth::CallType::Call as i32, trx.calls[1].call_type);
        });
}

// ============================================================================
// TestTracer_WrappedErrors - Test error chain walking
// ============================================================================

#[test]
fn test_wrapped_execution_reverted() {
    // Create a wrapped error chain: "custom context" -> ExecutionReverted
    let inner_err = ExecutionRevertedError;
    let err = WrappedError {
        message: format!("custom context: {}", ERR_EXECUTION_REVERTED),
        source: Box::new(inner_err),
    };

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call_failed(vec![], 5000, &err, true)
        .end_block_trx(Some(failed_receipt(21000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert!(call.status_failed, "Call should be marked as failed");
            assert!(
                call.status_reverted,
                "Call should be marked as reverted even with wrapped error"
            );
            assert_eq!("custom context: execution reverted", call.failure_reason);
        });
}

#[test]
fn test_wrapped_insufficient_balance() {
    // Test wrapped insufficient balance error
    let inner_err = InsufficientBalanceError;
    let err = WrappedError {
        message: format!("transfer failed: {}", ERR_INSUFFICIENT_BALANCE_TRANSFER),
        source: Box::new(inner_err),
    };

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call_failed(vec![], 0, &err, true)
        .end_block_trx(Some(failed_receipt(21000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert!(call.status_failed);
            assert!(
                call.status_reverted,
                "Insufficient balance should be reverted"
            );
            assert_eq!(
                "transfer failed: insufficient balance for transfer",
                call.failure_reason
            );
        });
}

#[test]
fn test_double_wrapped_error() {
    // Double-wrapped error chain
    let base_err = MaxCallDepthError;
    let layer1_err = WrappedError {
        message: format!("context layer 1: {}", ERR_MAX_CALL_DEPTH),
        source: Box::new(base_err),
    };
    let layer2_err = WrappedError {
        message: format!("context layer 2: context layer 1: {}", ERR_MAX_CALL_DEPTH),
        source: Box::new(layer1_err),
    };

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call_failed(vec![], 0, &layer2_err, true)
        .end_block_trx(Some(failed_receipt(21000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert!(call.status_failed);
            assert!(
                call.status_reverted,
                "Should find revert error through multiple wrapping layers"
            );
            assert_eq!(
                "context layer 2: context layer 1: max call depth exceeded",
                call.failure_reason
            );
        });
}

// ============================================================================
// TestTracer_Precompiles - Test calls to precompiled contracts
// ============================================================================

// Precompile addresses (from go-ethereum params/protocol_params.go)
const ECRECOVER_ADDR: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];
const SHA256_ADDR: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
];
const RIPEMD160_ADDR: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03,
];
const BN256_ADD_ADDR: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x06,
];
const BN256_SCALAR_MUL_ADDR: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07,
];

#[test]
fn test_ecrecover_precompile_success() {
    use alloy_primitives::Address;
    // Valid ecrecover input data
    let input = vec![0u8; 128];
    let output = vec![0u8; 32]; // ecrecover returns 32 bytes (address)
    let ecrecover_addr = Address::from(ECRECOVER_ADDR);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 50000, vec![])
        // Contract calls ecrecover precompile
        .start_static_call(bob_addr(), ecrecover_addr, 5000, input.clone())
        .end_call(output.clone(), 4500)
        .end_call(vec![], 45000)
        .end_block_trx(Some(success_receipt(50000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(2, trx.calls.len());

            let precompile_call = &trx.calls[1];
            assert_eq!(pbeth::CallType::Static as i32, precompile_call.call_type);
            assert_eq!(&ECRECOVER_ADDR[..], &precompile_call.address[..]);
            assert!(!precompile_call.status_failed);
            assert_eq!(128, precompile_call.input.len());
            assert_eq!(&output[..], &precompile_call.return_data[..]);
        });
}

#[test]
fn test_sha256_precompile_success() {
    use alloy_primitives::Address;
    let input = b"test data for sha256".to_vec();
    let output = vec![0u8; 32]; // sha256 returns 32 bytes
    let sha256_addr = Address::from(SHA256_ADDR);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 50000, vec![])
        .start_static_call(bob_addr(), sha256_addr, 5000, input.clone())
        .end_call(output.clone(), 4800)
        .end_call(vec![], 45000)
        .end_block_trx(Some(success_receipt(50000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let precompile_call = &trx.calls[1];
            assert_eq!(&SHA256_ADDR[..], &precompile_call.address[..]);
            assert!(!precompile_call.status_failed);
        });
}

#[test]
fn test_ripemd160_precompile_success() {
    use alloy_primitives::Address;
    let input = b"test".to_vec();
    let output = vec![0u8; 32]; // ripemd160 returns 32 bytes (20 byte hash right-padded)
    let ripemd160_addr = Address::from(RIPEMD160_ADDR);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 50000, vec![])
        .start_static_call(bob_addr(), ripemd160_addr, 5000, input.clone())
        .end_call(output.clone(), 4900)
        .end_call(vec![], 45000)
        .end_block_trx(Some(success_receipt(50000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let precompile_call = &trx.calls[1];
            assert_eq!(&RIPEMD160_ADDR[..], &precompile_call.address[..]);
            assert!(!precompile_call.status_failed);
        });
}

#[test]
fn test_bn256_add_precompile_success() {
    use alloy_primitives::Address;
    // bn256Add takes 128 bytes (4 * 32-byte values)
    let input = vec![0u8; 128];
    let output = vec![0u8; 64]; // Returns 2 * 32-byte values
    let bn256_add_addr = Address::from(BN256_ADD_ADDR);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 50000, vec![])
        .start_static_call(bob_addr(), bn256_add_addr, 10000, input.clone())
        .end_call(output.clone(), 9500)
        .end_call(vec![], 40000)
        .end_block_trx(Some(success_receipt(50000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let precompile_call = &trx.calls[1];
            assert_eq!(&BN256_ADD_ADDR[..], &precompile_call.address[..]);
            assert!(!precompile_call.status_failed);
        });
}

#[test]
fn test_bn256_scalar_mul_precompile_success() {
    use alloy_primitives::Address;
    // bn256ScalarMul takes 96 bytes
    let input = vec![0u8; 96];
    let output = vec![0u8; 64];
    let bn256_scalar_mul_addr = Address::from(BN256_SCALAR_MUL_ADDR);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 50000, vec![])
        .start_static_call(bob_addr(), bn256_scalar_mul_addr, 10000, input.clone())
        .end_call(output.clone(), 9000)
        .end_call(vec![], 40000)
        .end_block_trx(Some(success_receipt(50000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let precompile_call = &trx.calls[1];
            assert_eq!(&BN256_SCALAR_MUL_ADDR[..], &precompile_call.address[..]);
            assert!(!precompile_call.status_failed);
        });
}

#[test]
fn test_bn256_scalar_mul_precompile_failure() {
    use alloy_primitives::Address;
    // Invalid input causes precompile to fail
    let invalid_input = vec![0x12, 0x34, 0x56]; // Wrong size
    let err = std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid input");
    let bn256_scalar_mul_addr = Address::from(BN256_SCALAR_MUL_ADDR);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 50000, vec![])
        .start_static_call(
            bob_addr(),
            bn256_scalar_mul_addr,
            10000,
            invalid_input.clone(),
        )
        .end_call_failed(vec![], 0, &err, true)
        .end_call(vec![], 40000)
        .end_block_trx(Some(success_receipt(50000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let precompile_call = &trx.calls[1];
            assert_eq!(&BN256_SCALAR_MUL_ADDR[..], &precompile_call.address[..]);
            assert!(
                precompile_call.status_failed,
                "Precompile should fail with invalid input"
            );
            assert_eq!(
                0, precompile_call.gas_consumed,
                "Failed precompile consumes no gas"
            );
        });
}

#[test]
fn test_multiple_precompiles_in_transaction() {
    use alloy_primitives::Address;
    // Transaction calls multiple precompiles
    let sha256_input = b"test".to_vec();
    let sha256_output = vec![0u8; 32];
    let ecrecover_input = vec![0u8; 128];
    let ecrecover_output = vec![0u8; 32];
    let sha256_addr = Address::from(SHA256_ADDR);
    let ecrecover_addr = Address::from(ECRECOVER_ADDR);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 80000, vec![])
        // First precompile: sha256
        .start_static_call(bob_addr(), sha256_addr, 5000, sha256_input.clone())
        .end_call(sha256_output.clone(), 4800)
        // Second precompile: ecrecover
        .start_static_call(bob_addr(), ecrecover_addr, 5000, ecrecover_input.clone())
        .end_call(ecrecover_output.clone(), 4500)
        .end_call(vec![], 70000)
        .end_block_trx(Some(success_receipt(80000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(3, trx.calls.len(), "Root call + 2 precompile calls");

            assert_eq!(&SHA256_ADDR[..], &trx.calls[1].address[..]);
            assert_eq!(&ECRECOVER_ADDR[..], &trx.calls[2].address[..]);
            assert!(!trx.calls[1].status_failed);
            assert!(!trx.calls[2].status_failed);
        });
}

#[test]
fn test_nested_precompile_calls() {
    use alloy_primitives::Address;
    // Root call -> Contract call -> Precompile call
    let input = b"nested test".to_vec();
    let output = vec![0u8; 32];
    let sha256_addr = Address::from(SHA256_ADDR);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 80000, vec![])
        // Bob calls Charlie
        .start_call(bob_addr(), charlie_addr(), big_int(0), 40000, vec![])
        // Charlie calls sha256 precompile
        .start_static_call(charlie_addr(), sha256_addr, 5000, input.clone())
        .end_call(output.clone(), 4800)
        .end_call(vec![0x01], 35000)
        .end_call(vec![], 45000)
        .end_block_trx(Some(success_receipt(80000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(3, trx.calls.len());

            let precompile_call = &trx.calls[2];
            assert_eq!(&SHA256_ADDR[..], &precompile_call.address[..]);
            assert_eq!(
                2, precompile_call.parent_index,
                "Precompile's parent is Charlie (index 2)"
            );
            assert!(!precompile_call.status_failed);
        });
}

// ============================================================================
// TestTracer_CREATE2EdgeCases - Test CREATE2-specific edge cases
// ============================================================================

#[test]
fn test_create2_collision_address_already_exists() {
    // Simulate CREATE2 collision: trying to deploy to an address that already has code
    let contract_addr = charlie_addr();
    let contract_code = vec![0x60, 0x80];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 200000, vec![])
        // First CREATE2 succeeds
        .start_create2_call(
            bob_addr(),
            contract_addr,
            big_int(0),
            100000,
            contract_code.clone(),
        )
        .end_call(contract_code.clone(), 95000)
        // Second CREATE2 to same address fails
        .start_create2_call(
            bob_addr(),
            contract_addr,
            big_int(0),
            50000,
            contract_code.clone(),
        )
        .end_call_failed(vec![], 0, &ExecutionRevertedError, true)
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(200000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(3, trx.calls.len(), "Root + 2 CREATE2 calls");

            // First CREATE2 succeeds
            assert!(!trx.calls[1].status_failed);
            assert_eq!(pbeth::CallType::Create as i32, trx.calls[1].call_type);

            // Second CREATE2 fails due to collision
            assert!(trx.calls[2].status_failed);
            assert_eq!(pbeth::CallType::Create as i32, trx.calls[2].call_type);
            assert_eq!(contract_addr.as_slice(), trx.calls[2].address.as_slice());
        });
}

#[test]
fn test_create2_with_insufficient_funds() {
    // CREATE2 fails because contract doesn't have enough balance to transfer
    let contract_addr = charlie_addr();
    let large_value = must_big_int("1000000000000000000000"); // 1000 ETH
    let contract_code = vec![0x60, 0x80];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![])
        // CREATE2 with value larger than available balance
        .start_create2_call(
            bob_addr(),
            contract_addr,
            large_value,
            50000,
            contract_code.clone(),
        )
        .end_call_failed(vec![], 0, &InsufficientBalanceError, true)
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let create2_call = &trx.calls[1];

            assert!(create2_call.status_failed);
            assert!(
                create2_call.status_reverted,
                "Insufficient balance should be reverted"
            );
        });
}

// ============================================================================
// TestTracer_ConstructorEdgeCases - Test constructor-related edge cases
// ============================================================================

#[test]
fn test_constructor_with_storage_and_logs() {
    // Constructor performs state changes
    let contract_addr = charlie_addr();
    let code = vec![0x60, 0x80, 0x60, 0x40, 0x52];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![])
        .start_create_call(bob_addr(), contract_addr, big_int(0), 80000, code.clone())
        // Constructor changes storage
        .storage_change(contract_addr, hash32(1), hash32(0), hash32(100))
        // Constructor emits log
        .log(contract_addr, vec![hash32(1)], vec![0xaa, 0xbb], 0)
        .end_call(code.clone(), 70000)
        .end_call(vec![], 30000)
        .end_block_trx(
            Some(receipt_with_logs(
                100000,
                vec![log1(contract_addr, hash32(1), vec![0xaa, 0xbb])],
            )),
            None,
            None,
        )
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let create_call = &trx.calls[1];

            assert!(!create_call.status_failed);
            assert_eq!(1, create_call.storage_changes.len());
            assert_eq!(1, create_call.logs.len());
        });
}

#[test]
fn test_constructor_fails_reverts_state_changes() {
    // Constructor that fails should revert its state changes
    let contract_addr = charlie_addr();
    let code = vec![0x60, 0x80];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![])
        .start_create_call(bob_addr(), contract_addr, big_int(0), 80000, code.clone())
        // Constructor tries to change storage (will be reverted)
        .storage_change(contract_addr, hash32(1), hash32(0), hash32(100))
        // Constructor fails
        .end_call_failed(vec![], 0, &ExecutionRevertedError, true)
        .end_call(vec![], 20000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let create_call = &trx.calls[1];

            assert!(create_call.status_failed);
            assert!(create_call.status_reverted);
            // Storage changes exist in call but should be marked as reverted
            assert_eq!(1, create_call.storage_changes.len());
        });
}

#[test]
fn test_recursive_constructor_failure() {
    // Constructor creates another contract, which fails
    let first_contract_addr = charlie_addr();
    let second_contract_addr = addr_from_hex("0x0000000000000000000000000000000000000abc");
    let code = vec![0x60, 0x80];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 200000, vec![])
        // First CREATE
        .start_create_call(
            bob_addr(),
            first_contract_addr,
            big_int(0),
            150000,
            code.clone(),
        )
        // First constructor creates second contract
        .start_create_call(
            first_contract_addr,
            second_contract_addr,
            big_int(0),
            80000,
            code.clone(),
        )
        // Second constructor fails
        .end_call_failed(vec![], 0, &ExecutionRevertedError, true)
        // First constructor also fails due to nested failure
        .end_call_failed(vec![], 0, &ExecutionRevertedError, true)
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(200000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(3, trx.calls.len(), "Root + 2 CREATE calls");

            // Both CREATEs should fail
            assert!(trx.calls[1].status_failed, "First CREATE should fail");
            assert!(trx.calls[2].status_failed, "Second CREATE should fail");
            assert_eq!(
                2, trx.calls[2].parent_index,
                "Second CREATE's parent is first CREATE"
            );
        });
}

#[test]
fn test_constructor_out_of_gas() {
    // Constructor runs out of gas during execution
    let contract_addr = charlie_addr();
    let code = vec![0x60, 0x80];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![])
        .start_create_call(bob_addr(), contract_addr, big_int(0), 50000, code.clone())
        // Constructor runs out of gas
        .end_call_failed(vec![], 0, &OutOfGasError, true)
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("nestedcalls", |block| {
            let trx = &block.transaction_traces[0];
            let create_call = &trx.calls[1];

            assert!(create_call.status_failed);
            assert!(!create_call.status_reverted, "Out of gas is not reverted");
            assert_eq!(0, create_call.gas_consumed);
        });
}
