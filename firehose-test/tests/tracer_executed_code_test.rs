use firehose_test::{
    alice_addr, bob_addr, charlie_addr, success_receipt, test_legacy_trx, TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

// =============================================================================
// ExecutedCode Tests
// =============================================================================
// ExecutedCode is set to true when calls are made and opcodes execute

#[test]
fn test_call_executed_code_true() {
    // ExecutedCode = true for CALL when opcode executes
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![0x01, 0x02],
        )
        .opcode(0, 0x60, 21000, 3) // Execute a PUSH opcode
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("executedcode", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(pbeth::CallType::Call as i32, call.call_type);
            assert!(
                call.executed_code,
                "ExecutedCode should be true when opcodes execute"
            );
        });
}

#[test]
fn test_staticcall_executed_code_true() {
    // ExecutedCode = true for STATICCALL
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            charlie_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![0x01],
        )
        .opcode(0, 0x60, 100000, 3)
        .start_static_call(charlie_addr(), bob_addr(), 50000, vec![0x02])
        .opcode(0, 0x60, 50000, 3)
        .end_call(vec![], 45000)
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("executedcode", |block| {
            let trx = &block.transaction_traces[0];
            let static_call = &trx.calls[1];

            assert_eq!(pbeth::CallType::Static as i32, static_call.call_type);
            assert!(
                static_call.executed_code,
                "ExecutedCode should be true for STATICCALL"
            );
        });
}

#[test]
fn test_delegatecall_executed_code_true() {
    // ExecutedCode = true for DELEGATECALL
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            charlie_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![0x01],
        )
        .opcode(0, 0x60, 100000, 3)
        .start_delegate_call(
            charlie_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            50000,
            vec![0x02],
        )
        .opcode(0, 0x60, 50000, 3)
        .end_call(vec![], 45000)
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("executedcode", |block| {
            let trx = &block.transaction_traces[0];
            let delegate_call = &trx.calls[1];

            assert_eq!(pbeth::CallType::Delegate as i32, delegate_call.call_type);
            assert!(
                delegate_call.executed_code,
                "ExecutedCode should be true for DELEGATECALL"
            );
        });
}

#[test]
fn test_create_executed_code_true() {
    // ExecutedCode = true for CREATE
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
        .opcode(0, 0x60, 53000, 3)
        .end_call(contract_code, 50000)
        .end_block_trx(Some(success_receipt(53000)), None, None)
        .validate_with_category("executedcode", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(pbeth::CallType::Create as i32, call.call_type);
            assert!(call.executed_code, "ExecutedCode should be true for CREATE");
        });
}
