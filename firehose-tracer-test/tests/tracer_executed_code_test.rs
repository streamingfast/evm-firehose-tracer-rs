use firehose_tracer::pb::sf::ethereum::r#type::v2 as pbeth;
use firehose_tracer::types::Opcode;
use firehose_tracer_test::{
    alice_addr, bob_addr, charlie_addr, success_receipt, test_legacy_trx, TracerTester,
};

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

#[test]
fn test_call_no_opcodes_executed_code_false() {
    // ExecutedCode = false when a call completes with no opcodes (e.g. plain value transfer)
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
        // no opcode fired
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("executedcode", |block| {
            let call = &block.transaction_traces[0].calls[0];
            assert!(
                !call.executed_code,
                "ExecutedCode should be false when no opcodes execute"
            );
        });
}

#[test]
fn test_on_call_executed_code_false() {
    // ExecutedCode = false when the call was recorded via on_call (no per-opcode visibility)
    // e.g. Monad pre-aggregated call frame events. Target must be marked as existing in
    // the mock state — otherwise the EIP-158 spurious-dragon branch of
    // `compute_executed_code_at_call_start` fires (CALL to non-existent target with
    // non-empty input + zero value → `executed_code = true`, matching geth-firehose).
    let mut tester = TracerTester::new();
    tester.set_mock_state_exist(bob_addr(), true);
    tester.start_block_trx(test_legacy_trx());
    tester.tracer.on_call(
        0,
        Opcode::Call as u8,
        alice_addr(),
        bob_addr(),
        &[0x01],
        21000,
        alloy_primitives::U256::ZERO,
        vec![],
        21000,
        None,
        true,
    );
    tester
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("executedcode", |block| {
            let call = &block.transaction_traces[0].calls[0];
            assert!(
                !call.executed_code,
                "ExecutedCode should be false when recorded via on_call (no opcode visibility)"
            );
        });
}

// =============================================================================
// `compute_executed_code_at_call_start` regression tests
// =============================================================================
// These pin the geth-firehose `getExecutedCode` mirror added to `on_call_enter`.
// Without this initialization, calls whose interpreter loop is bypassed by revm
// (empty bytecode, precompile, EIP-158 spurious dragon target) never set
// `executed_code` because `step` never fires — visible bug in production for
// EIP-7702 calls whose delegate address holds no code.

#[test]
fn test_call_to_nonexistent_target_executed_code_true_eip158() {
    // Geth `getExecutedCode` line 1336-1341: CALL to a non-existent target with zero
    // value on EIP-158-active chains sets `executed_code = len(input) > 0` at
    // call-start. revm's `make_call_frame` short-circuits (empty bytecode → Stop)
    // and `step` never fires, so this initialization is the only source of truth.
    let mut tester = TracerTester::new();
    // bob deliberately NOT marked as existing (default false) — this is the case
    // that triggers the EIP-158 branch.
    tester.start_block_trx(test_legacy_trx());
    tester.tracer.on_call(
        0,
        Opcode::Call as u8,
        alice_addr(),
        bob_addr(),
        &[0x2c, 0x7b, 0xdd, 0xf4], // 4-byte selector — non-empty input
        21000,
        alloy_primitives::U256::ZERO, // zero value (required for EIP-158 branch)
        vec![],
        21000,
        None,
        true,
    );
    tester
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("executedcode", |block| {
            let call = &block.transaction_traces[0].calls[0];
            assert!(
                call.executed_code,
                "EIP-158 spurious-dragon CALL with non-empty input must have executed_code=true"
            );
        });
}

#[test]
fn test_call_to_nonexistent_target_with_empty_input_executed_code_false() {
    // Negative control for the EIP-158 branch: when input is empty, geth's
    // `len(input) > 0` returns false. revm's interpreter is still bypassed (empty
    // bytecode), so executed_code stays false.
    let mut tester = TracerTester::new();
    tester.start_block_trx(test_legacy_trx());
    tester.tracer.on_call(
        0,
        Opcode::Call as u8,
        alice_addr(),
        bob_addr(),
        &[], // empty input
        21000,
        alloy_primitives::U256::ZERO,
        vec![],
        21000,
        None,
        true,
    );
    tester
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("executedcode", |block| {
            let call = &block.transaction_traces[0].calls[0];
            assert!(
                !call.executed_code,
                "EIP-158 spurious-dragon CALL with empty input must have executed_code=false"
            );
        });
}

#[test]
fn test_call_to_nonexistent_target_with_value_executed_code_false() {
    // Negative control for the EIP-158 branch: non-zero value disqualifies (geth's
    // condition `call.Value.Sign() == 0` blocks the branch). Plain CALL → defers to
    // opcode → no opcode → false.
    let mut tester = TracerTester::new();
    tester.start_block_trx(test_legacy_trx());
    tester.tracer.on_call(
        0,
        Opcode::Call as u8,
        alice_addr(),
        bob_addr(),
        &[0x01],
        21000,
        alloy_primitives::U256::from(1_u64), // non-zero value disables EIP-158 branch
        vec![],
        21000,
        None,
        true,
    );
    tester
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("executedcode", |block| {
            let call = &block.transaction_traces[0].calls[0];
            assert!(
                !call.executed_code,
                "CALL with value (even to non-existent target) skips EIP-158 branch → executed_code=false"
            );
        });
}

#[test]
fn test_staticcall_no_opcode_executed_code_true() {
    // Branch 4/5: non-CALL types get `executed_code = len(input) > 0` at call-start
    // regardless of whether opcodes execute. Catches the bug where STATICCALL/
    // DELEGATECALL/CALLCODE to an empty-bytecode target would have stayed false.
    let mut tester = TracerTester::new();
    tester.set_mock_state_exist(charlie_addr(), true);
    tester.set_mock_state_exist(bob_addr(), true);
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            charlie_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![0x01],
        )
        .opcode(0, 0x60, 100000, 3) // outer call runs an opcode
        .start_static_call(charlie_addr(), bob_addr(), 50000, vec![0x02])
        // INTENTIONALLY no opcode in the inner staticcall — simulates empty-bytecode
        // target where revm bypasses inspect_instructions
        .end_call(vec![], 49000)
        .end_call(vec![], 99000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("executedcode", |block| {
            let static_call = &block.transaction_traces[0].calls[1];
            assert_eq!(pbeth::CallType::Static as i32, static_call.call_type);
            assert!(
                static_call.executed_code,
                "STATICCALL with non-empty input must have executed_code=true even when interpreter is bypassed"
            );
        });
}

#[test]
fn test_create_no_opcode_executed_code_false() {
    // Branch 4: CREATE is forced false at call-start by `getExecutedCode` and only
    // becomes true if the constructor runs at least one opcode. Pin this so a future
    // refactor doesn't accidentally lump CREATE into the `len(input) > 0` default.
    let mut tester = TracerTester::new();
    tester.set_mock_state_exist(bob_addr(), true);
    tester
        .start_block_trx(test_legacy_trx())
        .start_create_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            53000,
            vec![0x60, 0x80], // non-empty constructor input
        )
        // INTENTIONALLY no opcode — simulates a CREATE that fails before any
        // constructor bytecode runs (e.g. address collision, depth limit pre-check)
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(53000)), None, None)
        .validate_with_category("executedcode", |block| {
            let call = &block.transaction_traces[0].calls[0];
            assert_eq!(pbeth::CallType::Create as i32, call.call_type);
            assert!(
                !call.executed_code,
                "CREATE with no opcode execution must have executed_code=false (forced false at call-start)"
            );
        });
}
