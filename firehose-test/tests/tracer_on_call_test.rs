use firehose::{Opcode, StringError};
use firehose_test::{
    alice_addr, bob_addr, charlie_addr, success_receipt, test_legacy_trx, TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

// on_call defers the exit until the next epth call arrives
#[test]
fn test_on_call_single_call_closed_at_tx_end() {
    // A single deferred call frame is closed when the transaction ends
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), alloy_primitives::U256::ZERO, 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("on_call", |block| {
            let trx = &block.transaction_traces[0];
            assert_eq!(1, trx.calls.len(), "single call should be recorded");
            assert_eq!(bob_addr().as_slice(), trx.calls[0].address.as_slice());
        });
}

#[test]
fn test_on_call_nested_calls_closed_in_order() {
    // Sub-call must close before its parent; ordinals must reflect this
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), alloy_primitives::U256::ZERO, 100_000, vec![])
        .start_call(bob_addr(), charlie_addr(), alloy_primitives::U256::ZERO, 50_000, vec![])
        .end_call(vec![], 10_000)
        .end_call(vec![], 50_000)
        .end_block_trx(Some(success_receipt(100_000)), None, None)
        .validate_with_category("on_call", |block| {
            let calls = &block.transaction_traces[0].calls;
            assert_eq!(2, calls.len());
            assert_eq!(0, calls[0].depth, "root at depth 0");
            assert_eq!(1, calls[1].depth, "sub-call at depth 1");
            assert!(
                calls[0].begin_ordinal < calls[1].begin_ordinal,
                "root must open before sub-call"
            );
            assert!(
                calls[1].end_ordinal < calls[0].end_ordinal,
                "sub-call must close before root"
            );
        });
}

#[test]
fn test_flush_open_calls_depth_1_keeps_root_open() {
    // flush(1) closes sub-calls but keeps root open — state changes after
    // flush still attach to the root call
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), alloy_primitives::U256::ZERO, 100_000, vec![])
        .start_call(bob_addr(), charlie_addr(), alloy_primitives::U256::ZERO, 50_000, vec![])
        .end_call(vec![], 10_000) // depth-1 closed (simulates flush(1))
        // balance change after sub-call closes but root still open
        .balance_change(
            bob_addr(),
            alloy_primitives::U256::from(100),
            alloy_primitives::U256::from(200),
            pbeth::balance_change::Reason::GasRefund,
        )
        .end_call(vec![], 50_000) // depth-0 closed
        .end_block_trx(Some(success_receipt(100_000)), None, None)
        .validate_with_category("on_call", |block| {
            let calls = &block.transaction_traces[0].calls;
            assert_eq!(2, calls.len());
            assert_eq!(1, calls[0].balance_changes.len(), "root call should have the balance change");
            assert_eq!(0, calls[1].balance_changes.len(), "sub-call should have no balance change");
        });
}

#[test]
fn test_on_call_create_emits_code_change_on_close() {
    // on_call with a successful CREATE must emit a code change when flushed
    let contract_code = vec![0x60, 0x80, 0x60, 0x40];
    let mut tester = TracerTester::new();
    tester.start_block_trx(test_legacy_trx());
    tester.tracer.on_call(
        0,
        Opcode::Create as u8,
        alice_addr(),
        bob_addr(),
        &[],
        53_000,
        alloy_primitives::U256::ZERO,
        &contract_code,
        50_000,
        true,
        None,
    );
    tester.tracer.flush_open_calls(0);
    tester
        .end_block_trx(Some(success_receipt(53_000)), None, None)
        .validate_with_category("on_call", |block| {
            let call = &block.transaction_traces[0].calls[0];
            assert_eq!(pbeth::CallType::Create as i32, call.call_type);
            assert_eq!(1, call.code_changes.len(), "CREATE should emit a code change");
            let cc = &call.code_changes[0];
            assert_eq!(bob_addr().as_slice(), cc.address.as_slice());
            assert!(cc.old_code.is_empty(), "old code should be empty before deployment");
            assert_eq!(contract_code, cc.new_code, "new code should be deployed bytecode");
        });
}

#[test]
fn test_on_call_failed_create_no_code_change() {
    // on_call with a failed CREATE must NOT emit a code change
    let mut tester = TracerTester::new();
    tester.start_block_trx(test_legacy_trx());
    tester.tracer.on_call(
        0,
        Opcode::Create as u8,
        alice_addr(),
        bob_addr(),
        &[],
        53_000,
        alloy_primitives::U256::ZERO,
        &[],
        53_000,
        true,
        Some(StringError("execution reverted".to_string())),
    );
    tester.tracer.flush_open_calls(0);
    tester
        .end_block_trx(Some(success_receipt(53_000)), None, None)
        .validate_with_category("on_call", |block| {
            let call = &block.transaction_traces[0].calls[0];
            assert_eq!(0, call.code_changes.len(), "failed CREATE must not emit a code change");
        });
}
