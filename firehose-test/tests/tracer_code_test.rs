use firehose_test::{
    alice_addr, bob_addr, charlie_addr, hash32, success_receipt, test_legacy_trx, TracerTester,
};

#[test]
fn test_code_change_with_active_call() {
    // Normal code deployment during active call (CREATE/CREATE2)
    let code = vec![0x60, 0x80, 0x60, 0x40]; // Simple bytecode
    let code_hash = hash32(123);
    let prev_hash = alloy_primitives::B256::ZERO; // Empty for new deployment

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
        .code_change(bob_addr(), prev_hash, code_hash, vec![], code.clone())
        .end_call(vec![], 90000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("oncodechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.code_changes.len(), "Should have 1 code change");
            let cc = &call.code_changes[0];
            assert_eq!(bob_addr().as_slice(), cc.address.as_slice());
            assert_eq!(prev_hash.as_slice(), cc.old_hash.as_slice());
            assert_eq!(code_hash.as_slice(), cc.new_hash.as_slice());
            assert_eq!(code, cc.new_code);
        });
}

#[test]
fn test_code_change_deferred_state_eip7702() {
    // EIP-7702: Code change before call stack initialization
    // This happens when SetCode transaction sets delegation
    let code = vec![0xef, 0x01, 0x00]; // EIP-7702 delegation bytecode
    let code_hash = hash32(456);
    let prev_hash = alloy_primitives::B256::ZERO;

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // Code change BEFORE call starts (EIP-7702 authorization)
        .code_change(alice_addr(), prev_hash, code_hash, vec![], code.clone())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("oncodechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Deferred code change should be applied to root call
            assert_eq!(1, call.code_changes.len(), "Should have 1 code change");
            let cc = &call.code_changes[0];
            assert_eq!(alice_addr().as_slice(), cc.address.as_slice());
            assert_eq!(code, cc.new_code);
        });
}

#[test]
fn test_code_change_block_level() {
    // Block-level code change (no transaction context)
    let code = vec![0x60, 0x01];
    let code_hash = hash32(789);
    let prev_hash = alloy_primitives::B256::ZERO;

    let mut tester = TracerTester::new();
    tester
        .start_block()
        .code_change(charlie_addr(), prev_hash, code_hash, vec![], code.clone())
        .end_block(None)
        .validate_with_category("oncodechange", |block| {
            // Block-level code changes
            assert_eq!(
                1,
                block.code_changes.len(),
                "Should have 1 block-level code change"
            );
            let cc = &block.code_changes[0];
            assert_eq!(charlie_addr().as_slice(), cc.address.as_slice());
            assert_eq!(prev_hash.as_slice(), cc.old_hash.as_slice());
            assert_eq!(code_hash.as_slice(), cc.new_hash.as_slice());
            assert_eq!(code, cc.new_code);
        });
}

#[test]
fn test_code_change_with_previous_code() {
    // Code change replacing existing code (upgrade scenario)
    let old_code = vec![0x60, 0x01];
    let new_code = vec![0x60, 0x02];
    let old_hash = hash32(111);
    let new_hash = hash32(222);

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
        .code_change(
            bob_addr(),
            old_hash,
            new_hash,
            old_code.clone(),
            new_code.clone(),
        )
        .end_call(vec![], 90000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("oncodechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.code_changes.len(), "Should have 1 code change");
            let cc = &call.code_changes[0];
            assert_eq!(bob_addr().as_slice(), cc.address.as_slice());
            assert_eq!(old_hash.as_slice(), cc.old_hash.as_slice());
            assert_eq!(new_hash.as_slice(), cc.new_hash.as_slice());
            assert_eq!(old_code, cc.old_code);
            assert_eq!(new_code, cc.new_code);
        });
}
