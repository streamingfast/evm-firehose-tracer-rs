use firehose_test::{alice_addr, bob_addr, success_receipt, test_legacy_trx, TracerTester};

#[test]
fn test_nonce_change_with_active_call() {
    // Nonce change during active call execution
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
        .nonce_change(alice_addr(), 5, 6)
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("onnoncechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.nonce_changes.len(), "Should have 1 nonce change");
            let nc = &call.nonce_changes[0];
            assert_eq!(alice_addr().as_slice(), nc.address.as_slice());
            assert_eq!(5, nc.old_value);
            assert_eq!(6, nc.new_value);
        });
}

#[test]
fn test_nonce_change_deferred_state() {
    // Nonce change before call stack initialization (deferred)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // Nonce change BEFORE call starts
        .nonce_change(alice_addr(), 5, 6)
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("onnoncechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Deferred nonce change should be applied to root call
            assert_eq!(1, call.nonce_changes.len(), "Should have 1 nonce change");
            let nc = &call.nonce_changes[0];
            assert_eq!(alice_addr().as_slice(), nc.address.as_slice());
            assert_eq!(5, nc.old_value);
            assert_eq!(6, nc.new_value);
        });
}

#[test]
fn test_multiple_nonce_changes_in_call() {
    // Multiple nonce changes in same call (unusual but possible)
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
        .nonce_change(alice_addr(), 5, 6)
        .nonce_change(bob_addr(), 10, 11)
        .nonce_change(alice_addr(), 6, 7)
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("onnoncechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(3, call.nonce_changes.len(), "Should have 3 nonce changes");

            // Verify ordering (ordinals should be increasing)
            assert!(
                call.nonce_changes[0].ordinal < call.nonce_changes[1].ordinal,
                "First nonce change ordinal should be less than second"
            );
            assert!(
                call.nonce_changes[1].ordinal < call.nonce_changes[2].ordinal,
                "Second nonce change ordinal should be less than third"
            );

            // Verify values
            assert_eq!(
                alice_addr().as_slice(),
                call.nonce_changes[0].address.as_slice()
            );
            assert_eq!(5, call.nonce_changes[0].old_value);
            assert_eq!(6, call.nonce_changes[0].new_value);

            assert_eq!(
                bob_addr().as_slice(),
                call.nonce_changes[1].address.as_slice()
            );
            assert_eq!(10, call.nonce_changes[1].old_value);
            assert_eq!(11, call.nonce_changes[1].new_value);

            assert_eq!(
                alice_addr().as_slice(),
                call.nonce_changes[2].address.as_slice()
            );
            assert_eq!(6, call.nonce_changes[2].old_value);
            assert_eq!(7, call.nonce_changes[2].new_value);
        });
}

#[test]
fn test_nonce_change_zero_to_one() {
    // Test the common case of first nonce increment (0 -> 1)
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
        .nonce_change(alice_addr(), 0, 1)
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("onnoncechange", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.nonce_changes.len(), "Should have 1 nonce change");
            let nc = &call.nonce_changes[0];
            assert_eq!(0, nc.old_value);
            assert_eq!(1, nc.new_value);
        });
}
