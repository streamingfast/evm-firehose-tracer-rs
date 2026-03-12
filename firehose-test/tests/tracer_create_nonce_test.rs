use firehose_test::{
    alice_addr, big_int, create_address, success_receipt, test_legacy_trx, TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

// =============================================================================
// CREATE Address Calculation Tests
// =============================================================================
// Tests that CREATE address is calculated correctly using sender nonce

#[test]
fn test_create_with_nonce_0() {
    // Test that CREATE address is calculated correctly using sender nonce
    // Expected address = create_address(alice, 0)
    let expected_addr = create_address(alice_addr(), 0);

    let mut tester = TracerTester::new();
    tester
        .set_mock_state_nonce(alice_addr(), 0)
        .start_block_trx(test_legacy_trx())
        .start_create_call(
            alice_addr(),
            expected_addr,
            big_int(0),
            53000,
            vec![0x60, 0x80],
        )
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(53000)), None, None)
        .validate_with_category("create_addresscalculation", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                pbeth::CallType::Create as i32,
                call.call_type,
                "Call type should be CREATE"
            );
            assert_eq!(
                expected_addr.0.as_slice(),
                call.address.as_slice(),
                "CREATE address should match computed address"
            );
        });
}

#[test]
fn test_create_with_nonce_5() {
    // Test with non-zero nonce
    let expected_addr = create_address(alice_addr(), 5);

    let mut tester = TracerTester::new();
    tester
        .set_mock_state_nonce(alice_addr(), 5)
        .start_block_trx(test_legacy_trx())
        .start_create_call(
            alice_addr(),
            expected_addr,
            big_int(0),
            53000,
            vec![0x60, 0x80],
        )
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(53000)), None, None)
        .validate_with_category("create_addresscalculation", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                pbeth::CallType::Create as i32,
                call.call_type,
                "Call type should be CREATE"
            );
            assert_eq!(
                expected_addr.0.as_slice(),
                call.address.as_slice(),
                "CREATE address should match computed address with nonce 5"
            );
        });
}
