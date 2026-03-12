use firehose::utils::{create2_address, create_address};
use firehose_test::{alice_addr, success_receipt, test_legacy_trx, TracerTester};
use pb::sf::ethereum::r#type::v2 as pbeth;

// =============================================================================
// CREATE Address Calculation Tests
// =============================================================================

#[test]
fn test_create_with_nonce_0() {
    // Test that CREATE address is calculated correctly using sender nonce
    let expected_addr = create_address(alice_addr(), 0);

    let mut tester = TracerTester::new();
    tester
        .set_mock_state_nonce(alice_addr(), 0)
        .start_block_trx(test_legacy_trx())
        .start_create_call(
            alice_addr(),
            expected_addr,
            alloy_primitives::U256::ZERO,
            53000,
            vec![0x60, 0x80],
        )
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(53000)), None, None)
        .validate_with_category("create_addresscalculation", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(pbeth::CallType::Create as i32, call.call_type);
            assert_eq!(
                expected_addr.as_slice(),
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
            alloy_primitives::U256::ZERO,
            53000,
            vec![0x60, 0x80],
        )
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(53000)), None, None)
        .validate_with_category("create_addresscalculation", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(pbeth::CallType::Create as i32, call.call_type);
            assert_eq!(
                expected_addr.as_slice(),
                call.address.as_slice(),
                "CREATE address should match computed address with nonce 5"
            );
        });
}

// =============================================================================
// CREATE2 Address Calculation Tests
// =============================================================================

#[test]
fn test_create2_with_salt_and_init_code() {
    // Test that CREATE2 address is calculated correctly using sender, salt, and init_code_hash
    let salt = alloy_primitives::B256::from([1u8; 32]);
    let init_code = vec![0x60, 0x80, 0x60, 0x40];
    let init_code_hash = alloy_primitives::keccak256(&init_code);
    let expected_addr = create2_address(alice_addr(), salt, init_code_hash);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_create2_call(
            alice_addr(),
            expected_addr,
            alloy_primitives::U256::ZERO,
            53000,
            init_code,
        )
        .end_call(vec![], 50000)
        .end_block_trx(Some(success_receipt(53000)), None, None)
        .validate_with_category("create_addresscalculation", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // CREATE2 is mapped to CREATE in call_type
            assert_eq!(pbeth::CallType::Create as i32, call.call_type);
            assert_eq!(
                expected_addr.as_slice(),
                call.address.as_slice(),
                "CREATE2 address should match computed address"
            );
        });
}
