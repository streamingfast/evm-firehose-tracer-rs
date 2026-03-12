use alloy_primitives::{Address, Keccak256, B256};
use firehose_test::testing_helpers::*;
use firehose_test::tracer_tester::{test_legacy_trx, test_set_code_trx, TracerTester};
use pb::sf::ethereum::r#type::v2 as pbeth;

// Helper function to hash bytes using keccak256
fn hash_bytes(data: &[u8]) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize()
}

// TestTracer_EIP7702_DelegationDetection tests the detection of EIP-7702 delegation
// designators in contract code (0xef0100 prefix)

#[test]
fn test_call_with_delegation_bytecode() {
    // Create delegation bytecode: 0xef0100 + address (23 bytes total)
    // Delegation points to CharlieAddr
    let mut delegation_code = vec![0xef, 0x01, 0x00];
    delegation_code.extend_from_slice(charlie_addr().as_slice());
    assert_eq!(
        23,
        delegation_code.len(),
        "Delegation code should be 23 bytes"
    );

    // Alice has delegation code pointing to Charlie
    // Set mock state so GetCode returns delegation bytecode
    let mut tester = TracerTester::new_prague();
    tester
        .set_mock_state_code(alice_addr(), delegation_code.clone())
        .start_block_trx(test_set_code_trx())
        // EIP-7702: Authorization nonce change happens before root call
        .nonce_change(alice_addr(), 0, 1)
        // Code change: Alice gets delegation code
        .code_change(
            alice_addr(),
            hash_bytes(&[]),
            hash_bytes(&delegation_code),
            vec![],
            delegation_code.clone(),
        )
        .start_call(
            bob_addr(),
            alice_addr(),
            big_int(100),
            21000,
            vec![0x01, 0x02],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("eip7702_delegationdetection", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Verify delegation was detected
            assert!(
                call.address_delegates_to.is_some(),
                "AddressDelegatesTo should be set"
            );
            assert_eq!(
                charlie_addr().as_slice(),
                call.address_delegates_to.as_ref().unwrap().as_slice(),
                "Should delegate to CharlieAddr"
            );
        });
}

#[test]
fn test_call_with_empty_code() {
    // Alice has no code (empty account)
    // No delegation should be detected
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            bob_addr(),
            alice_addr(),
            big_int(100),
            21000,
            vec![0x01, 0x02],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("eip7702_delegationdetection", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // No delegation for empty code
            assert!(
                call.address_delegates_to.is_none(),
                "AddressDelegatesTo should be nil for empty code"
            );
        });
}

#[test]
fn test_call_with_regular_contract_code() {
    // Alice has regular contract code (not delegation)
    let regular_code = vec![0x60, 0x80, 0x60, 0x40]; // Some EVM bytecode

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .code_change(
            alice_addr(),
            hash_bytes(&[]),
            hash_bytes(&regular_code),
            vec![],
            regular_code.clone(),
        )
        .start_call(
            bob_addr(),
            alice_addr(),
            big_int(100),
            21000,
            vec![0x01, 0x02],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("eip7702_delegationdetection", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // No delegation for regular code
            assert!(
                call.address_delegates_to.is_none(),
                "AddressDelegatesTo should be nil for regular contract code"
            );
        });
}

#[test]
fn test_call_with_invalid_delegation_wrong_length() {
    // Invalid delegation: correct prefix but wrong length (should be 23 bytes)
    let invalid_delegation = vec![0xef, 0x01, 0x00, 0x11, 0x22]; // Only 5 bytes

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .code_change(
            alice_addr(),
            hash_bytes(&[]),
            hash_bytes(&invalid_delegation),
            vec![],
            invalid_delegation.clone(),
        )
        .start_call(
            bob_addr(),
            alice_addr(),
            big_int(100),
            21000,
            vec![0x01, 0x02],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("eip7702_delegationdetection", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // No delegation for invalid length
            assert!(
                call.address_delegates_to.is_none(),
                "AddressDelegatesTo should be nil for invalid delegation length"
            );
        });
}

#[test]
fn test_call_with_invalid_delegation_wrong_prefix() {
    // Invalid delegation: wrong prefix (23 bytes but doesn't start with 0xef0100)
    let mut invalid_delegation = vec![0u8; 23];
    invalid_delegation[0] = 0xef;
    invalid_delegation[1] = 0x01;
    invalid_delegation[2] = 0x01; // Wrong! Should be 0x00
    invalid_delegation[3..].copy_from_slice(charlie_addr().as_slice());

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .code_change(
            alice_addr(),
            hash_bytes(&[]),
            hash_bytes(&invalid_delegation),
            vec![],
            invalid_delegation.clone(),
        )
        .start_call(
            bob_addr(),
            alice_addr(),
            big_int(100),
            21000,
            vec![0x01, 0x02],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("eip7702_delegationdetection", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // No delegation for wrong prefix
            assert!(
                call.address_delegates_to.is_none(),
                "AddressDelegatesTo should be nil for invalid delegation prefix"
            );
        });
}

#[test]
fn test_create_transaction_no_delegation_check() {
    // CREATE transactions should NOT check for delegation (callType != CREATE check in code)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_create_call(
            alice_addr(),
            Address::ZERO,
            big_int(0),
            21000,
            vec![0x60, 0x80],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("eip7702_delegationdetection", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(pbeth::CallType::Create as i32, call.call_type);
            // CREATE calls should not have delegation check
            assert!(call.address_delegates_to.is_none());
        });
}
