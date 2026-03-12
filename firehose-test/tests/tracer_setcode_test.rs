use firehose_test::eip7702::*;
use firehose_test::testing_helpers::*;
use firehose_test::tracer_tester::{test_set_code_trx_with_auth, TracerTester};
use pb::sf::ethereum::r#type::v2 as pbeth;

// TestTracer_SetCodeAuthorization tests EIP-7702 SetCode authorization validation

#[test]
fn test_valid_authorization_with_nonce_change() {
    // Alice signs an authorization to delegate to Charlie's code
    let auth = sign_set_code_auth_as_struct(&alice_key(), 1, charlie_addr(), 0);

    let mut tester = TracerTester::new_prague();
    tester
        .start_block_trx(test_set_code_trx_with_auth(vec![auth]))
        // EIP-7702: Authorization application happens BEFORE the root call
        // The authorizer's nonce is incremented when the authorization is applied
        .nonce_change(alice_addr(), 0, 1)
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("tracer_setcode", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            // Validate transaction type
            assert_eq!(
                pbeth::transaction_trace::Type::TrxTypeSetCode as i32,
                trx.r#type,
                "Transaction type should be TRX_TYPE_SET_CODE"
            );

            // Validate authorization list
            assert!(
                !trx.set_code_authorizations.is_empty(),
                "SetCodeAuthorizations should be present"
            );
            assert_eq!(
                1,
                trx.set_code_authorizations.len(),
                "Should have one authorization"
            );

            let auth_result = &trx.set_code_authorizations[0];

            // Validate authorization fields
            assert_eq!(
                charlie_addr().as_slice(),
                auth_result.address.as_slice(),
                "Authorization address should match"
            );
            assert_eq!(0, auth_result.nonce, "Authorization nonce should be 0");

            // Validate signature recovery - Authority should be populated with Alice's address
            assert!(
                auth_result.authority.is_some(),
                "Authority should be populated from signature"
            );
            assert_eq!(
                alice_addr().as_slice(),
                auth_result.authority.as_ref().unwrap().as_slice(),
                "Authority should be Alice (the signer)"
            );

            // Validate that the authorization was NOT discarded (signature valid + nonce change present)
            assert!(
                !auth_result.discarded,
                "Authorization should not be discarded"
            );
        });
}

#[test]
fn test_invalid_signature_discarded() {
    // Create authorization with valid signature
    let mut auth = sign_set_code_auth_as_struct(&alice_key(), 1, charlie_addr(), 0);

    // Corrupt the signature by changing V
    auth.v += 10; // Invalid V value

    let mut tester = TracerTester::new_prague();
    tester
        .start_block_trx(test_set_code_trx_with_auth(vec![auth]))
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("tracer_setcode", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            assert!(!trx.set_code_authorizations.is_empty());
            assert_eq!(1, trx.set_code_authorizations.len());

            let auth_result = &trx.set_code_authorizations[0];

            // Invalid signature - Authority should be empty
            assert!(
                auth_result.authority.is_none()
                    || auth_result.authority.as_ref().unwrap().is_empty(),
                "Authority should be empty for invalid signature"
            );

            // Invalid signature - should be discarded
            assert!(
                auth_result.discarded,
                "Authorization with invalid signature should be discarded"
            );
        });
}

#[test]
fn test_missing_nonce_change_discarded() {
    // Alice signs an authorization to delegate to Charlie's code
    let auth = sign_set_code_auth_as_struct(&alice_key(), 1, charlie_addr(), 0);

    let mut tester = TracerTester::new_prague();
    tester
        .start_block_trx(test_set_code_trx_with_auth(vec![auth]))
        // NOTE: We do NOT add a nonce change for Alice
        // This simulates the authorization not being applied (e.g., wrong nonce, already applied, etc.)
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("tracer_setcode", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            assert!(!trx.set_code_authorizations.is_empty());
            assert_eq!(1, trx.set_code_authorizations.len());

            let auth_result = &trx.set_code_authorizations[0];

            // Signature is valid - Authority should be populated
            assert!(
                auth_result.authority.is_some(),
                "Authority should be populated from valid signature"
            );
            assert_eq!(
                alice_addr().as_slice(),
                auth_result.authority.as_ref().unwrap().as_slice(),
                "Authority should be Alice"
            );

            // But no nonce change - should be discarded
            assert!(
                auth_result.discarded,
                "Authorization without nonce change should be discarded"
            );
        });
}

#[test]
fn test_multiple_authorizations_mixed_validity() {
    // Alice signs a valid authorization
    let alice_auth = sign_set_code_auth_as_struct(&alice_key(), 1, charlie_addr(), 0);

    // Bob signs a valid authorization
    let bob_auth = sign_set_code_auth_as_struct(&bob_key(), 1, charlie_addr(), 0);

    // Charlie signs an authorization (but we won't add nonce change - will be discarded)
    let charlie_auth = sign_set_code_auth_as_struct(&charlie_key(), 1, alice_addr(), 0);

    let mut tester = TracerTester::new_prague();
    tester
        .start_block_trx(test_set_code_trx_with_auth(vec![
            alice_auth,
            bob_auth,
            charlie_auth,
        ]))
        // Add nonce changes for Alice and Bob (they get applied)
        // Charlie's authorization does NOT get applied (no nonce change)
        .nonce_change(alice_addr(), 0, 1)
        .nonce_change(bob_addr(), 0, 1)
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("tracer_setcode", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            assert!(!trx.set_code_authorizations.is_empty());
            assert_eq!(
                3,
                trx.set_code_authorizations.len(),
                "Should have three authorizations"
            );

            // Alice's authorization - valid signature + nonce change = NOT discarded
            let alice_result = &trx.set_code_authorizations[0];
            assert_eq!(
                alice_addr().as_slice(),
                alice_result.authority.as_ref().unwrap().as_slice(),
                "Alice's authority should match"
            );
            assert!(
                !alice_result.discarded,
                "Alice's authorization should NOT be discarded"
            );

            // Bob's authorization - valid signature + nonce change = NOT discarded
            let bob_result = &trx.set_code_authorizations[1];
            assert_eq!(
                bob_addr().as_slice(),
                bob_result.authority.as_ref().unwrap().as_slice(),
                "Bob's authority should match"
            );
            assert!(
                !bob_result.discarded,
                "Bob's authorization should NOT be discarded"
            );

            // Charlie's authorization - valid signature but NO nonce change = discarded
            let charlie_result = &trx.set_code_authorizations[2];
            assert_eq!(
                charlie_addr().as_slice(),
                charlie_result.authority.as_ref().unwrap().as_slice(),
                "Charlie's authority should match"
            );
            assert!(
                charlie_result.discarded,
                "Charlie's authorization should be discarded (no nonce change)"
            );
        });
}

#[test]
fn test_empty_authorizations_list() {
    // SetCode transaction with empty authorization list should be valid
    let mut tester = TracerTester::new_prague();
    tester
        .start_block_trx(test_set_code_trx_with_auth(vec![]))
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("tracer_setcode", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            // Validate transaction type
            assert_eq!(
                pbeth::transaction_trace::Type::TrxTypeSetCode as i32,
                trx.r#type,
                "Transaction type should be TRX_TYPE_SET_CODE"
            );

            // Empty authorization list
            assert!(
                trx.set_code_authorizations.is_empty(),
                "SetCodeAuthorizations should be empty for empty list"
            );
        });
}

#[test]
fn test_nonce_mismatch_discarded() {
    // Authorization expects nonce 0→1, but actual nonce change is 5→6
    let auth = sign_set_code_auth_as_struct(&alice_key(), 1, charlie_addr(), 0);

    let mut tester = TracerTester::new_prague();
    tester
        .start_block_trx(test_set_code_trx_with_auth(vec![auth]))
        // Nonce change exists but doesn't match authorization's expected nonce
        .nonce_change(alice_addr(), 5, 6) // Wrong nonce range
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("tracer_setcode", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            assert!(!trx.set_code_authorizations.is_empty());
            assert_eq!(1, trx.set_code_authorizations.len());

            let auth_result = &trx.set_code_authorizations[0];

            // Signature is valid
            assert!(
                auth_result.authority.is_some(),
                "Authority should be populated"
            );
            assert_eq!(
                alice_addr().as_slice(),
                auth_result.authority.as_ref().unwrap().as_slice(),
                "Authority should be Alice"
            );

            // But nonce mismatch - should be discarded
            assert!(
                auth_result.discarded,
                "Authorization with nonce mismatch should be discarded"
            );
        });
}

#[test]
fn test_duplicate_nonce_change_only_one_used() {
    // Two authorizations from same authority with same nonce
    // Only one nonce change available - second should be discarded
    let auth1 = sign_set_code_auth_as_struct(&alice_key(), 1, charlie_addr(), 0);

    // Create second authorization from same key (Alice) with same nonce
    let auth2 = sign_set_code_auth_as_struct(&alice_key(), 1, bob_addr(), 0);

    let mut tester = TracerTester::new_prague();
    tester
        .start_block_trx(test_set_code_trx_with_auth(vec![auth1, auth2]))
        // Only ONE nonce change for Alice (0→1)
        // Both authorizations are from Alice with nonce=0, but only one can match
        .nonce_change(alice_addr(), 0, 1)
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("tracer_setcode", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            assert!(!trx.set_code_authorizations.is_empty());
            assert_eq!(2, trx.set_code_authorizations.len());

            // Both have valid signatures
            let auth1_result = &trx.set_code_authorizations[0];
            assert_eq!(
                alice_addr().as_slice(),
                auth1_result.authority.as_ref().unwrap().as_slice()
            );

            let auth2_result = &trx.set_code_authorizations[1];
            assert_eq!(
                alice_addr().as_slice(),
                auth2_result.authority.as_ref().unwrap().as_slice()
            );

            // Only one can use the nonce change
            // First one gets it, second one is discarded
            let discarded_count = auth1_result.discarded as usize + auth2_result.discarded as usize;

            assert_eq!(
                1, discarded_count,
                "Exactly one authorization should be discarded (nonce change reuse prevention)"
            );
        });
}

#[test]
fn test_setcode_with_access_list() {
    // SetCode transaction can include an access list (EIP-1559 feature)
    let auth = sign_set_code_auth_as_struct(&alice_key(), 1, charlie_addr(), 0);

    // Create transaction with access list
    let mut tx_event = test_set_code_trx_with_auth(vec![auth]);
    tx_event.access_list = vec![firehose::types::AccessTuple {
        address: bob_addr(),
        storage_keys: vec![[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]
        .into()], // Storage slot 1
    }];

    let mut tester = TracerTester::new_prague();
    tester
        .start_block_trx(tx_event)
        .nonce_change(alice_addr(), 0, 1)
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("tracer_setcode", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            // Validate transaction type
            assert_eq!(
                pbeth::transaction_trace::Type::TrxTypeSetCode as i32,
                trx.r#type,
                "Transaction type should be TRX_TYPE_SET_CODE"
            );

            // Validate access list is present
            assert!(!trx.access_list.is_empty(), "Access list should be present");
            assert_eq!(
                1,
                trx.access_list.len(),
                "Should have one access list entry"
            );

            // Validate authorization
            assert!(!trx.set_code_authorizations.is_empty());
            assert_eq!(1, trx.set_code_authorizations.len());

            let auth_result = &trx.set_code_authorizations[0];
            assert!(
                !auth_result.discarded,
                "Authorization should not be discarded"
            );
            assert_eq!(
                alice_addr().as_slice(),
                auth_result.authority.as_ref().unwrap().as_slice()
            );
        });
}
