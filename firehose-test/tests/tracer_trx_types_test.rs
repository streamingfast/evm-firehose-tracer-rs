use firehose_test::{
    alice_addr, big_int, bob_addr, charlie_addr, success_receipt, test_access_list_trx,
    test_blob_trx, test_dynamic_fee_trx, test_legacy_trx, test_set_code_trx, TracerTester,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

// =============================================================================
// Transaction Type Tests
// =============================================================================
// Tests all transaction types: Legacy, EIP-2930, EIP-1559, EIP-4844, EIP-7702

#[test]
fn test_legacy_transaction_type() {
    // Type 0: Legacy transaction (pre-EIP-2718)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("txtypes", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            // Validate transaction type
            assert_eq!(
                pbeth::transaction_trace::Type::TrxTypeLegacy as i32,
                trx.r#type,
                "Type should be LEGACY"
            );

            // Validate basic transaction fields
            assert!(!trx.hash.is_empty(), "Hash should be set");
            assert_eq!(alice_addr().as_slice(), trx.from.as_slice());
            assert_eq!(bob_addr().as_slice(), trx.to.as_slice());
            // Value is stored as big-endian bytes, last byte contains small values
            let value = *trx.value.as_ref().unwrap().bytes.last().unwrap_or(&0);
            assert_eq!(100, value, "Value should be 100");
            assert_eq!(21000, trx.gas_limit);

            // Legacy transactions don't have access list or EIP-1559 fields
            assert!(
                trx.access_list.is_empty(),
                "Legacy transaction should have no access list"
            );
            assert!(
                trx.max_fee_per_gas.is_none(),
                "Legacy transaction should have no MaxFeePerGas"
            );
            assert!(
                trx.max_priority_fee_per_gas.is_none(),
                "Legacy transaction should have no MaxPriorityFeePerGas"
            );
        });
}

#[test]
fn test_access_list_transaction_type() {
    // Type 1: EIP-2930 access list transaction
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_access_list_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("txtypes", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            // Validate transaction type
            assert_eq!(
                pbeth::transaction_trace::Type::TrxTypeAccessList as i32,
                trx.r#type,
                "Type should be ACCESS_LIST"
            );

            // Validate basic transaction fields
            assert!(!trx.hash.is_empty(), "Hash should be set");
            assert_eq!(alice_addr().as_slice(), trx.from.as_slice());
            assert_eq!(bob_addr().as_slice(), trx.to.as_slice());

            // Validate access list is present
            assert!(!trx.access_list.is_empty(), "Access list should be present");
            assert_eq!(
                1,
                trx.access_list.len(),
                "Should have one access list entry"
            );
            assert_eq!(bob_addr().as_slice(), trx.access_list[0].address.as_slice());
            assert_eq!(
                1,
                trx.access_list[0].storage_keys.len(),
                "Should have one storage key"
            );
        });
}

#[test]
fn test_dynamic_fee_transaction_type() {
    // Type 2: EIP-1559 dynamic fee transaction
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_dynamic_fee_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("txtypes", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            // Validate transaction type
            assert_eq!(
                pbeth::transaction_trace::Type::TrxTypeDynamicFee as i32,
                trx.r#type,
                "Type should be DYNAMIC_FEE"
            );

            // Validate basic transaction fields
            assert!(!trx.hash.is_empty(), "Hash should be set");
            assert_eq!(alice_addr().as_slice(), trx.from.as_slice());
            assert_eq!(bob_addr().as_slice(), trx.to.as_slice());

            // Validate EIP-1559 fields
            assert!(
                trx.max_fee_per_gas.is_some(),
                "MaxFeePerGas should be present"
            );
            let max_fee = *trx
                .max_fee_per_gas
                .as_ref()
                .unwrap()
                .bytes
                .last()
                .unwrap_or(&0);
            assert_eq!(20, max_fee, "MaxFeePerGas should be 20");

            assert!(
                trx.max_priority_fee_per_gas.is_some(),
                "MaxPriorityFeePerGas should be present"
            );
            let priority_fee = *trx
                .max_priority_fee_per_gas
                .as_ref()
                .unwrap()
                .bytes
                .last()
                .unwrap_or(&0);
            assert_eq!(2, priority_fee, "MaxPriorityFeePerGas should be 2");

            // Validate access list is present
            assert!(!trx.access_list.is_empty(), "Access list should be present");
            assert_eq!(
                1,
                trx.access_list.len(),
                "Should have one access list entry"
            );
        });
}

#[test]
fn test_blob_transaction_type() {
    // Type 3: EIP-4844 blob transaction
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_blob_trx())
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("txtypes", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have one transaction"
            );
            let trx = &block.transaction_traces[0];

            // Validate transaction type
            assert_eq!(
                pbeth::transaction_trace::Type::TrxTypeBlob as i32,
                trx.r#type,
                "Type should be BLOB"
            );

            // Validate basic transaction fields
            assert!(!trx.hash.is_empty(), "Hash should be set");
            assert_eq!(alice_addr().as_slice(), trx.from.as_slice());
            assert_eq!(bob_addr().as_slice(), trx.to.as_slice());

            // Validate EIP-4844 blob fields
            assert!(
                trx.blob_gas_fee_cap.is_some(),
                "BlobGasFeeCap should be present"
            );
            let blob_fee = *trx
                .blob_gas_fee_cap
                .as_ref()
                .unwrap()
                .bytes
                .last()
                .unwrap_or(&0);
            assert_eq!(5, blob_fee, "BlobGasFeeCap should be 5");

            assert!(!trx.blob_hashes.is_empty(), "BlobHashes should be present");
            assert_eq!(1, trx.blob_hashes.len(), "Should have one blob hash");
        });
}

#[test]
fn test_set_code_transaction_type() {
    // Type 4: EIP-7702 set code transaction
    // Note: This test uses placeholder signatures. Proper signature validation
    // is tested in the delegation tests.
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_set_code_trx())
        // For EIP-7702, authorization application happens BEFORE the root call
        // However, without proper signature validation, we skip the nonce change
        .start_call(alice_addr(), bob_addr(), big_int(100), 21000, vec![])
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("txtypes", |block| {
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
                "Type should be SET_CODE"
            );

            // Validate basic transaction fields
            assert!(!trx.hash.is_empty(), "Hash should be set");
            assert_eq!(alice_addr().as_slice(), trx.from.as_slice());
            assert_eq!(bob_addr().as_slice(), trx.to.as_slice());

            // Validate EIP-7702 set code authorization list
            assert!(
                !trx.set_code_authorizations.is_empty(),
                "SetCodeAuthorizations should be present"
            );
            assert_eq!(
                1,
                trx.set_code_authorizations.len(),
                "Should have one authorization"
            );
            let auth = &trx.set_code_authorizations[0];
            assert_eq!(
                charlie_addr().as_slice(),
                auth.address.as_slice(),
                "Authorization address should match"
            );
            assert_eq!(0, auth.nonce, "Authorization nonce should be 0");

            // Note: Without proper signature validation, we can't test the Authority
            // and Discarded fields. Those are tested in the delegation tests with
            // properly signed authorizations.
        });
}
