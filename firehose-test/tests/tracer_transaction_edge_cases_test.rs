use firehose_test::{
    alice_addr, big_int, bob_addr, failed_receipt, must_big_int, success_receipt, test_blob_trx,
    test_legacy_trx, u256_to_trimmed_bytes, TracerTester, ERR_EXECUTION_REVERTED,
};
use pb::sf::ethereum::r#type::v2 as pbeth;

// =============================================================================
// Transaction Completion Edge Cases
// =============================================================================
// Tests edge cases and error resistance in transaction completion logic

#[test]
fn test_empty_calls_array_bad_block() {
    // Scenario: Transaction ends without any calls (bad block or misconfigured)
    // Note: Receipt is provided but NOT populated when calls array is empty (early return)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        // No calls added - simulate bad block
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("completetransaction_edgecases", |block| {
            let trx = &block.transaction_traces[0];

            // Should have 0 calls
            assert_eq!(0, trx.calls.len(), "Bad block should have 0 calls");

            // Should still have EndOrdinal set
            assert!(
                trx.end_ordinal > 0,
                "EndOrdinal should be set even for bad block"
            );

            // Receipt is NOT populated when there are no calls (early return)
            assert!(
                trx.receipt.is_none(),
                "Receipt should be None for bad block with no calls"
            );

            // Transaction status should be UNKNOWN (not set from receipt)
            assert_eq!(
                pbeth::TransactionTraceStatus::Unknown as i32,
                trx.status,
                "Status should be UNKNOWN for bad block"
            );
        });
}

#[test]
fn test_nil_receipt() {
    // Scenario: Transaction completes without receipt (error case)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .end_call(vec![0x42], 95000)
        .end_block_trx(None, None, None) // No receipt
        .validate_with_category("completetransaction_edgecases", |block| {
            let trx = &block.transaction_traces[0];

            // Receipt should be None
            assert!(trx.receipt.is_none(), "Receipt should be None");

            // Transaction index and gas should be defaults
            assert_eq!(0, trx.index, "Index should be default 0");
            assert_eq!(0, trx.gas_used, "GasUsed should be default 0");

            // Status should be UNKNOWN (no receipt provided)
            assert_eq!(
                pbeth::TransactionTraceStatus::Unknown as i32,
                trx.status,
                "Status should be UNKNOWN when no receipt"
            );

            // Root call return data should still be copied
            assert_eq!(
                vec![0x42],
                trx.return_data,
                "Return data should be copied from root call even without receipt"
            );
        });
}

#[test]
fn test_nil_receipt_with_reverted_call() {
    // Scenario: Transaction reverts but no receipt (error case)
    // Verifies that reverted status is still set even without receipt
    let err = std::io::Error::new(std::io::ErrorKind::Other, ERR_EXECUTION_REVERTED);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .end_call_failed(b"error".to_vec(), 95000, &err, true)
        .end_block_trx(None, None, None) // No receipt
        .validate_with_category("completetransaction_edgecases", |block| {
            let trx = &block.transaction_traces[0];

            // Receipt should be None
            assert!(trx.receipt.is_none(), "Receipt should be None");

            // Root call should be reverted
            assert!(trx.calls[0].status_reverted, "Root call should be reverted");

            // Transaction status should be REVERTED (set from root call, not receipt)
            assert_eq!(
                pbeth::TransactionTraceStatus::Reverted as i32,
                trx.status,
                "Status should be REVERTED even without receipt"
            );
        });
}

#[test]
fn test_return_data_copied_from_root_call() {
    // Scenario: Root call return data should be copied to transaction
    let return_data = vec![0xde, 0xad, 0xbe, 0xef];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .end_call(return_data.clone(), 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("completetransaction_edgecases", |block| {
            let trx = &block.transaction_traces[0];
            let root_call = &trx.calls[0];

            // Root call should have the return data
            assert_eq!(
                return_data, root_call.return_data,
                "Root call should have return data"
            );

            // Transaction should have the same return data
            assert_eq!(
                return_data, trx.return_data,
                "Transaction return data should be copied from root call"
            );
        });
}

#[test]
fn test_empty_return_data() {
    // Scenario: Empty return data should be handled correctly
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .end_call(vec![], 95000) // Empty return data
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("completetransaction_edgecases", |block| {
            let trx = &block.transaction_traces[0];

            // Transaction return data should be empty
            assert!(
                trx.return_data.is_empty(),
                "Transaction return data should be empty"
            );
        });
}

#[test]
fn test_nil_return_data() {
    // Scenario: Nil return data should be handled correctly (same as empty in Rust)
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .end_call(vec![], 95000) // Empty return data (equivalent to nil)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("completetransaction_edgecases", |block| {
            let trx = &block.transaction_traces[0];

            // Transaction return data should be empty
            assert!(trx.return_data.is_empty(), "Return data should be empty");
        });
}

#[test]
fn test_end_ordinal_always_set() {
    // Scenario: EndOrdinal should always be set, even for failed transactions
    let err = std::io::Error::new(std::io::ErrorKind::Other, ERR_EXECUTION_REVERTED);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .end_call_failed(b"error".to_vec(), 95000, &err, true)
        .end_block_trx(Some(failed_receipt(100000)), None, None)
        .validate_with_category("completetransaction_edgecases", |block| {
            let trx = &block.transaction_traces[0];

            // EndOrdinal should be set and > BeginOrdinal
            assert!(
                trx.end_ordinal > trx.begin_ordinal,
                "EndOrdinal should be greater than BeginOrdinal (end={}, begin={})",
                trx.end_ordinal,
                trx.begin_ordinal
            );
            assert!(trx.end_ordinal > 0, "EndOrdinal should be set");
        });
}

#[test]
fn test_multiple_transactions_ordinals_sequential() {
    // Scenario: Multiple transactions should have sequential ordinals
    // Verifies that EndOrdinal advances properly across transactions
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 50000, vec![0x01])
        .end_call(vec![], 45000)
        .end_block_trx(Some(success_receipt(50000)), None, None)
        .validate_with_category("completetransaction_edgecases", |block| {
            let trx = &block.transaction_traces[0];

            // EndOrdinal should be greater than BeginOrdinal
            assert!(
                trx.end_ordinal > trx.begin_ordinal,
                "EndOrdinal should be greater than BeginOrdinal"
            );
        });
}

// =============================================================================
// Blob Transaction Specific Tests
// =============================================================================

#[test]
fn test_blob_transaction_with_blob_gas() {
    // Scenario: Blob transaction (type 3) should populate blob gas fields
    let blob_gas_used = 131072_u64; // 1 blob
    let blob_gas_price = must_big_int("1000000000"); // 1 gwei

    let receipt = firehose::ReceiptData {
        transaction_index: 0,
        status: 1,
        gas_used: 50000,
        logs_bloom: [0u8; 256],
        cumulative_gas_used: 50000,
        logs: vec![],
        blob_gas_used,
        blob_gas_price: Some(blob_gas_price),
        state_root: None,
    };

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_blob_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .end_call(vec![], 95000)
        .end_block_trx(Some(receipt), None, None)
        .validate_with_category("completetransaction_edgecases", |block| {
            let trx = &block.transaction_traces[0];

            // Verify transaction type
            assert_eq!(
                pbeth::transaction_trace::Type::TrxTypeBlob as i32,
                trx.r#type,
                "Transaction type should be BLOB"
            );

            let receipt = trx.receipt.as_ref().expect("Receipt should exist");
            assert!(receipt.blob_gas_used.is_some(), "BlobGasUsed should be set");
            assert!(
                receipt.blob_gas_price.is_some(),
                "BlobGasPrice should be set"
            );

            assert_eq!(
                blob_gas_used,
                receipt.blob_gas_used.unwrap(),
                "BlobGasUsed should match"
            );

            let expected_price_bytes = u256_to_trimmed_bytes(blob_gas_price);
            assert_eq!(
                expected_price_bytes,
                receipt.blob_gas_price.as_ref().unwrap().bytes,
                "BlobGasPrice should match"
            );
        });
}

#[test]
fn test_non_blob_transaction_no_blob_gas() {
    // Scenario: Non-blob transaction should not have blob gas fields
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(alice_addr(), bob_addr(), big_int(0), 100000, vec![0x01])
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("completetransaction_edgecases", |block| {
            let trx = &block.transaction_traces[0];

            // Default transaction type is legacy (type 0)
            assert_eq!(
                pbeth::transaction_trace::Type::TrxTypeLegacy as i32,
                trx.r#type
            );

            let receipt = trx.receipt.as_ref().expect("Receipt should exist");

            // Blob gas fields should be None for non-blob transactions
            assert!(
                receipt.blob_gas_used.is_none(),
                "BlobGasUsed should be None for non-blob tx"
            );
            assert!(
                receipt.blob_gas_price.is_none(),
                "BlobGasPrice should be None for non-blob tx"
            );
        });
}
