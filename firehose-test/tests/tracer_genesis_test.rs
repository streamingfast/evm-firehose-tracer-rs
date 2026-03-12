use alloy_primitives::{Bytes, B256, U256};
use firehose::types::{GenesisAccount, GenesisAlloc};
use firehose_test::testing_helpers::*;
use firehose_test::tracer_tester::TracerTester;
use pb::sf::ethereum::r#type::v2 as pbeth;
use std::collections::HashMap;

// TestTracer_GenesisBlock tests genesis block processing

#[test]
fn test_empty_genesis() {
    // Scenario: Genesis block with no accounts
    let alloc: GenesisAlloc = HashMap::new();

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            assert_eq!(0, block.number, "Block number should be 0");
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have 1 synthetic transaction"
            );

            let trx = &block.transaction_traces[0];
            assert_eq!(1, trx.calls.len(), "Should have 1 synthetic call");

            let call = &trx.calls[0];
            assert_eq!(
                0,
                call.balance_changes.len(),
                "Should have no balance changes"
            );
            assert_eq!(0, call.code_changes.len(), "Should have no code changes");
            assert_eq!(0, call.nonce_changes.len(), "Should have no nonce changes");
            assert_eq!(
                0,
                call.storage_changes.len(),
                "Should have no storage changes"
            );
        });
}

#[test]
fn test_single_account_with_balance() {
    // Scenario: Genesis block with one account having only balance
    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        alice_addr(),
        GenesisAccount {
            balance: Some(must_big_int("1000000000000000000")), // 1 ETH
            code: None,
            storage: HashMap::new(),
            nonce: 0,
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Should have 1 balance change
            assert_eq!(
                1,
                call.balance_changes.len(),
                "Should have 1 balance change"
            );

            let change = &call.balance_changes[0];
            assert_eq!(
                alice_addr().as_slice(),
                &change.address,
                "Address should be Alice"
            );
            assert!(change.old_value.is_none(), "Old value should be nil (zero)");
            assert!(change.new_value.is_some(), "New value should not be nil");

            let new_val = U256::from_be_slice(&change.new_value.as_ref().unwrap().bytes);
            assert_eq!(
                must_big_int("1000000000000000000"),
                new_val,
                "New value should be 1 ETH"
            );
            assert_eq!(
                pbeth::balance_change::Reason::GenesisBalance as i32,
                change.reason,
                "Reason should be GENESIS_BALANCE"
            );
        });
}

#[test]
fn test_single_account_with_code() {
    // Scenario: Genesis block with contract deployment
    let contract_code = vec![0x60, 0x80, 0x60, 0x40, 0x52];

    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        bob_addr(),
        GenesisAccount {
            balance: Some(U256::ZERO),
            code: Some(Bytes::from(contract_code.clone())),
            storage: HashMap::new(),
            nonce: 0,
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Should have 1 code change
            assert_eq!(1, call.code_changes.len(), "Should have 1 code change");

            let change = &call.code_changes[0];
            assert_eq!(
                bob_addr().as_slice(),
                &change.address,
                "Address should be Bob"
            );
            assert_eq!(
                B256::ZERO.as_slice(),
                &change.old_hash,
                "Old hash should be empty"
            );
            assert_eq!(contract_code, change.new_code, "New code should match");

            // Verify code hash is computed correctly
            let expected_hash = alloy_primitives::keccak256(&contract_code);
            assert_eq!(
                expected_hash.as_slice(),
                &change.new_hash,
                "Code hash should be keccak256 of code"
            );
        });
}

#[test]
fn test_single_account_with_nonce() {
    // Scenario: Genesis block with account having a nonce
    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        charlie_addr(),
        GenesisAccount {
            balance: Some(U256::ZERO),
            code: None,
            storage: HashMap::new(),
            nonce: 42,
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Should have 1 nonce change
            assert_eq!(1, call.nonce_changes.len(), "Should have 1 nonce change");

            let change = &call.nonce_changes[0];
            assert_eq!(
                charlie_addr().as_slice(),
                &change.address,
                "Address should be Charlie"
            );
            assert_eq!(0, change.old_value, "Old nonce should be 0");
            assert_eq!(42, change.new_value, "New nonce should be 42");
        });
}

#[test]
fn test_single_account_with_storage() {
    // Scenario: Genesis block with contract having storage
    let mut storage: HashMap<B256, B256> = HashMap::new();
    storage.insert(hash32(1), hash32(100));
    storage.insert(hash32(2), hash32(200));

    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        bob_addr(),
        GenesisAccount {
            balance: Some(U256::ZERO),
            code: None,
            storage,
            nonce: 0,
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Should have 2 storage changes
            assert_eq!(
                2,
                call.storage_changes.len(),
                "Should have 2 storage changes"
            );

            // Storage changes should be sorted by key
            // hash32(1) < hash32(2) in bytes order
            let change0 = &call.storage_changes[0];
            let change1 = &call.storage_changes[1];

            let key1 = hash32(1);
            let key2 = hash32(2);
            let val100 = hash32(100);
            let val200 = hash32(200);

            assert_eq!(
                bob_addr().as_slice(),
                &change0.address,
                "Address should be Bob"
            );
            assert_eq!(
                key1.as_slice(),
                &change0.key,
                "First key should be hash32(1)"
            );
            assert_eq!(
                B256::ZERO.as_slice(),
                &change0.old_value,
                "Old value should be empty"
            );
            assert_eq!(
                val100.as_slice(),
                &change0.new_value,
                "New value should be hash32(100)"
            );

            assert_eq!(
                key2.as_slice(),
                &change1.key,
                "Second key should be hash32(2)"
            );
            assert_eq!(
                val200.as_slice(),
                &change1.new_value,
                "New value should be hash32(200)"
            );
        });
}

#[test]
fn test_complete_account() {
    // Scenario: Account with all fields populated
    let contract_code = vec![0x60, 0x80, 0x60, 0x40, 0x52];

    let mut storage: HashMap<B256, B256> = HashMap::new();
    storage.insert(hash32(1), hash32(111));
    storage.insert(hash32(2), hash32(222));
    storage.insert(hash32(3), hash32(333));

    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        alice_addr(),
        GenesisAccount {
            balance: Some(must_big_int("5000000000000000000")), // 5 ETH
            code: Some(Bytes::from(contract_code.clone())),
            storage,
            nonce: 10,
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Verify all changes are present
            assert_eq!(
                1,
                call.balance_changes.len(),
                "Should have 1 balance change"
            );
            assert_eq!(1, call.code_changes.len(), "Should have 1 code change");
            assert_eq!(1, call.nonce_changes.len(), "Should have 1 nonce change");
            assert_eq!(
                3,
                call.storage_changes.len(),
                "Should have 3 storage changes"
            );

            // Verify balance
            let new_val =
                U256::from_be_slice(&call.balance_changes[0].new_value.as_ref().unwrap().bytes);
            assert_eq!(must_big_int("5000000000000000000"), new_val);

            // Verify code
            assert_eq!(contract_code, call.code_changes[0].new_code);

            // Verify nonce
            assert_eq!(10, call.nonce_changes[0].new_value);

            // Verify storage is sorted
            let key1 = hash32(1);
            let key2 = hash32(2);
            let key3 = hash32(3);
            assert_eq!(key1.as_slice(), &call.storage_changes[0].key);
            assert_eq!(key2.as_slice(), &call.storage_changes[1].key);
            assert_eq!(key3.as_slice(), &call.storage_changes[2].key);
        });
}

// TestTracer_GenesisBlock_Ordering tests deterministic ordering of genesis changes

#[test]
fn test_multiple_accounts_sorted_by_address() {
    // Scenario: Multiple accounts should be processed in sorted address order
    // Create accounts with deliberately unsorted addresses
    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        charlie_addr(), // 0x6813eb...
        GenesisAccount {
            balance: Some(U256::from(300)),
            code: None,
            storage: HashMap::new(),
            nonce: 0,
        },
    );
    alloc.insert(
        alice_addr(), // 0x7e5f45...
        GenesisAccount {
            balance: Some(U256::from(100)),
            code: None,
            storage: HashMap::new(),
            nonce: 0,
        },
    );
    alloc.insert(
        bob_addr(), // 0x2b5ad5...
        GenesisAccount {
            balance: Some(U256::from(200)),
            code: None,
            storage: HashMap::new(),
            nonce: 0,
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                3,
                call.balance_changes.len(),
                "Should have 3 balance changes"
            );

            // Balance changes should be ordered by address bytes
            // Sorted order: BobAddr (0x2b5a...) < CharlieAddr (0x6813eb...) < AliceAddr (0x7e5f...)
            let change0 = &call.balance_changes[0];
            let change1 = &call.balance_changes[1];
            let change2 = &call.balance_changes[2];

            // Verify they are in sorted order
            assert_eq!(
                bob_addr().as_slice(),
                &change0.address,
                "First should be BobAddr"
            );
            assert_eq!(
                charlie_addr().as_slice(),
                &change1.address,
                "Second should be CharlieAddr"
            );
            assert_eq!(
                alice_addr().as_slice(),
                &change2.address,
                "Third should be AliceAddr"
            );

            // Verify values match
            assert_eq!(
                U256::from(200),
                U256::from_be_slice(&change0.new_value.as_ref().unwrap().bytes)
            );
            assert_eq!(
                U256::from(300),
                U256::from_be_slice(&change1.new_value.as_ref().unwrap().bytes)
            );
            assert_eq!(
                U256::from(100),
                U256::from_be_slice(&change2.new_value.as_ref().unwrap().bytes)
            );
        });
}

#[test]
fn test_storage_keys_sorted() {
    // Scenario: Storage keys should be sorted deterministically
    let mut storage: HashMap<B256, B256> = HashMap::new();
    storage.insert(hash32(999), hash32(9990));
    storage.insert(hash32(1), hash32(10));
    storage.insert(hash32(500), hash32(5000));
    storage.insert(hash32(100), hash32(1000));

    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        alice_addr(),
        GenesisAccount {
            balance: Some(U256::ZERO),
            code: None,
            storage,
            nonce: 0,
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                4,
                call.storage_changes.len(),
                "Should have 4 storage changes"
            );

            // Extract keys to verify sorting
            let keys: Vec<B256> = call
                .storage_changes
                .iter()
                .map(|change| B256::from_slice(&change.key))
                .collect();

            // Verify keys are in sorted order
            assert_eq!(hash32(1), keys[0], "First key should be hash32(1)");
            assert_eq!(hash32(100), keys[1], "Second key should be hash32(100)");
            assert_eq!(hash32(500), keys[2], "Third key should be hash32(500)");
            assert_eq!(hash32(999), keys[3], "Fourth key should be hash32(999)");
        });
}

#[test]
fn test_deterministic_across_runs() {
    // Scenario: Genesis block should produce identical output across multiple runs
    // This tests that map iteration order doesn't affect output
    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        alice_addr(),
        GenesisAccount {
            balance: Some(must_big_int("1000000000000000000")),
            code: None,
            storage: HashMap::new(),
            nonce: 0,
        },
    );
    alloc.insert(
        bob_addr(),
        GenesisAccount {
            balance: Some(must_big_int("2000000000000000000")),
            code: None,
            storage: HashMap::new(),
            nonce: 0,
        },
    );
    alloc.insert(
        charlie_addr(),
        GenesisAccount {
            balance: Some(must_big_int("3000000000000000000")),
            code: None,
            storage: HashMap::new(),
            nonce: 0,
        },
    );

    // Run twice and compare
    let mut first_block = None;
    let mut second_block = None;

    let mut tester1 = TracerTester::new();
    tester1
        .genesis_block(0, hash32(100), alloc.clone())
        .validate_with_category("genesisblock", |block| {
            first_block = Some(block.transaction_traces[0].calls[0].balance_changes.clone());
        });

    let mut tester2 = TracerTester::new();
    tester2
        .genesis_block(0, hash32(100), alloc.clone())
        .validate_with_category("genesisblock", |block| {
            second_block = Some(block.transaction_traces[0].calls[0].balance_changes.clone());
        });

    // Blocks should be identical
    assert!(first_block.is_some());
    assert!(second_block.is_some());

    let first_changes = first_block.unwrap();
    let second_changes = second_block.unwrap();

    // Balance changes should be identical and in same order
    assert_eq!(first_changes.len(), second_changes.len());
    for i in 0..first_changes.len() {
        assert_eq!(
            first_changes[i].address, second_changes[i].address,
            "Balance change {} address should match",
            i
        );
        assert_eq!(
            first_changes[i].new_value, second_changes[i].new_value,
            "Balance change {} value should match",
            i
        );
    }
}

// TestTracer_GenesisBlock_EdgeCases tests edge cases and special scenarios

#[test]
fn test_zero_balance_not_recorded() {
    // Scenario: Accounts with zero balance should not have balance changes recorded
    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        alice_addr(),
        GenesisAccount {
            balance: Some(U256::ZERO), // Zero balance
            code: None,
            storage: HashMap::new(),
            nonce: 1, // But has nonce
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Should have nonce change but no balance change
            assert_eq!(
                0,
                call.balance_changes.len(),
                "Zero balance should not be recorded"
            );
            assert_eq!(
                1,
                call.nonce_changes.len(),
                "Nonce change should be recorded"
            );
        });
}

#[test]
fn test_nil_balance_not_recorded() {
    // Scenario: Accounts with nil balance should not have balance changes
    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        bob_addr(),
        GenesisAccount {
            balance: None, // Nil balance
            code: Some(Bytes::from(vec![0x60, 0x80])),
            storage: HashMap::new(),
            nonce: 0,
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Should have code change but no balance change
            assert_eq!(
                0,
                call.balance_changes.len(),
                "Nil balance should not be recorded"
            );
            assert_eq!(1, call.code_changes.len(), "Code change should be recorded");
        });
}

#[test]
fn test_zero_nonce_not_recorded() {
    // Scenario: Zero nonce should not be recorded
    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        charlie_addr(),
        GenesisAccount {
            balance: Some(U256::from(100)),
            code: None,
            storage: HashMap::new(),
            nonce: 0, // Zero nonce
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Should have balance change but no nonce change
            assert_eq!(
                1,
                call.balance_changes.len(),
                "Balance change should be recorded"
            );
            assert_eq!(
                0,
                call.nonce_changes.len(),
                "Zero nonce should not be recorded"
            );
        });
}

#[test]
fn test_empty_code_not_recorded() {
    // Scenario: Empty code should not be recorded
    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        alice_addr(),
        GenesisAccount {
            balance: Some(U256::from(100)),
            code: Some(Bytes::new()), // Empty code
            storage: HashMap::new(),
            nonce: 0,
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Should have balance change but no code change
            assert_eq!(
                1,
                call.balance_changes.len(),
                "Balance change should be recorded"
            );
            assert_eq!(
                0,
                call.code_changes.len(),
                "Empty code should not be recorded"
            );
        });
}

#[test]
fn test_empty_storage_not_recorded() {
    // Scenario: Empty storage map should not record any changes
    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        bob_addr(),
        GenesisAccount {
            balance: Some(U256::from(100)),
            code: None,
            storage: HashMap::new(), // Empty storage
            nonce: 0,
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Should have balance change but no storage changes
            assert_eq!(
                1,
                call.balance_changes.len(),
                "Balance change should be recorded"
            );
            assert_eq!(
                0,
                call.storage_changes.len(),
                "Empty storage should not record changes"
            );
        });
}

#[test]
fn test_receipt_status_success() {
    // Scenario: Genesis transaction should have successful receipt
    let mut alloc: GenesisAlloc = HashMap::new();
    alloc.insert(
        alice_addr(),
        GenesisAccount {
            balance: Some(U256::from(100)),
            code: None,
            storage: HashMap::new(),
            nonce: 0,
        },
    );

    let mut tester = TracerTester::new();
    tester
        .genesis_block(0, hash32(100), alloc)
        .validate_with_category("genesisblock", |block| {
            let trx = &block.transaction_traces[0];

            // Transaction should be successful
            assert_eq!(
                pbeth::TransactionTraceStatus::Succeeded as i32,
                trx.status,
                "Genesis transaction should succeed"
            );

            // Receipt should exist and be successful
            assert!(trx.receipt.is_some(), "Receipt should exist");
            // Genesis receipt has no logs
            assert_eq!(
                0,
                trx.receipt.as_ref().unwrap().logs.len(),
                "Genesis receipt should have no logs"
            );
        });
}
