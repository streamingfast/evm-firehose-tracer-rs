use alloy_primitives::B256;
use firehose_test::{
    alice_addr, bob_addr, charlie_addr, success_receipt, test_legacy_trx, TracerTester,
};

/// Computes keccak256 hash of the given data
fn hash_bytes(data: &[u8]) -> B256 {
    use alloy_primitives::keccak256;
    keccak256(data)
}

#[test]
fn test_single_keccak_preimage() {
    // Scenario: Contract computes keccak256 of some data
    // Example: keccak256("hello") = 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
    let preimage = b"hello".to_vec();
    let hash = hash_bytes(&preimage);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![0x01],
        )
        .keccak(hash, preimage.clone())
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("keccakpreimages", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert!(
                !call.keccak_preimages.is_empty(),
                "KeccakPreimages should not be empty"
            );
            assert_eq!(
                1,
                call.keccak_preimages.len(),
                "Should have 1 keccak preimage"
            );

            let hash_hex = hex::encode(hash);
            let preimage_hex = hex::encode(&preimage);

            assert!(
                call.keccak_preimages.contains_key(&hash_hex),
                "Hash should be in preimages map"
            );
            assert_eq!(
                &preimage_hex, &call.keccak_preimages[&hash_hex],
                "Preimage should match"
            );
        });
}

#[test]
fn test_multiple_keccak_preimages_same_call() {
    // Scenario: Contract computes multiple keccak256 hashes
    let preimage1 = b"storage_slot_1".to_vec();
    let hash1 = hash_bytes(&preimage1);

    let preimage2 = b"storage_slot_2".to_vec();
    let hash2 = hash_bytes(&preimage2);

    let preimage3 = b"event_signature".to_vec();
    let hash3 = hash_bytes(&preimage3);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![0x01],
        )
        .keccak(hash1, preimage1.clone())
        .keccak(hash2, preimage2.clone())
        .keccak(hash3, preimage3.clone())
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("keccakpreimages", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert!(
                !call.keccak_preimages.is_empty(),
                "KeccakPreimages should not be empty"
            );
            assert_eq!(
                3,
                call.keccak_preimages.len(),
                "Should have 3 keccak preimages"
            );

            // Verify all three preimages
            assert_eq!(
                hex::encode(&preimage1),
                call.keccak_preimages[&hex::encode(hash1)]
            );
            assert_eq!(
                hex::encode(&preimage2),
                call.keccak_preimages[&hex::encode(hash2)]
            );
            assert_eq!(
                hex::encode(&preimage3),
                call.keccak_preimages[&hex::encode(hash3)]
            );
        });
}

#[test]
fn test_keccak_preimages_across_nested_calls() {
    // Scenario: Keccak computations happen in both parent and child calls
    let preimage_parent = b"parent_data".to_vec();
    let hash_parent = hash_bytes(&preimage_parent);

    let preimage_child = b"child_data".to_vec();
    let hash_child = hash_bytes(&preimage_child);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![0x01],
        )
        .keccak(hash_parent, preimage_parent.clone())
        .start_call(
            bob_addr(),
            charlie_addr(),
            alloy_primitives::U256::ZERO,
            50000,
            vec![0x02],
        )
        .keccak(hash_child, preimage_child.clone())
        .end_call(vec![], 45000)
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("keccakpreimages", |block| {
            let trx = &block.transaction_traces[0];
            let parent_call = &trx.calls[0];
            let child_call = &trx.calls[1];

            // Parent call should have its keccak preimage
            assert_eq!(1, parent_call.keccak_preimages.len());
            assert_eq!(
                hex::encode(&preimage_parent),
                parent_call.keccak_preimages[&hex::encode(hash_parent)]
            );

            // Child call should have its keccak preimage
            assert_eq!(1, child_call.keccak_preimages.len());
            assert_eq!(
                hex::encode(&preimage_child),
                child_call.keccak_preimages[&hex::encode(hash_child)]
            );
        });
}

#[test]
fn test_duplicate_keccak_preimage_ignored() {
    // Scenario: Same preimage hashed multiple times in same call
    // Should only store once
    let preimage = b"repeated_data".to_vec();
    let hash = hash_bytes(&preimage);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![0x01],
        )
        .keccak(hash, preimage.clone())
        .keccak(hash, preimage.clone()) // Duplicate
        .keccak(hash, preimage.clone()) // Duplicate
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("keccakpreimages", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Should only store once, not three times
            assert_eq!(
                1,
                call.keccak_preimages.len(),
                "Should deduplicate keccak preimages"
            );
            assert_eq!(
                hex::encode(&preimage),
                call.keccak_preimages[&hex::encode(hash)]
            );
        });
}

#[test]
fn test_keccak_empty_preimage() {
    // Scenario: keccak256 of empty data
    // Example: keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    let preimage = vec![];
    let hash = hash_bytes(&preimage);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![0x01],
        )
        .keccak(hash, preimage.clone())
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("keccakpreimages", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                1,
                call.keccak_preimages.len(),
                "Should have 1 keccak preimage"
            );

            let hash_hex = hex::encode(hash);
            // In non-backward-compatible mode (Ver 4), empty preimage is stored as empty string
            assert_eq!(
                "", &call.keccak_preimages[&hash_hex],
                "Empty preimage should be stored as empty string"
            );
        });
}

#[test]
fn test_keccak_large_preimage() {
    // Scenario: keccak256 of large data (e.g., contract bytecode, large calldata)
    let mut preimage = vec![0u8; 1024]; // 1 KB of data
    for (i, byte) in preimage.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    let hash = hash_bytes(&preimage);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![0x01],
        )
        .keccak(hash, preimage.clone())
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("keccakpreimages", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(
                1,
                call.keccak_preimages.len(),
                "Should have 1 keccak preimage"
            );

            let hash_hex = hex::encode(hash);
            let preimage_hex = hex::encode(&preimage);

            assert_eq!(
                &preimage_hex, &call.keccak_preimages[&hash_hex],
                "Large preimage should match"
            );
            assert_eq!(
                2048,
                call.keccak_preimages[&hash_hex].len(),
                "Hex-encoded preimage should be 2x original size"
            );
        });
}

#[test]
fn test_keccak_storage_slot_mapping() {
    use alloy_primitives::B256;
    // Real-world scenario: Mapping storage slot calculation
    // In Solidity, mapping(address => uint256) at slot 0 would compute:
    // keccak256(abi.encodePacked(key, slot))

    // Example: Storage slot for Alice address at mapping slot 0
    let address_bytes = alice_addr();
    let slot_bytes = vec![0u8; 32]; // slot 0
    let mut preimage = Vec::new();
    preimage.extend_from_slice(address_bytes.as_slice());
    preimage.extend_from_slice(&slot_bytes);

    let hash = hash_bytes(&preimage);
    let empty_hash = B256::ZERO;
    let storage_value = hash_bytes(&[0x01]);

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![0x01],
        )
        .keccak(hash, preimage.clone()) // Contract computes storage slot
        .storage_change(bob_addr(), hash, empty_hash, storage_value) // Then writes to that slot
        .end_call(vec![], 95000)
        .end_block_trx(Some(success_receipt(100000)), None, None)
        .validate_with_category("keccakpreimages", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            // Verify keccak preimage is stored
            assert_eq!(
                1,
                call.keccak_preimages.len(),
                "Should have 1 keccak preimage"
            );

            let hash_hex = hex::encode(hash);
            let preimage_hex = hex::encode(&preimage);
            assert_eq!(&preimage_hex, &call.keccak_preimages[&hash_hex]);

            // Verify storage change also recorded
            assert_eq!(
                1,
                call.storage_changes.len(),
                "Should have 1 storage change"
            );
            assert_eq!(
                hash.as_slice(),
                call.storage_changes[0].key.as_slice(),
                "Storage key should match keccak hash"
            );
        });
}
