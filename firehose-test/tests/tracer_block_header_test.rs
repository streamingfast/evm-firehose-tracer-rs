use firehose::{BlockData, BlockEvent};
use firehose_test::{alice_addr, big_int, hash32, TracerTester};

// =============================================================================
// Block Header EIP Fields Tests
// =============================================================================
// Tests that EIP-specific block header fields are properly populated

#[test]
fn test_eip4895_withdrawals_root() {
    // EIP-4895: Shanghai withdrawals root
    let withdrawals_root = hash32(12345);

    let block_event = BlockEvent {
        block: BlockData {
            number: 100,
            hash: hash32(1),
            parent_hash: hash32(2),
            uncle_hash: hash32(3),
            coinbase: alice_addr(),
            root: hash32(4),
            tx_hash: hash32(5),
            receipt_hash: hash32(6),
            bloom: alloy_primitives::Bloom::ZERO,
            difficulty: big_int(0),
            gas_limit: 15_000_000,
            gas_used: 0,
            time: 1000,
            extra: alloy_primitives::Bytes::new(),
            mix_digest: hash32(7),
            nonce: 0,
            base_fee: Some(big_int(1_000_000_000)),
            uncles: vec![],
            size: 1024,
            withdrawals: vec![],
            withdrawals_root: Some(withdrawals_root), // EIP-4895
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_root: None,
            requests_hash: None,
            tx_dependency: None,
        },
        finalized: None,
    };

    let mut tester = TracerTester::new();
    tester.validate_with_custom_block(block_event, |block| {
        assert!(block.header.is_some(), "Header should exist");
        let header = block.header.as_ref().unwrap();
        assert!(
            !header.withdrawals_root.is_empty(),
            "WithdrawalsRoot should be set"
        );
        assert_eq!(
            withdrawals_root.as_slice(),
            header.withdrawals_root.as_slice()
        );
    });
}

#[test]
fn test_eip4844_blob_gas_fields() {
    // EIP-4844: Cancun blob gas tracking
    let blob_gas_used = 262144_u64; // 128KB blob
    let excess_blob_gas = 524288_u64; // 256KB excess

    let block_event = BlockEvent {
        block: BlockData {
            number: 100,
            hash: hash32(1),
            parent_hash: hash32(2),
            uncle_hash: hash32(3),
            coinbase: alice_addr(),
            root: hash32(4),
            tx_hash: hash32(5),
            receipt_hash: hash32(6),
            bloom: alloy_primitives::Bloom::ZERO,
            difficulty: big_int(0),
            gas_limit: 15_000_000,
            gas_used: 0,
            time: 1000,
            extra: alloy_primitives::Bytes::new(),
            mix_digest: hash32(7),
            nonce: 0,
            base_fee: Some(big_int(1_000_000_000)),
            uncles: vec![],
            size: 1024,
            withdrawals: vec![],
            withdrawals_root: None,
            blob_gas_used: Some(blob_gas_used),     // EIP-4844
            excess_blob_gas: Some(excess_blob_gas), // EIP-4844
            parent_beacon_root: None,
            requests_hash: None,
            tx_dependency: None,
        },
        finalized: None,
    };

    let mut tester = TracerTester::new();
    tester.validate_with_custom_block(block_event, |block| {
        assert!(block.header.is_some(), "Header should exist");
        let header = block.header.as_ref().unwrap();
        assert!(header.blob_gas_used.is_some(), "BlobGasUsed should be set");
        assert_eq!(blob_gas_used, header.blob_gas_used.unwrap());
        assert!(
            header.excess_blob_gas.is_some(),
            "ExcessBlobGas should be set"
        );
        assert_eq!(excess_blob_gas, header.excess_blob_gas.unwrap());
    });
}

#[test]
fn test_eip4788_parent_beacon_root() {
    // EIP-4788: Cancun parent beacon block root
    let parent_beacon_root = hash32(99999);

    let block_event = BlockEvent {
        block: BlockData {
            number: 100,
            hash: hash32(1),
            parent_hash: hash32(2),
            uncle_hash: hash32(3),
            coinbase: alice_addr(),
            root: hash32(4),
            tx_hash: hash32(5),
            receipt_hash: hash32(6),
            bloom: alloy_primitives::Bloom::ZERO,
            difficulty: big_int(0),
            gas_limit: 15_000_000,
            gas_used: 0,
            time: 1000,
            extra: alloy_primitives::Bytes::new(),
            mix_digest: hash32(7),
            nonce: 0,
            base_fee: Some(big_int(1_000_000_000)),
            uncles: vec![],
            size: 1024,
            withdrawals: vec![],
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_root: Some(parent_beacon_root), // EIP-4788
            requests_hash: None,
            tx_dependency: None,
        },
        finalized: None,
    };

    let mut tester = TracerTester::new();
    tester.validate_with_custom_block(block_event, |block| {
        assert!(block.header.is_some(), "Header should exist");
        let header = block.header.as_ref().unwrap();
        assert!(
            !header.parent_beacon_root.is_empty(),
            "ParentBeaconRoot should be set"
        );
        assert_eq!(
            parent_beacon_root.as_slice(),
            header.parent_beacon_root.as_slice()
        );
    });
}

#[test]
fn test_eip7685_requests_hash() {
    // EIP-7685: Prague execution requests hash
    let requests_hash = hash32(88888);

    let block_event = BlockEvent {
        block: BlockData {
            number: 100,
            hash: hash32(1),
            parent_hash: hash32(2),
            uncle_hash: hash32(3),
            coinbase: alice_addr(),
            root: hash32(4),
            tx_hash: hash32(5),
            receipt_hash: hash32(6),
            bloom: alloy_primitives::Bloom::ZERO,
            difficulty: big_int(0),
            gas_limit: 15_000_000,
            gas_used: 0,
            time: 1000,
            extra: alloy_primitives::Bytes::new(),
            mix_digest: hash32(7),
            nonce: 0,
            base_fee: Some(big_int(1_000_000_000)),
            uncles: vec![],
            size: 1024,
            withdrawals: vec![],
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_root: None,
            requests_hash: Some(requests_hash), // EIP-7685
            tx_dependency: None,
        },
        finalized: None,
    };

    let mut tester = TracerTester::new();
    tester.validate_with_custom_block(block_event, |block| {
        assert!(block.header.is_some(), "Header should exist");
        let header = block.header.as_ref().unwrap();
        assert!(
            !header.requests_hash.is_empty(),
            "RequestsHash should be set"
        );
        assert_eq!(requests_hash.as_slice(), header.requests_hash.as_slice());
    });
}

#[test]
fn test_polygon_tx_dependency() {
    // Polygon-specific: Transaction dependency metadata
    // Example: tx[1] depends on tx[0], tx[3] depends on tx[2]

    let block_event = BlockEvent {
        block: BlockData {
            number: 100,
            hash: hash32(1),
            parent_hash: hash32(2),
            uncle_hash: hash32(3),
            coinbase: alice_addr(),
            root: hash32(4),
            tx_hash: hash32(5),
            receipt_hash: hash32(6),
            bloom: alloy_primitives::Bloom::ZERO,
            difficulty: big_int(0),
            gas_limit: 15_000_000,
            gas_used: 0,
            time: 1000,
            extra: alloy_primitives::Bytes::new(),
            mix_digest: hash32(7),
            nonce: 0,
            base_fee: Some(big_int(1_000_000_000)),
            uncles: vec![],
            size: 1024,
            withdrawals: vec![],
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_root: None,
            requests_hash: None,
            tx_dependency: Some(vec![
                vec![],     // tx[0] has no dependencies
                vec![0],    // tx[1] depends on tx[0]
                vec![],     // tx[2] has no dependencies
                vec![2],    // tx[3] depends on tx[2]
                vec![1, 3], // tx[4] depends on both tx[1] and tx[3]
            ]),
        },
        finalized: None,
    };

    let mut tester = TracerTester::new();
    tester.validate_with_custom_block(block_event, |block| {
        assert!(block.header.is_some(), "Header should exist");
        let header = block.header.as_ref().unwrap();
        assert!(header.tx_dependency.is_some(), "TxDependency should be set");

        let deps = header.tx_dependency.as_ref().unwrap();
        assert_eq!(5, deps.val.len(), "Should have 5 transaction dependencies");

        // Verify structure
        assert_eq!(
            0,
            deps.val[0].val.len(),
            "tx[0] should have no dependencies"
        );
        assert_eq!(vec![0], deps.val[1].val, "tx[1] should depend on tx[0]");
        assert_eq!(
            0,
            deps.val[2].val.len(),
            "tx[2] should have no dependencies"
        );
        assert_eq!(vec![2], deps.val[3].val, "tx[3] should depend on tx[2]");
        assert_eq!(
            vec![1, 3],
            deps.val[4].val,
            "tx[4] should depend on tx[1] and tx[3]"
        );
    });
}

#[test]
fn test_all_eip_fields_combined() {
    // Test all EIP fields together (representing a post-Prague block)
    let withdrawals_root = hash32(11111);
    let blob_gas_used = 262144_u64;
    let excess_blob_gas = 524288_u64;
    let parent_beacon_root = hash32(22222);
    let requests_hash = hash32(33333);

    let block_event = BlockEvent {
        block: BlockData {
            number: 100,
            hash: hash32(1),
            parent_hash: hash32(2),
            uncle_hash: hash32(3),
            coinbase: alice_addr(),
            root: hash32(4),
            tx_hash: hash32(5),
            receipt_hash: hash32(6),
            bloom: alloy_primitives::Bloom::ZERO,
            difficulty: big_int(0),
            gas_limit: 15_000_000,
            gas_used: 0,
            time: 1000,
            extra: alloy_primitives::Bytes::new(),
            mix_digest: hash32(7),
            nonce: 0,
            base_fee: Some(big_int(1_000_000_000)),
            uncles: vec![],
            size: 1024,
            withdrawals: vec![],
            withdrawals_root: Some(withdrawals_root),
            blob_gas_used: Some(blob_gas_used),
            excess_blob_gas: Some(excess_blob_gas),
            parent_beacon_root: Some(parent_beacon_root),
            requests_hash: Some(requests_hash),
            tx_dependency: None,
        },
        finalized: None,
    };

    let mut tester = TracerTester::new();
    tester.validate_with_custom_block(block_event, |block| {
        assert!(block.header.is_some(), "Header should exist");
        let header = block.header.as_ref().unwrap();

        // Verify all EIP fields are present
        assert!(
            !header.withdrawals_root.is_empty(),
            "WithdrawalsRoot should be set"
        );
        assert_eq!(
            withdrawals_root.as_slice(),
            header.withdrawals_root.as_slice()
        );

        assert!(header.blob_gas_used.is_some(), "BlobGasUsed should be set");
        assert_eq!(blob_gas_used, header.blob_gas_used.unwrap());

        assert!(
            header.excess_blob_gas.is_some(),
            "ExcessBlobGas should be set"
        );
        assert_eq!(excess_blob_gas, header.excess_blob_gas.unwrap());

        assert!(
            !header.parent_beacon_root.is_empty(),
            "ParentBeaconRoot should be set"
        );
        assert_eq!(
            parent_beacon_root.as_slice(),
            header.parent_beacon_root.as_slice()
        );

        assert!(
            !header.requests_hash.is_empty(),
            "RequestsHash should be set"
        );
        assert_eq!(requests_hash.as_slice(), header.requests_hash.as_slice());
    });
}

#[test]
fn test_nil_eip_fields_pre_fork() {
    // Test that pre-fork blocks (without EIP fields) don't populate these fields
    let block_event = BlockEvent {
        block: BlockData {
            number: 100,
            hash: hash32(1),
            parent_hash: hash32(2),
            uncle_hash: hash32(3),
            coinbase: alice_addr(),
            root: hash32(4),
            tx_hash: hash32(5),
            receipt_hash: hash32(6),
            bloom: alloy_primitives::Bloom::ZERO,
            difficulty: big_int(1000), // Pre-merge (has difficulty)
            gas_limit: 15_000_000,
            gas_used: 0,
            time: 1000,
            extra: alloy_primitives::Bytes::new(),
            mix_digest: hash32(7),
            nonce: 12345,
            base_fee: Some(big_int(1_000_000_000)),
            uncles: vec![],
            size: 1024,
            withdrawals: vec![],
            // All EIP fields are None (pre-fork block)
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_root: None,
            requests_hash: None,
            tx_dependency: None,
        },
        finalized: None,
    };

    let mut tester = TracerTester::new();
    tester.validate_with_custom_block(block_event, |block| {
        assert!(block.header.is_some(), "Header should exist");
        let header = block.header.as_ref().unwrap();

        // Verify all EIP fields are empty/nil for pre-fork blocks
        assert!(
            header.withdrawals_root.is_empty(),
            "WithdrawalsRoot should be empty"
        );
        assert!(header.blob_gas_used.is_none(), "BlobGasUsed should be None");
        assert!(
            header.excess_blob_gas.is_none(),
            "ExcessBlobGas should be None"
        );
        assert!(
            header.parent_beacon_root.is_empty(),
            "ParentBeaconRoot should be empty"
        );
        assert!(
            header.requests_hash.is_empty(),
            "RequestsHash should be empty"
        );
        assert!(
            header.tx_dependency.is_none(),
            "TxDependency should be None"
        );
    });
}
