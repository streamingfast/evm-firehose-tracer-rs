use firehose::{BlockData, BlockEvent};
use firehose_test::{alice_addr, big_int, hash_from_hex, TracerTester};

// =============================================================================
// Skipped Block Tests
// =============================================================================
// Tests for OnSkippedBlock handling - blocks that should be traced but have no transactions

#[test]
fn test_empty_skipped_block() {
    // Skipped blocks should have 0 transactions and be traced as normal empty blocks
    let mut tester = TracerTester::new();
    tester
        .skipped_block(100)
        .validate_with_category("onskippedblock", |block| {
            // Should have a block with number 100
            assert_eq!(100, block.number, "Block number should be 100");

            // Should have no transactions (skipped blocks have 0 transactions)
            assert!(
                block.transaction_traces.is_empty(),
                "Skipped block should have no transactions"
            );

            // Should have proper header
            assert!(block.header.is_some(), "Block should have header");
            let header = block.header.as_ref().unwrap();
            assert_eq!(100, header.number, "Header number should be 100");
        });
}

#[test]
fn test_skipped_block_preserves_coinbase() {
    // Ensure skipped blocks preserve coinbase and other block metadata
    let block_data = BlockData {
        number: 200,
        hash: hash_from_hex("0x96c3afce2aab3c77e1f8ce47d01e50817d98f884d697e0af9b35c11e2626be8b"),
        parent_hash: hash_from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000063",
        ),
        uncle_hash: alloy_primitives::B256::ZERO,
        coinbase: alice_addr(),
        root: hash_from_hex("0x0000000000000000000000000000000000000000000000000000000000000000"),
        tx_hash: alloy_primitives::B256::ZERO,
        receipt_hash: alloy_primitives::B256::ZERO,
        bloom: alloy_primitives::Bloom::ZERO,
        difficulty: big_int(0),
        gas_limit: 15_000_000,
        gas_used: 0,
        time: 1704067200,
        extra: alloy_primitives::Bytes::new(),
        mix_digest: hash_from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        ),
        nonce: 0,
        base_fee: Some(big_int(0)),
        uncles: vec![],
        size: 509,
        withdrawals: vec![],
        is_merge: true,
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_root: None,
        requests_hash: None,
        tx_dependency: None,
    };

    let block_event = BlockEvent {
        block: block_data,
        finalized: None,
    };

    let mut tester = TracerTester::new();
    tester.tracer.on_skipped_block(block_event);

    tester.validate_with_category("onskippedblock", |block| {
        assert_eq!(200, block.number, "Block number should be 200");
        assert!(
            block.transaction_traces.is_empty(),
            "Skipped block should have no transactions"
        );

        assert!(block.header.is_some(), "Block should have header");
        let header = block.header.as_ref().unwrap();
        assert_eq!(200, header.number, "Header number should be 200");
        assert_eq!(
            alice_addr().as_slice(),
            header.coinbase.as_slice(),
            "Coinbase should be Alice"
        );
        assert_eq!(15_000_000, header.gas_limit, "Gas limit should match");
    });
}

#[test]
fn test_multiple_skipped_blocks() {
    // Test processing multiple skipped blocks
    let mut tester = TracerTester::new();
    tester
        .skipped_block(100)
        .skipped_block(101)
        .skipped_block(102);

    // Parse all blocks from output
    let blocks = tester.parse_firehose_blocks();

    // Should have 3 blocks
    assert_eq!(3, blocks.len(), "Should have 3 blocks");

    // Validate each block
    for (i, block) in blocks.iter().enumerate() {
        let expected_number = 100 + i as u64;
        assert_eq!(
            expected_number, block.number,
            "Block {} number should be {}",
            i, expected_number
        );
        assert!(
            block.transaction_traces.is_empty(),
            "Block {} should have no transactions",
            i
        );
    }
}
