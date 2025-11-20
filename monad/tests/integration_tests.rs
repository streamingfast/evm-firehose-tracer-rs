//! Integration tests for the Monad Firehose tracer
//!
//! These tests verify the core transformation logic from Monad events
//! to Firehose protobuf blocks.

use eyre::Result;
use monad_tracer as tracer;
use monad_plugin::ProcessedEvent;
#[cfg(target_os = "linux")]
use monad_plugin::{initialize_plugin, PluginConfig};
use pb::{block, Block, BlockHeader};
use tracer::{EventMapper, FirehoseTracer, TracerConfig};

#[tokio::test]
async fn test_event_mapper_block_lifecycle() -> Result<()> {
    let mut mapper = EventMapper::new();

    // Test complete block lifecycle with realistic JSON data
    let block_start_data = r#"{
        "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "uncle_hash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "coinbase": "0x0000000000000000000000000000000000000000",
        "transactions_root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "difficulty": 0,
        "number": 100,
        "gas_limit": 30000000,
        "timestamp": 1234567890,
        "extra_data": "0x",
        "mix_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "nonce": 0,
        "base_fee_per_gas": {"limbs": [0, 0, 0, 0]},
        "withdrawals_root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    }"#;

    let block_start_event = ProcessedEvent {
        block_number: 100,
        event_type: "BLOCK_START".to_string(),
        firehose_data: block_start_data.as_bytes().to_vec(),
    };

    let result = mapper.process_event(block_start_event).await?;
    assert!(result.is_none(), "Block should not be complete after start event");

    let block_end_data = r#"{
        "hash": "0x0c108fee8a6f4f12e321ac99ba9477e0431d7fa326cf16c3a51d1d6490fef23f",
        "state_root": "0xc1e12619ef31a9b85683cdbfa5be401aa8aa591b7527ba9aaacf7efaaa0eb67b",
        "receipts_root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "gas_used": 0
    }"#;

    let block_end_event = ProcessedEvent {
        block_number: 100,
        event_type: "BLOCK_END".to_string(),
        firehose_data: block_end_data.as_bytes().to_vec(),
    };

    let result = mapper.process_event(block_end_event).await?;
    assert!(result.is_some(), "Block should be complete after end event");

    let block = result.unwrap();
    assert_eq!(block.number, 100);
    assert!(block.header.is_some());
    assert_eq!(block.detail_level, block::DetailLevel::DetaillevelBase as i32);

    Ok(())
}

#[tokio::test]
async fn test_event_mapper_transaction_processing() -> Result<()> {
    let mut mapper = EventMapper::new();

    // Start a block
    let block_start_data = r#"{
        "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "uncle_hash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "coinbase": "0x0000000000000000000000000000000000000000",
        "transactions_root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "difficulty": 0,
        "number": 200,
        "gas_limit": 30000000,
        "timestamp": 1234567890,
        "extra_data": "0x",
        "mix_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "nonce": 0,
        "base_fee_per_gas": {"limbs": [0, 0, 0, 0]},
        "withdrawals_root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    }"#;

    let block_start = ProcessedEvent {
        block_number: 200,
        event_type: "BLOCK_START".to_string(),
        firehose_data: block_start_data.as_bytes().to_vec(),
    };
    mapper.process_event(block_start).await?;

    // Add a transaction header
    let tx_header_data = r#"{
        "txn_index": 0,
        "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "from": "0x0000000000000000000000000000000000000000",
        "to": "0x0000000000000000000000000000000000000000",
        "nonce": 0,
        "gas_limit": 21000,
        "value": {"limbs": [0, 0, 0, 0]},
        "max_fee_per_gas": {"limbs": [0, 0, 0, 0]},
        "max_priority_fee_per_gas": {"limbs": [0, 0, 0, 0]},
        "r": {"limbs": [0, 0, 0, 0]},
        "s": {"limbs": [0, 0, 0, 0]},
        "y_parity": false,
        "txn_type": 2,
        "chain_id": {"limbs": [0, 0, 0, 0]},
        "input": "0x",
        "access_list_count": 0,
        "blob_versioned_hash_length": 0,
        "blob_hashes": "",
        "max_fee_per_blob_gas": {"limbs": [0, 0, 0, 0]}
    }"#;

    let tx_header = ProcessedEvent {
        block_number: 200,
        event_type: "TX_HEADER".to_string(),
        firehose_data: tx_header_data.as_bytes().to_vec(),
    };
    mapper.process_event(tx_header).await?;

    // Add transaction receipt
    let tx_receipt_data = r#"{
        "txn_index": 0,
        "status": true,
        "gas_used": 21000,
        "log_count": 0,
        "call_frame_count": 0
    }"#;

    let tx_receipt = ProcessedEvent {
        block_number: 200,
        event_type: "TX_RECEIPT".to_string(),
        firehose_data: tx_receipt_data.as_bytes().to_vec(),
    };
    mapper.process_event(tx_receipt).await?;

    // End the block
    let block_end_data = r#"{
        "hash": "0x0c108fee8a6f4f12e321ac99ba9477e0431d7fa326cf16c3a51d1d6490fef23f",
        "state_root": "0xc1e12619ef31a9b85683cdbfa5be401aa8aa591b7527ba9aaacf7efaaa0eb67b",
        "receipts_root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "gas_used": 21000
    }"#;

    let block_end = ProcessedEvent {
        block_number: 200,
        event_type: "BLOCK_END".to_string(),
        firehose_data: block_end_data.as_bytes().to_vec(),
    };

    let result = mapper.process_event(block_end).await?;
    assert!(result.is_some());

    let block = result.unwrap();
    assert_eq!(block.transaction_traces.len(), 1);
    assert_eq!(block.transaction_traces[0].index, 0);
    assert_eq!(block.transaction_traces[0].gas_used, 21000);

    Ok(())
}

#[tokio::test]
async fn test_event_mapper_malformed_json() -> Result<()> {
    let mut mapper = EventMapper::new();

    // Test with malformed JSON - should not panic
    let malformed_event = ProcessedEvent {
        block_number: 100,
        event_type: "BLOCK_START".to_string(),
        firehose_data: b"{invalid json".to_vec(),
    };

    // This should return an error, not panic
    let result = mapper.process_event(malformed_event).await;
    assert!(result.is_err(), "Malformed JSON should cause an error");

    Ok(())
}

#[tokio::test]
async fn test_event_mapper_empty_block() -> Result<()> {
    let mut mapper = EventMapper::new();

    // Test empty block (no transactions)
    let block_start_data = r#"{
        "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "uncle_hash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "coinbase": "0x0000000000000000000000000000000000000000",
        "transactions_root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "difficulty": 0,
        "number": 300,
        "gas_limit": 30000000,
        "timestamp": 1234567890,
        "extra_data": "0x",
        "mix_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "nonce": 0,
        "base_fee_per_gas": {"limbs": [0, 0, 0, 0]},
        "withdrawals_root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    }"#;

    let block_start = ProcessedEvent {
        block_number: 300,
        event_type: "BLOCK_START".to_string(),
        firehose_data: block_start_data.as_bytes().to_vec(),
    };
    mapper.process_event(block_start).await?;

    let block_end_data = r#"{
        "hash": "0x0c108fee8a6f4f12e321ac99ba9477e0431d7fa326cf16c3a51d1d6490fef23f",
        "state_root": "0xc1e12619ef31a9b85683cdbfa5be401aa8aa591b7527ba9aaacf7efaaa0eb67b",
        "receipts_root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "gas_used": 0
    }"#;

    let block_end = ProcessedEvent {
        block_number: 300,
        event_type: "BLOCK_END".to_string(),
        firehose_data: block_end_data.as_bytes().to_vec(),
    };

    let result = mapper.process_event(block_end).await?;
    assert!(result.is_some());

    let block = result.unwrap();
    assert_eq!(block.transaction_traces.len(), 0); // Empty block
    assert_eq!(block.header.as_ref().unwrap().gas_used, 0);

    Ok(())
}

#[tokio::test]
async fn test_tracer_configuration() -> Result<()> {
    let config = TracerConfig {
        chain_id: 1337,
        network_name: "test-monad".to_string(),
        debug: true,
        buffer_size: 512,
        output_format: tracer::config::OutputFormat::Json,
    };

    let tracer = FirehoseTracer::new(config);
    assert_eq!(tracer.config().chain_id, 1337);
    assert_eq!(tracer.config().network_name, "test-monad");
    assert!(tracer.config().debug);

    Ok(())
}

#[test]
fn test_block_header_creation() {
    // Test that we can create valid block headers
    let header = BlockHeader {
        number: 12345,
        gas_limit: 30_000_000,
        gas_used: 21_000,
        hash: vec![0u8; 32],
        parent_hash: vec![1u8; 32],
        ..Default::default()
    };

    assert_eq!(header.number, 12345);
    assert_eq!(header.gas_limit, 30_000_000);
    assert_eq!(header.gas_used, 21_000);
    assert_eq!(header.hash.len(), 32);
    assert_eq!(header.parent_hash.len(), 32);
}

#[test]
fn test_block_creation() {
    // Test that we can create valid blocks
    let block = Block {
        number: 54321,
        hash: vec![2u8; 32],
        size: 1024,
        header: Some(BlockHeader {
            number: 54321,
            hash: vec![2u8; 32],
            ..Default::default()
        }),
        transaction_traces: Vec::new(),
        balance_changes: Vec::new(),
        code_changes: Vec::new(),
        system_calls: Vec::new(),
        ver: 1,
        detail_level: pb::block::DetailLevel::DetaillevelExtended as i32,
        ..Default::default()
    };

    assert_eq!(block.number, 54321);
    assert_eq!(block.size, 1024);
    assert!(block.header.is_some());
    assert_eq!(block.header.as_ref().unwrap().number, 54321);
    assert_eq!(block.ver, 1);
}
