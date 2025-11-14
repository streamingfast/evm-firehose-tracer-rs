//! Integration tests for the Monad Firehose tracer
//!
//! These tests verify the core transformation logic from Monad events
//! to Firehose protobuf blocks.

use eyre::Result;
use pb::{Block, BlockHeader};
use plugin::{initialize_plugin, PluginConfig, ProcessedEvent};
use tracer::{EventMapper, FirehoseTracer, TracerConfig};

#[tokio::test]
async fn test_event_mapper_block_lifecycle() -> Result<()> {
    let mut mapper = EventMapper::new();

    // Test block start event
    let block_start_event = ProcessedEvent {
        block_number: 100,
        event_type: "BLOCK_START".to_string(),
        firehose_data: vec![1, 2, 3, 4],
    };

    let result = mapper.process_event(block_start_event).await?;
    assert!(
        result.is_none(),
        "Block should not be complete after start event"
    );

    // Test block end event
    let block_end_event = ProcessedEvent {
        block_number: 100,
        event_type: "BLOCK_END".to_string(),
        firehose_data: vec![5, 6, 7, 8],
    };

    let result = mapper.process_event(block_end_event).await?;
    assert!(result.is_some(), "Block should be complete after end event");

    let block = result.unwrap();
    assert_eq!(block.number, 100);
    assert!(block.header.is_some());

    Ok(())
}

#[tokio::test]
async fn test_event_mapper_transaction_processing() -> Result<()> {
    let mut mapper = EventMapper::new();

    // Start a block
    let block_start = ProcessedEvent {
        block_number: 200,
        event_type: "BLOCK_START".to_string(),
        firehose_data: vec![1, 2, 3, 4],
    };
    mapper.process_event(block_start).await?;

    // Add a transaction
    let tx_start = ProcessedEvent {
        block_number: 200,
        event_type: "TX_START".to_string(),
        firehose_data: vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
    };
    mapper.process_event(tx_start).await?;

    let tx_end = ProcessedEvent {
        block_number: 200,
        event_type: "TX_END".to_string(),
        firehose_data: vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
    };
    mapper.process_event(tx_end).await?;

    // End the block
    let block_end = ProcessedEvent {
        block_number: 200,
        event_type: "BLOCK_END".to_string(),
        firehose_data: vec![5, 6, 7, 8],
    };

    let result = mapper.process_event(block_end).await?;
    assert!(result.is_some());

    let block = result.unwrap();
    assert_eq!(block.transaction_traces.len(), 1);
    assert_eq!(block.transaction_traces[0].index, 0);

    Ok(())
}

#[tokio::test]
async fn test_event_mapper_balance_changes() -> Result<()> {
    let mut mapper = EventMapper::new();

    // Start a block
    let block_start = ProcessedEvent {
        block_number: 300,
        event_type: "BLOCK_START".to_string(),
        firehose_data: vec![1, 2, 3, 4],
    };
    mapper.process_event(block_start).await?;

    // Add a balance change
    let balance_change = ProcessedEvent {
        block_number: 300,
        event_type: "BALANCE_CHANGE".to_string(),
        firehose_data: vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    };
    mapper.process_event(balance_change).await?;

    // End the block
    let block_end = ProcessedEvent {
        block_number: 300,
        event_type: "BLOCK_END".to_string(),
        firehose_data: vec![5, 6, 7, 8],
    };

    let result = mapper.process_event(block_end).await?;
    assert!(result.is_some());

    let block = result.unwrap();
    assert_eq!(block.balance_changes.len(), 1);
    assert!(block.balance_changes[0].new_value.is_some());

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

#[tokio::test]
async fn test_plugin_initialization() -> Result<()> {
    let config = PluginConfig {
        event_ring_path: "/tmp/test_monad_events".to_string(),
        buffer_size: 256,
        timeout_ms: 500,
    };

    let consumer = initialize_plugin(config).await?;
    // Just verify we can create the consumer without errors
    // In a real test, we would verify it can consume events

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
