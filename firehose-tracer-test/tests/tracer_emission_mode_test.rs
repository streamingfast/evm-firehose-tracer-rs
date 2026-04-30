// Tests for EmissionMode: Blocking, Async, Auto, cursor file, and ShutdownHandle.

use firehose_tracer::config::{ChainConfig, Config, EmissionMode};
use firehose_tracer::{InMemoryBuffer, Tracer};
use firehose_tracer_test::{parse_firehose_block_entries, test_block};
use std::time::Duration;

// ============================================================================
// Helpers
// ============================================================================

/// Build a tracer backed by an in-memory buffer with the given emission mode.
///
/// Returns `(tracer, buffer)`.  The tracer has already received `on_blockchain_init`.
fn make_tracer(mode: EmissionMode) -> (Tracer, InMemoryBuffer) {
    let config = Config::new().with_emission_mode(mode);
    let buffer = InMemoryBuffer::new();
    let mut tracer = Tracer::new_with_writer(config, Box::new(buffer.clone()));
    tracer.on_blockchain_init("test", "1.0.0", ChainConfig::new(1));
    (tracer, buffer)
}

/// Clone the test_block and change the block number.
fn block_with_number(number: u64) -> firehose_tracer::types::BlockEvent {
    let mut event = test_block();
    event.block.number = number;
    event
}

// ============================================================================
// Blocking mode – existing behaviour must be byte-identical
// ============================================================================

#[test]
fn test_blocking_mode_emits_block() {
    let (mut tracer, buffer) = make_tracer(EmissionMode::Blocking);

    tracer.on_block_start(test_block());
    tracer.on_block_end(None);

    let output = buffer.get_bytes();
    let entries = parse_firehose_block_entries(&output);
    assert_eq!(1, entries.len(), "should emit exactly one block");
    assert_eq!(100, entries[0].block_num);
}

#[test]
fn test_blocking_mode_multiple_blocks_in_order() {
    let (mut tracer, buffer) = make_tracer(EmissionMode::Blocking);

    for block_num in [100u64, 101, 102] {
        tracer.on_block_start(block_with_number(block_num));
        tracer.on_block_end(None);
    }

    let output = buffer.get_bytes();
    let entries = parse_firehose_block_entries(&output);
    assert_eq!(3, entries.len());
    assert_eq!(100, entries[0].block_num);
    assert_eq!(101, entries[1].block_num);
    assert_eq!(102, entries[2].block_num);
}

// ============================================================================
// Async mode – blocks must arrive in order, no drops
// ============================================================================

#[test]
fn test_async_mode_emits_block_after_drain() {
    let (mut tracer, buffer) = make_tracer(EmissionMode::Async {
        channel_capacity: 32,
    });

    tracer.on_block_start(test_block());
    tracer.on_block_end(None);

    // Drop the tracer to drain the background thread before reading the buffer.
    drop(tracer);

    let output = buffer.get_bytes();
    let entries = parse_firehose_block_entries(&output);
    assert_eq!(1, entries.len(), "should emit exactly one block");
    assert_eq!(100, entries[0].block_num);
}

#[test]
fn test_async_mode_multiple_blocks_in_order() {
    let (mut tracer, buffer) = make_tracer(EmissionMode::Async {
        channel_capacity: 32,
    });

    for block_num in [200u64, 201, 202, 203, 204] {
        tracer.on_block_start(block_with_number(block_num));
        tracer.on_block_end(None);
    }

    drop(tracer); // drain

    let output = buffer.get_bytes();
    let entries = parse_firehose_block_entries(&output);
    assert_eq!(5, entries.len(), "all 5 blocks must be emitted");
    for (i, expected_num) in [200u64, 201, 202, 203, 204].iter().enumerate() {
        assert_eq!(
            *expected_num, entries[i].block_num,
            "block {i} out of order"
        );
    }
}

#[test]
fn test_async_mode_shutdown_handle_drain() {
    let (mut tracer, buffer) = make_tracer(EmissionMode::Async {
        channel_capacity: 32,
    });

    // Emit a block first.
    tracer.on_block_start(test_block());
    tracer.on_block_end(None);

    // Obtain a shutdown handle after emitting blocks (this moves the sender out of the tracer).
    let handle = tracer
        .shutdown_handle()
        .expect("should have a handle for Async mode");

    // Drain via the handle – this must wait for all blocks to be written.
    handle.drain();

    let output = buffer.get_bytes();
    let entries = parse_firehose_block_entries(&output);
    assert_eq!(1, entries.len());
    assert_eq!(100, entries[0].block_num);
}

#[test]
fn test_blocking_mode_shutdown_handle_is_none() {
    let (mut tracer, _buffer) = make_tracer(EmissionMode::Blocking);
    assert!(
        tracer.shutdown_handle().is_none(),
        "Blocking mode must not return a shutdown handle"
    );
}

// ============================================================================
// Cursor file
// ============================================================================

#[test]
fn test_cursor_file_written_on_blocking_mode() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let cursor_path = tmp_dir.path().join("cursor.txt");

    let config = Config::new()
        .with_emission_mode(EmissionMode::Blocking)
        .with_cursor_path(cursor_path.clone());

    let buffer = InMemoryBuffer::new();
    let mut tracer = Tracer::new_with_writer(config, Box::new(buffer.clone()));
    tracer.on_blockchain_init("test", "1.0.0", ChainConfig::new(1));

    tracer.on_block_start(test_block()); // block 100
    tracer.on_block_end(None);

    // Cursor should be updated synchronously in blocking mode.
    let content = std::fs::read_to_string(&cursor_path).expect("cursor file must exist");
    assert_eq!("100\n", content);
}

#[test]
fn test_cursor_file_written_on_async_mode() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let cursor_path = tmp_dir.path().join("cursor.txt");

    let config = Config::new()
        .with_emission_mode(EmissionMode::Async {
            channel_capacity: 32,
        })
        .with_cursor_path(cursor_path.clone());

    let buffer = InMemoryBuffer::new();
    let mut tracer = Tracer::new_with_writer(config, Box::new(buffer.clone()));
    tracer.on_blockchain_init("test", "1.0.0", ChainConfig::new(1));

    tracer.on_block_start(test_block()); // block 100
    tracer.on_block_end(None);

    // Drop tracer to drain the background thread – cursor must be written by then.
    drop(tracer);

    let content = std::fs::read_to_string(&cursor_path).expect("cursor file must exist");
    assert_eq!("100\n", content);
}

#[test]
fn test_last_confirmed_block_returns_none_when_no_cursor() {
    let (tracer, _buffer) = make_tracer(EmissionMode::Blocking);
    assert_eq!(None, tracer.last_confirmed_block());
}

#[test]
fn test_last_confirmed_block_returns_correct_value() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let cursor_path = tmp_dir.path().join("cursor.txt");

    let config = Config::new()
        .with_emission_mode(EmissionMode::Blocking)
        .with_cursor_path(cursor_path.clone());

    let buffer = InMemoryBuffer::new();
    let mut tracer = Tracer::new_with_writer(config, Box::new(buffer.clone()));
    tracer.on_blockchain_init("test", "1.0.0", ChainConfig::new(1));

    // No block yet → None
    assert_eq!(None, tracer.last_confirmed_block());

    tracer.on_block_start(test_block()); // block 100
    tracer.on_block_end(None);

    assert_eq!(Some(100), tracer.last_confirmed_block());

    // Simulate restart: create a new tracer pointing at the same cursor file.
    let config2 = Config::new()
        .with_emission_mode(EmissionMode::Blocking)
        .with_cursor_path(cursor_path.clone());
    let buffer2 = InMemoryBuffer::new();
    let tracer2 = Tracer::new_with_writer(config2, Box::new(buffer2));
    assert_eq!(
        Some(100),
        tracer2.last_confirmed_block(),
        "last_confirmed_block should survive restart via cursor file"
    );
}

// ============================================================================
// Auto mode
// ============================================================================

#[test]
fn test_auto_mode_uses_blocking_for_live_blocks() {
    // A block with a timestamp very close to now should take the Blocking path.
    // We verify this by checking that the block is immediately visible in the
    // buffer (no async thread involved).
    let (mut tracer, buffer) = make_tracer(EmissionMode::Auto {
        channel_capacity: 32,
        live_threshold: Duration::from_secs(60),
    });

    // Use a block timestamp close to now (within live_threshold).
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut event = test_block();
    event.block.time = now_secs; // live tip
    tracer.on_block_start(event);
    tracer.on_block_end(None);

    // Should be immediately visible (blocking path).
    let output = buffer.get_bytes();
    let entries = parse_firehose_block_entries(&output);
    assert_eq!(1, entries.len(), "live block must be emitted synchronously");
}

#[test]
fn test_auto_mode_uses_async_for_historical_blocks() {
    // A block with a timestamp older than live_threshold should take the Async path.
    let (mut tracer, buffer) = make_tracer(EmissionMode::Auto {
        channel_capacity: 32,
        live_threshold: Duration::from_secs(60),
    });

    let mut event = test_block();
    // A block from a year ago is definitely historical.
    event.block.time = 1_000_000_000; // Jan 2001
    tracer.on_block_start(event);
    tracer.on_block_end(None);

    // Drop to drain the background thread.
    drop(tracer);

    let output = buffer.get_bytes();
    let entries = parse_firehose_block_entries(&output);
    assert_eq!(
        1,
        entries.len(),
        "historical block must be emitted via async path"
    );
}
