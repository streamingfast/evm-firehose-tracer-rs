//! Tests for the common `panic_invalid_state` reporting path.
//!
//! Every invalid-state / broken-invariant panic in the tracer is routed through
//! a single method that enriches the message with the position we were at (block,
//! transaction, call) plus a snapshot of the boolean state flags. These tests lock
//! in that enrichment so the debuggability never silently regresses.

use firehose_tracer_test::{test_block, test_legacy_trx, TracerTester};

/// Runs `f`, expecting it to panic, and returns the panic payload as a string.
/// The default panic hook is muted for the duration so the (expected) panic does
/// not pollute the test output.
fn capture_panic(f: impl FnOnce()) -> String {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(previous_hook);

    let payload = result.expect_err("expected the call to panic but it did not");
    payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .expect("panic payload was not a string")
        .to_string()
}

#[test]
fn panic_invalid_state_reports_state_flags_without_block() {
    // Fresh, initialized tracer that is not in any block: the guard must still
    // report the boolean state flags so the failure is self-describing.
    let tester = TracerTester::new();

    let message = capture_panic(|| {
        tester.tracer.ensure_in_block();
    });

    assert!(
        message.contains("caller expected to be in block state but we were not"),
        "got: {message}"
    );
    assert!(message.contains("init=true"), "got: {message}");
    assert!(message.contains("in_block=false"), "got: {message}");
    assert!(message.contains("in_transaction=false"), "got: {message}");
    // The caller location must point at the failing guard, not at the common sink.
    assert!(message.contains("caller="), "got: {message}");
}

#[test]
fn panic_invalid_state_reports_block_and_transaction_context() {
    // Drive the tracer into block + transaction state, then trip a guard so we can
    // assert the panic carries the block number/hash and the transaction.
    let mut tester = TracerTester::new();
    tester.start_block_trx(test_legacy_trx());

    let message = capture_panic(|| {
        // OnSkippedBlock while in a transaction is an invalid state.
        tester.tracer.on_skipped_block(test_block());
    });

    assert!(
        message.contains("skipped blocks must have 0 transactions"),
        "got: {message}"
    );
    assert!(message.contains("at block #"), "got: {message}");
    assert!(message.contains("in transaction "), "got: {message}");
    assert!(message.contains("in_block=true"), "got: {message}");
    assert!(message.contains("in_transaction=true"), "got: {message}");
}
