use firehose_tracer::call_data_limit::{MAX_CALL_INPUT_BYTES_PER_TX, MAX_RETURN_DATA_BYTES_PER_TX};
use firehose_tracer_test::{alice_addr, bob_addr, success_receipt, test_legacy_trx, TracerTester};

const MIB: usize = 1024 * 1024;

/// Traces one transaction whose root call makes `count` sibling internal calls, each with
/// `input_len` bytes of input and `return_len` bytes of return data.
fn trace_internal_calls(
    tester: &mut TracerTester,
    count: usize,
    input_len: usize,
    return_len: usize,
) {
    tester.start_trx(test_legacy_trx()).start_call(
        alice_addr(),
        bob_addr(),
        alloy_primitives::U256::ZERO,
        1_000_000,
        vec![0x01; 256],
    );
    for _ in 0..count {
        tester
            .start_call(
                bob_addr(),
                alice_addr(),
                alloy_primitives::U256::ZERO,
                1_000,
                vec![0xab; input_len],
            )
            .end_call(vec![0xcd; return_len], 1_000);
    }
    tester
        .end_call(vec![0x02; 256], 1_000_000)
        .end_trx(Some(success_receipt(1_000_000)), None);
}

#[test]
fn test_internal_calls_past_the_transaction_limits_are_truncated() {
    let calls = MAX_CALL_INPUT_BYTES_PER_TX / MIB + 2;
    let mut tester = TracerTester::new();
    tester.start_block();
    trace_internal_calls(&mut tester, calls, MIB, MIB);
    // The next transaction starts with fresh limits.
    trace_internal_calls(&mut tester, 1, MIB, MIB);
    tester.end_block(None);

    tester.validate(|block| {
        let trx = &block.transaction_traces[0];
        let root = &trx.calls[0];
        assert_eq!((root.input.len(), root.return_data.len()), (256, 256));
        assert!(!root.input_truncated && !root.return_data_truncated);

        let internal = &trx.calls[1..];
        assert_eq!(internal.len(), calls);
        let full_inputs = MAX_CALL_INPUT_BYTES_PER_TX / MIB;
        let full_return_data = MAX_RETURN_DATA_BYTES_PER_TX / MIB;
        for (i, call) in internal.iter().enumerate() {
            if i < full_inputs {
                assert_eq!(call.input.len(), MIB, "call {i}");
                assert!(!call.input_truncated, "call {i}");
            } else {
                assert_eq!(call.input, vec![0xab; 4], "call {i}");
                assert!(call.input_truncated, "call {i}");
            }
            if i < full_return_data {
                assert_eq!(call.return_data.len(), MIB, "call {i}");
                assert!(!call.return_data_truncated, "call {i}");
            } else {
                assert!(call.return_data.is_empty(), "call {i}");
                assert!(call.return_data_truncated, "call {i}");
            }
        }

        let next = &block.transaction_traces[1].calls[1];
        assert_eq!((next.input.len(), next.return_data.len()), (MIB, MIB));
        assert!(!next.input_truncated && !next.return_data_truncated);
    });
}
