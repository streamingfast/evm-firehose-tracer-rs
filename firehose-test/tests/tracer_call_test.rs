use firehose_test::{alice_addr, bob_addr, success_receipt, test_legacy_trx, TracerTester};
use pb::sf::ethereum::r#type::v2::CallType;

#[test]
fn test_simple_call() {
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::from(100),
            21000,
            vec![],
        )
        .end_call(vec![], 21000)
        .end_block_trx(Some(success_receipt(21000)), None, None)
        .validate_with_category("call", |block| {
            assert_eq!(
                1,
                block.transaction_traces.len(),
                "Should have 1 transaction trace"
            );
            let trx = &block.transaction_traces[0];
            assert_eq!(1, trx.calls.len(), "Should have one call");

            let call = &trx.calls[0];
            assert_eq!(CallType::Call as i32, call.call_type, "Should be CALL type");
            assert_eq!(alice_addr().as_slice(), call.caller.as_slice());
            assert_eq!(bob_addr().as_slice(), call.address.as_slice());
            assert_eq!(0, call.depth, "Root call should have depth 0");
            assert_eq!(21000, call.gas_limit);
        });
}
