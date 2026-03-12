use firehose_test::TracerTester;

#[test]
fn test_simple_block_builder() {
    let mut tester = TracerTester::new();
    tester
        .start_block()
        .end_block(None)
        .validate_with_category("simpleblocktest", |block| {
            assert_eq!(block.number, 100, "Block number should be 100");
        });
}
