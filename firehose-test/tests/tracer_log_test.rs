use alloy_primitives::Bytes;
use firehose::LogData;
use firehose_test::{
    alice_addr, bob_addr, charlie_addr, hash32, receipt_with_logs, test_legacy_trx, TracerTester,
};

#[test]
fn test_log_with_0_topics() {
    // Log with no topics (anonymous event)
    let data = vec![0x01, 0x02, 0x03, 0x04];
    let topics: Vec<alloy_primitives::B256> = vec![];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .log(bob_addr(), topics.clone(), data.clone(), 0)
        .end_call(vec![], 90000)
        .end_block_trx(
            Some(receipt_with_logs(
                100000,
                vec![LogData {
                    address: bob_addr(),
                    topics: topics.clone(),
                    data: Bytes::from(data.clone()),
                    block_index: 0,
                }],
            )),
            None,
            None,
        )
        .validate_with_category("onlog", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.logs.len(), "Should have 1 log");
            let log = &call.logs[0];
            assert_eq!(bob_addr().as_slice(), log.address.as_slice());
            assert_eq!(0, log.topics.len());
            assert_eq!(data, log.data);
            assert_eq!(0, log.index);
            assert_eq!(0, log.block_index);
        });
}

#[test]
fn test_log_with_1_topic() {
    // Log with 1 topic (common for simple events)
    let data = vec![0x01, 0x02];
    let topics = vec![hash32(100)];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .log(bob_addr(), topics.clone(), data.clone(), 0)
        .end_call(vec![], 90000)
        .end_block_trx(
            Some(receipt_with_logs(
                100000,
                vec![LogData {
                    address: bob_addr(),
                    topics: topics.clone(),
                    data: Bytes::from(data.clone()),
                    block_index: 0,
                }],
            )),
            None,
            None,
        )
        .validate_with_category("onlog", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.logs.len(), "Should have 1 log");
            let log = &call.logs[0];
            assert_eq!(1, log.topics.len(), "Should have 1 topic");
            assert_eq!(topics[0].as_slice(), log.topics[0].as_slice());
        });
}

#[test]
fn test_log_with_2_topics() {
    // Log with 2 topics (indexed event with 1 indexed parameter)
    let data = vec![0x01, 0x02];
    let topics = vec![hash32(100), hash32(200)];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .log(bob_addr(), topics.clone(), data.clone(), 0)
        .end_call(vec![], 90000)
        .end_block_trx(
            Some(receipt_with_logs(
                100000,
                vec![LogData {
                    address: bob_addr(),
                    topics: topics.clone(),
                    data: Bytes::from(data.clone()),
                    block_index: 0,
                }],
            )),
            None,
            None,
        )
        .validate_with_category("onlog", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.logs.len(), "Should have 1 log");
            let log = &call.logs[0];
            assert_eq!(2, log.topics.len(), "Should have 2 topics");
            assert_eq!(topics[0].as_slice(), log.topics[0].as_slice());
            assert_eq!(topics[1].as_slice(), log.topics[1].as_slice());
        });
}

#[test]
fn test_log_with_3_topics() {
    // Log with 3 topics (indexed event with 2 indexed parameters)
    let data = vec![0x01, 0x02];
    let topics = vec![hash32(100), hash32(200), hash32(300)];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .log(bob_addr(), topics.clone(), data.clone(), 0)
        .end_call(vec![], 90000)
        .end_block_trx(
            Some(receipt_with_logs(
                100000,
                vec![LogData {
                    address: bob_addr(),
                    topics: topics.clone(),
                    data: Bytes::from(data.clone()),
                    block_index: 0,
                }],
            )),
            None,
            None,
        )
        .validate_with_category("onlog", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.logs.len(), "Should have 1 log");
            let log = &call.logs[0];
            assert_eq!(3, log.topics.len(), "Should have 3 topics");
            assert_eq!(topics[0].as_slice(), log.topics[0].as_slice());
            assert_eq!(topics[1].as_slice(), log.topics[1].as_slice());
            assert_eq!(topics[2].as_slice(), log.topics[2].as_slice());
        });
}

#[test]
fn test_log_with_4_topics() {
    // Log with 4 topics (maximum - indexed event with 3 indexed parameters)
    let data = vec![0x01, 0x02];
    let topics = vec![hash32(100), hash32(200), hash32(300), hash32(400)];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .log(bob_addr(), topics.clone(), data.clone(), 0)
        .end_call(vec![], 90000)
        .end_block_trx(
            Some(receipt_with_logs(
                100000,
                vec![LogData {
                    address: bob_addr(),
                    topics: topics.clone(),
                    data: Bytes::from(data.clone()),
                    block_index: 0,
                }],
            )),
            None,
            None,
        )
        .validate_with_category("onlog", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.logs.len());
            let log = &call.logs[0];
            assert_eq!(4, log.topics.len());
            assert_eq!(topics[0].as_slice(), log.topics[0].as_slice());
            assert_eq!(topics[1].as_slice(), log.topics[1].as_slice());
            assert_eq!(topics[2].as_slice(), log.topics[2].as_slice());
            assert_eq!(topics[3].as_slice(), log.topics[3].as_slice());
        });
}

#[test]
fn test_multiple_logs_per_call() {
    // Multiple logs in same call
    let data1 = vec![0x01];
    let data2 = vec![0x02];
    let data3 = vec![0x03];
    let topics1 = vec![hash32(100)];
    let topics2 = vec![hash32(200)];
    let topics3 = vec![hash32(300)];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .log(bob_addr(), topics1.clone(), data1.clone(), 0)
        .log(bob_addr(), topics2.clone(), data2.clone(), 1)
        .log(bob_addr(), topics3.clone(), data3.clone(), 2)
        .end_call(vec![], 90000)
        .end_block_trx(
            Some(receipt_with_logs(
                100000,
                vec![
                    LogData {
                        address: bob_addr(),
                        topics: topics1.clone(),
                        data: Bytes::from(data1.clone()),
                        block_index: 0,
                    },
                    LogData {
                        address: bob_addr(),
                        topics: topics2.clone(),
                        data: Bytes::from(data2.clone()),
                        block_index: 1,
                    },
                    LogData {
                        address: bob_addr(),
                        topics: topics3.clone(),
                        data: Bytes::from(data3.clone()),
                        block_index: 2,
                    },
                ],
            )),
            None,
            None,
        )
        .validate_with_category("onlog", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(3, call.logs.len(), "Should have 3 logs");

            // Verify index incrementing
            assert_eq!(0, call.logs[0].index);
            assert_eq!(1, call.logs[1].index);
            assert_eq!(2, call.logs[2].index);

            // Verify ordinals are increasing
            assert!(call.logs[0].ordinal < call.logs[1].ordinal);
            assert!(call.logs[1].ordinal < call.logs[2].ordinal);
        });
}

#[test]
fn test_logs_across_multiple_calls() {
    // Logs in nested calls
    let data1 = vec![0x01];
    let data2 = vec![0x02];
    let topics1 = vec![hash32(100)];
    let topics2 = vec![hash32(200)];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            200000,
            vec![],
        )
        .log(bob_addr(), topics1.clone(), data1.clone(), 0)
        .start_call(
            bob_addr(),
            charlie_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .log(charlie_addr(), topics2.clone(), data2.clone(), 1)
        .end_call(vec![], 90000)
        .end_call(vec![], 180000)
        .end_block_trx(
            Some(receipt_with_logs(
                200000,
                vec![
                    LogData {
                        address: bob_addr(),
                        topics: topics1.clone(),
                        data: Bytes::from(data1.clone()),
                        block_index: 0,
                    },
                    LogData {
                        address: charlie_addr(),
                        topics: topics2.clone(),
                        data: Bytes::from(data2.clone()),
                        block_index: 1,
                    },
                ],
            )),
            None,
            None,
        )
        .validate_with_category("onlog", |block| {
            let trx = &block.transaction_traces[0];

            // Root call has 1 log
            assert_eq!(1, trx.calls[0].logs.len());
            assert_eq!(0, trx.calls[0].logs[0].index);
            assert_eq!(0, trx.calls[0].logs[0].block_index);

            // Nested call has 1 log
            assert_eq!(1, trx.calls[1].logs.len());
            assert_eq!(1, trx.calls[1].logs[0].index);
            assert_eq!(1, trx.calls[1].logs[0].block_index);
        });
}

#[test]
fn test_log_with_empty_data() {
    // Log with no data (only topics)
    let empty_data = vec![];
    let topics = vec![hash32(100)];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .log(bob_addr(), topics.clone(), empty_data.clone(), 0)
        .end_call(vec![], 90000)
        .end_block_trx(
            Some(receipt_with_logs(
                100000,
                vec![LogData {
                    address: bob_addr(),
                    topics: topics.clone(),
                    data: Bytes::from(empty_data.clone()),
                    block_index: 0,
                }],
            )),
            None,
            None,
        )
        .validate_with_category("onlog", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.logs.len());
            let log = &call.logs[0];
            assert_eq!(1, log.topics.len());
            assert_eq!(0, log.data.len());
        });
}

#[test]
fn test_log_with_large_data() {
    // Log with large data payload
    let mut large_data = vec![0u8; 1024];
    for (i, byte) in large_data.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    let topics = vec![hash32(100)];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .log(bob_addr(), topics.clone(), large_data.clone(), 0)
        .end_call(vec![], 90000)
        .end_block_trx(
            Some(receipt_with_logs(
                100000,
                vec![LogData {
                    address: bob_addr(),
                    topics: topics.clone(),
                    data: Bytes::from(large_data.clone()),
                    block_index: 0,
                }],
            )),
            None,
            None,
        )
        .validate_with_category("onlog", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.logs.len());
            let log = &call.logs[0];
            assert_eq!(large_data, log.data);
            assert_eq!(1024, log.data.len());
        });
}

#[test]
fn test_log_topic_conversion() {
    use alloy_primitives::B256;
    // Verify topic bytes are correctly converted
    let topic1 = B256::from([
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let topic2 = B256::from([
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let topics = vec![topic1, topic2];
    let data = vec![0x01];

    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_legacy_trx())
        .start_call(
            alice_addr(),
            bob_addr(),
            alloy_primitives::U256::ZERO,
            100000,
            vec![],
        )
        .log(bob_addr(), topics.clone(), data.clone(), 0)
        .end_call(vec![], 90000)
        .end_block_trx(
            Some(receipt_with_logs(
                100000,
                vec![LogData {
                    address: bob_addr(),
                    topics: topics.clone(),
                    data: Bytes::from(data.clone()),
                    block_index: 0,
                }],
            )),
            None,
            None,
        )
        .validate_with_category("onlog", |block| {
            let trx = &block.transaction_traces[0];
            let call = &trx.calls[0];

            assert_eq!(1, call.logs.len());
            let log = &call.logs[0];
            assert_eq!(2, log.topics.len());

            // Verify exact byte conversion
            assert_eq!(topic1.as_slice(), log.topics[0].as_slice());
            assert_eq!(topic2.as_slice(), log.topics[1].as_slice());
        });
}
