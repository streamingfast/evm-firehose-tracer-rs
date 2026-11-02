//! A block whose transactions are traced by detached tracers and attached in block order is the
//! block the serial transaction lifecycle produces, whatever order the detached traces complete in.

use alloy_primitives::{Bytes, B256, U256};
use firehose_tracer::pb::sf::ethereum::r#type::v2 as pbeth;
use firehose_tracer::types::{
    BlockEvent, FlashBlockData, LogData, ReceiptData, StringError, TransactionPlacement, TxEvent,
};
use firehose_tracer::Tracer;
use firehose_tracer_test::{
    alice_addr, big_int, bob_addr, charlie_addr, hash32, miner_addr, parse_firehose_block,
    parse_firehose_block_entries, test_block, test_legacy_trx, TracerTester,
};

const GAS_USED: u64 = 50_000;

/// Transaction `index` of the block: a root call that changes a balance and a storage slot, a
/// nested call that emits a log, a nested call that reverts after emitting a log, and a log at
/// the root.
fn transaction(index: u32) -> TxEvent {
    TxEvent {
        hash: hash32(1_000 + index as u64),
        nonce: index as u64,
        index,
        gas: 100_000,
        ..test_legacy_trx()
    }
}

/// Emits the transaction events between `on_tx_start` and the end of the transaction, with the
/// committed logs counted from `log_index_start`, and returns the receipt as the integration
/// builds it for that log offset.
fn trace_transaction(tracer: &mut Tracer, index: u32, log_index_start: u32) -> ReceiptData {
    let caller = alice_addr();
    let contract = bob_addr();
    let other = charlie_addr();
    let slot = hash32(7);
    let topic = hash32(42);
    let data = vec![index as u8; 4];

    tracer.on_call_enter(
        0,
        firehose_tracer::types::Opcode::Call as u8,
        caller,
        contract,
        &[0xde, 0xad],
        90_000,
        U256::ZERO,
    );
    tracer.on_balance_change(
        caller,
        big_int(1_000_000),
        big_int(900_000),
        pbeth::balance_change::Reason::GasBuy,
    );
    tracer.on_nonce_change(caller, index as u64, index as u64 + 1);
    tracer.on_storage_change(contract, slot, B256::ZERO, hash32(index as u64 + 1));

    // Nested call that commits a log.
    tracer.on_call_enter(
        1,
        firehose_tracer::types::Opcode::Call as u8,
        contract,
        other,
        &[],
        50_000,
        U256::ZERO,
    );
    tracer.on_log(other, &[topic], &data, log_index_start);
    tracer.on_call_exit(1, &[], 10_000, None, false);

    // Nested call that reverts: its log is not in the receipt and keeps no block index.
    tracer.on_call_enter(
        1,
        firehose_tracer::types::Opcode::Call as u8,
        contract,
        other,
        &[],
        40_000,
        U256::ZERO,
    );
    tracer.on_log(other, &[topic], &[0xff], log_index_start + 1);
    let revert = StringError("execution reverted".to_string());
    tracer.on_call_exit(1, &[], 5_000, Some(&revert), true);

    tracer.on_log(contract, &[topic], &data, log_index_start + 1);
    tracer.on_call_exit(0, &[], GAS_USED, None, false);

    tracer.on_balance_change(
        miner_addr(),
        big_int(0),
        big_int(GAS_USED as i64),
        pbeth::balance_change::Reason::RewardTransactionFee,
    );

    let mut receipt = ReceiptData::new(index, GAS_USED, 1, GAS_USED * (index as u64 + 1));
    receipt.add_log(LogData::new(
        other,
        vec![topic],
        Bytes::from(data.clone()),
        log_index_start,
    ));
    receipt.add_log(LogData::new(
        contract,
        vec![topic],
        Bytes::from(data),
        log_index_start + 1,
    ));
    receipt
}

/// Pre-execution system call, as the block executor emits it before the transactions.
fn pre_execution_system_call(tracer: &mut Tracer) {
    tracer.on_system_call_start();
    tracer.on_call_enter(
        0,
        firehose_tracer::types::Opcode::Call as u8,
        alice_addr(),
        bob_addr(),
        &[0x01],
        30_000,
        U256::ZERO,
    );
    tracer.on_storage_change(bob_addr(), hash32(1), B256::ZERO, hash32(2));
    tracer.on_call_exit(0, &[], 20_000, None, false);
    tracer.on_system_call_end();
}

/// Serial reference: every transaction on the block tracer, with block-cumulative receipts.
fn serial_block() -> pbeth::Block {
    let (mut tracer, buffer) = TracerTester::new().into_parts();
    tracer.on_block_start(test_block());
    pre_execution_system_call(&mut tracer);
    for index in 0..3u32 {
        tracer.on_tx_start(transaction(index), None);
        let receipt = trace_transaction(&mut tracer, index, index * 2);
        tracer.on_tx_end(Some(&receipt), None);
    }
    tracer.on_balance_change(
        miner_addr(),
        big_int(0),
        big_int(1),
        pbeth::balance_change::Reason::Withdrawal,
    );
    tracer.on_block_end(None);
    parse_firehose_block(&buffer.get_bytes())
}

/// The same block with its transactions traced by two detached tracers, the second transaction
/// completing before the first, and the traces attached in block order.
fn attached_block() -> pbeth::Block {
    let (mut tracer, buffer) = TracerTester::new().into_parts();
    tracer.on_block_start(test_block());
    pre_execution_system_call(&mut tracer);

    let mut first = tracer.detached();
    let mut second = tracer.detached();
    first.on_block_start(test_block());
    second.on_block_start(test_block());

    // The detached tracers see transaction-relative receipts: index 0, their own gas as the
    // cumulative gas, logs counted from 0.
    let trace = |worker: &mut Tracer, index: u32| {
        worker.on_tx_start(transaction(index), None);
        let mut receipt = trace_transaction(worker, index, 0);
        receipt.transaction_index = 0;
        receipt.cumulative_gas_used = GAS_USED;
        worker.on_tx_end_detached(Some(&receipt), None)
    };
    let trx1 = trace(&mut second, 1);
    let trx0 = trace(&mut first, 0);
    let trx2 = trace(&mut first, 2);

    for (index, trx) in [trx0, trx1, trx2].into_iter().enumerate() {
        let index = index as u32;
        tracer.attach_transaction(
            trx,
            TransactionPlacement {
                index,
                cumulative_gas_used: GAS_USED * (index as u64 + 1),
                log_index_start: index * 2,
            },
        );
    }

    tracer.on_balance_change(
        miner_addr(),
        big_int(0),
        big_int(1),
        pbeth::balance_change::Reason::Withdrawal,
    );
    tracer.on_block_end(None);
    parse_firehose_block(&buffer.get_bytes())
}

#[test]
fn attached_transactions_match_the_serial_block() {
    let serial = serial_block();
    let attached = attached_block();

    // The scenario exercises what attaching rebases: three transactions after a system call,
    // nested calls with logs, a reverted call, and a block-level change after the transactions.
    assert_eq!(serial.transaction_traces.len(), 3);
    assert_eq!(serial.system_calls.len(), 1);
    assert_eq!(serial.balance_changes.len(), 1);
    let last = serial.transaction_traces.last().unwrap();
    assert_eq!(last.index, 2);
    assert_eq!(
        last.receipt.as_ref().unwrap().cumulative_gas_used,
        GAS_USED * 3
    );
    assert_eq!(last.receipt.as_ref().unwrap().logs[1].block_index, 5);
    assert_eq!(last.calls.len(), 3);
    assert!(last.calls[2].state_reverted);
    assert_eq!(last.calls[2].logs[0].block_index, 0);
    assert!(serial.balance_changes[0].ordinal > last.end_ordinal);

    assert_eq!(attached, serial);
}

#[test]
fn detached_tracer_never_prints() {
    let (mut tracer, buffer) = TracerTester::new().into_parts();
    tracer.on_block_start(test_block());
    // The block tracer printed its FIRE INIT line; nothing may follow it.
    let printed_before = buffer.get_bytes();
    let mut detached = tracer.detached();
    detached.on_block_start(test_block());
    detached.on_tx_start(transaction(0), None);
    let receipt = trace_transaction(&mut detached, 0, 0);
    let trx = detached.on_tx_end_detached(Some(&receipt), None);
    drop(detached);

    assert_eq!(trx.calls.len(), 3);
    assert_eq!(
        buffer.get_bytes(),
        printed_before,
        "the detached tracer wrote to the output"
    );
}

#[test]
#[should_panic(expected = "attached out of block order")]
fn attaching_out_of_block_order_panics() {
    let (mut tracer, _buffer) = TracerTester::new().into_parts();
    tracer.on_block_start(test_block());
    let mut detached = tracer.detached();
    detached.on_block_start(test_block());
    detached.on_tx_start(transaction(1), None);
    let receipt = trace_transaction(&mut detached, 1, 0);
    let trx = detached.on_tx_end_detached(Some(&receipt), None);

    // The block has no transaction yet, so index 1 is not the next one.
    tracer.attach_transaction(
        trx,
        TransactionPlacement {
            index: 1,
            cumulative_gas_used: GAS_USED,
            log_index_start: 0,
        },
    );
}

fn flash_block_event(idx: u64) -> BlockEvent {
    let mut event = test_block();
    event.flash_block = Some(FlashBlockData {
        idx,
        is_final: false,
    });
    event
}

/// First flashblock iteration of a block, two transactions traced serially, snapshotted for the
/// next iteration.
fn first_flash_block_iteration(tracer: &mut Tracer) {
    tracer.on_block_start(flash_block_event(1));
    for index in 0..2u32 {
        tracer.on_tx_start(transaction(index), None);
        let receipt = trace_transaction(tracer, index, index * 2);
        tracer.on_tx_end(Some(&receipt), None);
    }
    tracer.snapshot_flash_block_for_next_iteration();
    tracer.on_block_end(None);
}

/// The second flashblock iteration runs a fresh executor, whose values restart at 0 for the one
/// transaction it adds. The serial path offsets the receipt's values; attaching must offset the
/// placement the same way.
#[test]
fn attached_transaction_gets_the_flash_block_offsets() {
    let (mut serial_tracer, serial_buffer) = TracerTester::new().into_parts();
    first_flash_block_iteration(&mut serial_tracer);
    serial_tracer.on_block_start(flash_block_event(2));
    serial_tracer.on_tx_start(transaction(2), None);
    let mut receipt = trace_transaction(&mut serial_tracer, 2, 0);
    receipt.transaction_index = 0;
    receipt.cumulative_gas_used = GAS_USED;
    serial_tracer.on_tx_end(Some(&receipt), None);
    serial_tracer.on_block_end(None);

    let (mut tracer, buffer) = TracerTester::new().into_parts();
    first_flash_block_iteration(&mut tracer);
    tracer.on_block_start(flash_block_event(2));
    let mut detached = tracer.detached();
    detached.on_block_start(flash_block_event(2));
    detached.on_tx_start(transaction(2), None);
    let mut receipt = trace_transaction(&mut detached, 2, 0);
    receipt.transaction_index = 0;
    receipt.cumulative_gas_used = GAS_USED;
    let trx = detached.on_tx_end_detached(Some(&receipt), None);
    tracer.attach_transaction(
        trx,
        TransactionPlacement {
            index: 0,
            cumulative_gas_used: GAS_USED,
            log_index_start: 0,
        },
    );
    tracer.on_block_end(None);

    let second_iteration = |bytes: Vec<u8>| {
        let mut entries = parse_firehose_block_entries(&bytes);
        assert_eq!(entries.len(), 2);
        entries.pop().unwrap().block
    };
    let serial = second_iteration(serial_buffer.get_bytes());
    let attached = second_iteration(buffer.get_bytes());

    let last = serial.transaction_traces.last().unwrap();
    assert_eq!(serial.transaction_traces.len(), 3);
    assert_eq!(last.index, 2);
    assert_eq!(
        last.receipt.as_ref().unwrap().cumulative_gas_used,
        GAS_USED * 3
    );
    assert_eq!(last.receipt.as_ref().unwrap().logs[1].block_index, 5);

    assert_eq!(attached, serial);
}
