//! Account abstraction transactions (type 0x79): the signed calls run as children of the root
//! call, grouped in phases, and a phase that fails is rolled back after its calls returned.

use alloy_primitives::{Address, Bytes, B256, U256};
use firehose_tracer::pb::sf::ethereum::r#type::v2 as pbeth;
use firehose_tracer::types::LogData;
use firehose_tracer_test::{
    alice_addr, failed_receipt, failed_receipt_with_logs, success_receipt, test_aa_trx,
    BlockInvariants, TracerTester,
};

#[derive(Debug)]
struct Reverted;

impl std::fmt::Display for Reverted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("execution reverted")
    }
}

impl std::error::Error for Reverted {}

fn target(byte: u8) -> Address {
    Address::repeat_byte(byte)
}

fn nonce_manager() -> Address {
    alloy_primitives::address!("0x813000000000000000000000000000000000aa01")
}

fn call_indexes(trx: &pbeth::TransactionTrace) -> Vec<Vec<u32>> {
    trx.aa_trx_input
        .as_ref()
        .expect("aa_trx_input is set")
        .phases
        .iter()
        .map(|phase| phase.calls.iter().map(|call| call.call_index).collect())
        .collect()
}

fn state_reverted(trx: &pbeth::TransactionTrace) -> Vec<bool> {
    trx.calls.iter().map(|call| call.state_reverted).collect()
}

#[test]
fn failed_phase_reverts_its_calls_and_keeps_committed_ones() {
    // Phases [[a], [b, c, d], [e]]: `b` calls `f` and succeeds, `c` reverts, so phase 1 is
    // rolled back with `b` and `f`, `d` never runs and phase 2 is skipped.
    let (a, b, c, d, e, f) = (
        target(0xa1),
        target(0xb1),
        target(0xc1),
        target(0xd1),
        target(0xe1),
        target(0xf1),
    );
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_aa_trx(vec![vec![a], vec![b, c, d], vec![e]]))
        .balance_change(
            alice_addr(),
            U256::from(1_000_000),
            U256::from(980_000),
            pbeth::balance_change::Reason::GasBuy,
        )
        .nonce_change(alice_addr(), 0, 1)
        .start_call(alice_addr(), alice_addr(), U256::ZERO, 100_000, vec![0x79])
        .log(nonce_manager(), vec![B256::repeat_byte(0x01)], vec![], 0)
        .start_call(alice_addr(), a, U256::ZERO, 90_000, vec![])
        .end_call(vec![], 1_000)
        .start_call(alice_addr(), b, U256::ZERO, 80_000, vec![])
        .log(b, vec![B256::repeat_byte(0x02)], vec![], 1)
        .start_call(b, f, U256::ZERO, 70_000, vec![])
        .end_call(vec![], 1_000)
        .end_call(vec![], 2_000)
        .start_call(alice_addr(), c, U256::ZERO, 60_000, vec![])
        .end_call_failed(vec![], 1_000, &Reverted, true)
        .end_call_failed(vec![], 30_000, &Reverted, true)
        .balance_change(
            alice_addr(),
            U256::from(980_000),
            U256::from(990_000),
            pbeth::balance_change::Reason::GasRefund,
        )
        .aa_committed_phases(1)
        .end_block_trx(
            Some(failed_receipt_with_logs(
                30_000,
                vec![LogData {
                    address: nonce_manager(),
                    topics: vec![B256::repeat_byte(0x01)],
                    data: Bytes::new(),
                    block_index: 0,
                }],
            )),
            None,
            None,
        )
        .validate(|block| {
            BlockInvariants::assert(block).expect("block invariants hold");
            let trx = &block.transaction_traces[0];

            assert_eq!(pbeth::transaction_trace::Type::TrxTypeAa as i32, trx.r#type);
            assert_eq!(pbeth::TransactionTraceStatus::Failed as i32, trx.status);
            assert_eq!(
                Some(1),
                trx.receipt
                    .as_ref()
                    .and_then(|r| r.aa_trx_output.as_ref())
                    .map(|o| o.committed_phases)
            );

            // Calls: #1 root, #2 a, #3 b, #4 f (under b), #5 c.
            assert_eq!(vec![vec![2], vec![3, 5, 0], vec![0]], call_indexes(trx));
            assert_eq!(vec![false, false, true, true, true], state_reverted(trx));

            let root = &trx.calls[0];
            assert!(
                !root.status_failed && !root.status_reverted,
                "root call is never failed"
            );
            assert!(root.failure_reason.is_empty());
            let reasons: Vec<i32> = root.balance_changes.iter().map(|bc| bc.reason).collect();
            assert_eq!(
                vec![
                    pbeth::balance_change::Reason::GasBuy as i32,
                    pbeth::balance_change::Reason::GasRefund as i32
                ],
                reasons
            );
            assert_eq!(1, root.nonce_changes.len());
            assert_eq!(
                1,
                root.logs.len(),
                "the protocol log written before the root call"
            );
            assert_eq!(1, trx.receipt.as_ref().unwrap().logs.len());
            assert_eq!(
                0, trx.calls[2].logs[0].block_index,
                "b's log is reverted with phase 1"
            );

            // `b` succeeded on its own: only the phase rollback reverts it.
            assert!(!trx.calls[2].status_failed);
            assert!(trx.calls[4].status_reverted);
        });
}

#[test]
fn committed_phases_link_every_call() {
    let (a, b) = (target(0xa1), target(0xb1));
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_aa_trx(vec![vec![a], vec![b]]))
        .start_call(alice_addr(), alice_addr(), U256::ZERO, 100_000, vec![0x79])
        .start_call(alice_addr(), a, U256::ZERO, 90_000, vec![])
        .end_call(vec![], 1_000)
        .start_call(alice_addr(), b, U256::ZERO, 80_000, vec![])
        .end_call(vec![], 1_000)
        .end_call(vec![], 30_000)
        .aa_committed_phases(2)
        .end_block_trx(Some(success_receipt(30_000)), None, None)
        .validate(|block| {
            let trx = &block.transaction_traces[0];

            assert_eq!(pbeth::TransactionTraceStatus::Succeeded as i32, trx.status);
            assert_eq!(vec![vec![2], vec![3]], call_indexes(trx));
            assert_eq!(vec![false, false, false], state_reverted(trx));
        });
}

#[test]
fn phase_refused_before_its_first_call_has_no_executed_call() {
    // The protocol refuses to dispatch phase 1's only call (for example, the actor policy blocks
    // it), so it fails without a frame and the receipt counts one committed phase.
    let (a, b) = (target(0xa1), target(0xb1));
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_aa_trx(vec![vec![a], vec![b]]))
        .start_call(alice_addr(), alice_addr(), U256::ZERO, 100_000, vec![0x79])
        .start_call(alice_addr(), a, U256::ZERO, 90_000, vec![])
        .end_call(vec![], 1_000)
        .end_call_failed(vec![], 30_000, &Reverted, true)
        .aa_committed_phases(1)
        .end_block_trx(Some(failed_receipt(30_000)), None, None)
        .validate(|block| {
            let trx = &block.transaction_traces[0];

            assert_eq!(pbeth::TransactionTraceStatus::Failed as i32, trx.status);
            assert_eq!(vec![vec![2], vec![0]], call_indexes(trx));
            assert_eq!(vec![false, false], state_reverted(trx));
        });
}

#[test]
#[should_panic(expected = "set_aa_trx_output must be called before on_tx_end")]
fn missing_receipt_output_panics() {
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_aa_trx(vec![vec![target(0xa1)]]))
        .start_call(alice_addr(), alice_addr(), U256::ZERO, 100_000, vec![0x79])
        .start_call(alice_addr(), target(0xa1), U256::ZERO, 90_000, vec![])
        .end_call(vec![], 1_000)
        .end_call(vec![], 30_000)
        .end_block_trx(Some(success_receipt(30_000)), None, None);
}

#[test]
#[should_panic(expected = "committed phase 1 of account abstraction transaction has a call")]
fn committed_phase_without_its_calls_panics() {
    let mut tester = TracerTester::new();
    tester
        .start_block_trx(test_aa_trx(vec![vec![target(0xa1)], vec![target(0xb1)]]))
        .start_call(alice_addr(), alice_addr(), U256::ZERO, 100_000, vec![0x79])
        .start_call(alice_addr(), target(0xa1), U256::ZERO, 90_000, vec![])
        .end_call(vec![], 1_000)
        .end_call(vec![], 30_000)
        .aa_committed_phases(2)
        .end_block_trx(Some(success_receipt(30_000)), None, None);
}
