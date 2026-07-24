//! Content-independent property assertions over a captured Firehose block.
//!
//! These are the always-on floor of a tracing regression suite: they encode block-version-5
//! semantics (no no-op state changes, strictly ordered ordinals, receipt/call log agreement)
//! without pinning a single byte of chain-specific content. Unlike a golden they never need
//! regenerating on an upstream port — a violation is always a real tracing bug.

use std::collections::BTreeMap;

use firehose_tracer::pb::sf::ethereum::r#type::v2::{
    BigInt, Block, Log, TransactionTrace, TransactionTraceStatus,
};

/// The one knob a chain can legitimately need to set.
///
/// Everything else is deliberately not configurable: an invariant with a per-chain escape hatch
/// stops being a floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantConfig {
    /// Block `ver` every emitted block must carry.
    pub expected_block_version: i32,
}

impl Default for InvariantConfig {
    fn default() -> Self {
        Self {
            expected_block_version: 5,
        }
    }
}

/// A single invariant violation found in a captured block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Dotted path of the offending entity, e.g. `tx[1].call#3.log[0]`.
    pub path: String,
    /// Description of what is wrong.
    pub detail: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.detail)
    }
}

/// Property assertions that must hold for every Firehose block regardless of its content.
#[derive(Debug)]
pub struct BlockInvariants;

impl BlockInvariants {
    /// Runs every invariant under the default config and returns the violations found.
    pub fn violations(block: &Block) -> Vec<Violation> {
        Self::violations_with(block, &InvariantConfig::default())
    }

    /// Runs every invariant and returns the violations found, in a stable order.
    pub fn violations_with(block: &Block, config: &InvariantConfig) -> Vec<Violation> {
        let mut out = Vec::new();

        Self::check_block_version(block, config, &mut out);
        Self::check_transaction_indices(block, &mut out);
        Self::check_ordinals_unique(block, &mut out);
        Self::check_log_block_index_dense(block, &mut out);

        for (index, trace) in block.transaction_traces.iter().enumerate() {
            let path = format!("tx[{index}]");
            Self::check_call_tree(&path, trace, &mut out);
            Self::check_call_ordinal_nesting(&path, trace, &mut out);
            Self::check_no_op_changes(&path, trace, &mut out);
            Self::check_receipt_logs(&path, trace, &mut out);
            Self::check_status_consistency(&path, trace, &mut out);
        }

        out
    }

    /// Runs every invariant under the default config, failing with a combined report.
    pub fn assert(block: &Block) -> eyre::Result<()> {
        Self::assert_with(block, &InvariantConfig::default())
    }

    /// Runs every invariant and fails with a combined report if any was violated.
    pub fn assert_with(block: &Block, config: &InvariantConfig) -> eyre::Result<()> {
        let violations = Self::violations_with(block, config);
        if violations.is_empty() {
            return Ok(());
        }

        let report = violations
            .iter()
            .map(|v| format!("  - {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        Err(eyre::eyre!(
            "{} Firehose invariant violation(s) in block #{}:\n{report}",
            violations.len(),
            block.number,
        ))
    }

    /// A silent version downgrade means the mapper lost its version bump.
    fn check_block_version(block: &Block, config: &InvariantConfig, out: &mut Vec<Violation>) {
        if block.ver != config.expected_block_version {
            out.push(Violation {
                path: "block".to_owned(),
                detail: format!(
                    "ver is {} but block version {} is expected",
                    block.ver, config.expected_block_version
                ),
            });
        }
    }

    /// `TransactionTrace.index` must match the transaction's position in the block.
    fn check_transaction_indices(block: &Block, out: &mut Vec<Violation>) {
        for (index, trace) in block.transaction_traces.iter().enumerate() {
            if trace.index as usize != index {
                out.push(Violation {
                    path: format!("tx[{index}]"),
                    detail: format!("index field is {} but position is {index}", trace.index),
                });
            }
        }
    }

    /// Ordinals order every event within a block, so no two events may share one.
    ///
    /// Ordinal `0` is the unset value used by entities the tracer does not order (block-level
    /// genesis balance changes, logs on reverted calls), so it is exempt.
    fn check_ordinals_unique(block: &Block, out: &mut Vec<Violation>) {
        let mut seen: BTreeMap<u64, String> = BTreeMap::new();
        let mut record = |ordinal: u64, path: String, out: &mut Vec<Violation>| {
            if ordinal == 0 {
                return;
            }
            if let Some(previous) = seen.insert(ordinal, path.clone()) {
                out.push(Violation {
                    path,
                    detail: format!("ordinal {ordinal} is already used by {previous}"),
                });
            }
        };

        for (index, trace) in block.transaction_traces.iter().enumerate() {
            let tx = format!("tx[{index}]");
            record(trace.begin_ordinal, format!("{tx}.begin_ordinal"), out);
            record(trace.end_ordinal, format!("{tx}.end_ordinal"), out);

            for call in &trace.calls {
                let call_path = format!("{tx}.call#{}", call.index);
                record(
                    call.begin_ordinal,
                    format!("{call_path}.begin_ordinal"),
                    out,
                );
                record(call.end_ordinal, format!("{call_path}.end_ordinal"), out);
                for (i, log) in call.logs.iter().enumerate() {
                    record(log.ordinal, format!("{call_path}.log[{i}]"), out);
                }
                for (i, change) in call.storage_changes.iter().enumerate() {
                    record(change.ordinal, format!("{call_path}.storage[{i}]"), out);
                }
                for (i, change) in call.balance_changes.iter().enumerate() {
                    record(change.ordinal, format!("{call_path}.balance[{i}]"), out);
                }
                for (i, change) in call.nonce_changes.iter().enumerate() {
                    record(change.ordinal, format!("{call_path}.nonce[{i}]"), out);
                }
                for (i, change) in call.code_changes.iter().enumerate() {
                    record(change.ordinal, format!("{call_path}.code[{i}]"), out);
                }
            }
        }
    }

    /// Every log kept by the chain carries a block-wide index; those indices must be dense.
    fn check_log_block_index_dense(block: &Block, out: &mut Vec<Violation>) {
        let mut indices: Vec<u32> = block
            .transaction_traces
            .iter()
            .flat_map(|trace| trace.receipt.iter().flat_map(|receipt| receipt.logs.iter()))
            .map(|log| log.block_index)
            .collect();
        indices.sort_unstable();

        for (position, block_index) in indices.iter().enumerate() {
            if *block_index as usize != position {
                out.push(Violation {
                    path: "block.receipt_logs".to_owned(),
                    detail: format!(
                        "receipt log block_index sequence is not dense: expected {position} at \
                         sorted position {position}, got {block_index}"
                    ),
                });
                break;
            }
        }
    }

    /// Call indices must be 1-based and dense, and every non-root call must point at a real parent
    /// one level up that appears before it.
    fn check_call_tree(path: &str, trace: &TransactionTrace, out: &mut Vec<Violation>) {
        let depth_by_index: BTreeMap<u32, u32> = trace
            .calls
            .iter()
            .map(|call| (call.index, call.depth))
            .collect();

        for (position, call) in trace.calls.iter().enumerate() {
            let call_path = format!("{path}.call#{}", call.index);
            if call.index as usize != position + 1 {
                out.push(Violation {
                    path: call_path.clone(),
                    detail: format!("index is {} but position is {}", call.index, position + 1),
                });
            }

            if call.parent_index == 0 {
                if call.depth != 0 {
                    out.push(Violation {
                        path: call_path,
                        detail: format!("root call (parent_index 0) has depth {}", call.depth),
                    });
                }
                continue;
            }

            if call.parent_index >= call.index {
                out.push(Violation {
                    path: call_path,
                    detail: format!(
                        "parent_index {} does not point at an earlier call",
                        call.parent_index
                    ),
                });
                continue;
            }

            match depth_by_index.get(&call.parent_index) {
                Some(parent_depth) if *parent_depth + 1 == call.depth => {}
                Some(parent_depth) => out.push(Violation {
                    path: call_path,
                    detail: format!(
                        "depth is {} but parent #{} has depth {parent_depth}",
                        call.depth, call.parent_index
                    ),
                }),
                None => out.push(Violation {
                    path: call_path,
                    detail: format!("parent_index {} does not exist", call.parent_index),
                }),
            }
        }
    }

    /// Everything a call records must happen between the call's begin and end ordinals.
    fn check_call_ordinal_nesting(path: &str, trace: &TransactionTrace, out: &mut Vec<Violation>) {
        for call in &trace.calls {
            let call_path = format!("{path}.call#{}", call.index);
            if call.begin_ordinal == 0 || call.end_ordinal == 0 {
                continue;
            }

            if call.begin_ordinal >= call.end_ordinal {
                out.push(Violation {
                    path: call_path.clone(),
                    detail: format!(
                        "begin_ordinal {} is not before end_ordinal {}",
                        call.begin_ordinal, call.end_ordinal
                    ),
                });
                continue;
            }

            let range = call.begin_ordinal..=call.end_ordinal;
            let check = |ordinal: u64, what: String, out: &mut Vec<Violation>| {
                if ordinal != 0 && !range.contains(&ordinal) {
                    out.push(Violation {
                        path: format!("{call_path}.{what}"),
                        detail: format!(
                            "ordinal {ordinal} is outside the call's [{}, {}] range",
                            call.begin_ordinal, call.end_ordinal
                        ),
                    });
                }
            };

            for (i, log) in call.logs.iter().enumerate() {
                check(log.ordinal, format!("log[{i}]"), out);
            }
            for (i, change) in call.storage_changes.iter().enumerate() {
                check(change.ordinal, format!("storage[{i}]"), out);
            }
            // The root call carries the transaction-level nonce bump, which the tracer orders with
            // the pre-execution gas buy — that is, *before* the root call begins. Only nested calls
            // record nonce changes that must fall inside their own range.
            if call.depth > 0 {
                for (i, change) in call.nonce_changes.iter().enumerate() {
                    check(change.ordinal, format!("nonce[{i}]"), out);
                }
            }
            for (i, change) in call.code_changes.iter().enumerate() {
                check(change.ordinal, format!("code[{i}]"), out);
            }
        }
    }

    /// Block version 5 drops state-change entries whose old and new values are identical.
    fn check_no_op_changes(path: &str, trace: &TransactionTrace, out: &mut Vec<Violation>) {
        for call in &trace.calls {
            let call_path = format!("{path}.call#{}", call.index);

            for (i, change) in call.storage_changes.iter().enumerate() {
                if change.old_value == change.new_value {
                    out.push(Violation {
                        path: format!("{call_path}.storage[{i}]"),
                        detail: "no-op storage change (old_value == new_value)".to_owned(),
                    });
                }
            }

            for (i, change) in call.code_changes.iter().enumerate() {
                if change.old_hash == change.new_hash && change.old_code == change.new_code {
                    out.push(Violation {
                        path: format!("{call_path}.code[{i}]"),
                        detail: "no-op code change (prev == new)".to_owned(),
                    });
                }
            }

            for (i, change) in call.nonce_changes.iter().enumerate() {
                if change.old_value == change.new_value {
                    out.push(Violation {
                        path: format!("{call_path}.nonce[{i}]"),
                        detail: "no-op nonce change (old_value == new_value)".to_owned(),
                    });
                }
            }

            for (i, change) in call.balance_changes.iter().enumerate() {
                if Self::big_int_bytes(change.old_value.as_ref())
                    == Self::big_int_bytes(change.new_value.as_ref())
                {
                    out.push(Violation {
                        path: format!("{call_path}.balance[{i}]"),
                        detail: "no-op balance change (old_value == new_value)".to_owned(),
                    });
                }
            }
        }
    }

    /// Every receipt log must appear in exactly one non-reverted call, and vice versa.
    ///
    /// This is the invariant that native-precompile logs going missing from, or duplicated across,
    /// the call tree shows up as.
    fn check_receipt_logs(path: &str, trace: &TransactionTrace, out: &mut Vec<Violation>) {
        let Some(receipt) = trace.receipt.as_ref() else {
            return;
        };

        let mut call_logs: Vec<&Log> = trace
            .calls
            .iter()
            .filter(|call| !call.state_reverted)
            .flat_map(|call| call.logs.iter())
            .collect();
        call_logs.sort_by_key(|log| log.block_index);

        if call_logs.len() != receipt.logs.len() {
            out.push(Violation {
                path: path.to_owned(),
                detail: format!(
                    "{} log(s) across non-reverted calls but {} log(s) in the receipt",
                    call_logs.len(),
                    receipt.logs.len()
                ),
            });
            return;
        }

        for (i, (call_log, receipt_log)) in call_logs.iter().zip(receipt.logs.iter()).enumerate() {
            if call_log.address != receipt_log.address
                || call_log.topics != receipt_log.topics
                || call_log.data != receipt_log.data
            {
                out.push(Violation {
                    path: format!("{path}.receipt.logs[{i}]"),
                    detail: "receipt log has no matching call log at the same block_index"
                        .to_owned(),
                });
            }
        }
    }

    /// A transaction whose root call failed cannot be reported as succeeded.
    fn check_status_consistency(path: &str, trace: &TransactionTrace, out: &mut Vec<Violation>) {
        let Some(root) = trace.calls.iter().find(|call| call.depth == 0) else {
            return;
        };

        let succeeded = trace.status == TransactionTraceStatus::Succeeded as i32;
        if succeeded && (root.status_failed || root.status_reverted) {
            out.push(Violation {
                path: path.to_owned(),
                detail: format!(
                    "status is SUCCEEDED but the root call reports status_failed={} \
                     status_reverted={}",
                    root.status_failed, root.status_reverted
                ),
            });
        }

        if !succeeded && !root.status_failed && !root.status_reverted {
            out.push(Violation {
                path: path.to_owned(),
                detail: format!(
                    "status is {} but the root call reports neither failure nor revert",
                    Self::status_name(trace.status)
                ),
            });
        }
    }

    /// Normalises a `BigInt` to its minimal big-endian byte form so that leading zeroes and an
    /// absent value all compare equal.
    fn big_int_bytes(value: Option<&BigInt>) -> &[u8] {
        let bytes = value.map_or(&[][..], |v| v.bytes.as_slice());
        let first_significant = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len());
        &bytes[first_significant..]
    }

    /// Renders a `TransactionTraceStatus` discriminant as its protobuf name.
    fn status_name(status: i32) -> &'static str {
        TransactionTraceStatus::try_from(status).map_or("UNKNOWN", |status| status.as_str_name())
    }
}

#[cfg(test)]
mod tests {
    //! The blocks here are built by hand rather than through `TracerTester`: an invariant only
    //! earns its place if it catches a *malformed* block, and the tracer refuses to emit one. Each
    //! test therefore starts from a well-formed block and breaks exactly one thing.

    use firehose_tracer::pb::sf::ethereum::r#type::v2 as pbeth;

    use super::*;

    /// A minimal well-formed block: one succeeded transaction, one root call, one log agreeing with
    /// the receipt, and one storage change.
    fn valid_block() -> pbeth::Block {
        let log = pbeth::Log {
            address: vec![0xbb; 20],
            topics: vec![vec![0x01; 32]],
            data: vec![1, 2, 3],
            index: 0,
            block_index: 0,
            ordinal: 4,
        };

        pbeth::Block {
            number: 100,
            ver: 5,
            transaction_traces: vec![pbeth::TransactionTrace {
                index: 0,
                hash: vec![0xaa; 32],
                status: pbeth::TransactionTraceStatus::Succeeded as i32,
                begin_ordinal: 1,
                end_ordinal: 9,
                receipt: Some(pbeth::TransactionReceipt {
                    logs: vec![log.clone()],
                    ..Default::default()
                }),
                calls: vec![pbeth::Call {
                    index: 1,
                    parent_index: 0,
                    depth: 0,
                    call_type: pbeth::CallType::Call as i32,
                    begin_ordinal: 2,
                    end_ordinal: 8,
                    logs: vec![log],
                    storage_changes: vec![pbeth::StorageChange {
                        address: vec![0xbb; 20],
                        key: vec![0x01; 32],
                        old_value: vec![0x00; 32],
                        new_value: vec![0x02; 32],
                        ordinal: 3,
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// Asserts that some violation's detail contains `expected`.
    fn assert_only_violation(block: &pbeth::Block, expected: &str) {
        let violations = BlockInvariants::violations(block);

        assert!(
            !violations.is_empty(),
            "expected a violation mentioning {expected:?}, found none"
        );
        assert!(
            violations
                .iter()
                .any(|violation| violation.detail.contains(expected)),
            "expected a violation mentioning {expected:?}, got {violations:?}"
        );
    }

    #[test]
    fn a_well_formed_block_has_no_violations() {
        let violations = BlockInvariants::violations(&valid_block());

        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
        assert!(BlockInvariants::assert(&valid_block()).is_ok());
    }

    #[test]
    fn a_wrong_block_version_is_a_violation() {
        let mut block = valid_block();
        block.ver = 4;

        assert_only_violation(&block, "block version 5 is expected");
    }

    #[test]
    fn the_expected_block_version_is_configurable() {
        let mut block = valid_block();
        block.ver = 6;

        let config = InvariantConfig {
            expected_block_version: 6,
        };

        let violations = BlockInvariants::violations_with(&block, &config);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn a_transaction_index_that_disagrees_with_its_position_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0].index = 3;

        assert_only_violation(&block, "index field is 3 but position is 0");
    }

    #[test]
    fn a_reused_ordinal_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0].calls[0].storage_changes[0].ordinal = 4;

        assert_only_violation(&block, "is already used by");
    }

    #[test]
    fn a_zero_ordinal_is_exempt_from_uniqueness() {
        let mut block = valid_block();
        block.transaction_traces[0].calls[0].storage_changes[0].ordinal = 0;

        let violations = BlockInvariants::violations(&block);
        assert!(
            violations.is_empty(),
            "ordinal 0 means unset, not duplicated: {violations:?}"
        );
    }

    #[test]
    fn a_call_recording_something_outside_its_ordinal_range_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0].calls[0].storage_changes[0].ordinal = 42;

        assert_only_violation(&block, "outside the call's [2, 8] range");
    }

    #[test]
    fn the_root_calls_nonce_change_may_precede_the_call() {
        let mut block = valid_block();
        block.transaction_traces[0].calls[0].nonce_changes = vec![pbeth::NonceChange {
            address: vec![0xaa; 20],
            old_value: 4,
            new_value: 5,
            // Ordered with the pre-execution gas buy, before the root call begins.
            ordinal: 0,
        }];

        let violations = BlockInvariants::violations(&block);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn a_call_pointing_at_a_missing_parent_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0].calls.push(pbeth::Call {
            index: 2,
            parent_index: 7,
            depth: 1,
            call_type: pbeth::CallType::Call as i32,
            begin_ordinal: 5,
            end_ordinal: 6,
            ..Default::default()
        });

        assert_only_violation(&block, "does not point at an earlier call");
    }

    #[test]
    fn a_call_whose_depth_disagrees_with_its_parent_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0].calls.push(pbeth::Call {
            index: 2,
            parent_index: 1,
            depth: 5,
            call_type: pbeth::CallType::Call as i32,
            begin_ordinal: 5,
            end_ordinal: 6,
            ..Default::default()
        });

        assert_only_violation(&block, "depth is 5 but parent #1 has depth 0");
    }

    #[test]
    fn a_no_op_storage_change_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0].calls[0].storage_changes[0].new_value = vec![0x00; 32];

        assert_only_violation(&block, "no-op storage change");
    }

    #[test]
    fn a_no_op_balance_change_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0].calls[0].balance_changes = vec![pbeth::BalanceChange {
            address: vec![0xaa; 20],
            // Leading zeroes must not hide that these are the same value.
            old_value: Some(pbeth::BigInt {
                bytes: vec![0x00, 0x64],
            }),
            new_value: Some(pbeth::BigInt { bytes: vec![0x64] }),
            reason: pbeth::balance_change::Reason::Transfer as i32,
            ordinal: 5,
        }];

        assert_only_violation(&block, "no-op balance change");
    }

    #[test]
    fn a_receipt_log_missing_from_the_call_tree_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0].calls[0].logs.clear();

        assert_only_violation(
            &block,
            "0 log(s) across non-reverted calls but 1 log(s) in the receipt",
        );
    }

    #[test]
    fn a_receipt_log_whose_payload_disagrees_with_the_call_log_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0].calls[0].logs[0].data = vec![9, 9, 9];

        assert_only_violation(&block, "no matching call log");
    }

    #[test]
    fn a_sparse_receipt_log_block_index_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0]
            .receipt
            .as_mut()
            .expect("receipt")
            .logs[0]
            .block_index = 3;
        block.transaction_traces[0].calls[0].logs[0].block_index = 3;

        assert_only_violation(&block, "not dense");
    }

    #[test]
    fn a_succeeded_transaction_whose_root_call_failed_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0].calls[0].status_failed = true;

        assert_only_violation(&block, "status is SUCCEEDED but the root call reports");
    }

    #[test]
    fn a_failed_transaction_whose_root_call_succeeded_is_a_violation() {
        let mut block = valid_block();
        block.transaction_traces[0].status = pbeth::TransactionTraceStatus::Failed as i32;

        assert_only_violation(&block, "reports neither failure nor revert");
    }

    #[test]
    fn assert_reports_every_violation_at_once() {
        let mut block = valid_block();
        block.ver = 4;
        block.transaction_traces[0].index = 3;

        let error = BlockInvariants::assert(&block).expect_err("a broken block must fail");
        let message = error.to_string();

        assert!(
            message.contains("2 Firehose invariant violation(s) in block #100"),
            "{message}"
        );
        assert!(message.contains("block version 5 is expected"), "{message}");
        assert!(message.contains("index field is 3"), "{message}");
    }
}
