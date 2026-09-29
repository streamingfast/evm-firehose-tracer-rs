//! Limits on the call input and return data a block records.
//!
//! A transaction that passes large calldata to many internal calls produces a block far larger
//! than its gas usage suggests, and can push it past the ~2 GiB Firehose message limit. Two
//! limits keep blocks under it:
//!
//! - **Per transaction, while tracing.** When the internal calls that started before a call have
//!   passed more than [`MAX_CALL_INPUT_BYTES_PER_TX`] of input in total, the call records only its
//!   4-byte selector and sets `Call.input_truncated`. Return data works the same way with
//!   [`MAX_RETURN_DATA_BYTES_PER_TX`], counting the internal calls that ended before, and is left
//!   out entirely (`Call.return_data_truncated`). The call that passes a limit is still recorded
//!   in full.
//! - **Per block, before encoding.** When the block would encode to more than
//!   [`MAX_BLOCK_ENCODED_LEN`], [`fit_block`] halves both per-transaction limits and applies them
//!   again to every transaction and system call, until the block fits.
//!
//! Applying a lower limit to calls already traced with a higher one gives the same calls as
//! tracing them with the lower limit in the first place, so a block's content depends only on the
//! limit it ends up with.
//!
//! The root call of a transaction is never truncated: its input and return data are also in
//! `TransactionTrace.input` and `TransactionTrace.return_data`.

use crate::pb::sf::ethereum::r#type::v2::{Block, Call};
use prost::Message;

/// Input bytes the internal calls of one transaction may record before later ones are cut to
/// their selector.
pub const MAX_CALL_INPUT_BYTES_PER_TX: usize = 50 * 1024 * 1024;

/// Return data bytes the internal calls of one transaction may record before later ones are
/// left out.
pub const MAX_RETURN_DATA_BYTES_PER_TX: usize = 25 * 1024 * 1024;

/// Largest encoded block [`fit_block`] lets through untouched. Its base64 line stays well under
/// the ~2 GiB Firehose message limit.
pub const MAX_BLOCK_ENCODED_LEN: usize = 1024 * 1024 * 1024;

const SELECTOR_LEN: usize = 4;

/// The part of a call input recorded once the limit is passed: its first 4 bytes (the selector).
pub(crate) fn four_bytes(input: &[u8]) -> &[u8] {
    &input[..input.len().min(SELECTOR_LEN)]
}

/// Truncates the calls of `block` until it encodes to at most `max_len` bytes, and returns its
/// encoded length.
///
/// Each round halves the per-transaction input and return data limits, starting from
/// [`MAX_CALL_INPUT_BYTES_PER_TX`] and [`MAX_RETURN_DATA_BYTES_PER_TX`], and applies them to every
/// transaction and system call. When both limits reach 0, only the first internal call of each
/// transaction keeps its input and return data; if the block still does not fit, it is returned
/// as is.
pub fn fit_block(block: &mut Block, max_len: usize) -> usize {
    let len = block.encoded_len();
    if len <= max_len {
        return len;
    }
    shrink_block(block, max_len, len)
}

#[cold]
#[inline(never)]
fn shrink_block(block: &mut Block, max_len: usize, original_len: usize) -> usize {
    let mut len = original_len;
    let mut input_limit = MAX_CALL_INPUT_BYTES_PER_TX;
    let mut return_data_limit = MAX_RETURN_DATA_BYTES_PER_TX;
    let mut order = Vec::new();

    while len > max_len && (input_limit > 0 || return_data_limit > 0) {
        input_limit /= 2;
        return_data_limit /= 2;

        for trx in &mut block.transaction_traces {
            truncate_calls(&mut trx.calls, input_limit, return_data_limit, &mut order);
        }
        // System calls are appended in the order they end, so each one's root call closes it.
        for calls in block
            .system_calls
            .split_inclusive_mut(|call| call.depth == 0)
        {
            truncate_calls(calls, input_limit, return_data_limit, &mut order);
        }

        len = block.encoded_len();
        tracing::warn!(
            block = block.number,
            original_len,
            len,
            input_limit,
            return_data_limit,
            "block over {max_len} bytes encoded, truncated its call inputs and return data with lower per-transaction limits"
        );
    }

    if len > max_len {
        tracing::error!(
            block = block.number,
            original_len,
            len,
            "block still over {max_len} bytes encoded with the call input and return data limits at 0"
        );
    }
    len
}

/// Applies the per-transaction limits to the calls of one transaction or system call.
///
/// Inputs are counted in the order calls start and return data in the order they end, the order
/// the tracer sees them while tracing. Calls already truncated count what they still hold.
fn truncate_calls(
    calls: &mut [Call],
    input_limit: usize,
    return_data_limit: usize,
    order: &mut Vec<usize>,
) {
    order.clear();
    order.extend(0..calls.len());

    order.sort_unstable_by_key(|&i| calls[i].begin_ordinal);
    let mut total = 0usize;
    for &i in order.iter() {
        let call = &mut calls[i];
        if call.depth == 0 {
            continue;
        }
        if total > input_limit && call.input.len() > SELECTOR_LEN {
            call.input.truncate(SELECTOR_LEN);
            call.input_truncated = true;
        }
        total += call.input.len();
    }

    order.sort_unstable_by_key(|&i| calls[i].end_ordinal);
    let mut total = 0usize;
    for &i in order.iter() {
        let call = &mut calls[i];
        if call.depth == 0 {
            continue;
        }
        if total > return_data_limit && !call.return_data.is_empty() {
            call.return_data = Vec::new();
            call.return_data_truncated = true;
        }
        total += call.return_data.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::sf::ethereum::r#type::v2::TransactionTrace;

    /// A transaction's calls, root first, with the given internal call input and return data
    /// sizes. Calls are siblings under the root: each starts and ends before the next.
    fn calls(sizes: &[(usize, usize)]) -> Vec<Call> {
        let mut calls = vec![Call {
            depth: 0,
            input: vec![0xaa; 64],
            return_data: vec![0xbb; 64],
            begin_ordinal: 0,
            end_ordinal: 1000,
            ..Default::default()
        }];
        for (i, &(input, return_data)) in sizes.iter().enumerate() {
            let i = i as u64;
            calls.push(Call {
                depth: 1,
                input: vec![0x11; input],
                return_data: vec![0x22; return_data],
                begin_ordinal: 1 + 2 * i,
                end_ordinal: 2 + 2 * i,
                ..Default::default()
            });
        }
        calls
    }

    fn lens(calls: &[Call]) -> Vec<(usize, usize, bool, bool)> {
        calls
            .iter()
            .map(|c| {
                (
                    c.input.len(),
                    c.return_data.len(),
                    c.input_truncated,
                    c.return_data_truncated,
                )
            })
            .collect()
    }

    #[test]
    fn truncates_calls_after_the_limit_is_passed() {
        let mut calls = calls(&[(6, 3), (6, 3), (2, 0), (6, 3)]);
        truncate_calls(&mut calls, 10, 5, &mut Vec::new());
        assert_eq!(
            lens(&calls),
            vec![
                // Root call: never truncated.
                (64, 64, false, false),
                // Nothing before it.
                (6, 3, false, false),
                // 6 input bytes and 3 return data bytes before it: under both limits, recorded
                // in full even though it takes both totals over.
                (6, 3, false, false),
                // 12 > 10 and 6 > 5 before it, but nothing to leave out of a 2-byte input or an
                // empty return data.
                (2, 0, false, false),
                // 14 > 10: cut to the selector. 6 > 5: left out.
                (4, 0, true, true),
            ]
        );
    }

    #[test]
    fn inputs_count_in_start_order_and_return_data_in_end_order() {
        // Call 1 starts first and ends last (it is the parent of call 2).
        let mut calls = calls(&[(8, 8), (8, 8)]);
        calls[1].end_ordinal = 5;
        calls[2].begin_ordinal = 2;
        calls[2].end_ordinal = 3;
        calls[2].depth = 2;
        truncate_calls(&mut calls, 7, 7, &mut Vec::new());
        assert_eq!(calls[1].input.len(), 8);
        assert_eq!(calls[2].input.len(), 4);
        assert_eq!(calls[2].return_data.len(), 8);
        assert_eq!(calls[1].return_data.len(), 0);
    }

    #[test]
    fn lower_limit_on_truncated_calls_matches_lower_limit_from_the_start() {
        let sizes = [(7, 5), (9, 1), (3, 8), (12, 2), (5, 5), (1, 9)];
        for (high, low) in [(20, 10), (20, 3), (30, 0), (15, 14)] {
            let mut twice = calls(&sizes);
            truncate_calls(&mut twice, high, high, &mut Vec::new());
            truncate_calls(&mut twice, low, low, &mut Vec::new());

            let mut once = calls(&sizes);
            truncate_calls(&mut once, low, low, &mut Vec::new());

            assert_eq!(lens(&twice), lens(&once), "high={high} low={low}");
        }
    }

    fn block(txs: usize, sizes: &[(usize, usize)]) -> Block {
        Block {
            number: 1,
            transaction_traces: (0..txs)
                .map(|_| TransactionTrace {
                    calls: calls(sizes),
                    ..Default::default()
                })
                .collect(),
            system_calls: {
                // In end order: the internal call ends before its root.
                let mut calls = calls(&[(4096, 4096)]);
                calls.rotate_left(1);
                calls
            },
            ..Default::default()
        }
    }

    #[test]
    fn fit_block_leaves_a_block_that_fits_untouched() {
        let mut block = block(2, &[(1024, 1024); 4]);
        let original = block.clone();
        let len = fit_block(&mut block, original.encoded_len());
        assert_eq!(len, original.encoded_len());
        assert_eq!(block, original);
    }

    #[test]
    fn fit_block_halves_the_limits_until_the_block_fits() {
        let mut block = block(4, &[(1024, 1024); 8]);
        let max_len = block.encoded_len() / 2;
        let len = fit_block(&mut block, max_len);
        assert!(len <= max_len, "len={len} max_len={max_len}");
        assert_eq!(len, block.encoded_len());

        for trx in &block.transaction_traces {
            assert!(!trx.calls[0].input_truncated && !trx.calls[0].return_data_truncated);
            assert_eq!(trx.calls[0].input.len(), 64);
            // Truncation starts at some call and covers every call after it.
            let first = trx.calls.iter().position(|c| c.input_truncated).unwrap();
            assert!(trx.calls[first..]
                .iter()
                .all(|c| c.input_truncated && c.input.len() == 4));
            assert!(trx.calls[1..first].iter().all(|c| c.input.len() == 1024));
        }
        let system_root = block.system_calls.iter().find(|c| c.depth == 0).unwrap();
        assert_eq!(system_root.input.len(), 64);
    }

    #[test]
    fn fit_block_stops_when_nothing_is_left_to_truncate() {
        let mut block = block(1, &[(1024, 1024); 3]);
        let len = fit_block(&mut block, 1);
        assert_eq!(len, block.encoded_len());
        let trx = &block.transaction_traces[0];
        // Nothing comes before the first internal call, so even a limit of 0 keeps it.
        assert_eq!(
            (trx.calls[1].input.len(), trx.calls[1].return_data.len()),
            (1024, 1024)
        );
        assert!(trx.calls[2..]
            .iter()
            .all(|c| c.input.len() == 4 && c.return_data.is_empty()));
    }
}
