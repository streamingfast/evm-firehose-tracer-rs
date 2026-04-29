# Sync State: evm-firehose-tracer-rs ↔ evm-firehose-tracer-go

## Overview

This directory tracks the sync state between the Rust version of the EVM Firehose Tracer
and the upstream Golang version at https://github.com/streamingfast/evm-firehose-tracer-go.

The Golang version is the source of truth. This Rust version was originally ported from it.

## Current State

- **Last synced Golang commit**: `975cf50b8770f9be73bbd1252056af6185dbcbc3`
- **Last synced Golang commit (short)**: `975cf50`
- **Sync date**: 2026-04-29
- **Rust repo version**: `5.0.0` (aligned with Golang v5.0.0)

## Sync History

| Run | Golang From | Golang To | Status | Date |
|-----|-------------|-----------|--------|------|
| 1 | `7744bb7` | `7750eb7` | Completed | 2026-03-16 |
| 2 | `7750eb7` | `a96a677` | Completed | 2026-03-16 |
| 3 | `a96a677` | `c6eb9e2` | Completed | 2026-03-23 |
| 4 | `c6eb9e2` | `30d8bce` | Completed | 2026-04-16 |
| 5 | `30d8bce` | `de0dd7d` | Completed | 2026-04-17 |
| 6 | `de0dd7d` | `975cf50` | Completed | 2026-04-29 |

## Notes

### Features NOT ported (skipped intentionally)

The following Golang features are not ported to Rust because the foundational work
for them is not present in the Rust version:

- **Parallel tracing**: coordinator, isolated tracer, `OnTxSpawn`, `OnTxCommit`
- **Concurrent block flushing**: `ConcurrentFlushQueue`, `Config#ConcurrentBufferSize`

Any commits related to these features are skipped during sync.

### Protocol Version History

- **v4 (BLOCK_VERSION=4)**: Initial version
- **v5 (BLOCK_VERSION=5)**: Removed GasChange tracking (run 2)

### Not ported to Rust (proto limitation)

- `Block.Withdrawals` array field: The protobuf Block struct in this Rust version
  does not have a `withdrawals` field. As of v5, withdrawals are always recorded
  (no SkipWithdrawals config) in the Golang version. The Rust version never had
  SkipWithdrawals either.
