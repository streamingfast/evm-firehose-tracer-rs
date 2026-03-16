# Sync State: evm-firehose-tracer-rs ↔ evm-firehose-tracer-go

## Overview

This directory tracks the sync state between the Rust version of the EVM Firehose Tracer
and the upstream Golang version at https://github.com/streamingfast/evm-firehose-tracer-go.

The Golang version is the source of truth. This Rust version was originally ported from it.

## Current State

- **Last synced Golang commit**: `7750eb7a7baeb40296088a624b1d95343fdebbb9`
- **Last synced Golang commit (short)**: `7750eb7`
- **Sync date**: 2026-03-16
- **Rust repo version**: `4.0.0` (aligned with Golang v4.0.0)

## Sync History

| Run | Golang From | Golang To | Status | Date |
|-----|-------------|-----------|--------|------|
| 1 | `7744bb7` | `7750eb7` | Completed | 2026-03-16 |

## Notes

### Features NOT ported (skipped intentionally)

The following Golang features are not ported to Rust because the foundational work
for them is not present in the Rust version:

- **Parallel tracing**: coordinator, isolated tracer, `OnTxSpawn`, `OnTxCommit`
- **Concurrent block flushing**: `ConcurrentFlushQueue`, `Config#ConcurrentBufferSize`

Any commits related to these features are skipped during sync.
