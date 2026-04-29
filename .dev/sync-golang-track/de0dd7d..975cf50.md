# Sync Run: de0dd7d..975cf50

## Overview

Two commits to port from Golang evm-firehose-tracer-go.

## Commits

### 1. `abb2af6` — Add detailed opcode logging and human-readable opcode names

**Files changed in Go:** `CHANGELOG.md`, `tracer.go`, `tracer_debug.go`

**What to port:**
- Add `OpCodeView` type (wraps `u8`) implementing `Display` — looks up human-readable name or falls back to `0x??` hex
- Add `OP_CODE_NAMES` static map covering all standard EVM opcodes
- In `on_opcode`: add `firehose_trace_full!` log line at the top (before the `callStack.Peek()` check)
- In `on_opcode_fault`: update debug log message from old format to new format using `OpCodeView`
- Update `CHANGELOG.md`

**Status:** [x] DONE — Rust commit `2c17ea4`

### 2. `975cf50` — Enhance logging for balance, nonce, code, and storage changes

**Files changed in Go:** `CHANGELOG.md`, `tracer.go`

**What to port:**
- `on_balance_change`: move the `firehose_trace!` log line to BEFORE the `Reason::Unknown` guard (already at top), and inline `new_balance_change` method (Go removed this helper method). In Rust the log is already at the top, but let's align.
- `on_nonce_change`: add `firehose_debug!` log BEFORE the `old_nonce == new_nonce` early-return guard  
- `on_code_change`: move `firehose_debug!` BEFORE the `prev_code_hash == new_code_hash` early-return guard
- `on_storage_change`: move `firehose_trace!` BEFORE the `old_value == new_value` early-return guard
- Update `CHANGELOG.md`

**Note:** The `newBalanceChange` helper removal in Go is not relevant because Rust already inlines it.

**Status:** [x] DONE — Rust commit `b2bd075`

## Result

- [x] Tests pass
- [x] CHANGELOG.md updated  
- [x] state.md updated
