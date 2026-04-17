# Track: Infer balance/nonce changes from journal entries

## Overview

Refactor the depth==0 gas buy / nonce emission to use journal entries as the source of truth instead of reconstructing changes from `original_info` vs `info` account state comparison.

Currently we have two code paths:
- **depth > 0**: `process_journal_changes` reads journal entries and emits balance/nonce changes
- **depth == 0**: skip journal, manually compare `account.original_info` vs `account.info` and emit with correct reasons (`GasBuy`, nonce)

The journal already contains the entries from `deduct_caller` (`BalanceChange` for gas cost, `NonceBump` for CALL transactions). We should use them directly and infer the reason from context rather than bypassing them.

## Motivation

- Single code path for all depths instead of two
- Journal is the authoritative record of what changed; reconstructing from account state is indirect
- If revm changes what `deduct_caller` does (adds new entries), the journal path picks them up automatically; the manual path silently misses them
- Less fragile coupling to revm internals

## Approach

In `process_journal_changes`, when at depth 0 and before the root call has been pushed:
- `BalanceChange` for the tx caller address → emit with reason `GasBuy` (instead of `Transfer`)
- `NonceBump` for the tx caller address → emit nonce change as today

The heuristic is deterministic: the only `BalanceChange`/`NonceBump` entries before the root call at depth 0 are from `deduct_caller`. This isn't really a heuristic -- it's a structural invariant of the EVM execution flow.

### Key revm facts

- `deduct_caller` calls `set_balance()` → pushes `JournalEntry::BalanceChange`
- `deduct_caller` calls `bump_nonce()` (CALL txs only) → pushes `JournalEntry::NonceBump`
- For CREATE txs, `deduct_caller` does NOT bump nonce; `create_account_checkpoint` does it later
- `load_accounts` (warm coinbase/access-list) pushes `AccountWarmed` entries (no tracer effect)

### Implementation sketch

Add a flag like `root_call_entered: bool` to `FirehoseInspector`. Before `on_call_enter` at depth 0, it's `false`. After, it's `true`. In `process_journal_changes`, when `!root_call_entered`:
- Override reason for `BalanceChange` on caller → `GasBuy`
- Process `NonceBump` on caller normally

This removes the `if depth == 0 { ... } else { process_journal_changes(...) }` split in both `call` and `create` hooks.

## Current State

Not started. Tracked for future refactoring.
