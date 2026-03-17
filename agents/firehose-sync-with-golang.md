## Ultimate Goal

Keep Rust version of EVM Firehose Tracer Rust (.) in sync with Golang EVM (https://github.com/streamingfast/evm-firehose-tracer-go).

## Context

This repository is essentially a clone of https://github.com/streamingfast/evm-firehose-tracer-go but for the Rust language. While the Golang version is used with Geth (https://github.com/ethereum/go-ethereum) Optimism and some others, the Rust version is meant to be used with Reth and Monad.

The source of truth is the Golang version and this entire project was created by an agent porting and converting the main code (firehose/src) and the full test suite (firehose-test).

Your goal is to keep the Rust version in sync based on recent commits made on the Golang version. At initial time this task was created, the initial synced commit on `evm-firehose-tracer-go` is `7744bb74641d3f90f7db267d3c6fc815bd140e0c`.

Create a context-driven state folder `.dev/sync-golang-track` which will be ever increasing. Initial state should give information about the sync state and the last synced commit.

Here the steps that must be taken:
- Inspect `.dev/sync-golang-track` plan + spec to understand what is the last synced commit from Golang (create it if it's the first run, initial commit synced on Golang side is `7744bb74641d3f90f7db267d3c6fc815bd140e0c`).
- Determine the set of commits to port and create a "run" specific plan `<short_sha_from>..<short_sha_target>.md` with details of work to do, resume from it if it already exists
- Implement the work items ensuring that all tests passes and they are ported faithfully keep the `.dev/sync-golang-track` with latest state at all time, as this will be used on restart to continue where we left off.
- Implement as faithfully as possible keeping the intent of the Golang version but adapted to Rust code. Stay focus on commits to port and nothing else.
- Also take into consideration versioning and tags, updating versioning in Rust to follow Golang major version of the module. Create tags for releases when they need to be performed. DO NOT care about releases, we will deal with that thing later on, tags should be enough for now.

### Extra Instructions

Currently the Rust version didn't port two features of the Golang version:
- The parallel tracing capabilities via coordinator, isolated tracer and parallel hook `OnTxSpawn` and `OnTxCommit`
- The concurrent blocks flushing capability related to `ConcurrentFlushQueue`, `Config#ConcurrentBufferSize` and related pieces.

If there is commits related to those or code changes, they should not be ported over and should simply be ignored from the work items as they cannot be ported since the foundational work for those features is not ported yet.