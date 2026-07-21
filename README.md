# EVM Firehose Tracer (Rust)

A chain-agnostic EVM execution tracer that produces [Firehose](https://firehose.streamingfast.io/) protobuf blocks for blockchain indexing and analytics. This is the Rust implementation, intended for use with [Reth](https://github.com/paradigmxyz/reth) and [Monad](https://www.monad.xyz/).

The source of truth and Golang implementation can be found at [evm-firehose-tracer-go](https://github.com/streamingfast/evm-firehose-tracer-go), used with go-ethereum, Optimism, and others.

## Overview

This repository contains a **shared tracer implementation** that can be integrated into any Rust EVM-compatible blockchain client (Reth, etc.). The tracer captures detailed execution data—including state changes, calls, logs, and gas consumption—and outputs structured protobuf blocks for downstream processing.

### Key Features

- **Chain-agnostic**: Core tracer has zero dependencies on specific blockchain implementations
- **Protocol v4.0**: Latest Firehose protocol with full EIP support (EIP-1559, EIP-4844, EIP-7702, etc.)
- **Comprehensive state tracking**: Balance changes, nonce changes, code changes, storage changes, gas changes, logs
- **System call support**: Chain-specific system calls (e.g., Beacon root, withdrawals)
- **Genesis block handling**: Synthetic transaction for genesis allocation

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Blockchain Client (Reth, Monad, etc.)                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Chain-Specific Adapter                                │ │
│  │  - Converts client types to shared types              │ │
│  │  - Implements StateReader interface                    │ │
│  │  - Computes chain-specific values                     │ │
│  └─────────────────────┬──────────────────────────────────┘ │
│                        │                                     │
│                        ▼                                     │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Shared Tracer (firehose crate)                       │ │
│  │  - Chain-agnostic core                                │ │
│  │  - Lifecycle hooks (OnBlockStart, OnTxStart, etc.)    │ │
│  │  - State change tracking                              │ │
│  │  - Ordinal management                                 │ │
│  │  - Protobuf serialization                             │ │
│  └─────────────────────┬──────────────────────────────────┘ │
└────────────────────────┼────────────────────────────────────┘
                         │
                         ▼
              Firehose Protobuf Output
           (sf.ethereum.type.v2.Block)
```

## Integrations

This library is consumed by the following StreamingFast forks that add Firehose tracing to their respective clients:

- **[streamingfast/reth](https://github.com/streamingfast/reth)** — Reth fork with Firehose instrumentation
- **[streamingfast/base](https://github.com/streamingfast/base)** — Base (OP-Stack) Reth fork with Firehose instrumentation
- **[streamingfast/monad-firehose-tracer](https://github.com/streamingfast/monad-firehose-tracer)** — Monad client fork with Firehose instrumentation

## Testing

```bash
# Run all tests
cargo test --workspace

# Run specific test suite
cargo test -p firehose-tracer-test tracer_setcode

# Run with debug output
RUST_LOG=debug cargo test --workspace
```

## Key Concepts

### Lifecycle Hooks

The tracer follows a strict lifecycle with hooks for each phase:

1. **Blockchain Init**: `on_blockchain_init(node_name, version, chain_config)`
2. **Block Lifecycle**:
   - `on_block_start(event)` → `on_tx_start(...)` → ... → `on_tx_end(...)` → `on_block_end(err)`
3. **Transaction Lifecycle**:
   - `on_tx_start(event, state_reader)` → `on_call_enter(...)` → ... → `on_call_exit(...)` → `on_tx_end(receipt, err)`
4. **Call Lifecycle**:
   - `on_call_enter(depth, typ, from, to, ...)` → state changes → `on_call_exit(depth, output, ...)`

### State Changes

All state changes are recorded with ordinals for deterministic ordering:

- **Balance Changes**: `on_balance_change(addr, prev, new, reason)`
- **Nonce Changes**: `on_nonce_change(addr, prev, new)`
- **Code Changes**: `on_code_change(addr, prev_hash, new_hash, prev_code, new_code)`
- **Storage Changes**: `on_storage_change(addr, key, prev, new)`
- **Gas Changes**: `on_gas_change(old_gas, new_gas, reason)`
- **Logs**: `on_log(addr, topics, data, block_index)`

### Ordinals

Ordinals provide deterministic ordering of all events within a block:
- Every state change, call, and log receives a monotonically increasing ordinal
- Enables precise reconstruction of execution order

## Workspace Crates

- **`firehose-tracer`**: Core chain-agnostic tracer implementation
- **`firehose-tracer-test`**: Test helpers and the full integration test suite

## Repository

https://github.com/streamingfast/evm-firehose-tracer-rs

## License

Apache 2.0

## Resources

- [Firehose Documentation](https://firehose.streamingfast.io/)
- [Protobuf Definitions](https://github.com/streamingfast/firehose-ethereum/tree/develop/types/pb)
- [StreamingFast](https://www.streamingfast.io/)
- [Go version (source of truth)](https://github.com/streamingfast/evm-firehose-tracer-go)
