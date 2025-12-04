# EVM Firehose Tracer

A multi-chain EVM Firehose tracer for StreamingFast. This workspace provides block and transaction tracing capabilities for different blockchain implementations.

## Current Implementation

This repository currently focuses on **Monad** blockchain integration with a 3-container split architecture:

- **Consensus Layer** (monad-node)
- **Execution Layer** (monad)
- **Reader + RPC** (monad-firehose-tracer + monad-rpc)

## Prerequisites

- [Rust](https://rust-lang.org/tools/install) & Cargo
- Docker (for containerized deployment)

## Build

Build the Monad tracer from source:

```bash
cargo build --release -p monad-tracer
```

## Docker

The Dockerfile supports building 3 separate container targets:

```bash
# Build consensus container
docker build --target consensus -t monad-consensus .

# Build execution container
docker build --target execution -t monad-execution .

# Build reader-rpc container
docker build --target reader-rpc -t monad-reader-rpc .
```

## Repository

https://github.com/streamingfast/evm-firehose-tracer-rs
