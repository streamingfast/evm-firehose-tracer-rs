# Reth Firehose Tracer

A multi-chain Firehose tracer built on Reth node components. This workspace provides block and transaction tracing capabilities for different blockchain implementations.

**Note:** This is currently experimental as it doesn't yet implement the full tracing API.

## Workspace Structure

```
reth-firehose-tracer/
├── pb/                     # Protobuf definitions (shared)
├── firehose/               # Shared firehose tracer library
├── ethereum/               # Ethereum tracer binary (reth-firehose-tracer)
└── optimism/               # OP-Reth tracer binary (op-reth-firehose-tracer)
```

## Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) & Cargo
- [Firehose Ethereum CLI (fireeth)](https://github.com/streamingfast/firehose-ethereum)

## Build

Build all workspace members (produces both binaries):

```sh
cargo build
```

Or build specific chains:

```sh
cargo build -p ethereum   # Builds reth-firehose-tracer
cargo build -p optimism   # Builds op-reth-firehose-tracer
```

## Run

### Ethereum

Start the Ethereum Reth node with Firehose tracer:

```sh
fireeth start -c fireeth.config.yaml
```

This runs:
- Binary: `./target/debug/reth-firehose-tracer`
- Data dir: `.firehose-data`
- Firehose gRPC: `localhost:10001`
- Substreams gRPC: `localhost:10000`
- HTTP RPC: `localhost:8545`

### Optimism (OP Stack)

Start the OP-Reth node with Firehose tracer:

```sh
fireeth start -c fireeth.optimism.yaml
```

This runs:
- Binary: `./target/debug/op-reth-firehose-tracer`
- Data dir: `.firehose-data-optimism`
- Firehose gRPC: `localhost:10003`
- Substreams gRPC: `localhost:10002`
- HTTP RPC: `localhost:8546`

**Note:** The optimism tracer is currently a placeholder and will be implemented with flashblocks support.

## Test

Once running, you can test the different endpoints:

### Ethereum
- **Test Firehose**: `fireeth tools firehose-client localhost:10001 -o text --insecure -- -1`
- **Test Substreams**: `substreams run -e localhost:10000 common@v0.1.0 --insecure -s "-1"`

### Optimism
- **Test Firehose**: `fireeth tools firehose-client localhost:10003 -o text --insecure -- -1`
- **Test Substreams**: `substreams run -e localhost:10002 common@v0.1.0 --insecure -s "-1"`

## Clean State

To clean up the local state and restart fresh:

```sh
# Ethereum
rm -rf .firehose-data
fireeth start -c fireeth.config.yaml

# Optimism
rm -rf .firehose-data-optimism
fireeth start -c fireeth.optimism.yaml
```
