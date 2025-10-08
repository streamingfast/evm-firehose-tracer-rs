# Reth based Firehose Tracer

A Firehose Ethereum Tracer built on top of Reth node components. This experimental project provides block and transaction tracing capabilities that can power the `reader-node` component in the Firehose Ethereum stack.

**Note:** This is currently experimental as it doesn't yet implement the full tracing API.

## Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) & Cargo
- [Firehose Ethereum CLI (fireeth)](https://github.com/streamingfast/firehose-ethereum)

## Compile

Build the project using Cargo:

```sh
cargo build
```

### Install

For a global installation, you can do:

```sh
cargo install --path .
```

## Run

Start the local development node through the Firehose stack. This will run the compiled binary (`target/debug/reth`) as part of the Firehose Ethereum infrastructure:

```sh
fireeth start -c fireeth.config.yaml
```


### Test

Once running, you can test the different endpoints:

- **Test Firehose**: `fireeth tools firehose-client localhost:10001 -o text --insecure -- -1`
- **Test Substreams**: `substreams run -e localhost:10000 common@v0.1.0 --insecure -s "-1"`

## Delete state and restart

To clean up the local state and restart fresh:

```sh
rm -rf .firehose-data
fireeth start -c fireeth.config.yaml
```
