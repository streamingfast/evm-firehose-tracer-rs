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

### Mac OS X

Monad requires a recent LLVM version, the one that comes from stock OSX is often outdated so it's better to have a version from Brew directly. Technically recent OSX Tahoe version with latest Command Line Tools has LLVM 17 which works properly, going the Homebrew route is still recommend. However `brew` will not hook it automatically to the system, you need to manually activate it. Ensure you have a recent version enough of LLVM:

```bash
brew install llvm@20 zstd
```

> [!NOTE]
> Locally I got llvm@20 and it worked, `clang --version` `20.1.2` and it worked, ensure `clang/clang++` points to Homebrew version

Then you can use this `.envrc` file to auto-load LLVM first:

```bash
llvm_path="$(brew --prefix llvm@20)"
zstd_path="$(brew --prefix zstd)"

path_add PATH "$llvm_path"/bin
path_add LIBRARY_PATH "$llvm_path"/lib
path_add LIBRARY_PATH "$zstd_path"/lib

export CC="${llvm_path}/bin/clang"
export CXX="${llvm_path}/bin/clang++"
export LLVM_CONFIG_PATH="${llvm_path}/bin/llvm-config"
```

#### Rust Analyzer

In VSCode, it's possible to easily get the rust analyzer to work by installing https://github.com/direnv/direnv-vscode which will forces plugins to load with those environment so that Rust Analyzer sees the same as from `cargo build` on the terminal.

For others, the goal is simply to have the environment variables defined above when the `rust-analyzer` lsp server needs to start.

## Build

Build the Monad tracer from source:

```bash
cargo build --release -p monad-tracer
```

## Docker Images

GitHub Actions automatically builds and publishes images to:

- `ghcr.io/streamingfast/evm-firehose-tracer-rs/monad-consensus`
- `ghcr.io/streamingfast/evm-firehose-tracer-rs/monad-execution`
- `ghcr.io/streamingfast/evm-firehose-tracer-rs/monad-reader-rpc`

### Local Build

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
