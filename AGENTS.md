# Agent Instructions

## Ubuntu 24 — Required System Dependencies

Some crates in this workspace require native system libraries. On Ubuntu 24, install them before building:

```bash
sudo apt-get update && sudo apt-get install -y libclang-dev
```

### Why

- `reth-firehose` depends on `reth-mdbx-sys` which uses `bindgen` to generate FFI bindings at compile time. `bindgen` requires `libclang` to parse C headers.
- The `monad` and  crates similarly require `libclang` (and `cmake`).

### Affected crates

- `reth-firehose` — needs `libclang-dev`
- `monad` needs `libclang-dev` + `cmake`

### Building without native deps

To build and test only the crates that don't require native libraries:

```bash
cargo test -p firehose -p firehose-test
```
