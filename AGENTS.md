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
cargo test -p firehose-tracer -p firehose-tracer-test
```

## Regenerating the protobuf artifacts

The generated Rust types and the reflection descriptor come from the same BSR module and **must be
regenerated together**. `firehose-tracer-test`'s golden projection walks blocks against the
descriptor, so a descriptor older than the generated types would silently stop rendering the fields
added in between.

```bash
# Generated Rust types, into firehose-tracer/src/pb
buf generate buf.build/streamingfast/firehose-ethereum

# Reflection descriptor, into firehose-tracer-test/descriptor.binpb
scripts/generate-protobuf.sh
```

The descriptor step is a script rather than a `build.rs` step on purpose — generation pulls the
schema from the Buf Schema Registry over the network, which must not run on every `cargo build`. The
`descriptor_drift` unit tests in `firehose-tracer-test` fail if the two fall out of sync, so a
missed run surfaces in the normal test run rather than as a quietly incomplete golden.

## Golden files

Tests that compare against a golden regenerate with `GOLDEN_UPDATE=1`:

```bash
GOLDEN_UPDATE=1 cargo test -p firehose-tracer-test
```

`Golden::is_json_equal` / `is_text_equal` do no diffing themselves: they return a `BlockDiff` with
the golden and captured sides verbatim, and the caller asserts on it (e.g. `diff.assert_equal()`),
so the diff you see is the test framework's own. Review it before committing a regenerated golden.
