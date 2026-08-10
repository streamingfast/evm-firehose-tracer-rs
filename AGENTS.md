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
- `firehose-tracer-prestate` needs `cmake`

### Why `firehose-tracer-prestate` needs `cmake`

Its archive client and its production Firehose client both terminate TLS through `rustls`, whose
default provider is `aws-lc-rs`, and `aws-lc-sys` builds its C sources with `cmake`. It does *not*
need `libclang` (pre-generated bindings ship for the common targets), and `cmake` is preinstalled on
the `ubuntu-24.04` runner CI uses.

### Building without native deps

To build and test only the crates that don't require native libraries:

```bash
cargo test -p firehose-tracer -p firehose-tracer-test
```

## Regenerating the protobuf artifacts

The generated Rust types and the reflection descriptor come from the same input and **must be
regenerated together**. `firehose-tracer-test`'s golden projection walks blocks against the
descriptor, so a descriptor older than the generated types would silently stop rendering the fields
added in between.

```bash
# Generated Rust types, into firehose-tracer/src/pb (then run rustfmt over them)
buf generate --include-imports proto

# Reflection descriptor, into firehose-tracer-test/descriptor.binpb
scripts/generate-protobuf.sh
```

### The `proto` module

Both commands take the local `proto` module rather than a BSR module directly. It is generation
config, not schema: `proto/generation.proto` declares no messages, it only imports, and
`--include-imports` is what makes the generation cover everything those imports reach. Two reasons:

* **One generated tree.** The workspace needs types from two BSR modules — the *block* schema
  (`buf.build/streamingfast/firehose-ethereum`, which `firehose-tracer` renders) and the *transport*
  schema (`buf.build/streamingfast/firehose`, whose `Fetch/Block` `firehose-tracer-prestate` reads a
  production block back with). Listing them as two inputs does not work: the `prost-crate` plugin
  runs once per input and each run overwrites the previous `pb.rs`, so only the last input's module
  tree survives. A buf workspace does not help either — `modules` entries are local paths, and
  remote modules can only enter as `deps`, which are generated for only when something imports
  them. Importing both from one local module makes them a single image and produces one `pb.rs`
  covering both.
* **One pinned version.** `proto/buf.lock` pins both modules, and the types and the descriptor are
  built from that same lock, so they cannot resolve to different schema versions.

To pull in another module's types: add a `deps` entry in `proto/buf.yaml`, run `buf dep update` in
`proto/`, add the import to `generation.proto`, and regenerate. Any number of modules works.

Two details of `generation.proto` are deliberate and explained in the file itself: it reuses an
existing package rather than declaring one of its own (a package of its own would appear as an empty
module in the generated tree), and `proto/buf.yaml` therefore excludes it from `buf lint`, which
would otherwise flag both the package/directory mismatch and the "unused" imports that are the whole
point of the file.

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

## Publishing to crates.io

`firehose-tracer`, `firehose-tracer-test` and `firehose-tracer-prestate` are all published, at the
same workspace version. They form a chain — `firehose-tracer-test` depends on `firehose-tracer`, and
`firehose-tracer-prestate` on both — by `version` + `path`, so each can only be published once the
matching version of the one below it exists on the registry. Publish all three in one command and
let cargo order them:

```bash
# verify first
cargo publish --dry-run -p firehose-tracer -p firehose-tracer-test -p firehose-tracer-prestate
cargo publish -p firehose-tracer -p firehose-tracer-test -p firehose-tracer-prestate
```

The dry run resolves the not-yet-published siblings from the local packaging output, so it works
even though `firehose-tracer` at the new version is not on crates.io yet.

Notes:

- `descriptor.binpb` is `include_bytes!`-ed by `firehose-tracer-test`, so it must stay inside the
  crate directory to be packaged. Verify with `cargo package -p firehose-tracer-test --list`.
- The `[[test]]` targets are declared in `firehose-tracer-test/Cargo.toml`, so `tests/` cannot be
  `exclude`d from the package — cargo refuses to package a manifest whose declared targets are
  missing.
- `readme = "../README.md"` in both crates is resolved and copied at package time; the repository
  README is the crates.io front page for both.
