#!/usr/bin/env bash
#
# Regenerates the reflection descriptor set that `firehose-tracer-test`'s golden projection walks
# blocks against:
#
#   firehose-tracer-test/descriptor.binpb
#
# It is built from the same BSR module as the generated Rust types (firehose-tracer/src/pb, via
# buf.gen.yaml), so run it whenever those types are regenerated — a descriptor older than the types
# would silently stop the projection from rendering the fields added in between. The
# `descriptor_drift` unit tests in firehose-tracer-test fail if the two fall out of sync, so a
# forgotten run surfaces in the test suite rather than as a quietly incomplete golden.
#
# This is a script rather than a build.rs step on purpose: generation pulls the schema from the Buf
# Schema Registry over the network, which must not run on every `cargo build`.
#
# Usage: scripts/generate-protobuf.sh   (run from anywhere; paths resolve against the repo root)

set -euo pipefail

module="buf.build/streamingfast/firehose-ethereum"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v buf >/dev/null 2>&1; then
  echo "error: 'buf' is not installed — see https://buf.build/docs/installation" >&2
  exit 1
fi

echo "Generating descriptor set into firehose-tracer-test/descriptor.binpb ..."
buf build "$module" --as-file-descriptor-set -o firehose-tracer-test/descriptor.binpb

echo "Done. If you also regenerated the Rust types (buf generate), run:"
echo "  cargo test -p firehose-tracer-test"
