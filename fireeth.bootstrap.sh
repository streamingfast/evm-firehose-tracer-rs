#! /usr/bin/env bash

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

data_dir="${READER_NODE_DATA_DIR:="$ROOT"/.firehose-data/reader-node}"
binary="${READER_NODE_PATH:="$ROOT"/target/debug/reth-firehose-tracer}"
genesis="$ROOT/fireeth.genesis.json"

echo "Initializing reader node data dir at $data_dir using reth init ..."
echo ""

"$binary" init --datadir="$data_dir" --chain="$genesis"
