# Extract binaries from categoryxyz images
FROM categoryxyz/monad-bft:latest AS monad-bft
FROM categoryxyz/monad-execution:latest AS monad-execution
FROM categoryxyz/monad-rpc:latest AS monad-rpc

# Build monad-firehose-tracer from source
FROM ubuntu:24.04 AS tracer-builder

WORKDIR /build

RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    cmake \
    git \
    libhugetlbfs-dev \
    libzstd-dev \
    wget \
    gnupg \
    software-properties-common \
    && wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc \
    && add-apt-repository -y "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-20 main" \
    && apt-get update \
    && apt-get install -y clang-20 libclang-20-dev llvm-20-dev \
    && update-alternatives --install /usr/bin/clang clang /usr/lib/llvm-20/bin/clang 100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/lib/llvm-20/bin/clang++ 100 \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

COPY . .

RUN cargo build --release -p monad-tracer

# Base image with all binaries and libraries
FROM ubuntu:24.04 AS base

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libstdc++6 \
    bash \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy all binaries and libraries from categoryxyz images
RUN --mount=type=bind,from=monad-bft,target=/mnt/monad-bft \
    --mount=type=bind,from=monad-execution,target=/mnt/monad-execution \
    --mount=type=bind,from=monad-rpc,target=/mnt/monad-rpc \
    set -x && \
    find /mnt/monad-bft -type f -executable -name "monad-node" | while read f; do cp "$f" /app/monad-node; done || true && \
    find /mnt/monad-execution -type f -executable -name "monad" | while read f; do cp "$f" /app/monad; done || true && \
    find /mnt/monad-execution -type f -executable -name "monad_mpt" | while read f; do cp "$f" /app/monad_mpt; done || true && \
    find /mnt/monad-rpc -type f -executable -name "monad-rpc" | while read f; do cp "$f" /app/monad-rpc; done || true && \
    find /mnt/monad-bft/usr/local/lib /mnt/monad-bft/usr/lib -name "*.so*" -type f 2>/dev/null | grep -vE "(libc\.so|libpthread\.so|libdl\.so|libm\.so|librt\.so|libresolv\.so|libutil\.so|libnss_)" | while read f; do cp "$f" /usr/local/lib/ 2>/dev/null || true; done && \
    find /mnt/monad-execution/usr/local/lib /mnt/monad-execution/usr/lib -name "*.so*" -type f 2>/dev/null | grep -vE "(libc\.so|libpthread\.so|libdl\.so|libm\.so|librt\.so|libresolv\.so|libutil\.so|libnss_)" | while read f; do cp "$f" /usr/local/lib/ 2>/dev/null || true; done && \
    find /mnt/monad-rpc/usr/local/lib /mnt/monad-rpc/usr/lib -name "*.so*" -type f 2>/dev/null | grep -vE "(libc\.so|libpthread\.so|libdl\.so|libm\.so|librt\.so|libresolv\.so|libutil\.so|libnss_)" | while read f; do cp "$f" /usr/local/lib/ 2>/dev/null || true; done && \
    rm -f /usr/local/lib/libc.so* /usr/local/lib/libpthread.so* /usr/local/lib/libdl.so* /usr/local/lib/libm.so* /usr/local/lib/librt.so* /usr/local/lib/libresolv.so* /usr/local/lib/libutil.so* /usr/local/lib/libnss_*

COPY --from=tracer-builder /build/target/release/monad-firehose-tracer /app/monad-firehose-tracer

RUN ldconfig

ENV LD_LIBRARY_PATH=/usr/local/lib
ENV RUST_LOG=info

# Container 1: Consensus (monad-node)
FROM base AS consensus

RUN cat > /app/start.sh <<'EOF'
#!/bin/bash
set -e

echo "=== Starting Monad Consensus (monad-node) ==="

mkdir -p /data/ledger /data/wal /data/triedb /sockets

exec /app/monad-node \
  --secp-identity=/data/config/id-secp \
  --bls-identity=/data/config/id-bls \
  --node-config=/data/config/node.toml \
  --forkpoint-config=/data/config/forkpoint.toml \
  --validators-path=/data/config/validators.toml \
  --wal-path=/data/wal \
  --mempool-ipc-path=/sockets/mempool.sock \
  --control-panel-ipc-path=/sockets/controlpanel.sock \
  --ledger-path=/data/ledger \
  --statesync-ipc-path=/sockets/statesync.sock \
  --triedb-path=/data/triedb
EOF

RUN chmod +x /app/start.sh

ENTRYPOINT ["/app/start.sh"]

# Container 2: Execution (monad)
FROM base AS execution

RUN cat > /app/start.sh <<'EOF'
#!/bin/bash
set -e

echo "=== Starting Monad Execution Layer ==="

# Wait for ledger to be initialized
echo "Waiting for ledger initialization..."
while [ ! -d /data/ledger ] || [ -z "$(ls -A /data/ledger 2>/dev/null)" ]; do
  sleep 2
done

# Create event-rings directory in hugepages
mkdir -p /dev/hugepages/event-rings

exec /app/monad \
  --chain=monad_devnet \
  --db=/data/triedb/db \
  --block_db=/data/ledger \
  --nblocks=18446744073709551615 \
  --log_level=info \
  --exec-event-ring=monad-devnet-events
EOF

RUN chmod +x /app/start.sh

ENTRYPOINT ["/app/start.sh"]

# Container 3: Reader + RPC (monad-firehose-tracer + monad-rpc)
FROM base AS reader-rpc

RUN cat > /app/start.sh <<'EOF'
#!/bin/bash
set -e

echo "=== Starting Monad Reader + RPC ==="

mkdir -p /data/one-blocks

# Wait for event ring to be created
echo "Waiting for event ring..."
while [ ! -e /dev/hugepages/event-rings/monad-devnet-events ]; do
  sleep 2
done

echo "Starting monad-firehose-tracer..."
/app/monad-firehose-tracer \
  --chain-id=20143 \
  --network-name=devnet \
  --monad-event-ring-path=/dev/hugepages/event-rings/monad-devnet-events \
  --buffer-size=1024 \
  --timeout-ms=1000 \
  --debug &
READER_PID=$!

# Wait for mempool socket
echo "Waiting for mempool socket..."
while [ ! -S /sockets/mempool.sock ]; do
  sleep 2
done

echo "Starting monad-rpc..."
/app/monad-rpc \
  --ipc-path=/sockets/mempool.sock \
  --node-config=/data/config/node.toml \
  --triedb-path=/data/triedb \
  --rpc-addr=0.0.0.0 \
  --rpc-port=8545 &
RPC_PID=$!

echo "All processes started"
echo "Reader: $READER_PID | RPC: $RPC_PID"

cleanup() {
    kill $READER_PID $RPC_PID 2>/dev/null || true
    wait
}

trap cleanup EXIT INT TERM
wait
EOF

RUN chmod +x /app/start.sh

ENTRYPOINT ["/app/start.sh"]
