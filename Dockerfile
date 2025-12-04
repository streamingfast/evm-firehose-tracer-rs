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
