#!/bin/bash
# Setup script for Monad Localnet with Extended Blocks
# Run as root or with sudo

set -e

echo "=== Monad Localnet Setup ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or with sudo"
    exit 1
fi

echo "1. Setting system parameters..."
sysctl -w vm.nr_hugepages=2048
sysctl -w net.core.rmem_max=62500000
sysctl -w net.core.rmem_default=62500000
sysctl -w net.core.wmem_max=62500000
sysctl -w net.core.wmem_default=62500000
sysctl -w net.ipv4.tcp_rmem='4096 62500000 62500000'
sysctl -w net.ipv4.tcp_wmem='4096 62500000 62500000'

# Make persistent
echo "2. Making sysctl settings persistent..."
cat > /etc/sysctl.d/99-monad-localnet.conf <<EOF
# Monad localnet requirements
vm.nr_hugepages=2048
net.core.rmem_max=62500000
net.core.rmem_default=62500000
net.core.wmem_max=62500000
net.core.wmem_default=62500000
net.ipv4.tcp_rmem=4096 62500000 62500000
net.ipv4.tcp_wmem=4096 62500000 62500000
EOF

echo "3. Creating hugepages directory..."
mkdir -p /dev/hugepages/monad-localnet
chmod 755 /dev/hugepages/monad-localnet

echo "4. Creating data directories..."
mkdir -p localnet-data/config
mkdir -p localnet-data/config/validators
mkdir -p localnet-data/config/forkpoint
mkdir -p localnet-data/ledger
mkdir -p localnet-data/firehose/{one-blocks,reader,work}

echo "5. Downloading testnet node.toml as base..."
curl -s -o localnet-data/config/node.toml https://bucket.monadinfra.com/config/testnet/latest/full-node-node.toml

echo "6. Configuring node.toml for localnet (chain ID 20143)..."
# Detect OS for sed compatibility
if [[ "$OSTYPE" == "darwin"* ]]; then
    SED_INPLACE=(-i '')
else
    SED_INPLACE=(-i)
fi

# These sed commands modify the downloaded node.toml for localnet use
sed "${SED_INPLACE[@]}" 's/^beneficiary = .*/beneficiary = "0x0000000000000000000000000000000000000000"/' localnet-data/config/node.toml
sed "${SED_INPLACE[@]}" 's/^node_name = .*/node_name = "monad-localnet-node"/' localnet-data/config/node.toml

# Disable features not needed for single-node localnet
sed "${SED_INPLACE[@]}" '/\[fullnode_raptorcast\]/,/^\[/{s/enable_client = .*/enable_client = false/}' localnet-data/config/node.toml
sed "${SED_INPLACE[@]}" '/\[statesync\]/,/^\[/{s/expand_to_group = .*/expand_to_group = false/}' localnet-data/config/node.toml

echo "7. Creating .env file..."
cat > localnet-data/config/.env <<EOF
# Monad localnet environment
# WARNING: This password is insecure and for local testing only
KEYSTORE_PASSWORD='localnet-dev-password-do-not-use-in-production'

# No remote validators/forkpoint for localnet
EOF

echo "8. Generating keystores..."
echo "   Note: Requires 'monad' package to be installed for monad-keystore"

if command -v monad-keystore &> /dev/null; then
    echo "   Found monad-keystore, generating proper keystores..."

    monad-keystore create \
        --key-type secp \
        --keystore-path localnet-data/config/id-secp \
        --password "localnet-dev-password-do-not-use-in-production" \
        > /dev/null 2>&1 || echo "   Warning: SECP keystore generation failed"

    monad-keystore create \
        --key-type bls \
        --keystore-path localnet-data/config/id-bls \
        --password "localnet-dev-password-do-not-use-in-production" \
        > /dev/null 2>&1 || echo "   Warning: BLS keystore generation failed"

    chmod 600 localnet-data/config/id-* 2>/dev/null || true
    echo "   Keystores generated successfully"
else
    echo "   monad-keystore not found!"
    echo "   Creating placeholder keystores (node may not start properly)"
    echo "   Install monad package with: apt install monad=0.12.6"

    touch localnet-data/config/id-secp
    touch localnet-data/config/id-bls
    chmod 600 localnet-data/config/id-* 2>/dev/null || true
fi

echo "9. Creating empty validators and forkpoint configs..."
# Localnet doesn't need real validators/forkpoint files, but create empty ones
touch localnet-data/config/validators/.gitkeep
touch localnet-data/config/forkpoint/.gitkeep

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Configuration files created in localnet-data/:"
echo "  - config/node.toml      (from testnet template, modified for localnet)"
echo "  - config/.env           (keystore password)"
echo "  - config/id-secp        (SECP keystore)"
echo "  - config/id-bls         (BLS keystore)"
echo ""
echo "Next steps:"
echo "1. Build the Docker image:"
echo "   docker build -f Dockerfile.localnet -t monad-localnet-extended ."
echo ""
echo "2. Start the localnet:"
echo "   docker-compose -f docker-compose-localnet.yml up -d"
echo ""
echo "3. Test the RPC connection:"
echo "   curl -X POST http://localhost:8080 -H \"Content-Type: application/json\" \\"
echo "        --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":1}'"
echo ""
echo "   Expected: {\"jsonrpc\":\"2.0\",\"result\":\"0x4eaf\",\"id\":1} (0x4eaf = 20143)"
echo ""
echo "4. Check logs:"
echo "   docker logs -f monad-localnet-consensus"
echo "   docker logs -f monad-localnet-execution"
echo "   docker logs -f monad-localnet-rpc"
echo "   docker logs -f monad-localnet-firehose"
echo ""
echo "5. Access Firehose extended blocks:"
echo "   grpcurl -plaintext localhost:9000 sf.firehose.v2.Stream/Blocks"
