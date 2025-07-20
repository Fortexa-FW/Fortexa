#!/usr/bin/env bash
set -e

echo "🚀 Building Fortexa Firewall with TC eBPF module..."
echo "=============================================="

# Check prerequisites
echo "Checking prerequisites..."
if ! command -v clang &> /dev/null; then
    echo "❌ ERROR: clang not found. Please install: sudo apt install clang"
    exit 1
fi

if ! command -v make &> /dev/null; then
    echo "❌ ERROR: make not found. Please install: sudo apt install build-essential"
    exit 1
fi

if ! command -v bpftool &> /dev/null; then
    echo "⚠️  WARNING: bpftool not found. Install for testing: sudo apt install linux-tools-$(uname -r)"
fi

echo "✅ Prerequisites check passed"

# Go to project root
cd "$(dirname "$0")/.."

# Build netshield-ebpf (C implementation)
echo ""
echo "📦 Building netshield-ebpf C implementation..."
cd netshield-ebpf

# Clean previous builds
make clean

# Build the TC eBPF version (recommended for bidirectional firewall)
echo "Building TC eBPF version..."
make tc

# Test the build with bpftool (if available)
if command -v bpftool &> /dev/null; then
    echo "Testing TC eBPF program with bpftool..."
    make test-tc || echo "⚠️  bpftool test failed, but continuing..."
fi

# Install to system location
echo "Installing TC eBPF module to system location..."
sudo make install-tc

# Verify the installation
if [ -f "/usr/lib/fortexa/netshield_tc_secure.o" ]; then
    echo "✅ TC eBPF module successfully installed to /usr/lib/fortexa/netshield_tc_secure.o"
else
    echo "❌ ERROR: TC eBPF module installation failed!"
    exit 1
fi

# Build Fortexa
echo ""
echo "🔥 Building Fortexa firewall..."
cd ../Fortexa
cargo build --release --features ebpf_enabled

# Verify Fortexa build
if [ -f "target/release/fortexa" ]; then
    echo "✅ Fortexa firewall successfully built"
else
    echo "❌ ERROR: Fortexa build failed!"
    exit 1
fi

echo ""
echo "🎉 Build complete! TC eBPF module and Fortexa firewall are ready."
echo "=============================================="
echo "📍 TC eBPF module location: /usr/lib/fortexa/netshield_tc_secure.o"
echo "📍 Fortexa binary: target/release/fortexa"
echo ""
echo "Next steps:"
echo "  1. Run Fortexa: ./target/release/fortexa"
echo "  2. Check eBPF module: sudo bpftool prog show"
echo "  3. Monitor logs for TC attachment status"
