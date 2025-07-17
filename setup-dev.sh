#!/bin/bash
# Setup script for Fortexa development environment

set -e

echo "🔧 Setting up Fortexa development environment..."

# Check if we're in the fortexa repository
if [[ ! -f "Cargo.toml" ]] || ! grep -q "name = \"fortexa\"" Cargo.toml; then
    echo "❌ Please run this script from the fortexa repository root"
    exit 1
fi

# Check for netshield-ebpf
if [[ ! -d "netshield-ebpf" ]]; then
    echo "📦 netshield-ebpf not found. Adding as git submodule..."
    
    # Prompt for netshield-ebpf repository URL
    read -p "Enter netshield-ebpf repository URL: " NETSHIELD_REPO
    
    if [[ -n "$NETSHIELD_REPO" ]]; then
        git submodule add "$NETSHIELD_REPO" netshield-ebpf
        git submodule update --init --recursive
    else
        echo "ℹ️  You can manually clone netshield-ebpf later"
    fi
fi

# Check Rust toolchain
echo "🦀 Checking Rust toolchain..."
if ! rustup toolchain list | grep -q nightly; then
    echo "📥 Installing nightly Rust toolchain..."
    rustup toolchain install nightly
fi

# Install eBPF tools
echo "🔨 Installing eBPF build tools..."
rustup +nightly component add rust-src

if ! command -v bpf-linker &> /dev/null; then
    echo "📥 Installing bpf-linker..."
    cargo install bpf-linker
fi

# Build eBPF if available
if [[ -d "netshield-ebpf" ]]; then
    echo "🏗️  Building eBPF program..."
    cd netshield-ebpf
    cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
    cd ..
fi

echo "✅ Setup complete! You can now build Fortexa with eBPF support."
echo ""
echo "Next steps:"
echo "  cargo build --release"
echo "  sudo ./target/release/fortexa  # (requires root for eBPF)"
