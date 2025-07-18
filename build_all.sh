#!/usr/bin/env bash
set -e

# Go to project root
cd "$(dirname "$0")/.."

# Build netshield-ebpf
cd netshield-ebpf
cargo build --release

# Copy the .o file
OBJ=target/bpfel-unknown-none/release/netshield_xdp.o
DEST=/usr/lib/fortexa/netshield_xdp.o
if [ -f "$OBJ" ]; then
    echo "Copying $OBJ to $DEST"
    mkdir -p "/usr/lib/fortexa/"
    sudo cp "$OBJ" "$DEST"
else
    echo "ERROR: $OBJ not found!"
    exit 1
fi

# Build Fortexa
cd ../Fortexa
cargo build --release

echo "Build complete." 