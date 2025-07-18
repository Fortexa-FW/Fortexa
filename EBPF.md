# Fortexa eBPF Integration

## Overview

Fortexa uses eBPF/XDP for high-performance packet filtering with a modern, secure implementation. The eBPF program is maintained in a separate repository for modularity and uses the latest stable dependencies.

## 🚀 **Latest Improvements**

### **Dependencies & Compatibility**
- **network-types 0.0.8**: Latest stable release with enhanced API
- **aya-ebpf 0.1**: Stable release for better reliability
- **Rust 2024 Edition**: All components using the latest language features
- **API Compatibility**: Resolved breaking changes with differentiated field handling

### **Build System Enhancements**
- **Intelligent eBPF Building**: Reuses existing objects when available
- **Graceful Fallbacks**: Continues without eBPF if compilation fails
- **Zero-Warning Builds**: Clean compilation with optimized code
- **Cross-Platform Support**: Robust handling for non-Linux environments

## Development Setup

### Option 1: Git Submodule (Recommended)
```bash
# Add netshield-ebpf as a submodule
git submodule add https://github.com/fortexa-fw/netshield-ebpf.git netshield-ebpf
git submodule update --init --recursive

# Run the setup script
./setup-dev.sh
```

### Option 2: Sibling Directory
```bash
# Clone repositories as siblings
git clone https://github.com/fortexa-fw/fortexa.git
git clone https://github.com/fortexa-fw/netshield-ebpf.git

cd fortexa
cargo build --features ebpf_enabled
```

### Option 3: Manual eBPF Object
```bash
# Pre-compile eBPF object and place it manually
cp /path/to/netshield_xdp.o ./
cargo build --features ebpf_enabled
```

## Build Process

The enhanced build system automatically:
1. **Detects** if netshield-ebpf source is available in multiple locations
2. **Reuses** existing eBPF objects when available (faster builds)
3. **Builds** eBPF program with nightly Rust if needed
4. **Handles** API compatibility issues gracefully
5. **Embeds** the eBPF object file in the binary
6. **Falls back** gracefully if eBPF is not available (no build failures)

### **Build Features**
```bash
# Enable eBPF features explicitly
cargo build --features ebpf_enabled

# Check build without eBPF (for CI/testing)
cargo build

# Clean build with eBPF rebuild
cargo clean && cargo build --features ebpf_enabled
```

## Requirements

- **Linux** target (eBPF only works on Linux)
- **Nightly Rust** toolchain for eBPF compilation
- **bpf-linker** tool
- **Root privileges** for XDP attachment (runtime only)

### **Installation**
```bash
# Install nightly toolchain
rustup toolchain install nightly

# Install bpf-linker
cargo install bpf-linker

# Add eBPF target
rustup +nightly target add bpfel-unknown-none
```

## Architecture

```
fortexa/                             # Main application
├── src/modules/netshield/          
│   ├── mod.rs                      # eBPF loader with latest API compatibility
│   ├── security.rs                 # Production-ready security framework
│   └── constants.rs                # Clean constants (removed unused)
├── build.rs                        # Enhanced build script with fallbacks
├── Cargo.toml                      # Rust 2024 edition, ebpf_enabled feature
└── rustfmt.toml                    # Consistent formatting (edition 2024)

netshield-ebpf/                      # Separate eBPF repository
├── src/main.rs                     # eBPF/XDP program with optimized algorithms
├── build.rs                        # eBPF object creation and copying
├── Cargo.toml                      # Latest stable dependencies (2024 edition)
├── rustfmt.toml                    # Consistent formatting configuration
└── netshield-ebpf-common/          # Shared constants and types
    ├── src/lib.rs                  # Common definitions
    └── Cargo.toml                  # 2024 edition
```

## 🔧 **Technical Improvements**

### **API Compatibility**
- **Differentiated Field Handling**: TCP ports (u16) vs UDP ports ([u8;2])
- **Manual Packet Parsing**: Avoids packed struct alignment issues
- **Safe Memory Access**: All field access includes bounds checking
- **Network Types 0.0.8**: Latest API with proper byte array handling

### **Performance Optimizations**
- **Range Checks**: Using `RangeInclusive::contains()` for better performance
- **Memory Layout**: Optimized data structures for eBPF constraints
- **Minimal Allocations**: Stack-only operations in eBPF context

### **Code Quality**
- **Zero Clippy Warnings**: Clean, idiomatic Rust code
- **Consistent Formatting**: Standardized across all components
- **Modern Rust**: 2024 edition features for better performance
