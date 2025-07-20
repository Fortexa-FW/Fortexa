# Fortexa eBPF Integration

## Overview

Fortexa uses eBPF/TC (Traffic Control) for high-performance packet filtering with a modern, secure implementation. The eBPF program is maintained in a separate repository for modularity and uses the latest stable dependencies.

## 🚀 **Latest Improvements**

### **Architecture Updates**
- **TC-based Implementation**: Migrated from XDP to TC for better compatibility and flexibility
- **Ingress/Egress Filtering**: Comprehensive packet filtering on both directions
- **Host Byte Order**: Consistent IP address handling between Rust and eBPF components
- **Enhanced Security**: Magic number validation and robust error handling

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
cp /path/to/netshield_tc_secure.o ./
cargo build --features ebpf_enabled
```

## Build Process

The eBPF integration uses a multi-step build process:

1. **C Compilation**: eBPF C code compiled to bytecode using clang
2. **Rust Integration**: Aya framework loads and manages eBPF programs
3. **TC Attachment**: Programs attached to network interfaces via Traffic Control

### Build Commands

```bash
# Build eBPF program
cd netshield-ebpf
make clean && make

# Copy to system location
sudo cp build/netshield_tc_secure.o /usr/lib/fortexa/

# Build Rust application
cd ../Fortexa
cargo build --release --features ebpf_enabled
```

## Technical Architecture

### Traffic Control (TC) Integration

The eBPF program uses Linux Traffic Control for packet filtering:

- **Classifier Program**: SEC("classifier") for TC attachment
- **Ingress/Egress**: Attached to both directions for comprehensive filtering
- **clsact qdisc**: Required queueing discipline for TC eBPF programs
- **Return Values**: TC_ACT_OK (allow) / TC_ACT_SHOT (drop)

### Data Structures

```rust
struct SecureRule {
    magic: u32,           // Security validation (0x4E455453 "NETS")
    source_ip: u32,       // IPv4 in host byte order (0 = any)
    destination_ip: u32,  // IPv4 in host byte order (0 = any)
    source_port: u16,     // Port number (0 = any)
    destination_port: u16, // Port number (0 = any)
    protocol: u8,         // IP protocol (6=TCP, 17=UDP, 0=any)
    action: u8,           // 0=allow, 1=drop
    enabled: u8,          // 1=enabled, 0=disabled
    padding: u8,          // Alignment padding
}
```

### eBPF Maps

- **secure_rules_map**: Hash map storing firewall rules (max 3 entries)
- **security_stats**: Statistics counters for monitoring

### Packet Processing Flow

1. **Parse Ethernet Header**: Validate and extract IP packet
2. **Parse IP Header**: Extract source/destination IPs and protocol
3. **Parse Transport Header**: Extract TCP/UDP port numbers
4. **Convert Byte Order**: Convert network to host byte order for comparison
5. **Rule Matching**: Compare packet against rules in eBPF map
6. **Action Execution**: Allow or drop packet based on rule match

## Security Features

### Input Validation
- **Packet bounds checking**: Prevents buffer overflows
- **Header validation**: Ensures valid IP and transport headers
- **Magic number verification**: Validates rule integrity

### Memory Safety
- **Fixed-size structures**: No dynamic allocation in eBPF
- **Bounds-checked access**: All pointer dereferences validated
- **Stack limits**: eBPF enforces 512-byte stack limit

### Access Control
- **Interface filtering**: Configurable allowed network interfaces
- **Path validation**: eBPF object files restricted to approved paths
- **Rule limits**: Maximum number of rules enforced

## Performance Characteristics

### Advantages of TC over XDP
- **Protocol Coverage**: Works with all protocols, not just Ethernet
- **Flexibility**: Can be attached to any network interface
- **Compatibility**: Better support across different network drivers
- **Debugging**: Enhanced tracing and debugging capabilities

### Performance Metrics
- **Low Latency**: Microsecond-level packet processing
- **High Throughput**: Handles millions of packets per second
- **CPU Efficiency**: Minimal CPU overhead per packet
- **Memory Usage**: Fixed memory footprint with no allocations

## Debugging and Monitoring

### eBPF Trace Output
```bash
# Monitor real-time eBPF debug output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# View recent trace messages
sudo cat /sys/kernel/debug/tracing/trace
```

### Program Status
```bash
# List loaded eBPF programs
sudo bpftool prog list

# Show program details
sudo bpftool prog show id <PROGRAM_ID>
```

### Map Inspection
```bash
# View rules map
sudo bpftool map dump name secure_rules_map

# View statistics
sudo bpftool map dump name security_stats
```

### TC Status
```bash
# Show TC qdiscs
sudo tc qdisc show

# Show TC filters
sudo tc filter show dev <interface> ingress
sudo tc filter show dev <interface> egress
```

For comprehensive debugging information, see [DEBUG.md](DEBUG.md).

## Future Enhancements

### Planned Features
- **IPv6 Support**: Extend filtering to IPv6 packets
- **Advanced Rules**: More complex rule matching capabilities
- **Rate Limiting**: Packet rate limiting per rule
- **Connection Tracking**: Stateful connection monitoring

### Performance Optimizations
- **Map Optimization**: Improved data structures for faster lookups
- **Batch Processing**: Process multiple packets per eBPF call
- **Hardware Offload**: Support for smart NIC acceleration

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
