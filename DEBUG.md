# Fortexa eBPF Firewall Debugging Guide

This guide explains how to debug the Fortexa eBPF firewall system to ensure it's working properly and troubleshoot issues.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [eBPF Program Debugging](#ebpf-program-debugging)
3. [Rust Application Debugging](#rust-application-debugging)
4. [Network Traffic Analysis](#network-traffic-analysis)
5. [Rule Verification](#rule-verification)
6. [Performance Monitoring](#performance-monitoring)
7. [Common Issues](#common-issues)
8. [Tools and Commands](#tools-and-commands)

## Prerequisites

Before debugging, ensure you have the necessary tools installed:

```bash
# Install debugging tools
sudo apt update
sudo apt install bpftool tcpdump wireshark-common net-tools iproute2

# Ensure debugfs is mounted
sudo mount -t debugfs debugfs /sys/kernel/debug
```

## eBPF Program Debugging

### 1. Monitor eBPF Debug Output

The eBPF program uses `bpf_printk` for debug output. View these messages:

```bash
# Continuous monitoring of eBPF debug output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# View recent trace messages
sudo cat /sys/kernel/debug/tracing/trace

# Clear trace buffer before testing
sudo echo > /sys/kernel/debug/tracing/trace
```

### 2. Check eBPF Program Status

```bash
# List all loaded eBPF programs
sudo bpftool prog list

# Show detailed information about a specific program
sudo bpftool prog show id <PROGRAM_ID>

# Dump program bytecode (advanced)
sudo bpftool prog dump xlated id <PROGRAM_ID>
```

### 3. Inspect eBPF Maps

```bash
# List all eBPF maps
sudo bpftool map list

# Dump contents of the rules map
sudo bpftool map dump id <MAP_ID>

# Dump statistics map
sudo bpftool map dump name security_stats

# Monitor map updates in real-time
watch -n 1 'sudo bpftool map dump name secure_rules_map'
```

### 4. TC (Traffic Control) Status

```bash
# Check TC qdisc status
sudo tc qdisc show

# List TC filters on an interface
sudo tc filter show dev <INTERFACE> ingress
sudo tc filter show dev <INTERFACE> egress

# Remove TC setup (for cleanup)
sudo tc qdisc del dev <INTERFACE> clsact
```

## Rust Application Debugging

### 1. Enable Debug Logging

Set the log level to see detailed debug information:

```bash
# Run with debug logging
RUST_LOG=debug ./fortexa

# Or with trace-level logging for even more detail
RUST_LOG=trace ./fortexa

# Log only netshield module
RUST_LOG=fortexa::modules::netshield=debug ./fortexa
```

### 2. Check Application Logs

Look for these key log messages:

- **eBPF Loading**: `Successfully initialized Netshield with eBPF/TC`
- **Rule Conversion**: `Converted destination IP '...' to host bytes: ...`
- **Map Updates**: `Updated eBPF rules map with X rules`
- **Interface Attachment**: `Successfully attached TC to interface ...`

### 3. Rule Debugging

Monitor rule processing:

```bash
# Enable detailed rule logging
RUST_LOG=fortexa::modules::netshield::filter=debug ./fortexa
```

## Network Traffic Analysis

### 1. Capture Network Traffic

```bash
# Capture traffic on specific interface
sudo tcpdump -i <INTERFACE> -n

# Capture traffic to/from specific IP
sudo tcpdump -i any host 8.8.4.4

# Save traffic to file for analysis
sudo tcpdump -i any -w traffic.pcap host 8.8.4.4
```

### 2. Test Connectivity

```bash
# Test if blocking is working
ping 8.8.4.4
curl -I http://8.8.4.4
wget --timeout=5 -O /dev/null http://8.8.4.4

# Test with specific protocols
nc -u 8.8.4.4 53    # UDP DNS
nc -w 5 8.8.4.4 80  # TCP HTTP
```

### 3. Monitor Interface Statistics

```bash
# Check interface packet counters
cat /proc/net/dev

# Monitor interface traffic
watch -n 1 'cat /proc/net/dev | grep <INTERFACE>'
```

## Rule Verification

### 1. Check Rule Conversion

Verify that IP addresses are correctly converted:

```python
# Python script to verify IP conversion
import socket
import struct

def ip_to_host_order(ip_str):
    """Convert IP string to host byte order (little-endian on x86)"""
    ip_bytes = socket.inet_aton(ip_str)
    return struct.unpack('<I', ip_bytes)[0]

def host_order_to_ip(host_int):
    """Convert host byte order integer back to IP string"""
    ip_bytes = struct.pack('<I', host_int)
    return socket.inet_ntoa(ip_bytes)

# Test conversion
ip = "8.8.4.4"
host_int = ip_to_host_order(ip)
print(f"IP: {ip} -> Host order: {host_int} (0x{host_int:08x})")
print(f"Back to IP: {host_order_to_ip(host_int)}")
```

### 2. Manual Rule Testing

```bash
# Add test rule via API
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-block",
    "destination": "8.8.4.4",
    "action": "Block",
    "enabled": true
  }'

# Verify rule was added
curl http://localhost:8080/api/rules

# Test the rule
ping 8.8.4.4
```

## Performance Monitoring

### 1. eBPF Statistics

Monitor packet processing statistics:

```bash
# Check security stats map
sudo bpftool map dump name security_stats

# Continuous monitoring
watch -n 1 'sudo bpftool map dump name security_stats'
```

The statistics include:
- `0`: Packets processed
- `1`: Packets allowed
- `2`: Packets dropped
- `3`: Invalid packets

### 2. System Performance

```bash
# Check CPU usage
top -p $(pgrep fortexa)

# Monitor memory usage
ps aux | grep fortexa

# Check kernel messages
dmesg | tail -20
```

## Common Issues

### 1. eBPF Program Not Loading

**Symptoms**: Error messages about eBPF loading failure

**Solutions**:
```bash
# Check if eBPF is supported
ls /sys/fs/bpf

# Verify kernel version (needs 4.1+)
uname -r

# Check for required kernel configs
zgrep CONFIG_BPF /proc/config.gz
```

### 2. Rules Not Blocking Traffic

**Symptoms**: Traffic continues despite block rules

**Debug steps**:
1. Check if eBPF program is attached: `sudo bpftool prog list`
2. Verify rules in map: `sudo bpftool map dump name secure_rules_map`
3. Monitor debug output: `sudo cat /sys/kernel/debug/tracing/trace_pipe`
4. Check IP address conversion in logs

### 3. TC Attachment Failures

**Symptoms**: TC attachment errors in logs

**Solutions**:
```bash
# Clean up existing TC rules
sudo tc qdisc del dev <INTERFACE> clsact

# Check interface exists
ip link show

# Verify permissions
sudo -v
```

### 4. Byte Order Issues

**Symptoms**: Rules show wrong IP addresses in hex dump

**Debug**:
```bash
# Check what's actually in the map
sudo bpftool map dump name secure_rules_map

# Compare with expected values using Python
python3 -c "
import socket
ip = '8.8.4.4'
packed = socket.inet_aton(ip)
host_order = int.from_bytes(packed, 'little')
print(f'{ip} in host order: {host_order} (0x{host_order:08x})')
"
```

## Tools and Commands

### Essential Commands

```bash
# eBPF Management
sudo bpftool prog list                          # List programs
sudo bpftool map list                           # List maps
sudo bpftool map dump name secure_rules_map    # Dump rules
sudo bpftool map dump name security_stats      # Dump stats

# Network Debugging
sudo tcpdump -i any host 8.8.4.4              # Capture traffic
ping -c 3 8.8.4.4                             # Test connectivity
sudo netstat -tuln                             # Check listening ports

# TC Management
sudo tc qdisc show                             # Show qdiscs
sudo tc filter show dev eth0 ingress          # Show filters
sudo tc qdisc del dev eth0 clsact             # Clean TC

# System Information
sudo dmesg | tail                              # Kernel messages
cat /proc/net/dev                              # Interface stats
ps aux | grep fortexa                          # Process info
```

### Debug Script

Create a debug script for automated testing:

```bash
#!/bin/bash
# debug_firewall.sh

echo "=== Fortexa eBPF Firewall Debug Script ==="

echo "1. Checking eBPF programs..."
sudo bpftool prog list | grep -E "(tc|classifier)"

echo "2. Checking eBPF maps..."
sudo bpftool map list | grep -E "(secure_rules|security_stats)"

echo "3. Dumping rules map..."
sudo bpftool map dump name secure_rules_map 2>/dev/null || echo "Rules map not found"

echo "4. Dumping stats map..."
sudo bpftool map dump name security_stats 2>/dev/null || echo "Stats map not found"

echo "5. Testing connectivity..."
ping -c 1 8.8.4.4 >/dev/null 2>&1 && echo "8.8.4.4 reachable" || echo "8.8.4.4 blocked/unreachable"

echo "6. Recent eBPF traces (last 10 lines)..."
sudo tail -10 /sys/kernel/debug/tracing/trace 2>/dev/null || echo "Trace not available"

echo "=== Debug complete ==="
```

## Troubleshooting Workflow

1. **Start with logs**: Check application logs for errors
2. **Verify eBPF loading**: Ensure programs and maps are loaded
3. **Check rule conversion**: Verify IP addresses are correct in maps
4. **Monitor traffic**: Use tcpdump to see actual network packets
5. **Test incrementally**: Add simple rules first, then complex ones
6. **Use trace output**: Monitor eBPF debug messages during testing

This debugging approach will help you identify and resolve issues with the eBPF firewall system effectively.
