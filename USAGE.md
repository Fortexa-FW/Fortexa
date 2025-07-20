# Fortexa Netshield Usage Guide

This guide explains how to build, run, and test the Fortexa firewall with Netshield (eBPF/TC) support.

---

## 1. Prerequisites

- **Rust toolchain** (latest stable recommended)
- **libbpf-dev** and kernel headers (for eBPF/TC)
- **aya** and **bincode** crates (already in Cargo.toml)
- **Root privileges** to attach TC programs
- **tc (iproute2)** utility for Traffic Control support
- **A compiled eBPF object file** (e.g., `netshield_tc_secure.o`) in your project directory
- **(Optional)** Set a custom eBPF object path in your config.toml:

```toml
[modules.netshield]
enabled = true
rules_path = "/var/lib/fortexa/netshield_rules.json"
ebpf_path = "/usr/lib/fortexa/netshield_tc_secure.o"  # Path to your eBPF object file
```

If not set, the default build-time path will be used.

---

## 2. Build the Project

```sh
cargo build --release
```

---

## 3. Launch the Fortexa Daemon

**Run as root to allow eBPF/TC attachment:**

```sh
sudo ./target/release/fortexa
```

- The REST API will be available at `http://localhost:8080` (or as configured).
- The Netshield module will load and attach the eBPF program to all non-loopback interfaces using TC (Traffic Control).

---

## 4. Test the REST API

### Add a Netshield Rule

Create a rule to block traffic to a specific destination:

```bash
curl -X POST http://127.0.0.1:8080/api/filter/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "block-dns",
    "description": "Block DNS traffic to 8.8.8.8",
    "direction": "Both",
    "destination": "8.8.8.8",
    "protocol": "udp",
    "destination_port": 53,
    "action": "Block",
    "enabled": true,
    "priority": 100
  }'
```

### Test Rule Enforcement

After adding the rule, test if it's working:

```bash
# This should be blocked if the rule is working
ping 8.8.8.8

# Check eBPF debug output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# View rule statistics
sudo bpftool map dump name security_stats
```

### Debug eBPF Program

Monitor eBPF program activity:

```bash
# View loaded eBPF programs
sudo bpftool prog list

# Check eBPF maps
sudo bpftool map list

# View rules in the map
sudo bpftool map dump name secure_rules_map

# Monitor real-time packet processing
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Traffic Control Status

Check TC attachment status:

```bash
# View TC qdiscs
sudo tc qdisc show

# View TC filters on an interface
sudo tc filter show dev eth0 ingress
sudo tc filter show dev eth0 egress
```

---

## 5. Configuration Options

### Environment Variables

- `FORTEXA_DISABLE_EBPF`: Disable eBPF/TC functionality
- `RUST_LOG`: Set logging level (debug, trace, etc.)

### Security Configuration

The Netshield module includes several security features:

- **Interface filtering**: Only attach to allowed interfaces
- **Path validation**: Restrict eBPF object file paths
- **Rule limits**: Maximum number of rules (configurable)
- **Graceful fallback**: Continue without eBPF if attachment fails

---

## 6. Troubleshooting

### Common Issues

1. **Permission denied**: Ensure running as root
2. **TC attachment failure**: Check if interface supports TC
3. **eBPF load failure**: Verify kernel eBPF support
4. **Rules not blocking**: Check byte order and IP conversion

### Debug Commands

```bash
# Check kernel eBPF support
ls /sys/fs/bpf

# Verify TC utility
which tc

# Check interface capabilities
ip link show

# Monitor system logs
dmesg | tail

# Detailed debug information
RUST_LOG=debug sudo ./target/release/fortexa
```

For comprehensive debugging information, see [DEBUG.md](DEBUG.md).

---

## 7. Performance

The eBPF/TC implementation provides:

- **High performance**: Kernel-space packet processing
- **Low latency**: Minimal overhead per packet
- **Scalability**: Handles high packet rates efficiently
- **Statistics**: Built-in performance monitoring

Monitor performance with:

```bash
# View packet statistics
sudo bpftool map dump name security_stats

# Monitor interface statistics
cat /proc/net/dev

# Check CPU usage
top -p $(pgrep fortexa)
```

**Required fields:**
- `name` (string)
- `direction` ("Input" or "Output")
- `action` ("Block", "Allow", or "Log")

**Example:**
```sh
curl -X POST http://localhost:8080/api/netshield/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "block-dns",
    "direction": "Outgoing",
    "destination": "8.8.8.8",
    "action": "Block"
  }'
```

### List All Netshield Rules

```sh
curl http://localhost:8080/api/netshield/rules
```

### Update a Netshield Rule
{RULE_ID}
```sh
curl -X PUT http://localhost:8080/api/netshield/rules/dfc95503-dbaa-4ede-ad3f-cac333e8dc56 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "block-dns-updated",
    "direction": "Outgoing",
    "destination": "8.8.4.4",
    "action": "Block"
  }'
```

### Delete a Netshield Rule

```sh
curl -X DELETE http://localhost:8080/api/netshield/rules/{RULE_ID}
```

---

## 5. Verify eBPF/XDP Filtering

- **Check logs:**
  - The daemon logs will show lines like:
    ```
    [Netshield] Applying rule: id=... name=... action=... direction=... src=... dst=... group=...
    ```
- **Test network traffic:**
  - Try to access a blocked IP (e.g., `ping 8.8.8.8` or `curl http://8.8.8.8`).
  - The traffic should be dropped if the rule is active and your eBPF program is implemented to block it.
- **Check eBPF program attachment:**
  - Use `bpftool` or `ip link show` to verify XDP is attached:
    ```sh
    sudo bpftool net
    sudo ip link show
    ```

---

## 6. Troubleshooting

- **Permission denied:**
  - Make sure you run the daemon as root (`sudo`).
- **eBPF program not attached:**
  - Check kernel logs (`dmesg`) for errors.
  - Ensure your kernel supports XDP and eBPF.
- **Rules not applied:**
  - Check the daemon logs for errors.
  - Ensure the eBPF map is being updated (see logs).
- **REST API not responding:**
  - Ensure the daemon is running and listening on the correct port.

  sudo bpftool map list

---

## 7. Clean Shutdown

- To detach XDP programs and clean up, stop the daemon with `Ctrl+C` or send a SIGTERM.
- The `detach_all` method will be called to remove XDP from all interfaces.

---

## 8. Advanced

- **Custom eBPF/XDP logic:**
  - Edit your eBPF program and recompile to `netshield_xdp.o`.
  - Restart the daemon to reload the program.
- **Multiple interfaces:**
  - The Netshield module automatically attaches to all non-loopback interfaces.

---

## 9. Example: Full Test Cycle

```sh
# 1. Start the daemon
sudo ./target/release/fortexa

# 2. Add a rule
curl -X POST http://localhost:8080/api/netshield/rules \
  -H "Content-Type: application/json" \
  -d '{"name":"block-dns","direction":"Output","destination_ip":"8.8.8.8","action":"Block"}'

# 3. List rules
curl http://localhost:8080/api/netshield/rules

# 4. Test network traffic (should be blocked)
ping 8.8.8.8

# 5. Delete the rule
curl -X DELETE http://localhost:8080/api/netshield/rules/{RULE_ID}

# 6. Test network traffic again (should be allowed)
ping 8.8.8.8
```

---

## 10. Notes

- Make sure your eBPF program and userspace serialization are compatible.
- Always test on a non-production system first when working with XDP/eBPF.
- For more details, see the API documentation in `API.md`. 