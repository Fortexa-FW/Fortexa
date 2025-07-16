# Fortexa Netshield Usage Guide

This guide explains how to build, run, and test the Fortexa firewall with Netshield (eBPF/XDP) support.

---

## 1. Prerequisites

- **Rust toolchain** (latest stable recommended)
- **libbpf-dev** and kernel headers (for eBPF/XDP)
- **aya** and **bincode** crates (already in Cargo.toml)
- **Root privileges** to attach XDP programs
- **A compiled eBPF object file** (e.g., `netshield_xdp.o`) in your project directory

---

## 2. Build the Project

```sh
cargo build --release
```

---

## 3. Launch the Fortexa Daemon

**Run as root to allow eBPF/XDP attachment:**

```sh
sudo ./target/release/fortexa
```

- The REST API will be available at `http://localhost:8080` (or as configured).
- The Netshield module will load and attach the eBPF program to all non-loopback interfaces.

---

## 4. Test the REST API

### Add a Netshield Rule

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
    "direction": "Output",
    "destination": "8.8.8.8",
    "action": "Block"
  }'
```

### List All Netshield Rules

```sh
curl http://localhost:8080/api/netshield/rules
```

### Update a Netshield Rule

```sh
curl -X PUT http://localhost:8080/api/netshield/rules/{RULE_ID} \
  -H "Content-Type: application/json" \
  -d '{
    "name": "block-dns-updated",
    "direction": "Output",
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
  -d '{"name":"block-dns","direction":"Output","destination":"8.8.8.8","action":"Block"}'

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