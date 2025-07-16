<p align="center">
  <img src="/assets/img/logo-readme.png">
</p>

# Fortexa
A modern firewall solution built with Rust for superior performance and memory safety. We provide robust network security with minimal overhead, leveraging Rust's speed and reliability to protect your infrastructure against emerging threats.

> **Note:** For the latest and most complete REST API documentation, see [API.md](./API.md).

Daemon Logging:

Monitors all traffic on the network interface.

Checks packets against current rules.

Prints console messages when blocked traffic is detected (even though the kernel already dropped it).

## Fortexa Firewall API

### Modern REST API Usage

See [`API.md`](./API.md) for the full, up-to-date REST API documentation and usage examples.

### Overview

The Fortexa firewall API lets you **view, add, append, or delete firewall rules** for blocked/whitelisted IPs and ports.
All requests and responses use JSON.

_Base URL:_

```
http://localhost:8080
```

---

## Global Notes

- All modifications automatically sync firewall rules and update `rules.json`.
- Whitelist always takes priority over blocklist (a whitelisted IP/port is never blocked).
- Only supply the fields you want to change for append/delete.

---

## Security

- The API must be run with root privileges to manage network filtering.
- It is recommended to restrict network access (use localhost or firewall/API gateway for access control).

---

**Happy firewalling!**