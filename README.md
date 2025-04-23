<p align="center">
  <img src="/assets/img/logo-readme.png">
</p>

# Fortexa
A modern firewall solution built with Rust for superior performance and memory safety. We provide robust network security with minimal overhead, leveraging Rust's speed and reliability to protect your infrastructure against emerging threats.



Kernel-Level Blocking: Handled by FirewallManager via iptables.

Daemon Logging:

Monitors all traffic on the network interface.

Checks packets against current rules.

Prints console messages when blocked traffic is detected (even though the kernel already dropped it).

## Fortexa Firewall API

### Overview

The Fortexa firewall API lets you **view, add, append, or delete firewall rules** for blocked/whitelisted IPs and ports.
All requests and responses use JSON.

_Base URL:_

```
http://localhost:3000
```


---

### Endpoints

### 1. Get Current Rules

**`GET /rules`**

Returns your current firewall rules.

**Response Example:**

```json
{
  "input": {
    "blocked_ips": ["192.168.1.100/32", "10.0.0.0/8"],
    "blocked_ports": [22, 80],
    "whitelisted_ips": ["192.168.1.10/32"],
    "whitelisted_ports": [443]
  },
  "output": {
    "blocked_ips": ["8.8.8.8/32"],
    "blocked_ports": [25],
    "whitelisted_ips": [],
    "whitelisted_ports": []
  }
}
```


---

### 2. Replace All Rules

**`POST /rules`**

**(Warning: This replaces the entire current rule set!)**

**Body Example:**

```json
{
  "input": {
    "blocked_ips": ["192.168.1.100/32"],
    "blocked_ports": [22],
    "whitelisted_ips": [],
    "whitelisted_ports": []
  },
  "output": {
    "blocked_ips": [],
    "blocked_ports": [],
    "whitelisted_ips": [],
    "whitelisted_ports": []
  }
}
```

**Response:**

```
"Rules fully replaced and saved"
```


---

### 3. Append Rules (Partial Update)

**`POST /rules/append`**

Appends entries to existing rules (does not replace!). Fields are optional; only supplied fields are appended.

**Body Example:**

```json
{
  "input": {
    "blocked_ips": ["10.10.10.0/24"],
    "whitelisted_ports": [8443]
  }
}
```

**Response:**

```
"Rules appended successfully"
```


---

### 4. Delete Specific Rules

**`DELETE /rules/delete`**

Removes specific entries from blocked/whitelisted IPs/ports.
Fields are optional; only supplied rules will be deleted.

**Body Example:**

```json
{
  "input": {
    "blocked_ips": ["192.168.1.100/32"],
    "blocked_ports": [22]
  },
  "output": {
    "blocked_ips": ["8.8.8.8/32"]
  }
}
```

**Response:**

```
"Specified rules deleted successfully"
```


---

## Data Model

- **blocked_ips / whitelisted_ips**: Array of CIDR strings (e.g. `"192.168.1.0/24"`, `"8.8.8.8/32"`)
- **blocked_ports / whitelisted_ports**: Array of port numbers (e.g. `[443]`)

---

## Example Usage with cURL

**Replace all rules:**

```sh
curl -X POST http://localhost:3000/rules \
  -H "Content-Type: application/json" \
  -d @rules.json
```

**Append a blocked IP:**

```sh
curl -X POST http://localhost:3000/rules/append \
  -H "Content-Type: application/json" \
  -d '{"input":{"blocked_ips":["172.16.0.0/12"]}}'
```

**Delete a blocked port:**

```sh
curl -X DELETE http://localhost:3000/rules/delete \
  -H "Content-Type: application/json" \
  -d '{"output":{"blocked_ports":[25]}}'
```


---

## 5. Resetting All Firewall Rules

### Endpoint: `POST /rules/reset`

**Description:**
Removes (deletes) **all firewall rules** in both the kernel and the persisted `rules.json` file. After calling this endpoint, your firewall will be empty and allow all traffic (unless new rules are added).


### Request

```
POST /rules/reset
```

**No body required.**


### Response

```
"All firewall rules reset and deleted"
```


### Example using cURL

```sh
curl -X POST http://localhost:3000/rules/reset
```


**What Happens**

- All chains (`FORTEXA_INPUT`, `FORTEXA_OUTPUT`) are flushed and deleted from iptables (kernel).
- Subsequent `/rules` or `/rules/append`/`/rules/delete` POST requests can build new rules as needed.


**Security Note for resetting**

- This action removes **all protections** until new rules are added!
- It is recommended to protect this endpoint with authentication or network restrictions in production.

---

## Global Notes

- All modifications automatically sync firewall rules to iptables and update `rules.json`.
- Whitelist always takes priority over blocklist (a whitelisted IP/port is never blocked).
- Only supply the fields you want to change for append/delete.

---

## Security

- The API must be run with root privileges to manage iptables.
- It is recommended to restrict network access (use localhost or firewall/API gateway for access control).

---

**Happy firewalling!**