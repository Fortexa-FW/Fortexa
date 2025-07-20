# Fortexa REST API

This document describes the REST API for managing firewall rules with eBPF/TC integration.

The API base URL is `http://<bind_address>:<port>`. By default, this is `http://127.0.0.1:8080`.

## 1. Rules API

### 1.1 List all rules

- **GET** `/api/filter/rules`

Lists all currently configured firewall rules.

**Example:**

```bash
curl -X GET http://127.0.0.1:8080/api/filter/rules
```

**Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "block-malicious-ip",
    "description": "Block traffic from known malicious IP",
    "direction": "Both",
    "source": "192.168.1.100",
    "destination": null,
    "source_port": null,
    "destination_port": null,
    "protocol": "tcp",
    "action": "Block",
    "enabled": true,
    "priority": 100
  }
]
```

### 1.2 Add a new rule

- **POST** `/api/filter/rules`

Adds a new firewall rule and synchronizes it with the eBPF program.

**Payload:** A JSON object representing the rule.

```json
{
  "name": "block-dns-server",
  "description": "Block DNS queries to specific server",
  "direction": "Both",
  "source": null,
  "destination": "8.8.8.8",
  "source_port": null,
  "destination_port": 53,
  "protocol": "udp",
  "action": "Block",
  "enabled": true,
  "priority": 100
}
```

**Example Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "name": "block-dns-server",
  "description": "Block DNS queries to specific server",
  "direction": "Both",
  "source": null,
  "destination": "8.8.8.8",
  "source_port": null,
  "destination_port": 53,
  "protocol": "udp",
  "action": "Block",
  "enabled": true,
  "priority": 100
}
```

### 1.3 Get a specific rule

- **GET** `/api/filter/rules/{id}`

Retrieves a specific rule by its ID.

**Example:**

```bash
curl -X GET http://127.0.0.1:8080/api/filter/rules/550e8400-e29b-41d4-a716-446655440000
```

### 1.4 Update a rule

- **PUT** `/api/filter/rules/{id}`

Updates an existing rule and synchronizes changes with the eBPF program.

**Example:**

```bash
curl -X PUT http://127.0.0.1:8080/api/filter/rules/550e8400-e29b-41d4-a716-446655440000 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "block-dns-server-updated",
    "description": "Updated rule description",
    "enabled": false
  }'
```

### 1.5 Delete a rule

- **DELETE** `/api/filter/rules/{id}`

Deletes a rule and removes it from the eBPF program.

**Example:**

```bash
curl -X DELETE http://127.0.0.1:8080/api/filter/rules/550e8400-e29b-41d4-a716-446655440000
```

## 2. eBPF Integration

### 2.1 eBPF Status

- **GET** `/api/netshield/status`

Returns the current status of the eBPF/TC integration.

**Example:**

```bash
curl -X GET http://127.0.0.1:8080/api/netshield/status
```

**Response:**
```json
{
  "ebpf_loaded": true,
  "interfaces_attached": ["eth0", "wlan0"],
  "rules_count": 2,
  "statistics": {
    "packets_processed": 15420,
    "packets_allowed": 15418,
    "packets_dropped": 2,
    "invalid_packets": 0
  }
}
```

### 2.2 Reload eBPF Rules

- **POST** `/api/netshield/reload`

Forces a reload of all rules into the eBPF program.

**Example:**

```bash
curl -X POST http://127.0.0.1:8080/api/netshield/reload
```

### 2.3 eBPF Statistics

- **GET** `/api/netshield/stats`

Returns detailed eBPF program statistics.

**Example:**

```bash
curl -X GET http://127.0.0.1:8080/api/netshield/stats
```

**Response:**
```json
{
  "packets_processed": 15420,
  "packets_allowed": 15418,
  "packets_dropped": 2,
  "invalid_packets": 0,
  "rules_active": 2,
  "uptime_seconds": 3600
}
```

## 3. Rule Examples

### 3.1 Block Specific IP Address

Block all traffic to/from a specific IP:

```bash
curl -X POST http://127.0.0.1:8080/api/filter/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "block-malicious-ip",
    "description": "Block known malicious IP address",
    "direction": "Both",
    "source": "192.168.1.100",
    "destination": null,
    "protocol": null,
    "action": "Block",
    "enabled": true,
    "priority": 200
  }'
```

### 3.2 Block DNS to Specific Server

Block DNS queries to a specific DNS server:

```bash
curl -X POST http://127.0.0.1:8080/api/filter/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "block-dns-8888",
    "description": "Block DNS queries to 8.8.8.8",
    "direction": "Both",
    "destination": "8.8.8.8",
    "destination_port": 53,
    "protocol": "udp",
    "action": "Block",
    "enabled": true,
    "priority": 150
  }'
```

### 3.3 Allow SSH from Specific Network

Allow SSH access only from a specific network:

```bash
curl -X POST http://127.0.0.1:8080/api/filter/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "allow-ssh-admin",
    "description": "Allow SSH from admin network",
    "direction": "Incoming",
    "source": "10.0.0.0/24",
    "destination_port": 22,
    "protocol": "tcp",
    "action": "Allow",
    "enabled": true,
    "priority": 300
  }'
```

### 3.4 Block ICMP (Ping)

Block all ICMP traffic:

```bash
curl -X POST http://127.0.0.1:8080/api/filter/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "block-icmp",
    "description": "Block all ICMP traffic",
    "direction": "Both",
    "protocol": "icmp",
    "action": "Block",
    "enabled": true,
    "priority": 100
  }'
```

## 4. Error Responses

### 4.1 Validation Errors

When submitting invalid data:

```json
{
  "error": "Validation failed",
  "details": {
    "name": "Rule name must be unique",
    "destination_port": "Port must be between 1 and 65535"
  }
}
```

### 4.2 eBPF Errors

When eBPF operations fail:

```json
{
  "error": "eBPF operation failed",
  "message": "Failed to update rules map",
  "details": "Permission denied - ensure running as root"
}
```

### 4.3 Not Found

When requesting a non-existent rule:

```json
{
  "error": "Rule not found",
  "id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## 5. Rate Limiting and Security

### 5.1 Rate Limiting

The API implements rate limiting to prevent abuse:

- **Rules Management**: 100 requests per minute per IP
- **Status Queries**: 1000 requests per minute per IP
- **eBPF Operations**: 10 requests per minute per IP

### 5.2 Authentication

Currently, the API uses IP-based access control:

- **Local Access**: Unrestricted access from 127.0.0.1
- **Network Access**: Configurable IP whitelist for remote access
- **Future**: JWT token authentication planned

### 5.3 Input Validation

All inputs are validated:

- **IP Addresses**: Must be valid IPv4 addresses
- **Ports**: Must be between 1 and 65535
- **Protocols**: Must be tcp, udp, icmp, or null
- **Actions**: Must be Allow, Block, or Log
- **Rule Names**: Must be unique and alphanumeric

## 6. Integration Examples

### 6.1 Python Integration

```python
import requests
import json

class ForteXAClient:
    def __init__(self, base_url="http://127.0.0.1:8080"):
        self.base_url = base_url

    def add_rule(self, rule_data):
        response = requests.post(
            f"{self.base_url}/api/filter/rules",
            json=rule_data,
            headers={"Content-Type": "application/json"}
        )
        return response.json()

    def get_rules(self):
        response = requests.get(f"{self.base_url}/api/filter/rules")
        return response.json()

    def get_stats(self):
        response = requests.get(f"{self.base_url}/api/netshield/stats")
        return response.json()

# Usage example
client = ForteXAClient()

# Add a blocking rule
rule = {
    "name": "block-test",
    "destination": "1.2.3.4",
    "action": "Block",
    "enabled": True,
    "priority": 100
}

result = client.add_rule(rule)
print(f"Rule added: {result['id']}")

# Check statistics
stats = client.get_stats()
print(f"Packets processed: {stats['packets_processed']}")
```

### 6.2 Bash Script Integration

```bash
#!/bin/bash

# Fortexa API helper functions
API_BASE="http://127.0.0.1:8080"

add_block_rule() {
    local name="$1"
    local ip="$2"

    curl -s -X POST "$API_BASE/api/filter/rules" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$name\",
            \"destination\": \"$ip\",
            \"action\": \"Block\",
            \"enabled\": true,
            \"priority\": 100
        }"
}

get_stats() {
    curl -s "$API_BASE/api/netshield/stats" | jq .
}

# Usage
add_block_rule "block-malicious" "192.168.1.100"
get_stats
```

This API provides comprehensive control over the Fortexa eBPF firewall system with real-time rule management and monitoring capabilities.
- `source` (string, optional): Source IP address or network (e.g., `192.168.1.1/24`).
- `destination` (string, optional): Destination IP address or network.
- `source_port` (string, optional): Source port or port range (e.g., `1024:65535`).
- `destination_port` (string, optional): Destination port or port range.
- `protocol` (string, optional): `tcp`, `udp`, `icmp`, etc.
- `action` (string, required): `accept`, `drop`, `reject`, or `log`.
- `enabled` (boolean, optional): Whether the rule is enabled. Defaults to `true`.
- `priority` (integer, optional): Rule priority. Defaults to `0`.
- `auto_create_chain` (boolean, optional): If `true`, automatically creates the necessary iptables chain if it doesn't exist. Defaults to `false`.
- `reference_from` (string, optional): If `auto_create_chain` is true and the rule is for a custom chain, this field can be used to create a jump rule from a built-in chain (`INPUT`, `OUTPUT`, `FORWARD`) to the newly created custom chain.

**Example:**

```bash
curl -X POST http://127.0.0.1:8080/api/filter/rules \
-H "Content-Type: application/json" \
-d '{
  "name": "allow-http-in-custom-chain",
  "description": "Allow incoming HTTP traffic in my custom chain",
  "direction": "WEB_TRAFFIC",
  "destination_port": "80",
  "protocol": "tcp",
  "action": "accept",
  "auto_create_chain": true,
  "reference_from": "INPUT"
}'
```

This will create a rule in a new `FORTEXA_WEB_TRAFFIC` chain, and also add a jump rule from the `INPUT` chain to `FORTEXA_WEB_TRAFFIC`.

### 1.3 Reset all rules

**Description:**
Removes (deletes) **all firewall rules** in both the kernel and the persisted `rules.json` file. After calling this endpoint, your firewall will be empty and allow all traffic (unless new rules are added).



- **DELETE** `/api/filter/rules`

Deletes all firewall rules. Use with caution.

**Example:**

```bash
curl -X DELETE http://127.0.0.1:8080/api/filter/rules
```


### 1.4 Get a specific rule

- **GET** `/api/filter/rules/{id}`

Retrieves a single rule by its ID. The rule ID is returned when a rule is created.

**Example:** (assuming rule ID is `3a8f6e2e-a34f-4b0d-b82b-2d7c0f1b2c4d`)

```bash
curl -X GET http://127.0.0.1:8080/api/filter/rules/3a8f6e2e-a34f-4b0d-b82b-2d7c0f1b2c4d
```

### 1.5 Update a rule

- **PUT** `/api/filter/rules/{id}`

Updates an existing rule. The payload is the same as for adding a rule. All fields are overwritten.

**Example:** (assuming rule ID is `3a8f6e2e-a34f-4b0d-b82b-2d7c0f1b2c4d`)

```bash
curl -X PUT http://127.0.0.1:8080/api/filter/rules/3a8f6e2e-a34f-4b0d-b82b-2d7c0f1b2c4d \
-H "Content-Type: application/json" \
-d '{
  "name": "allow-ssh-in-updated",
  "description": "Allow incoming SSH traffic from a specific IP",
  "direction": "input",
  "source": "10.0.0.5",
  "destination_port": "22",
  "protocol": "tcp",
  "action": "accept"
}'
```

### 1.6 Delete a rule

- **DELETE** `/api/filter/rules/{id}`

Deletes a specific rule by its ID.

**Example:** (assuming rule ID is `3a8f...`)

```bash
curl -X DELETE http://127.0.0.1:8080/api/filter/rules/3a8f6e2e-a34f-4b0d-b82b-2d7c0f1b2c4d
```

## 2. Custom Chains API

### 2.1 Create a custom chain

- **POST** `/api/filter/custom_chain`

Creates a new custom iptables chain.

**Payload:** A JSON object.

```json
{
  "name": "MY_CUSTOM_CHAIN",
  "reference_from": "INPUT"
}
```

**Fields:**
- `name` (string, required): The name of the custom chain. If it doesn't start with the configured prefix (default `FORTEXA_`), the prefix will be added and the name will be uppercased.
- `reference_from` (string, optional): A built-in chain (`INPUT`, `OUTPUT`, `FORWARD`) to add a rule to, which jumps to this new custom chain.

**Example:**

```bash
curl -X POST http://127.0.0.1:8080/api/filter/custom_chain \
-H "Content-Type: application/json" \
-d '{
  "name": "WEB_TRAFFIC",
  "reference_from": "INPUT"
}'
```

This will create a chain named `FORTEXA_WEB_TRAFFIC` and add a rule to `INPUT` to jump to it.

### 2.1 Delete a custom chain

- **DELETE** `/api/filter/custom_chain`

Deletes a custom iptables chain.

**Payload:** A JSON object.

```json
{
  "name": "MY_CUSTOM_CHAIN",
  "reference_from": "INPUT"
}
```

**Fields:**
- `name` (string, required): The name of the custom chain. If it doesn't start with the configured prefix (default `FORTEXA_`), the prefix will be added and the name will be uppercased.
- `reference_from` (string, optional): If provided, the jump rule from the built-in chain will also be removed.

**Example:**

```bash
curl -X DELETE http://127.0.0.1:8080/api/filter/custom_chain \
-H "Content-Type: application/json" \
-d '{
  "name": "WEB_TRAFFIC",
  "reference_from": "INPUT"
}'
```

## Example using cURL

```sh
curl -X DELETE http://127.0.0.1:8080/api/filter/rules
```


**What Happens**

- All chains (`FORTEXA_INPUT`, `FORTEXA_OUTPUT`) are flushed and deleted from iptables (kernel).
- Subsequent `/api/filter/rules` POST requests can build new rules as needed.


**Security Note for resetting**

- This action removes **all protections** until new rules are added!
- It is recommended to protect this endpoint with authentication or network restrictions in production.

## 3. Netshield API (eBPF/XDP-based Filtering)

Netshield provides high-performance network filtering using eBPF/XDP. These rules are managed separately from iptables rules and are persisted in `/var/lib/fortexa/filter_rules.json`.

### 3.1 List all netshield rules

- **GET** `/api/netshield/rules`

Lists all currently configured netshield rules.

**Example:**

```bash
curl -X GET http://127.0.0.1:8080/api/netshield/rules
```

### 3.2 Add a new netshield rule

- **POST** `/api/netshield/rules`

Adds a new netshield rule.

**Payload:**

```json
{
  "name": "pxtest",
  "description": null,
  "direction": "Output",
  "source": null,
  "destination": "8.8.8.8",
  "source_port": null,
  "destination_port": null,
  "protocol": null,
  "action": "Log",
  "enabled": true,
  "priority": 0,
  "parameters": {}
}
```

**Fields:**
- `id` (string, optional): Unique rule ID. If omitted, a new UUID is generated.
- `name` (string, required): Name for the rule.
- `description` (string, optional): Description for the rule.
- `direction` (string, required): `Incoming`, `Outgoing`, or `Both`.
- `source` (string, optional): Source IP or CIDR.
- `destination` (string, optional): Destination IP or CIDR.
- `source_port` (integer, optional): Source port.
- `destination_port` (integer, optional): Destination port.
- `protocol` (string, optional): Protocol (e.g., `tcp`, `udp`).
- `action` (string, required): `Block`, `Allow`, or `Log`.
- `enabled` (boolean, optional): Whether the rule is enabled. Defaults to `true`.
- `priority` (integer, optional): Rule priority. Defaults to `0`.
- `parameters` (object, optional): Additional parameters as key-value pairs.
- `group` (string, optional): Group name for this rule. Used to organize rules into logical groups.

**Example:**

```bash
curl -X POST http://127.0.0.1:8080/api/netshield/rules \
-H "Content-Type: application/json" \
-d '{
  "name": "pxtest",
  "direction": "Outgoing",
  "destination": "8.8.8.8",
  "action": "Log"
}'
```

### 3.3 Get a specific netshield rule

- **GET** `/api/netshield/rules/{id}`

Retrieves a single netshield rule by its ID.

**Example:**

```bash
curl -X GET http://127.0.0.1:8080/api/netshield/rules/cb16dd5e-00d1-4abb-beba-cf43ba6b4668
```

### 3.4 Update a netshield rule

- **PUT** `/api/netshield/rules/{id}`

Updates an existing netshield rule. The payload is the same as for adding a rule. All fields are overwritten.

**Example:**

```bash
curl -X PUT http://127.0.0.1:8080/api/netshield/rules/cb16dd5e-00d1-4abb-beba-cf43ba6b4668 \
-H "Content-Type: application/json" \
-d '{
  "name": "pxtest",
  "description": "Updated description",
  "direction": "Outgoing",
  "destination": "8.8.8.8",
  "action": "Log",
  "enabled": true,
  "priority": 0,
  "parameters": {}
}'
```

### 3.5 Delete a netshield rule

- **DELETE** `/api/netshield/rules/{id}`

Deletes a specific netshield rule by its ID.

**Example:**

```bash
curl -X DELETE http://127.0.0.1:8080/api/netshield/rules/cb16dd5e-00d1-4abb-beba-cf43ba6b4668
```

### 3.6 List all netshield groups

- **GET** `/api/netshield/groups`

Returns a list of all unique group names used in netshield rules.

**Example:**

```bash
curl -X GET http://127.0.0.1:8080/api/netshield/groups
```

**Response:**
```json
[
  "web",
  "ssh"
]
```

### 3.7 List all rules in a group

- **GET** `/api/netshield/groups/{group}/rules`

Returns all rules that belong to the specified group.

**Example:**

```bash
curl -X GET http://127.0.0.1:8080/api/netshield/groups/web/rules
```

**Response:**
```json
[
  {
    "id": "cb16dd5e-00d1-4abb-beba-cf43ba6b4668",
    "name": "pxtest",
    "group": "web",
    ...
  }
]
```

---

Netshield rules are managed independently from iptables rules. Use these endpoints for eBPF/XDP-based filtering.
