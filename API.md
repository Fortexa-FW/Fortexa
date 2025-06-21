# Fortexa REST API

This document describes the REST API for managing firewall rules.

The API base URL is `http://<bind_address>:<port>`. By default, this is `http://127.0.0.1:8080`.

## Rules API

### List all rules

- **GET** `/api/filter/rules`

Lists all currently configured firewall rules.

**Example:**

```bash
curl -X GET http://127.0.0.1:8080/api/filter/rules
```

### Add a new rule

- **POST** `/api/filter/rules`

Adds a new firewall rule.

**Payload:** A JSON object representing the rule.

```json
{
  "name": "allow-ssh-in",
  "description": "Allow incoming SSH traffic",
  "direction": "input",
  "source": "192.168.1.100",
  "destination": null,
  "source_port": null,
  "destination_port": "22",
  "protocol": "tcp",
  "action": "accept",
  "enabled": true,
  "priority": 100,
  "auto_create_chain": true,
  "reference_from": null
}
```

**Fields:**
- `name` (string, required): A unique name for the rule.
- `description` (string, optional): A description for the rule.
- `direction` (string, required): `input`, `output`, `forward`, or the name of a custom chain. If a custom chain name is provided that does not start with the configured prefix (default `FORTEXA_`), the prefix will be added automatically and the name will be uppercased (e.g., `my_chain` becomes `FORTEXA_MY_CHAIN`).
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

### Reset all rules

- **DELETE** `/api/filter/rules`

Deletes all firewall rules. Use with caution.

**Example:**

```bash
curl -X DELETE http://127.0.0.1:8080/api/filter/rules
```

### Get a specific rule

- **GET** `/api/filter/rules/{id}`

Retrieves a single rule by its ID. The rule ID is returned when a rule is created.

**Example:** (assuming rule ID is `3a8f6e2e-a34f-4b0d-b82b-2d7c0f1b2c4d`)

```bash
curl -X GET http://127.0.0.1:8080/api/filter/rules/3a8f6e2e-a34f-4b0d-b82b-2d7c0f1b2c4d
```

### Update a rule

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

### Delete a rule

- **DELETE** `/api/filter/rules/{id}`

Deletes a specific rule by its ID.

**Example:** (assuming rule ID is `3a8f...`)

```bash
curl -X DELETE http://127.0.0.1:8080/api/filter/rules/3a8f6e2e-a34f-4b0d-b82b-2d7c0f1b2c4d
```

## Custom Chains API

### Create a custom chain

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

### Delete a custom chain

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
