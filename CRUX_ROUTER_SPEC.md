# Crux Policy Router — Agent Reference

## Overview

The **Policy Router** is the secure MCP gateway built into the Crux Mesh. Instead of connecting
agents directly to every tool server, you connect once to the crux-router binary. The router:

- Authenticates callers by clearance level
- Enforces per-server `allowed_tools` filters
- Scans for prompt-injection payloads before forwarding
- Applies optional per-server rate limits
- Sanitizes responses to redact nodes above the caller's clearance
- Emits a tamper-evident audit trail to `.crux-audit.json`

All external MCP servers are registered as `mcp_server_registration` nodes in the **policy crux**.

---

## Starting the Router

```bash
crux-router --policy-router
```

The router searches upward from the current directory for `.crux-mesh.json`, loads its policy
crux, and spawns registered stdio children. Set `CRUX_CALLER_CLEARANCE` to declare the calling
agent's level (default: `internal`).

```bash
CRUX_CALLER_CLEARANCE=confidential crux-router --policy-router
```

---

## How to Register a Server

Use the `mesh` tool, `register_mcp` action:

```json
{
  "action": "register_mcp",
  "alias": "filesystem",
  "transport": "stdio",
  "command": "my-fs-tool --mcp",
  "required_clearance": "internal",
  "allowed_tools": "read_file,write_file,list_directory",
  "rate_limit": "60/60"
}
```

| Field | Required | Description |
|---|---|---|
| `alias` | yes | Unique routing key. Tools are addressed as `alias` or `alias_*`. |
| `transport` | yes | `stdio` (subprocess) or `http` (remote HTTP server). |
| `command` | stdio only | Argv string, e.g. `"my-tool --mcp"`. |
| `url` | http only | `host:port/path`, e.g. `"localhost:8080/mcp"`. |
| `required_clearance` | no | Minimum caller clearance: `public` \| `internal` \| `confidential` \| `restricted`. Default: `internal`. |
| `allowed_tools` | no | Comma-separated tool names the router will forward, or `*` for all. Default: `*`. |
| `rate_limit` | no | `N/W` — max N calls per W-second sliding window, e.g. `"60/60"`. Omit for no limit. |

Registration is persisted as a `mcp_server_registration` node (classification: `restricted`) in the
policy crux. The router reloads registrations on startup.

---

## Clearance Levels

Levels are ordered by sensitivity:

| Level | Value | Who can call |
|---|---|---|
| `public` | 0 | Any caller |
| `internal` | 1 | Callers with clearance ≥ `internal` |
| `confidential` | 2 | Callers with clearance ≥ `confidential` |
| `restricted` | 3 | Only `restricted`-cleared callers |

The caller's clearance is set via `CRUX_CALLER_CLEARANCE` (default: `internal`).

If a caller's clearance is below `required_clearance`, the router returns JSON-RPC error `-32603`
and writes an audit entry.

---

## Rate Limiting

Rate limits are stored as `rate_limit=N/W` on the registration node. The router enforces a
sliding window: at most N calls within any W-second window.

On violation the router returns JSON-RPC error `-32029` ("Too many requests") and emits an
audit entry with `event="rate_limited"`.

Example: `"rate_limit": "60/60"` allows at most 60 calls per 60 seconds to a given server.

---

## Injection Scanning

Before forwarding any `tools/call`, the router scans the `arguments` JSON for:

- The phrase `"ignore previous instructions"` (case-insensitive)
- `"system:"` prefix patterns (case-insensitive)
- `<tool_call>` / `</tool_call>` tags
- Payloads larger than 50 KiB

Blocked requests return JSON-RPC error `-32602` and emit an audit entry with
`event="injection_blocked"`.

---

## Response Sanitization

After each successful forward, the router scans the response text. For every node in the
policy crux whose `security.classification` exceeds the caller's clearance and whose `name`
appears in the response body, the name's summary is replaced with `"[REDACTED]"`.

This prevents downstream prompt injection via restricted node names leaking into tool output.

---

## Reading the Audit Log

The audit log is a newline-delimited JSON file at `<mesh-root>/.crux-audit.json`.

```json
{"ts":1746000000,"event":"forward","subject":"filesystem","detail":"router_gate","allowed":true}
{"ts":1746000001,"event":"rate_limited","subject":"filesystem","detail":"router_gate","allowed":false}
{"ts":1746000002,"event":"injection_blocked","subject":"filesystem","detail":"router_gate","allowed":false}
```

Use standard JSON-processing tools (`jq`, Python) to query it, or use `crux query` on the
policy crux to find related audit nodes.

---

## Managing Registrations

**List:**
```json
{"action": "list_mcp_servers"}
```

**Revoke (soft-delete):**
```json
{"action": "revoke_mcp", "alias": "filesystem"}
```

Revoked registrations remain in the policy crux with a `deleted_at` timestamp for auditing.
The router skips them at startup.

---

## Relationship to crux://spec/agent

The Policy Router is the recommended tool-orchestration layer for any Crux Mesh deployment.
Instead of managing MCP server endpoints in agent code, register them once in the policy crux
and point all agents at the single router endpoint. The router handles access control,
observability, and injection defence transparently.

For the full Crux Mesh specification, read `crux://spec/agent`.
