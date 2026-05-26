# Crux Mesh: MCP Router Evolution Plan

## Executive Summary

**What we are doing:**  
Extend the existing **Policy Crux** to act as a **secure virtual MCP router / gateway**. Agents will connect *only* to the Policy Crux MCP server (one trusted endpoint). The Policy Crux will register, authenticate, authorize, sanitize, proxy, audit, and redact calls to any other MCP servers (local stdio, remote HTTP, or other Crux meshes) based on the mesh security policy.

**Why this is valuable:**
- Directly solves the major MCP security vulnerabilities (prompt injection, weak auth, malicious servers, credential exposure, etc.) that were highlighted in prior analysis.
- Leverages Crux’s already-strong security primitives (classification/redaction, audit log, W-OTS signatures, vector clocks, provenance) instead of bolting them on later.
- Turns Crux Mesh into a compelling **secure MCP fabric** — a single, hardened control plane for agent tool use.
- Minimal disruption: fully backward-compatible with existing Crux MCP tools and meshes.
- Strong differentiator for adoption (especially in enterprise/forensic/governed environments).

**Feasibility:** High. The architecture, data model, and Rust foundation are already well-suited. Estimated MVP: 3–4 weeks.

**Expected Outcome:** One trusted MCP endpoint per mesh that safely orchestrates all external tools while enforcing least-privilege, auditability, and redaction by design.

---

## Detailed Implementation Plan

### Phase 0: Quick Validation (1–2 days)
- Update `README.md`, `CRUX_AGENT_SPEC.md`, and pitch deck to introduce the “Policy Router” concept.
- Add CLI / MCP capability flag (e.g. `--policy-router` or new mesh setting).
- Define new node kind in Policy Crux: `mcp_server_registration`.

#### Phase 0 Status — COMPLETE (2026-04-30)

Deliverables landed:
1. **`mcp_server_registration` node kind** — `McpServerRegistration` struct + `build_mcp_server_registration` + `parse_mcp_server_registration` helpers in `crux/legacy/schema.rs`. Two unit tests (round-trip + missing-alias rejection).
2. **`--policy-router` flag** — Added to `crux-router` binary (`crux/src/bin/crux_router.rs`). Emits a Phase 0 banner on stderr; no proxy behavior changes. `--help` also added.
3. **Docs** — `crux/README.md` (Policy Router preview section), `crux/CRUX_AGENT_SPEC.md` (§4b mcp_server_registration reference), this file (Phase 0 status).

**Security primitive reality check** — updated after Phase 1:

| Primitive | Actual state |
|-----------|-------------|
| Classification/redaction (`filter_by_clearance`, `redact_node`) | **Works** |
| Policy crux data model + auto-seeding | **Works** |
| Cluster create/assign | **Works** — `mesh_query` now gates per `cluster_classification` |
| Audit log | **Works** — `crux/src/audit.rs` restored; wired into `mesh_query`, `tool_mesh_join/leave/create_cluster/assign_cluster/register_mcp` |
| W-OTS signing | **Works** — `wots_sign_raw`, `wots_verify_raw`, `sign_message`, `verify_signature` restored to `crux/legacy/crypto.rs` |
| Dynamic MCP registry | **Works** — `--policy-router` loads `mcp_server_registration` nodes at startup, spawns stdio children |
| Routing + clearance gate | **Works** — `CRUX_CALLER_CLEARANCE` env var; denied calls return JSON-RPC error + audit entry |
| `mesh_register_mcp` action | **Works** — new `mesh` tool action writes registration into policy crux |
| Vector clocks / signed propagation | **Absent** (out of scope Phase 1) |
| `mesh_link` traversal | Edge kind defined; **no traversal logic** (Phase 2) |

#### Phase 2 Status — COMPLETE (2026-04-30)

Deliverables:

1. **`tools/list` from dynamic children** (`crux/src/bin/crux_router.rs`) — when `--policy-router` is active, `tools/list` now queries each dynamic child whose `required_clearance` ≤ caller clearance, collects their tool arrays, and includes them in the merged response. New `merge_tools_lists_with_extra` helper; dynamic children are initialized (initialize + notifications/initialized) at spawn time so they are ready to serve `tools/list` immediately.

2. **`mesh_list_mcp_servers` and `mesh_revoke_mcp`** — two new actions on the `mesh` tool:
   - `list_mcp_servers`: reads all active `mcp_server_registration` nodes from the policy crux and formats them as a table (alias, transport, clearance, allowed_tools, audit). Backed by `mesh::mesh_list_mcp_servers` in `crux/src/mesh.rs`.
   - `revoke_mcp`: soft-deletes a registration by alias (sets `deleted_at`); emits an audit `NodeDeleted` entry. Backed by `mesh::mesh_revoke_mcp` in `crux/src/mesh.rs`. Both wired into dispatch, schema, and description in `crux/src/mcp.rs`.

3. **Response sanitization** (`sanitize_response`) — after a dynamic child (stdio or HTTP) returns a response, scans it against all nodes in the policy crux. For each node whose `security.classification` exceeds the caller's clearance and whose name appears in the response, replaces the node's summary with `"[REDACTED]"`. Implemented in `crux/src/bin/crux_router.rs`; policy crux JSON is loaded once at startup via the updated `build_dynamic_registry` return type `(Vec<DynamicRegistration>, String)`.

4. **Prompt injection scanning** (`check_injection`) — before forwarding any `tools/call` to a dynamic child, scans the `arguments` JSON for: `"ignore previous instructions"`, `"system:"` (case-insensitive), `<tool_call>` / `</tool_call>` tags, and payloads over 50 KiB. If triggered, returns a JSON-RPC `-32602` error and emits a router audit entry with `event="injection_blocked"`.

5. **HTTP transport proxy** (`forward_http`) — implements minimal HTTP/1.1 POST forwarding via `std::net::TcpStream` (no external deps). Parses `host:port[/path]` from the `url` field; sets 5s read timeout; strips HTTP response headers; returns the body. HTTP registrations store `http_url: Option<String>` in `DynamicRegistration`. Dynamic children with `transport=http` are now proxied rather than returning an error.

**Test counts:** 236 lib + 45 router + 3 package integration = **284 crux tests** (all pass).

#### Phase 1 Status — COMPLETE (2026-04-30)

Deliverables:

1. **Audit log restored** (`crux/src/audit.rs`) — `AuditLog::append`, convenience constructors (`log_node_added`, `log_query`, etc.), full test suite. Wired into `mesh_query` (Query event after each call) and key `tool_mesh_*` MCP handlers (MeshJoined / MeshLeft / NodeAdded / NodeUpdated).

2. **W-OTS sign/verify restored** (`crux/legacy/crypto.rs`) — `wots_message_nibbles` (64 data + 3 checksum nibbles), `bytes_to_chains`, `wots_sign_raw`, `wots_verify_raw`, `sign_message`, `verify_signature`. Five new unit tests (round-trip, wrong message, wrong key, checksum value, determinism).

3. **Cluster gating in `mesh_query`** (`crux/src/mesh.rs`) — `cluster_clearance_map` reads `cluster-definition` nodes; per-member cluster lookup skips entire crux if caller clearance < cluster's required level.

4. **`mesh_register_mcp` action** — `mesh_register_mcp` in `crux/src/mesh.rs` (validates alias uniqueness, transport, clearance; writes `mcp_server_registration` node to policy crux); `tool_mesh_register_mcp` in `crux/src/mcp.rs` (audit log entry); mesh tool description + dispatch + schema updated.

5. **Dynamic child registry in crux-router** (`crux/src/bin/crux_router.rs`) — when `--policy-router` is active: searches upward for `.crux-mesh.json`, finds policy crux, parses `mcp_server_registration` nodes, spawns stdio children. HTTP transport stubs (returns error, not yet proxied).

6. **Routing + policy gate** — at `tools/call` dispatch: alias-prefix routing (`alias` or `alias_*`), `CRUX_CALLER_CLEARANCE` env var check vs `required_clearance`, `allowed_tools` filter; JSON-RPC `-32603` error on violation; `emit_router_audit` writes to stderr + appends to `.crux-audit.json`.

**Test counts:** 231 lib + 27 router + 3 package integration = **261 crux tests** (all pass).

### Phase 1: Core Router Architecture (1–2 weeks)
- **Server Registration** (`mesh_register_mcp` tool):
  - Store registration as nodes in the Policy Crux.
  - Fields: alias, transport (stdio/http), command/URL, required clearance, allowed tools/scopes, public key, capability manifest.
- **Unified Proxy Tool** (e.g. `mesh_route` or extended `mesh` action):
  - Agent calls Policy Crux → router validates clearance → sanitizes → proxies → sanitizes response → audits → returns.
  - Support local stdio subprocesses and remote HTTP with proper OAuth 2.1 / audience validation.
- **Chaining Support**: Allow routing to other Crux meshes via existing `mesh_link` edges.

### Phase 2: Targeted Vulnerability Mitigations (parallel, ~1 week)
(Full mapping of every previously identified MCP risk → concrete Crux controls is included in the thinking trace / earlier response.)

### Phase 3: Polish, Testing & Ecosystem (1–2 weeks)
- New tools: `mesh_list_mcp_servers`, `mesh_revoke_mcp`, etc.
- Update `crux://spec/agent` resource.
- Helm UI enhancements (MCP Servers tab).
- Comprehensive testing (injection, clearance violations, malicious servers, fuzzing).
- Sandboxing options for high-risk back-ends.

### Phase 4: Crypto Hardening + Dynamic Discovery

#### Phase 4A — VectorClock + Audit Chain v2 ✓
- `seq`, `clock`, and `prev_hash` fields on every audit event.
- Chained SHA-256 integrity: each event covers the previous event's hash.
- `verify_chain` validates the full chain end-to-end.

#### Phase 4B — W-OTS Signed Audit Chain + Mesh Keyring ✓
- Each audit event carries a W-OTS signature over its canonical bytes.
- `mesh_keyring` node kind: stores per-member signing key metadata in the policy crux.
- `verify_chain` now checks both hash chain and per-event W-OTS signatures.

#### Phase 4C — Dynamic Discovery + Helm UI ✓
- `.crux-discovery/` directory: drop JSON manifests to auto-register MCP servers.
- `mesh_discover` scans the directory; idempotent (fingerprint-based dedup).
- `mesh_discover` action wired into the `mesh` MCP tool.
- Helm **MCP Servers** tab: table view, register modal, revoke button.
- `mesh_list_mcp_servers` and `mesh_revoke_mcp` mesh actions.

#### Phase 4D — External MCP Detector + Remediation ✓
- Passive scanner detects MCP servers running outside the mesh (Claude Desktop, VS Code, Cursor configs).
- Helm **Discovered** sub-tab lists unmanaged servers with risk badges.
- Helm **External** sub-tab shows remediation instructions for migrating each server under mesh control.
- `rate_limit` field on registrations enforced in the router (`-32029` on violation, audit entry).

#### Phase 4E — MCP Registration Self-Signing (D-session) ✓
- `compute_self_sig` signs each registration with a W-OTS subkey derived from the policy member's master key.
- `public_key` field format: `sig=<hex>;pk=<hex>` (sig + full subkey pubkey).
- `mesh verify` second pass checks every registration self-sig and reports `[OK]`/`[FAIL]`/`[SKIP]`.

#### Still Planned
- `mesh_link` traversal in `mesh_query` and `mesh_path` (cross-crux BFS, clearance-gated).
- Push/pull replication across linked meshes.