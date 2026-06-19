# Crux Agent Specification

This document is the complete reference for LLM agents building, populating, querying, and connecting cruxes. Read this before calling any MCP tools.

---

## 1. What Is a Crux?

A crux is a portable, version-controlled knowledge graph stored as a single JSON file (`.crux.json`). It models any knowledge domain — code, documentation, CRM contacts, preferences, org values, skillsets, forensic evidence — as a graph of typed nodes connected by typed edges.

A crux can:
- Stand alone as a local knowledge base
- Join a mesh of multiple cruxes for cross-graph queries
- Be queried by LLM agents via MCP tools
- Carry structured source references so original evidence can be retrieved

---

## 2. Quickstart

Choose the path that matches your situation.

> Tool calls use the unified form `tool action=<action>` (e.g. `mesh action=status`). The legacy single-purpose names shown in some examples below (`mesh_init`, `crux_create`, …) remain valid aliases.

### Path A: Join an existing mesh

```
1. mesh action=status    mesh_path=<path>          # discover members, health, cross-edges
2. mesh action=query     query="<topic>"           # find relevant nodes across all cruxes
3. crux action=load      path=<member-crux-path>   # inspect a specific crux in detail
4. crux action=query     path=<member>  query="…"  # drill into one crux
5. crux action=resolve   path=<member>  node_name="<name>"   # find source file for a node
6. crux action=extract   path=<member>  node_name="<name>"   # read original source bytes
```

### Path B: Start a new crux and mesh

```
1. crux_create      name="my-project"  kind="codebase"
2. crux_add_node    path=.  name="@main"  kind="function"  summary="Entry point"
3. crux_add_edge    path=.  src="@main"  dst="@init"  kind="calls"
4. mesh_init        name="my-mesh"  path=./mesh
5. mesh_join        crux_path=.  mesh_path=./mesh
6. mesh_query       query="<topic>"  mesh_path=./mesh
```

To create a **policy crux** first (recommended for multi-agent meshes):
```
1. crux_create      name="policy"  kind="organization"
2. crux_add_node    path=.  name="default-policy"  kind="policy"
               summary="Members: internal classification required. Max 50 nodes."
3. mesh_init        name="my-mesh"  path=./mesh
```

### Path C: Autonomous filesystem ingestion

For drives, archives, evidence collections, or large file sets:

```
1. crux_scan          path=/mnt/drive-1
   → returns file manifest with kinds (email, csv, markdown, …)
2. crux_generate_dir  source_path=/mnt/drive-1  output_path=./cruxes  mesh_name="drive-1"
   → creates one .crux.json per file kind; ingests all content
3. mesh_build         name="investigation"  crux_dir=./cruxes
   → init mesh + join all cruxes + cross-edge discovery in one call
4. mesh_query         query="<search term>"  mesh_path=./investigation
5. crux_resolve       path=<crux>  node_name="<match>"
   → resolves mount-resilient source reference to current filesystem path
6. crux_extract       path=<crux>  node_name="<match>"
   → reads the exact bytes from the source file
```

---

## 3. Schema Reference

### CruxDb (top-level object)

```json
{
  "crux_version": "2",
  "header": { ... },
  "nodes": [ ... ],
  "edges": [ ... ]
}
```

### CruxHeader

```json
{
  "crux_id": "sha256:<64 hex chars>",
  "crux_name": "my-project",
  "crux_kind": "codebase",
  "origin": "rust",
  "created_at": 1700000000,
  "updated_at": 1700000000,
  "public_key": "<hex>",
  "mesh_memberships": []
}
```

| Field | Type | Description |
|-------|------|-------------|
| `crux_id` | string | SHA-256 hex of `"crux:<name>:<timestamp>"` |
| `crux_name` | string | Human-readable name |
| `crux_kind` | string | See CruxKind below |
| `origin` | string | Data source identifier (e.g. "rust", "markdown", "salesforce") |
| `created_at` | u64 | Unix timestamp |
| `mesh_memberships` | array | Meshes this crux belongs to (see MeshMembership) |

**CruxKind values:** `codebase` `documentation` `preferences` `organization` `skillset` `api` `dataset` `custom`

### CruxNode

```json
{
  "node_id": "sha256:<64 hex chars>",
  "name": "@function_name",
  "kind": "function",
  "module": "src/main",
  "summary": "One-line description of what this node represents.",
  "schema": {
    "inputs": [{"name": "x", "type": "i32", "required": true, "description": ""}],
    "outputs": [{"name": "", "type": "String", "required": true, "description": ""}],
    "side_effects": []
  },
  "tags": ["io", "network"],
  "reach": ["downstream_node_name"],
  "properties": [
    "key=value",
    "source_ref.uri=file:///mnt/drive1/emails/inbox.mbox",
    "source_ref.byte_offset=48230",
    "source_ref.byte_length=3200",
    "provenance.acquired_at=1700000000"
  ],
  "warnings": ["deprecated: use new_fn instead"],
  "planning": {
    "priority": "high",
    "effort": "medium",
    "status": "stable",
    "owner": "",
    "milestone": ""
  },
  "security": {
    "classification": "internal",
    "redact_below": null
  },
  "content_hash": "sha256:<64 hex chars>",
  "deleted_at": null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `node_id` | string | SHA-256 of `"node:<crux_id>:<name>"` |
| `name` | string | Unique within the crux. Use `@` prefix for functions/methods |
| `kind` | string | Node kind (see Node Kinds below) |
| `module` | string | Logical grouping (package, file, namespace) |
| `summary` | string | ≤200 chars, what this node *is* or *does* |
| `schema` | object | Inputs/outputs (for functions/APIs); use `NodeSchema::empty()` otherwise |
| `tags` | string[] | Searchable labels |
| `reach` | string[] | Names of nodes this node directly affects |
| `properties` | string[] | `"key=value"` pairs — includes `source_ref.*` and `provenance.*` |
| `warnings` | string[] | Deprecation notices, known issues |
| `planning` | object | Priority, effort, status, owner, milestone |
| `security` | object | Classification level and optional redaction threshold |
| `content_hash` | string | SHA-256 of node content (for change detection) |
| `deleted_at` | u64\|null | Unix timestamp if soft-deleted, null if active |

**Node Kinds:**
- Code: `function` `struct` `enum` `module` `class` `interface` `trait` `constant` `macro` `test`
- Docs: `document` `section` `page` `chapter`
- Data: `record` `field` `table` `dataset` `schema`
- Org: `person` `team` `department` `role` `policy` `cluster-definition`
- Generic: `concept` `preference` `skill` `value` `goal`

### CruxEdge

```json
{
  "edge_id": "sha256:<64 hex chars>",
  "src": "@caller_function",
  "dst": "@callee_function",
  "kind": "calls",
  "weight": 1.0,
  "detail": "called on every request",
  "cross_crux": false,
  "binding": "",
  "created_at": 1700000000,
  "dangling": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| `edge_id` | string | SHA-256 of `"edge:<crux_id>:<src>:<dst>"` |
| `src` | string | Source node name |
| `dst` | string | Destination node name |
| `kind` | string | Edge kind (see Edge Kinds below) |
| `weight` | f64 | Relationship strength 0.0–1.0 (default 1.0) |
| `detail` | string | Human-readable description of the relationship |
| `cross_crux` | bool | True if src and dst are in different cruxes |
| `dangling` | bool | True if dst no longer exists (set automatically) |

### MeshMembership

```json
{
  "mesh_id": "sha256:<64 hex chars>",
  "mesh_name": "my-org",
  "joined_at": 1700000000,
  "cluster": "engineering",
  "public_key_hash": "sha256:<64 hex chars>"
}
```

---

## 4. Edge Kind Reference

| Kind | String | Use When |
|------|--------|----------|
| `Calls` | `calls` | A function/method invokes another |
| `Imports` | `imports` | A module depends on another module |
| `Contains` | `contains` | A parent structurally contains a child (module→function, doc→section) |
| `Extends` | `extends` | Inheritance or type extension |
| `Implements` | `implements` | A type satisfies a trait/interface |
| `DataFlow` | `data_flow` | Data produced by src is consumed by dst |
| `Reads` | `reads` | src reads from dst (file, DB table, config) |
| `Writes` | `writes` | src writes to dst |
| `Transforms` | `transforms` | src transforms input to produce dst |
| `Produces` | `produces` | src creates or emits dst |
| `RelatesTo` | `relates_to` | Generic semantic relationship |
| `Contradicts` | `contradicts` | src contradicts or conflicts with dst |
| `Supersedes` | `supersedes` | src replaces or deprecates dst |
| `Exemplifies` | `exemplifies` | src is an example or instance of dst |
| `BelongsToDomain` | `belongs_to_domain` | src is categorized under domain dst |
| `Tagged` | `tagged` | src is tagged with concept dst |
| `MeshLink` | `mesh_link` | Cross-mesh reference (set cross_crux: true) |

---

## 4b. MCP Server Registration Nodes

Nodes with `kind="mcp_server_registration"` live in the **policy crux** (module `"mcp"`) and represent external MCP servers managed by the Policy Router. Classification is always `restricted`.

### Required properties

| Property | Type | Description |
|----------|------|-------------|
| `alias` | string | Unique routing key used by agents to address this server |
| `transport` | `stdio` \| `http` | How the router reaches the server |

### Optional properties

| Property | Default | Description |
|----------|---------|-------------|
| `command` | `""` | Subprocess argv when `transport=stdio` (e.g. `"my-tool --mcp"`) |
| `url` | `""` | Base URL when `transport=http` |
| `required_clearance` | `internal` | Minimum agent clearance for forwarding: `public`, `internal`, `confidential`, or `restricted` |
| `allowed_tools` | `"*"` | Comma-separated tool names the router will forward; `"*"` = all |
| `rate_limit` | `""` | Optional rate limit: `N/W` = max N calls per W-second window, e.g. `"60/60"`. Empty = no limit. |
| `public_key` | `""` | Hex-encoded W-OTS public key for manifest signature verification (Phase 1+) |
| `audit_required` | `true` | Whether every forwarded call must produce an audit-log entry (Phase 1+) |
| `capability_manifest` | `""` | JSON-escaped `tools/list` snapshot for offline policy authoring |

> **Recommended tool orchestration pattern:** Register all external MCP servers in the policy crux
> and point all agents at the single `crux-router --policy-router` endpoint. The router handles
> access control, injection scanning, rate limiting, and audit transparently. Read
> `crux://spec/router` for the complete router reference.

### Example node JSON

```json
{
  "name": "filesystem",
  "kind": "mcp_server_registration",
  "module": "mcp",
  "summary": "filesystem MCP server (stdio)",
  "classification": "restricted",
  "properties": [
    "alias=filesystem",
    "transport=stdio",
    "command=npx @modelcontextprotocol/server-filesystem /tmp",
    "required_clearance=internal",
    "allowed_tools=*",
    "audit_required=true"
  ]
}
```

---

## 5. Security Classification

| Level | Value | Meaning |
|-------|-------|---------|
| Public | `public` | Safe to expose externally, to any mesh member |
| Internal | `internal` | Default. Visible within the org/mesh |
| Confidential | `confidential` | Restricted to specific roles or clearance |
| Restricted | `restricted` | Highest sensitivity. Visible only to Restricted-cleared requesters |

**`redact_below`**: If set, requesters below this level see the node's name and kind but `summary`, `tags`, and `schema` are replaced with `[REDACTED]`.

**Guidance:**
- Default all nodes to `internal` unless you have a reason otherwise
- Use `public` for OSS libraries, published APIs, external documentation
- Use `confidential` for PII, financial data, internal pricing
- Use `restricted` for credentials, cryptographic keys, executive-only data

---

## 6. Node ID Generation

Node IDs are deterministic SHA-256 hashes:

```
node_id = "sha256:" + sha256_hex("node:<crux_id>:<node_name>")
edge_id = "sha256:" + sha256_hex("edge:<crux_id>:<src_name>:<dst_name>")
```

When using MCP tools (`crux_add_node`, `crux_add_edge`), IDs are generated automatically.

---

## 7. Source References

Every node generated by a scanner or adapter carries `source_ref.*` properties that form a mount-resilient pointer back to the original evidence.

### source_ref properties

| Property | Description | Example |
|----------|-------------|---------|
| `source_ref.uri` | Canonical file URI | `file:///mnt/drive1/emails/inbox.mbox` |
| `source_ref.device_id` | Stable device identifier (volume UUID or label) | `Evidence_Drive_1` |
| `source_ref.volume_label` | Volume name for macOS/Linux remount resilience | `Evidence_Drive_1` |
| `source_ref.relative_path` | Path relative to volume root | `emails/inbox.mbox` |
| `source_ref.byte_offset` | Start byte (for multi-record files) | `48230` |
| `source_ref.byte_length` | Length of record in bytes | `3200` |
| `source_ref.record_index` | 0-based record number in file | `42` |
| `source_ref.record_delimiter` | What separates records (mbox: `From `) | `From ` |
| `source_ref.line_start` | Start line number | `150` |
| `source_ref.line_end` | End line number | `210` |
| `source_ref.row` | Row number in CSV/xlsx (1-based, excl. header) | `15` |
| `source_ref.sheet` | Sheet name in xlsx | `Sheet1` |

### Resolution order

`crux_resolve` tries paths in this order:
1. `source_ref.uri` stripped of `file://` prefix — if the file exists there, done
2. `/Volumes/<volume_label>/<relative_path>` (macOS)
3. `/mnt/<volume_label>/<relative_path>` (Linux)

The key insight: `source_ref.relative_path` + `source_ref.volume_label` survives drive remounting. If drive 1 is plugged into a different machine or mounted at a different path, resolution still works.

### Per-adapter behavior

| Adapter | `byte_offset` | `byte_length` | `record_index` |
|---------|--------------|---------------|----------------|
| Email (mbox) | Start of `From ` line | Length of this message | 0-based message number |
| CSV | — | — | Row number (see `source_ref.row`) |
| Slack export | — | — | Message index in JSON array |
| JSON API | — | — | Object index in array |
| Markdown, plaintext, source code | 0 | File size | — |

---

## 8. Provenance

Provenance properties record chain-of-custody metadata: who acquired the data, when, and from what device. They are stored as `provenance.*` entries in `properties`.

| Property | Description |
|----------|-------------|
| `provenance.source_path` | Original filesystem path at acquisition time |
| `provenance.source_file` | Filename (for display) |
| `provenance.acquired_at` | Unix timestamp of acquisition |
| `provenance.acquired_by` | Agent or user who ran the scan |
| `provenance.device_id` | Hardware device identifier |
| `provenance.volume_label` | Volume name at acquisition time |
| `provenance.mime_type` | Detected MIME type |
| `provenance.original_size` | Original file size in bytes |
| `provenance.content_md5` | Additional hash for forensic verification |

Provenance is populated automatically by `crux_scan` and `crux_generate_dir`. For manually-created nodes, add these properties yourself if chain-of-custody matters.

---

## 9. Audit Log

Every crux that has been modified records operations in `.crux-audit.json` (NDJSON — one JSON object per line) alongside the `.crux.json` file.

```json
{"event":"node_added","node_name":"@authenticate_user","actor":"agent","timestamp":1700000000}
{"event":"node_updated","node_name":"@authenticate_user","actor":"agent","timestamp":1700000001}
{"event":"node_deleted","node_name":"@old_handler","actor":"agent","timestamp":1700000002}
{"event":"edge_added","src":"@main","dst":"@init","kind":"calls","timestamp":1700000003}
{"event":"query","query":"authentication","results":3,"timestamp":1700000004}
{"event":"mesh_join","mesh_name":"my-org","timestamp":1700000005}
```

Use `crux_verify` to check content hash integrity and detect tampering since the audit log was written.

---

## 10. Node Modeling Guidance

### Codebase

- One node per exported function, struct, enum, trait, or module
- Name functions with `@` prefix: `@parse_request`, `@UserRepository`
- Name modules without prefix: `crate::auth`, `src/handlers`
- `module` field = the file or package path
- `reach` = list of node names this function directly calls or uses
- Add `calls` edges from callers to callees
- Add `contains` edges from module to its members

### Documentation

- One node per section (heading level 2+) or page
- Name = heading text
- `summary` = first sentence of the section
- Use `contains` edges for heading hierarchy

### CRM / People

- One node per contact, company, or deal
- `kind` = `person`, `team`, or `record`
- Store domain fields as `properties`: `"email=alice@example.com"`, `"status=active"`
- Use `relates_to` for associations, `belongs_to_domain` for categories

### Preferences / Config

- One node per preference or setting
- `kind` = `preference`
- `properties` = `["value=dark-mode", "scope=global"]`
- Use `supersedes` when a preference overrides another

### Org Values / Goals

- One node per value, goal, or principle
- `kind` = `value` or `goal`
- Use `relates_to` or `exemplifies` to connect goals to practices

---

## 11. MCP Tool Reference

All tools use JSON-RPC 2.0 over stdio. The server method is `tools/call`.

### Unified tool interface (Session 0122+)

The crux-router exposes **7 unified tools** — each dispatches by `action` parameter:

| Tool | `action` values |
|------|----------------|
| `crux` | `create` `load` `query` `add_node` `add_nodes` `add_edge` `add_edges` `update_node` `remove_node` `generate` `scan` `generate_dir` `verify` `resolve` `extract` `enrich` |
| `mesh` | `init` `join` `leave` `status` `query` `build` `diff` `create_cluster` `assign_cluster` |
| `pkg` | `search` `publish` `install` `deps` `audit` `update` |
| `project` | `init` |

**Legacy tool names** (e.g., `crux_create`, `crux_load`, `mesh_init`) are accepted as backward-compatible aliases and continue to work. The examples below use legacy names for readability.

### crux_create

Create an empty crux in the current directory.

```json
{
  "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": {
    "name": "crux_create",
    "arguments": {
      "name": "my-project",
      "kind": "codebase",
      "origin": "rust"
    }
  }
}
```

### crux_load

Load a crux and return its summary (header, node count, edge count, mesh memberships).

```json
{"name": "crux_load", "arguments": {"path": "/path/to/project"}}
```

### crux_query

Query nodes by name, kind, or tag substring within a single crux.

```json
{"name": "crux_query", "arguments": {"path": "/path/to/project", "query": "auth"}}
```

### crux_add_node

Add a node to an existing crux. Use this to build a crux programmatically.

```json
{
  "name": "crux_add_node",
  "arguments": {
    "path": "/path/to/project",
    "name": "@authenticate_user",
    "kind": "function",
    "module": "src/auth",
    "summary": "Validates credentials and returns a session token.",
    "tags": "auth,security",
    "classification": "internal"
  }
}
```

Optional fields: `tags` (comma-separated), `properties` (comma-separated `key=value`), `warnings`, `priority`, `effort`, `status`, `owner`, `milestone`, `classification`.

### crux_add_nodes_batch

Add multiple nodes in a single call. Deduplicates by name. Returns count added and skipped.

```json
{
  "name": "crux_add_nodes_batch",
  "arguments": {
    "path": "/path/to/project",
    "nodes": "[{\"name\":\"@fn_a\",\"kind\":\"function\",\"summary\":\"Does A\"},{\"name\":\"@fn_b\",\"kind\":\"function\",\"summary\":\"Does B\"}]"
  }
}
```

### crux_add_edge

Add a typed edge between two nodes.

```json
{
  "name": "crux_add_edge",
  "arguments": {
    "path": "/path/to/project",
    "src": "@handle_login",
    "dst": "@authenticate_user",
    "kind": "calls",
    "detail": "called on POST /login"
  }
}
```

### crux_add_edges_batch

Add multiple edges in a single call.

```json
{
  "name": "crux_add_edges_batch",
  "arguments": {
    "path": "/path/to/project",
    "edges": "[{\"src\":\"@main\",\"dst\":\"@init\",\"kind\":\"calls\"},{\"src\":\"@main\",\"dst\":\"@run\",\"kind\":\"calls\"}]"
  }
}
```

### crux_update_node

Update an existing node's fields without deleting and re-adding it. Only supplied fields are changed.

```json
{
  "name": "crux_update_node",
  "arguments": {
    "path": "/path/to/project",
    "name": "@authenticate_user",
    "summary": "Updated summary.",
    "tags": "auth,security,updated",
    "status": "deprecated"
  }
}
```

### crux_remove_node

Soft-delete a node (preserves history, sets `deleted_at`).

```json
{"name": "crux_remove_node", "arguments": {"path": "/path/to/project", "name": "@old_handler"}}
```

### crux_generate

Generate a crux from input text using an adapter.

```json
{
  "name": "crux_generate",
  "arguments": {
    "name": "readme-docs",
    "input": "# Introduction\nThis library...\n## Installation\n...",
    "format": "markdown",
    "path": "/path/to/output"
  }
}
```

`format` options: `auto` (detect), `markdown`, `plaintext`, `manual` (raw JSON passthrough), `email`, `csv`, `slack`, `json_api`

Optional: `file_path` — read input from a file instead of inline `input`.

### crux_scan

Recursively scan a directory and return a manifest of discovered files with their detected kinds. Does NOT ingest content — use this to map a drive before deciding what to generate.

```json
{
  "name": "crux_scan",
  "arguments": {
    "path": "/mnt/evidence-drive-1",
    "max_depth": 5,
    "extensions": "mbox,csv,md,json"
  }
}
```

Returns an array of `{"path", "size", "kind", "mime"}` objects. Detected kinds: `email`, `markdown`, `csv`, `json`, `plaintext`, `source`, `document`, `image`, `binary`.

### crux_generate_dir

Scan a directory and bulk-generate cruxes — one per file kind. Ingests all compatible files into their respective cruxes and writes them to `output_path`.

```json
{
  "name": "crux_generate_dir",
  "arguments": {
    "source_path": "/mnt/evidence-drive-1",
    "output_path": "./cruxes",
    "mesh_name": "drive-1-investigation"
  }
}
```

Returns a summary: files scanned, cruxes created, nodes generated. Each crux file is named `<kind>.crux.json` (e.g. `email.crux.json`, `csv.crux.json`).

### crux_verify

Recompute content hashes for all nodes and report any mismatches. Use for forensic integrity checking.

```json
{"name": "crux_verify", "arguments": {"path": "/path/to/project"}}
```

Returns: total nodes checked, any hash mismatches with node names. A clean crux reports "All N nodes verified."

### crux_resolve

Resolve a node's source reference to a current filesystem path. Searches known mount points using volume label and relative path, surviving drive remounting.

```json
{
  "name": "crux_resolve",
  "arguments": {
    "path": "/path/to/project",
    "node_name": "Email 42"
  }
}
```

Returns:
```
Node: Email 42
URI: file:///mnt/drive1/emails/inbox.mbox
Device ID: Evidence_Drive_1
Volume Label: Evidence_Drive_1
Relative Path: emails/inbox.mbox
Resolved Path: /Volumes/Evidence_Drive_1/emails/inbox.mbox
Accessible: yes
Byte Offset: 48230
Byte Length: 3200
Record Index: 42
Record Delimiter: From
```

### crux_extract

Read the original source bytes for a node. Uses `byte_offset` and `byte_length` from `source_ref.*` properties for precise extraction. Capped at 1 MB.

```json
{
  "name": "crux_extract",
  "arguments": {
    "path": "/path/to/project",
    "node_name": "Email 42"
  }
}
```

Returns the raw content prefixed with a source metadata header:
```
Source: /Volumes/Evidence_Drive_1/emails/inbox.mbox
Bytes: 48230–51430

From alice@example.com Mon Jan  1 00:00:00 2024
From: alice@example.com
To: bob@example.com
Subject: Re: Contract draft
...
```

### mesh_init

Create a new mesh manifest with a policy crux at `path`.

```json
{"name": "mesh_init", "arguments": {"name": "my-org", "path": "/path/to/mesh"}}
```

### mesh_join

Add a crux to the mesh. Validates against the policy crux (kinds allowed, member cap). Runs cross-edge discovery automatically.

```json
{
  "name": "mesh_join",
  "arguments": {
    "crux_path": "../my-project",
    "mesh_path": "/path/to/mesh"
  }
}
```

### mesh_leave

Remove a crux from the mesh by name or ID.

```json
{"name": "mesh_leave", "arguments": {"identifier": "my-project", "mesh_path": "/path/to/mesh"}}
```

### mesh_status

Show mesh health, member list, and cross-edge summary.

```json
{"name": "mesh_status", "arguments": {"mesh_path": "/path/to/mesh"}}
```

### mesh_query

Query nodes across all mesh members. Results are filtered by security policy.

```json
{
  "name": "mesh_query",
  "arguments": {
    "query": "authentication",
    "mesh_path": "/path/to/mesh",
    "limit": 20
  }
}
```

### mesh_build

Convenience tool: init a mesh + join all cruxes in a directory + run cross-edge discovery in one call.

```json
{
  "name": "mesh_build",
  "arguments": {
    "name": "investigation",
    "crux_dir": "./cruxes",
    "mesh_path": "./investigation"
  }
}
```

Use this after `crux_generate_dir` to immediately get a queryable mesh.

### mesh_diff

Show what changed in the mesh since a given timestamp. Useful after adding a second drive's cruxes.

```json
{
  "name": "mesh_diff",
  "arguments": {
    "mesh_path": "/path/to/mesh",
    "since": 1700000000
  }
}
```

Returns: new nodes added, new cross-crux edges discovered, duplicate content detected.

### mesh_create_cluster

Create a named access-control cluster within the mesh.

```json
{
  "name": "mesh_create_cluster",
  "arguments": {
    "name": "engineering",
    "classification": "internal",
    "policy": "allow",
    "mesh_path": "/path/to/mesh"
  }
}
```

### mesh_assign_cluster

Assign a crux to a cluster.

```json
{
  "name": "mesh_assign_cluster",
  "arguments": {
    "identifier": "my-project",
    "cluster": "engineering",
    "mesh_path": "/path/to/mesh"
  }
}
```

### project_init

Create a starter mesh at the given path — one call creates three linked cruxes (policy, code, coms) and seeds the code crux with 7 starter knowledge nodes. Intended as the recommended onboarding path for new projects.

```json
{
  "name": "project_init",
  "arguments": {
    "path": "/path/to/project"
  }
}
```

Returns a summary: cruxes created, seed nodes added, mesh manifest path.

---

## 12. Complete Examples

### Example A: Small Codebase Crux

```json
{
  "crux_version": "2",
  "header": {
    "crux_id": "sha256:abc123...",
    "crux_name": "auth-service",
    "crux_kind": "codebase",
    "origin": "rust",
    "created_at": 1700000000,
    "updated_at": 1700000000,
    "public_key": "",
    "mesh_memberships": []
  },
  "nodes": [
    {
      "node_id": "sha256:n1...",
      "name": "src/auth",
      "kind": "module",
      "module": "",
      "summary": "Authentication module handling login, logout, and session management.",
      "schema": {"inputs": [], "outputs": [], "side_effects": []},
      "tags": ["auth", "security"],
      "reach": [],
      "properties": [],
      "warnings": [],
      "planning": {"priority": "", "effort": "", "status": "stable", "owner": "", "milestone": ""},
      "security": {"classification": "internal", "redact_below": null},
      "content_hash": "sha256:c1...",
      "deleted_at": null
    },
    {
      "node_id": "sha256:n2...",
      "name": "@authenticate_user",
      "kind": "function",
      "module": "src/auth",
      "summary": "Validates username and password, returns a JWT on success.",
      "schema": {
        "inputs": [
          {"name": "username", "type": "String", "required": true, "description": ""},
          {"name": "password", "type": "String", "required": true, "description": ""}
        ],
        "outputs": [{"name": "", "type": "Result<Jwt, AuthError>", "required": true, "description": ""}],
        "side_effects": ["writes session to DB"]
      },
      "tags": ["auth", "jwt"],
      "reach": ["@hash_password", "@create_session"],
      "properties": [],
      "warnings": [],
      "planning": {"priority": "high", "effort": "low", "status": "stable", "owner": "alice", "milestone": ""},
      "security": {"classification": "confidential", "redact_below": null},
      "content_hash": "sha256:c2...",
      "deleted_at": null
    }
  ],
  "edges": [
    {
      "edge_id": "sha256:e1...",
      "src": "src/auth",
      "dst": "@authenticate_user",
      "kind": "contains",
      "weight": 1.0,
      "detail": "",
      "cross_crux": false,
      "binding": "",
      "created_at": 1700000000,
      "dangling": false
    }
  ]
}
```

### Example B: CRM Crux

Model contacts and companies as nodes. Use `properties` for domain fields.

```json
{
  "nodes": [
    {
      "name": "Alice Chen",
      "kind": "person",
      "module": "contacts",
      "summary": "VP Engineering at Acme Corp. Primary technical contact.",
      "tags": ["customer", "enterprise", "decision-maker"],
      "properties": ["email=alice@acme.com", "phone=+1-555-0100", "status=active", "deal=enterprise-q1"],
      "security": {"classification": "confidential", "redact_below": null}
    },
    {
      "name": "Acme Corp",
      "kind": "record",
      "module": "companies",
      "summary": "Enterprise customer. 500-seat license. Renewal in Q3.",
      "tags": ["enterprise", "renewal"],
      "properties": ["domain=acme.com", "arr=120000", "stage=customer", "owner=bob"]
    }
  ],
  "edges": [
    {
      "src": "Alice Chen",
      "dst": "Acme Corp",
      "kind": "belongs_to_domain",
      "detail": "Primary contact at this company"
    }
  ]
}
```

### Example C: Forensic Evidence Node

A node generated by ingesting an mbox file — fully source-referenced for evidence retrieval.

```json
{
  "name": "Email 42",
  "kind": "record",
  "module": "inbox.mbox",
  "summary": "Re: Contract draft — alice@example.com to bob@example.com, 2024-01-15",
  "tags": ["email", "contract", "alice", "bob"],
  "properties": [
    "from=alice@example.com",
    "to=bob@example.com",
    "subject=Re: Contract draft",
    "date=Mon, 15 Jan 2024 09:30:00 +0000",
    "source_ref.uri=file:///Volumes/Evidence_Drive_1/emails/inbox.mbox",
    "source_ref.volume_label=Evidence_Drive_1",
    "source_ref.relative_path=emails/inbox.mbox",
    "source_ref.byte_offset=48230",
    "source_ref.byte_length=3200",
    "source_ref.record_index=42",
    "source_ref.record_delimiter=From ",
    "provenance.acquired_at=1700000000",
    "provenance.acquired_by=forensic-agent-v1"
  ],
  "security": {"classification": "confidential", "redact_below": null}
}
```

### Example D: Documentation Crux

Generated automatically from Markdown via `crux_generate` with `format: "markdown"`. Each heading becomes a node; parent headings have `contains` edges to children.

---

## 13. Standalone-to-Mesh Workflow

### Step 1: Create a standalone crux

```
crux_create  name="my-project"  kind="codebase"
```

Or generate from existing content:
```
crux_generate  name="my-docs"  input="<markdown text>"  format="markdown"
```

### Step 2: Populate the crux

Add nodes and edges manually:
```
crux_add_node  path="."  name="@handle_request"  kind="function"  module="src/api"
crux_add_edge  path="."  src="@handle_request"  dst="@validate_input"  kind="calls"
```

### Step 3: Query standalone

```
crux_query  path="."  query="auth"
```

### Step 4: Create a mesh

```
mesh_init  name="my-org"  path="/workspace/mesh"
```

This creates the mesh manifest and a policy crux with default security settings.

### Step 5: Join the mesh

```
mesh_join  crux_path="../my-project"  mesh_path="/workspace/mesh"
```

The crux is validated against the policy (kinds allowed, member cap, cross-mesh rules). The crux's `.crux.json` is updated with the mesh membership.

### Step 6: Organize with clusters

```
mesh_create_cluster  name="engineering"  classification="internal"
mesh_assign_cluster  identifier="my-project"  cluster="engineering"
```

### Step 7: Query the mesh

```
mesh_query  query="authentication"  mesh_path="/workspace/mesh"
```

Results are filtered by the mesh's security policy and the querier's clearance level.

---

## 14. MCP Client Configuration

To connect an agent to Crux Mesh, configure the MCP server in your client.

### Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "crux-mesh": {
      "command": "/path/to/crux",
      "args": ["--mcp"]
    }
  }
}
```

### Generic MCP client (JSON-RPC 2.0 over stdio)

```bash
/path/to/crux --mcp
```

Send requests on stdin, read responses on stdout. One JSON object per line.

First call must be `initialize`:
```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"my-agent","version":"1.0"}}}
```

Then send `notifications/initialized` (no response expected):
```json
{"jsonrpc":"2.0","method":"notifications/initialized"}
```

Then call any tool:
```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mesh_status","arguments":{"mesh_path":"/path/to/mesh"}}}
```

---

## 15. Tips for Agents

- **Read the spec first**: Always call `resources/read uri=crux://spec/agent` when connecting to a new Crux Mesh server. This document is embedded in the binary and always current.
- **IDs are stable**: Node names must be unique within a crux. If you rename a node, its ID changes — prefer adding aliases as `properties` entries instead.
- **Soft-delete, don't hard-delete**: Use `crux_remove_node` to preserve history. Hard deletion is irreversible.
- **Summaries matter**: The `summary` field is what mesh queries and LLM context windows see first. Make them precise and factual.
- **Tags drive discovery**: Add 2–5 tags per node. Use consistent vocabulary across your cruxes for better mesh query results.
- **Properties for structured data**: Any domain-specific key-value data goes in `properties` as `"key=value"` strings. This keeps the schema flexible without breaking the core format.
- **Classification defaults to internal**: Nodes without an explicit classification default to `internal`. Only escalate when you have a reason.
- **One crux per domain**: Separate your codebase, documentation, and CRM into separate cruxes. Connect them via a mesh with cross-crux edges.
- **Use source references for evidence**: After `crux_query` or `mesh_query` returns a node, call `crux_resolve` to find the file, then `crux_extract` to read the original content. Never assume the summary contains everything.
- **mesh_build for bulk ingestion**: After `crux_generate_dir`, use `mesh_build` to get a fully connected, queryable mesh in one call.
- **mesh_diff for incremental updates**: When adding a second data source, call `mesh_diff since=<timestamp>` after joining to see exactly what cross-crux edges were newly discovered.

---

## 16. Helm — Visual Graph Editor (Session 0123+)

**Helm** is the built-in browser-based UI for exploring and editing a crux. Launch it with:

```bash
crux helm  # opens http://localhost:7337
```

### Inline editing

All nodes and edges are editable directly in the graph inspector panel — no policy gate required. Select any node or edge to open the inspector, then:

- **Edit node** — modify name, summary, kind, tags, properties, planning fields, and security classification in place; click Save to write changes to `.crux.json`
- **Add Node** — opens an inline form to create a new node without leaving the graph view
- **Add Edge** — opens an inline form to connect any two nodes by name with a chosen edge kind

### Domain templates

When creating a new crux via Helm ("New Crux" modal), five pre-seeded templates are available:

| Template | Kind | Pre-seeded with |
|----------|------|----------------|
| Project Tracker | `dataset` | Status, milestone, and owner node stubs |
| Contacts / CRM | `custom` | Person and company node stubs + common property keys |
| Knowledge Base | `documentation` | Section and document node stubs |
| Incident Log | `dataset` | Incident, timeline, and resolution node stubs |
| LML Project (language in development) | `codebase` | 7 LML knowledge nodes (parser, typeck, lower, codegen, interpreter, stdlib, runtime) |

Selecting a template creates the crux and populates it with the seed nodes in a single step.
