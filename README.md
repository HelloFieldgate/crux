# The Crux

> A hardened MCP gateway with a built-in knowledge graph — clearance-gated, injection-hardened, and audited.

[![Slide Deck](https://img.shields.io/badge/slide_deck-view-6B83BE?style=flat-square)](https://hellofieldgate.github.io/crux/)

**Crux Mesh** is a secure MCP router that acts as the single trusted endpoint between your AI agent and every tool it touches. All calls are clearance-gated, injection-scanned, rate-limited, response-sanitized, and appended to a tamper-evident audit chain. The same binary also ships a portable knowledge graph: a single `.crux.json` file holds typed, queryable memory for one domain; link multiple cruxes into a **mesh** for federated cross-graph queries.

Agents query for exactly what's relevant — no raw-file dumps bloating the context window.

Pure Rust. Zero external dependencies.

---

## What The Crux Does

### Knowledge graph for AI agents

A **crux** is a single portable `.crux.json` file — diffable, git-friendly, no database server required. Agents create, populate, and query it via an MCP server or the CLI.

- Mesh multiple cruxes for federated, cross-graph queries
- Autonomous filesystem ingestion: emails, CSV, JSON, Markdown, and source code → queryable nodes in one command
- Forensics-grade provenance — every node carries source references (file path, byte offset, device ID) back to the original bytes
- Four-level classification (`public` / `internal` / `confidential` / `restricted`) with field-level redaction per node

### Hardened MCP gateway

`crux-router --policy-router` makes your mesh the **one trusted MCP endpoint**. Every tool call routed through it is:

- **Clearance-gated** — set `CRUX_CALLER_CLEARANCE`; calls to servers requiring higher clearance are blocked
- **Injection-scanned** — suspicious argument patterns are blocked before forwarding (`-32602`)
- **Response-sanitized** — above-clearance node names in replies are automatically redacted
- **Rate-limited** — per-server sliding-window `N/W` enforcement (`-32029` on violation)
- **Audited** — every call recorded in a tamper-evident `.crux-audit.json` chain, signed with W-OTS (NIST SP 800-208)

---

## Why Pure Rust, Zero Dependencies

Crux has no external crate dependencies — stdlib only. JSON is hand-rolled. The W-OTS crypto implementation is hand-rolled. The `[dependencies]` section in `Cargo.toml` is empty.

This is a deliberate trade-off: we give up convenience for trustworthiness. The binary you ship is fully auditable in one read. There is no supply chain. It embeds anywhere Rust runs.

---

## Install

```bash
git clone https://github.com/HelloFieldgate/crux
cd crux
```

### Quick install (double-click)

After cloning, open the `install/` folder for your OS and double-click:

| OS | Install | Launch Helm |
|----|---------|-------------|
| macOS | `install/macOS/Install Crux.command` | `install/macOS/Launch Helm.command` |
| Windows | `install/Windows/Install-Crux.bat` | `install/Windows/Launch-Helm.bat` |
| Linux | `chmod +x install/Linux/install-crux.sh && ./install/Linux/install-crux.sh` | `./install/Linux/launch-helm.sh` |

The installer builds from source (Rust required). If Rust is not installed, the script will offer to install it for you via [rustup.rs](https://rustup.rs/).

Binaries land in `~/.local/bin/` (macOS/Linux) or `%USERPROFILE%\.crux\bin\` (Windows).

> **macOS first-launch note:** macOS may show an "unidentified developer" warning. Right-click the `.command` file and choose Open to bypass it once.

### Build manually

```bash
cargo build --release
# Binaries: target/release/{crux,crux-router,helm}
```

---

## Quickstart — Your First Five Minutes

After the installer finishes, you have three binaries on your machine: `crux`, `crux-router`, and `helm`. Nothing else — no mesh, no wiring, no Helm running. These four steps take you from that blank slate to a connected agent with every MCP server under a single audited gate.

### Step 1 — Make a place for your agent's memory to live

A **crux** is a single `.crux.json` file — a typed knowledge graph for one domain. A **mesh** is a directory holding one or more cruxes plus a `.crux-mesh.json` manifest. The router reads its policy from the mesh, so you need one before you can do anything else.

**The clickable way (recommended):**
```bash
helm
```
Helm opens at `http://localhost:8111`. Click **New Mesh**, pick a directory, and pick a starter template. You now have a mesh and a policy crux. Leave Helm running — you'll use it again in Step 3.

**The terminal way:**
```bash
mkdir ~/my-org && cd ~/my-org
crux create policy --kind organization
crux mesh init my-org
crux mesh join policy.crux.json
```

Either way, the outcome is a directory containing a `.crux-mesh.json` and at least one `.crux.json`. Note the absolute path — every step below needs it.

> Once your agent is wired up in Step 2, you can ask it to call `project_init` to expand the mesh into a full three-crux starter (policy, codebase, coms) with seed knowledge nodes in one call.

### Step 2 — Point your agent at the router (and *only* the router)

Your agent talks to `crux-router --policy-router`. The router talks to everything else. The agent never speaks MCP to anything but the router.

The router finds its mesh by walking up from its working directory looking for `.crux-mesh.json` — that's why every config snippet below sets `cwd` to the mesh directory.

Open your agent's MCP config file and replace its `mcpServers` block with one entry. Replace everything, including servers you already had — you'll put them back through Crux in Step 3. For now, they're intentionally disconnected.

**Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):
```json
{
  "mcpServers": {
    "crux": {
      "command": "crux-router",
      "args": ["--policy-router"],
      "cwd": "/absolute/path/to/my-org",
      "env": { "CRUX_CALLER_CLEARANCE": "internal" }
    }
  }
}
```

**Claude Code** — project-level `.mcp.json` at the project root, or `~/.claude/settings.json` user-wide under `"mcpServers"`. Same shape as Claude Desktop.

**Cursor** — `~/.cursor/mcp.json`. Same shape.

**OpenAI Codex CLI** — `~/.codex/config.toml`:
```toml
[mcp_servers.crux]
command = "crux-router"
args = ["--policy-router"]
cwd = "/absolute/path/to/my-org"
env = { CRUX_CALLER_CLEARANCE = "internal" }
```

**Gemini CLI** — `~/.gemini/settings.json` under `"mcpServers"`. Same shape as Claude Desktop.

**Grok / xAI** — Grok's terminal and IDE clients accept standard MCP server entries (config path varies by client). Use the same `command` / `args` / `cwd` / `env` shape as Claude Desktop.

> Vendor config paths change. The rule is universal: one entry, `command: crux-router`, `args: ["--policy-router"]`, `cwd:` pointing at your mesh directory. Wherever your tool used to list other MCP servers, replace the whole block with this one entry.

Restart your agent. It should see the standard `crux_*`, `mesh_*`, `project_*`, and `pkg_*` tools — those come from the router's two embedded children. If it does, you're connected. Full tool reference: [CRUX_AGENT_SPEC.md](CRUX_AGENT_SPEC.md).

### Step 3 — Move every other MCP server behind the router

Until you do this, the agent has lost access to every MCP server you used to have. Now we put them back — through Crux.

Open Helm if it isn't already:
```bash
helm ~/my-org
```

Click the **MCP Servers** tab. You'll see three sub-tabs:

- **Registered** — servers currently routed through Crux
- **Discovered** — servers advertising themselves on your machine
- **External** — *the one to watch* — servers Crux found in your other agents' config files that are not yet routed through it

Crux scans Claude Desktop, Claude Code, Cursor, VS Code, and Continue configs automatically. Every entry in the External tab is a server your agent could reach without going through the router — a gap in the policy. For each one you want to keep, click **Route via Crux**. Helm registers it into the policy crux with default clearance and rate-limit settings (tighten them in the modal before confirming). It then moves to Registered.

When the External tab is empty, you're clean. The agent talks only to the router; the router talks to everything else under policy.

### Step 4 — Confirm nothing is bypassing Crux

Two checks:

1. **Helm > MCP Servers > External** should be empty. If an entry reappears here later, another tool re-added a direct server to its config and you need to route it.
2. **The audit log** — every router decision is appended to `.crux-audit.json` in your mesh directory, hash-chained and signed with W-OTS (NIST SP 800-208). Ask your agent to invoke a tool from one of your newly registered servers; a `forward` entry should appear in the audit file within seconds. If the call succeeds and no entry appears, the agent is bypassing the router — re-check Step 2.

`CRUX_CALLER_CLEARANCE` controls what the agent is allowed to reach: `public`, `internal`, `confidential`, or `restricted`. Calls to servers requiring higher clearance are blocked at the router before the request ever leaves your machine.

That's it. Every tool call your agent makes from here is clearance-gated, injection-scanned, rate-limited, response-sanitized, and signed into the audit chain — on every call, automatically.

---

## Helm — Visual Graph Editor

Helm is the built-in browser UI for exploring and editing any crux or mesh.

```bash
helm ~/my-org          # opens http://localhost:8111
```

<!--
TODO: Add screenshots before public announcement.
![Helm graph view](docs/screenshots/helm-graph.png)
![Helm timeline view](docs/screenshots/helm-timeline.png)
-->

- **Graph tab** — force-directed node graph; click any node or edge to open the inline inspector and edit in place
- **Board, Table, Timeline tabs** — alternate views for project planning and chronological data
- **MCP Servers tab** — register, inspect, and revoke external MCP server registrations from the policy crux
- **New Crux modal** — four domain templates: Project Tracker, Contacts/CRM, Knowledge Base, Incident Log

---

## Core Concepts

- **Crux** — a single `.crux.json` file; a typed directed graph for one domain. Eight kinds: `codebase`, `documentation`, `preferences`, `organization`, `skillset`, `api`, `dataset`, `custom`.
- **Node** — one unit of knowledge: `name`, `kind`, `summary` (≤200 chars), `tags`, `classification`, `properties`, `planning`, `source_ref.*`. Full schema: [CRUX_AGENT_SPEC.md §3](CRUX_AGENT_SPEC.md).
- **Edge** — a typed directed relationship. Seventeen kinds including `calls`, `imports`, `contains`, `data_flow`, `mesh_link`. Can be cross-crux.
- **Mesh** — a network of cruxes linked by a `.crux-mesh.json` manifest. Each member gets a W-OTS keypair; `mesh_query` searches all members in one call.
- **Cluster** — an access-control grouping inside a mesh. Cruxes in a `confidential` cluster are invisible to agents below that clearance.

---

## MCP Tool Surface

| Tool | Key actions |
|------|-------------|
| `crux` | `create` `load` `query` `add_node` `add_edge` `update_node` `generate` `scan` `resolve` `extract` `verify` … |
| `mesh` | `init` `join` `leave` `status` `query` `build` `register_mcp` `list_mcp_servers` `revoke_mcp` … |
| `pkg` | `search` `publish` `install` `audit` `update` |
| `project` | `init` — bootstrap a three-crux starter mesh in one call |

Legacy single-purpose names (`crux_create`, `mesh_init`, `crux_add_node`, …) are accepted as aliases. Full action reference: [CRUX_AGENT_SPEC.md](CRUX_AGENT_SPEC.md).

---

## Security & the Policy Router

Running `crux-router --policy-router` turns your mesh's policy crux into a **single trusted MCP endpoint**. Agents register external MCP servers into it via `mesh_register_mcp`. On every forwarded call, the router checks clearance, scans for injection, sanitizes the response, enforces the rate limit, and appends a W-OTS-signed entry to the audit chain. Without this setup, every MCP server you add is an implicit trust boundary. With it, you have one.

The Policy Router is fully implemented (Phases 0–4E complete). See [CRUX_ROUTER_SPEC.md](CRUX_ROUTER_SPEC.md) for the full reference and [crux_router_evolution.md](crux_router_evolution.md) for the implementation log.

---

## Architecture

Crux is a single pure-Rust crate (~14 modules under `src/`) with an empty `[dependencies]` section — stdlib only. The MCP wire protocol, knowledge graph engine, mesh operations, W-OTS audit chain, and Helm browser UI all ship as one statically-linkable binary. Format adapters (Markdown, plaintext, CSV, JSON, source code) are pluggable.

```
cargo test   # all tests passing
```

---

## How It Compares

| | **Crux Mesh** | Plain MCP server | Vector DB | Graph DB (Neo4j) |
|---|---|---|---|---|
| Storage | Single portable `.crux.json` | Stateless | Server + index | Server + index |
| External dependencies | **Zero** | Varies | Many | Many |
| Built for AI agents | **Native (MCP first-class)** | Yes — no memory | Via embeddings | Via custom integration |
| Federation across graphs | **Native mesh + clusters** | None | Limited | Possible |
| Clearance / classification gating | **Built-in (4 levels)** | None | None | RBAC plugin |
| Prompt-injection defense | **Built-in** | None | None | None |
| Tamper-evident audit log | **Built-in (signed chain)** | None | None | Plugin |
| Provenance + source references | **First-class** | None | Manual | Manual |
| Post-quantum signatures | **W-OTS (NIST SP 800-208)** | N/A | None | None |
| Browser graph editor | **Helm (built-in)** | None | None | Neo4j Browser |

---

## Documentation

- [CRUX_AGENT_SPEC.md](CRUX_AGENT_SPEC.md) — full agent and MCP tool reference
- [CRUX_ROUTER_SPEC.md](CRUX_ROUTER_SPEC.md) — Policy Router reference
- [crux_router_evolution.md](crux_router_evolution.md) — phased roadmap and implementation status
- [PACKAGE_MANAGER_ROADMAP.md](PACKAGE_MANAGER_ROADMAP.md) — design doc for the agent-first package manager

---

## License

MIT
