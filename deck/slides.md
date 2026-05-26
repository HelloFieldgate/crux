---
theme: default
title: The Crux
titleTemplate: '%s — Hardened MCP Gateway'
info: |
  ## The Crux
  A hardened MCP gateway with a built-in knowledge graph.
  [github.com/HelloFieldgate/crux](https://github.com/HelloFieldgate/crux)
colorSchema: dark
highlighter: shiki
fonts:
  sans: 'Inter'
  mono: 'Fira Code'
themeConfig:
  primary: '#6B83BE'
css: unocss
---

<div class="flex flex-col items-center justify-center h-full text-center">
  <img src="/crux_desat.png" class="w-24 h-24 mb-8" />
  <h1 class="text-6xl font-bold text-[#6B83BE] mb-4" style="border:none;padding:0">The Crux</h1>
  <p class="text-2xl text-gray-300 mb-2">A hardened MCP gateway with a built-in knowledge graph</p>
  <div class="flex gap-3 mt-6 text-sm text-gray-400 flex-wrap justify-center">
    <span class="px-3 py-1 rounded-full border border-[#6B83BE]/60">clearance-gated</span>
    <span class="px-3 py-1 rounded-full border border-[#6B83BE]/60">injection-hardened</span>
    <span class="px-3 py-1 rounded-full border border-[#6B83BE]/60">audited</span>
    <span class="px-3 py-1 rounded-full border border-[#6B83BE]/60">pure Rust · zero deps</span>
  </div>
</div>

<style>
.slidev-layout h1 { border: none !important; }
</style>

---

# The AI Agent Problem

<div class="grid grid-cols-3 gap-6 mt-8">

<div class="p-6 rounded-xl border border-gray-700 bg-gray-800/40">
  <div class="text-4xl mb-3">🧠</div>
  <h3 class="text-lg font-semibold text-[#6B83BE] mb-2">Amnesia</h3>
  <p class="text-gray-300 text-sm leading-relaxed">Agents forget everything between sessions. Teams re-explain context endlessly, burning tokens and context window space.</p>
</div>

<div class="p-6 rounded-xl border border-gray-700 bg-gray-800/40">
  <div class="text-4xl mb-3">🕸️</div>
  <h3 class="text-lg font-semibold text-[#6B83BE] mb-2">Tool Sprawl</h3>
  <p class="text-gray-300 text-sm leading-relaxed">Agents connect to dozens of MCP servers with no unified policy plane. Each server is its own security island.</p>
</div>

<div class="p-6 rounded-xl border border-gray-700 bg-gray-800/40">
  <div class="text-4xl mb-3">🔓</div>
  <h3 class="text-lg font-semibold text-[#6B83BE] mb-2">No Perimeter</h3>
  <p class="text-gray-300 text-sm leading-relaxed">No injection defense. No clearance gating. No tamper-evident audit. Agents can be manipulated into leaking data or taking unauthorized actions.</p>
</div>

</div>

---
layout: center
class: text-center
title: One Trusted Endpoint
---

<div class="text-5xl font-bold text-[#6B83BE] mb-6 leading-tight">
  One trusted endpoint.<br/>One persistent graph.<br/>Zero blind spots.
</div>

<p class="text-xl text-gray-300 mt-6 max-w-2xl mx-auto leading-relaxed">
  The Crux is a single hardened gateway that gives your AI agents persistent, queryable memory and enforces security policy on every tool call — with a tamper-evident audit chain to prove it.
</p>

---
layout: two-cols
---

# Architecture

### Knowledge Graph

<div class="mt-4 space-y-3 pr-8">
  <div class="flex items-start gap-3">
    <span class="text-[#6B83BE] font-bold mt-0.5">◆</span>
    <div class="text-sm"><strong>Portable .crux.json</strong> — a typed, directed graph per domain. Version-controlled, diffable, no database server.</div>
  </div>
  <div class="flex items-start gap-3">
    <span class="text-[#6B83BE] font-bold mt-0.5">◆</span>
    <div class="text-sm"><strong>Eight domain kinds</strong> — codebase, docs, preferences, org, skillset, API, dataset, custom.</div>
  </div>
  <div class="flex items-start gap-3">
    <span class="text-[#6B83BE] font-bold mt-0.5">◆</span>
    <div class="text-sm"><strong>Mesh federation</strong> — multiple cruxes linked and queryable as one unified knowledge base.</div>
  </div>
  <div class="flex items-start gap-3">
    <span class="text-[#6B83BE] font-bold mt-0.5">◆</span>
    <div class="text-sm"><strong>Provenance-first</strong> — every node traces back to source bytes: file path, byte offset, device ID.</div>
  </div>
</div>

::right::

### Policy Router

<div class="mt-4 space-y-3 pl-4">
  <div class="flex items-start gap-3">
    <span class="text-[#6B83BE] font-bold mt-0.5">◆</span>
    <div class="text-sm"><strong>Single MCP endpoint</strong> — agents connect once; the router handles all external tool calls.</div>
  </div>
  <div class="flex items-start gap-3">
    <span class="text-[#6B83BE] font-bold mt-0.5">◆</span>
    <div class="text-sm"><strong>Clearance gating</strong> — 4-level classification with per-node access control and auto-redaction.</div>
  </div>
  <div class="flex items-start gap-3">
    <span class="text-[#6B83BE] font-bold mt-0.5">◆</span>
    <div class="text-sm"><strong>Injection scanning</strong> — every argument pattern-matched before forwarding upstream.</div>
  </div>
  <div class="flex items-start gap-3">
    <span class="text-[#6B83BE] font-bold mt-0.5">◆</span>
    <div class="text-sm"><strong>W-OTS audit chain</strong> — post-quantum signed record of every decision made.</div>
  </div>
</div>

---

# Knowledge Graph — Portable Memory

<div class="grid grid-cols-2 gap-8 mt-4">

<div>

**One file. One domain. Fully queryable.**

```json
{
  "kind": "codebase",
  "nodes": [
    {
      "id": "auth-service",
      "label": "Auth Service",
      "classification": "internal",
      "tags": ["rust", "oauth2"],
      "source": {
        "path": "src/auth/mod.rs",
        "offset": 0
      }
    }
  ],
  "edges": [
    {
      "from": "auth-service",
      "to": "token-store",
      "rel": "depends_on"
    }
  ]
}
```

</div>

<div class="space-y-4 pt-2">
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">8 domain kinds</strong><br>
    <span class="text-xs text-gray-400">codebase · documentation · preferences · organization · skillset · api · dataset · custom</span>
  </div>
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Typed edges</strong><br>
    <span class="text-xs text-gray-400">depends_on · documents · owns · references · related_to · and more</span>
  </div>
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Git-native</strong><br>
    <span class="text-xs text-gray-400">Single JSON file — fully diffable, PR-reviewable, no database required</span>
  </div>
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Forensic provenance</strong><br>
    <span class="text-xs text-gray-400">Every node carries file path + byte offset back to original bytes — mount-resilient</span>
  </div>
</div>

</div>

---

# Ingest Anything — In One Command

<div class="grid grid-cols-2 gap-8 mt-4">

<div>

**Six built-in source adapters:**

<div class="grid grid-cols-2 gap-2 mt-3">
  <div class="p-2 rounded bg-gray-800/60 border border-gray-700 text-xs">
    <div class="text-[#6B83BE] font-bold">Markdown</div>
    <div class="text-gray-400">Docs, READMEs, wikis</div>
  </div>
  <div class="p-2 rounded bg-gray-800/60 border border-gray-700 text-xs">
    <div class="text-[#6B83BE] font-bold">CSV</div>
    <div class="text-gray-400">Org charts, datasets</div>
  </div>
  <div class="p-2 rounded bg-gray-800/60 border border-gray-700 text-xs">
    <div class="text-[#6B83BE] font-bold">JSON</div>
    <div class="text-gray-400">Incident logs, configs</div>
  </div>
  <div class="p-2 rounded bg-gray-800/60 border border-gray-700 text-xs">
    <div class="text-[#6B83BE] font-bold">Source code</div>
    <div class="text-gray-400">Rust, Python, TS…</div>
  </div>
  <div class="p-2 rounded bg-gray-800/60 border border-gray-700 text-xs">
    <div class="text-[#6B83BE] font-bold">Email (MBOX)</div>
    <div class="text-gray-400">Full inbox ingestion</div>
  </div>
  <div class="p-2 rounded bg-gray-800/60 border border-gray-700 text-xs">
    <div class="text-[#6B83BE] font-bold">Slack export</div>
    <div class="text-gray-400">Channel history</div>
  </div>
</div>

<div class="mt-4 p-3 rounded-lg bg-[#6B83BE]/10 border border-[#6B83BE]/30 text-xs">
  <strong>Real example:</strong> Helios Robotics built a 6-crux mesh from an engineering spec, employee handbook, org chart CSV, incident JSON, email MBOX, and Slack exports — all queryable in one command.
</div>

</div>

<div>

**From mixed sources to a live mesh:**

```bash
# Scan a directory
crux_generate_dir path="./engineering"

# Scan an email archive
crux_scan source="inbox.mbox" \
          kind="documentation"

# Build federated mesh
mesh_build

# Query across all sources
mesh_query query="auth outage root cause"
# → returns nodes from engineering spec,
#   email thread, and incident log
#   filtered by your clearance level
```

</div>

</div>

---
layout: center
title: Context Without the Firehose
---

<div class="text-center">
  <div class="text-5xl font-bold text-[#6B83BE] mb-4">Context without the firehose.</div>
  <p class="text-lg text-gray-300 max-w-2xl mx-auto mt-4 leading-relaxed">
    Instead of loading entire files or repositories into the context window, agents ask the graph for exactly what's relevant — getting surgical answers backed by source-byte provenance.
  </p>

  <div class="grid grid-cols-2 gap-8 mt-8 text-left max-w-3xl mx-auto">
    <div class="p-5 rounded-xl border border-red-900/50 bg-red-950/20">
      <div class="text-red-400 font-bold mb-3 text-sm">Without Crux</div>
      <div class="text-sm text-gray-400 space-y-2">
        <div>→ Load 200 files into context</div>
        <div>→ Agent reads everything, uses 3%</div>
        <div>→ Context window exhausted</div>
        <div>→ No memory next session</div>
      </div>
    </div>
    <div class="p-5 rounded-xl border border-[#6B83BE]/40 bg-[#6B83BE]/10">
      <div class="text-[#6B83BE] font-bold mb-3 text-sm">With Crux</div>
      <div class="text-sm text-gray-300 space-y-2">
        <div>→ <code>crux_query("auth latency")</code></div>
        <div>→ Returns 4 relevant nodes + edges</div>
        <div>→ Source provenance included</div>
        <div>→ Persistent across all sessions</div>
      </div>
    </div>
  </div>
</div>

---

# Mesh Federation — Knowledge Scales With You

<div class="grid grid-cols-2 gap-8 mt-4">

<div>

<img src="/nodes_light.png" class="rounded-lg border border-gray-200 shadow-lg w-full" />
<p class="text-xs text-gray-500 mt-2 text-center">Helm showing the helios-robotics mesh — 8 cruxes, all online</p>

</div>

<div class="space-y-2 pt-2">
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Cross-graph queries</strong><br>
    <span class="text-xs text-gray-300">Ask a question once, get answers from all cruxes in the mesh — filtered by the caller's clearance level automatically.</span>
  </div>
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Clearance clusters</strong><br>
    <span class="text-xs text-gray-300">Group cruxes by sensitivity. An agent with <code>internal</code> clearance never sees <code>restricted</code> crux content — not even node names leak.</span>
  </div>
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Package registry</strong><br>
    <span class="text-xs text-gray-300">Publish and install crux packages with <code>pkg_publish</code> / <code>pkg_install</code>. Share domain knowledge graphs across teams.</span>
  </div>
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Cross-crux edges</strong><br>
    <span class="text-xs text-gray-300">Link nodes across cruxes with typed <code>mesh_link</code> edges. Query semantically across domain boundaries.</span>
  </div>
</div>

</div>

---

# Policy Router — One Perimeter For Everything

<div class="mt-4">

```
Your Agent
    │  (one MCP connection)
    ▼
┌─────────────────────────────────────────────────────────────┐
│                       crux-router                           │
│                                                             │
│  1. Clearance gate    →  block calls above caller level     │
│  2. Injection scan    →  block suspicious arg patterns      │
│  3. Rate limit        →  enforce per-server quotas          │
│  4. Forward           →  proxy to target MCP server         │
│  5. Response sanitize →  redact above-clearance content     │
│  6. Audit             →  sign & append to audit chain       │
└─────────────────────────────────────────────────────────────┘
         │               │               │
    MCP Server       MCP Server      MCP Server
      (files)          (web)          (database)
```

<div class="grid grid-cols-3 gap-4 mt-4">
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700 text-xs text-center">
    <div class="text-[#6B83BE] font-bold mb-1">Enable</div>
    <code>crux --policy-router</code>
  </div>
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700 text-xs text-center">
    <div class="text-[#6B83BE] font-bold mb-1">Set clearance</div>
    <code>CRUX_CALLER_CLEARANCE=internal</code>
  </div>
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700 text-xs text-center">
    <div class="text-[#6B83BE] font-bold mb-1">Register servers</div>
    <code>mesh_register_mcp</code>
  </div>
</div>

</div>

---
layout: two-cols
---

# Clearance Gating

**Four classification levels — enforced everywhere**

<div class="mt-4 space-y-3">
  <div class="flex items-center gap-3 p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <span class="w-24 text-center text-xs px-2 py-1 rounded bg-green-900/60 text-green-300 font-bold shrink-0">public</span>
    <span class="text-sm text-gray-300">Freely accessible to all agents</span>
  </div>
  <div class="flex items-center gap-3 p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <span class="w-24 text-center text-xs px-2 py-1 rounded bg-blue-900/60 text-blue-300 font-bold shrink-0">internal</span>
    <span class="text-sm text-gray-300">Team-level; not for external agents</span>
  </div>
  <div class="flex items-center gap-3 p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <span class="w-24 text-center text-xs px-2 py-1 rounded bg-yellow-900/60 text-yellow-300 font-bold shrink-0">confidential</span>
    <span class="text-sm text-gray-300">Restricted to named agents or roles</span>
  </div>
  <div class="flex items-center gap-3 p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <span class="w-24 text-center text-xs px-2 py-1 rounded bg-red-900/60 text-red-300 font-bold shrink-0">restricted</span>
    <span class="text-sm text-gray-300">Highest sensitivity; all else redacted</span>
  </div>
</div>

::right::

<div class="pl-6 pt-12 space-y-4">
  <div class="p-4 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Auto-redaction</strong><br>
    <span class="text-xs text-gray-300">Above-clearance node names in responses are stripped — not just content. The existence of sensitive data never leaks.</span>
  </div>
  <div class="p-4 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Field-level classification</strong><br>
    <span class="text-xs text-gray-300">Individual fields within a node can be classified separately. Agents see only the fields they're cleared for.</span>
  </div>
  <div class="p-4 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Call blocking</strong><br>
    <span class="text-xs text-gray-300">Calls to servers registered above the caller's clearance are blocked before forwarding — the upstream server never receives them.</span>
  </div>
  <div class="p-4 rounded-lg bg-[#6B83BE]/10 border border-[#6B83BE]/30">
    <strong class="text-[#6B83BE] text-sm">Cluster-level gating</strong><br>
    <span class="text-xs text-gray-300">An <code>internal</code>-cleared agent querying a <code>restricted</code> cluster gets zero results — not a hint the cluster exists.</span>
  </div>
</div>

---

# Injection Hardening

**Every argument scanned before forwarding**

<div class="grid grid-cols-2 gap-8 mt-4">

<div>

**Blocked patterns include:**

```
"ignore previous instructions"
"system:" prefixes in arguments
<tool_call> tags in payloads
Payloads exceeding 50 KB
Nested JSON-RPC injection attempts
```

**On detection — error returned to agent:**

```json
{
  "error": {
    "code": -32600,
    "message": "Request blocked: injection pattern",
    "data": {
      "pattern": "ignore previous instructions",
      "server": "filesystem"
    }
  }
}
```

</div>

<div class="space-y-4">
  <div class="p-4 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Pre-flight scanning</strong><br>
    <span class="text-xs text-gray-300">Arguments pattern-matched before any bytes leave the router. The upstream server never sees the bad request.</span>
  </div>
  <div class="p-4 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Response sanitization</strong><br>
    <span class="text-xs text-gray-300">Responses from upstream servers are scanned too — above-clearance content stripped on the way back to the agent.</span>
  </div>
  <div class="p-4 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Rate limiting</strong><br>
    <span class="text-xs text-gray-300">Per-server sliding-window enforcement. Default: 60 calls / 60 seconds per server. Configurable per registration.</span>
  </div>
</div>

</div>

---

# Tamper-Evident Audit Chain

**Every tool call signed. Every decision recorded.**

<div class="grid grid-cols-2 gap-8 mt-4">

<div>

```json
{
  "entries": [
    {
      "id": "a1b2c3d4",
      "timestamp": "2025-05-20T14:23:11Z",
      "caller_clearance": "internal",
      "server": "filesystem",
      "tool": "read_file",
      "args": { "path": "/docs/auth.md" },
      "verdict": "allowed",
      "response_sanitized": false,
      "signature": "WOTSxxxxxxxxxxxxxxxxxxxx",
      "prev_hash": "sha256:deadbeef..."
    }
  ]
}
```

</div>

<div class="space-y-4 pt-2">
  <div class="p-4 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">W-OTS post-quantum signatures</strong><br>
    <span class="text-xs text-gray-300">NIST SP 800-208 compliant. Every entry signed with a Winternitz one-time key — quantum-resistant and deterministic.</span>
  </div>
  <div class="p-4 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Hash-chained entries</strong><br>
    <span class="text-xs text-gray-300">Each entry includes the SHA-256 of the previous — any tampering breaks the chain. Verify with <code>crux_verify</code>.</span>
  </div>
  <div class="p-4 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Compliance-ready</strong><br>
    <span class="text-xs text-gray-300">Full agent call history for SOX, HIPAA, and FedRAMP-scope environments. Export and verify independently of the router.</span>
  </div>
</div>

</div>

---

# Helm — Visual Policy Editor

<div class="grid grid-cols-5 gap-6 mt-4">

<div class="col-span-3">
  <img src="/mcp_dark.png" class="rounded-lg shadow-xl w-full" />
  <p class="text-xs text-gray-500 mt-2 text-center">MCP Servers view — clearance levels, rate limits, and audit status per server</p>
</div>

<div class="col-span-2 space-y-3 pt-1">
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Five views</strong><br>
    <span class="text-xs text-gray-300">Graph · Board · Table · Timeline · MCP Servers — switch with one click</span>
  </div>
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Policy at a glance</strong><br>
    <span class="text-xs text-gray-300">Clearance level, allowed tools, rate limit, and audit status for every registered MCP server — no config files</span>
  </div>
  <div class="p-3 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Inline editing</strong><br>
    <span class="text-xs text-gray-300">Create nodes, add edges, search, filter, export to Markdown, import from CSV — full CRUD in browser</span>
  </div>
  <div class="p-3 rounded-lg bg-[#6B83BE]/10 border border-[#6B83BE]/30">
    <strong class="text-[#6B83BE] text-sm">Ships with the binary</strong><br>
    <span class="text-xs text-gray-300"><code>helm .</code> — no install. Opens at <code>localhost:8111</code></span>
  </div>
</div>

</div>

---

# Zero Dependencies — Deliberately

**Pure Rust. Standard library only.**

<div class="grid grid-cols-2 gap-8 mt-4">

<div>

**What "zero deps" actually means:**

- No `serde`, `tokio`, `reqwest`, or any external crate
- JSON serialization hand-rolled
- W-OTS cryptography hand-rolled
- Single statically-linked binary
- Zero `cargo audit` surface — no transitive dep tree to track

```bash
$ cargo tree | wc -l
1   # just crux itself

$ ls target/release/crux
-rwxr-xr-x  8.2M  crux   # single binary
```

</div>

<div class="space-y-4">
  <div class="p-4 rounded-lg bg-[#6B83BE]/10 border border-[#6B83BE]/30">
    <strong class="text-[#6B83BE] text-sm">Auditable in one read</strong><br>
    <span class="text-xs text-gray-300">Security teams can audit the full source — no "trust the dependency tree" problem. What you see is everything that runs.</span>
  </div>
  <div class="p-4 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Air-gap friendly</strong><br>
    <span class="text-xs text-gray-300">No external network calls. Runs fully offline. Deploy to restricted environments without supply-chain risk.</span>
  </div>
  <div class="p-4 rounded-lg bg-gray-800/60 border border-gray-700">
    <strong class="text-[#6B83BE] text-sm">Deliberate trade-off</strong><br>
    <span class="text-xs text-gray-300">We wrote more code so you don't have to trust code you didn't write. 284 passing tests. ~4,000 lines of Rust.</span>
  </div>
</div>

</div>

---

# How Crux Compares

<div class="mt-6 text-sm">

| Feature | **Crux** | Plain MCP | Vector DB | Graph DB |
|---|---|---|---|---|
| Storage | Single `.crux.json` | Stateless | Server + index | Server + index |
| External dependencies | **Zero** | Varies | Many | Many |
| Agent memory | **Native graph** | None | Via embeddings | Custom |
| Federation | **Native mesh** | None | Limited | Possible |
| Clearance gating | **Built-in (4 levels)** | None | None | RBAC plugin |
| Injection defense | **Built-in** | None | None | None |
| Tamper-evident audit | **Signed chain** | None | None | Plugin |
| Post-quantum crypto | **W-OTS (NIST 800-208)** | N/A | None | None |
| Visual graph editor | **Helm (built-in)** | None | None | Separate tool |
| Air-gap deployable | **Yes** | Varies | No | No |

</div>

---

# Who It's For

<div class="grid grid-cols-2 gap-5 mt-6">

<div class="p-5 rounded-xl border border-gray-700 bg-gray-800/40">
  <h3 class="text-[#6B83BE] font-bold mb-2 text-base">Enterprise AI Teams</h3>
  <p class="text-sm text-gray-300 leading-relaxed">Connect 20+ MCP servers through one router. One policy crux governs clearance, injection defense, rate limits, and auditing — across every agent and tool.</p>
</div>

<div class="p-5 rounded-xl border border-gray-700 bg-gray-800/40">
  <h3 class="text-[#6B83BE] font-bold mb-2 text-base">Regulated Industries</h3>
  <p class="text-sm text-gray-300 leading-relaxed">Finance, healthcare, legal — the clearance hierarchy, field-level redaction, and W-OTS audit chain address the compliance posture of SOX, HIPAA, and FedRAMP-scope environments.</p>
</div>

<div class="p-5 rounded-xl border border-gray-700 bg-gray-800/40">
  <h3 class="text-[#6B83BE] font-bold mb-2 text-base">Forensic & Incident Response</h3>
  <p class="text-sm text-gray-300 leading-relaxed">Mount-resilient source provenance traces every node to its original bytes. The signed audit chain proves no tampering — and shows exactly what every agent did, when, and why.</p>
</div>

<div class="p-5 rounded-xl border border-gray-700 bg-gray-800/40">
  <h3 class="text-[#6B83BE] font-bold mb-2 text-base">Multi-Agent Coordination</h3>
  <p class="text-sm text-gray-300 leading-relaxed">Agents in a mesh share knowledge via cross-crux edges while respecting clearance boundaries. No shared secrets — federated, policy-gated knowledge.</p>
</div>

</div>

---

# Quick Start — Double-Click to Install

<div class="grid grid-cols-2 gap-8 mt-4">

<div>

**Install (no prerequisites required):**

```bash
# macOS — double-click or run:
open install/install-macos.command

# Linux
bash install/install-linux.sh

# Windows — double-click:
install\install-windows.bat
```

The installer asks "Do you want Rust?" — handles everything. Binary lands in `~/.local/bin/crux`.

**Connect to Claude Desktop:**

```json
{
  "mcpServers": {
    "crux": {
      "command": "crux",
      "args": ["--mcp"]
    }
  }
}
```

</div>

<div>

**Bootstrap a starter mesh in one call:**

```
project_init name="my-project"
→ creates docs/, prefs/, org/ cruxes
→ links them in a mesh
→ registers common MCP servers
```

**Start the Helm UI:**

```bash
helm .
# → opens localhost:8111
# → point at any crux or mesh
```

**Enable the policy router:**

```bash
crux --policy-router \
     --mesh ./my-project.crux-mesh.json

# Set agent clearance:
export CRUX_CALLER_CLEARANCE=internal
```

</div>

</div>

---
layout: center
class: text-center
title: Get Started
---

<div class="flex flex-col items-center">
  <img src="/crux_desat.png" class="w-16 h-16 mb-6 opacity-90" />
  <h1 class="text-5xl font-bold text-[#6B83BE] mb-4" style="border:none;padding:0">Get Started</h1>
  <p class="text-xl text-gray-300 mb-8">Open source · Pure Rust · Zero dependencies · v0.2.0</p>

  <a href="https://github.com/HelloFieldgate/crux"
     class="px-10 py-4 rounded-xl bg-[#6B83BE] hover:bg-[#5a72ad] text-white hover:text-white font-bold text-lg no-underline transition-colors">
    github.com/HelloFieldgate/crux
  </a>

  <div class="mt-10 grid grid-cols-3 gap-8 text-center">
    <div>
      <div class="text-3xl font-bold text-[#6B83BE]">284</div>
      <div class="text-sm text-gray-400 mt-1">passing tests</div>
    </div>
    <div>
      <div class="text-3xl font-bold text-[#6B83BE]">0</div>
      <div class="text-sm text-gray-400 mt-1">external dependencies</div>
    </div>
    <div>
      <div class="text-3xl font-bold text-[#6B83BE]">v0.2.0</div>
      <div class="text-sm text-gray-400 mt-1">and counting</div>
    </div>
  </div>
</div>

<style>
.slidev-layout h1 { border: none !important; }
a { text-decoration: none !important; }
</style>
