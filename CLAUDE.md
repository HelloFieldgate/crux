# Crux Mesh — agent instructions

This repo dogfoods its own tool. A local mesh lives at the repo root (gitignored).

## At session start

Attach to the mesh before doing other work. Per [CRUX_AGENT_SPEC.md](CRUX_AGENT_SPEC.md) "Path A":

1. Call `mesh_status` with `mesh_path=.` — discovers the three members and reports health.
2. Call `crux action=query path=code/.crux.json query="<topic>"` to search the code crux for context relevant to the user's request. **Use this, not `mesh_query`, for code knowledge** — `mesh_query` has a known cross-member search gap and may return nothing even when nodes exist.
3. Optionally call `mesh_query` with `query="<topic>"` and `mesh_path=.` as a secondary sweep for coms/policy context.

If the `crux` MCP tool is not available in the current session, fall back to reading `.crux-mesh.json` and each member's `.crux.json` directly. Note the absence so the user can wire up the MCP server.

## The three cruxes

- **`policy/.crux.json`** — security/clearance rules and MCP server registrations. Read-mostly; only write when policy changes.
- **`code/.crux.json`** — knowledge about the Crux Mesh Rust codebase: modules, invariants, decisions, gotchas. Write `crux_add_node` here when you learn something durable about the code (a non-obvious constraint, a deliberate design choice, a fix and its reason). Reach for it via `crux action=query path=code/.crux.json` before doing nontrivial work.
- **`coms/.crux.json`** — messages and channels. Post a `message` node (channel=`general`) when you want to leave a note for future sessions or another agent.

## At session end (and after major mid-session changes)

Before closing a session, or immediately after any significant change (publish, architectural decision, notable fix, repo-level config change), write to the mesh:

1. **`coms/.crux.json`** — post a `message` node summarising what happened. Include: what changed, why, and any state future sessions need to know (commit SHAs, new file locations, decisions made). Use `kind=message`, `tags` matching the topic, and a `summary` of ≤200 chars.
2. **`code/.crux.json`** — if you learned something durable about the codebase (a non-obvious invariant, a deliberate design choice, a fix and its root cause), add a node there too.

Do not wait until the user asks. If something significant happened this session, write it before the conversation ends.

## What NOT to write to the mesh

- Ephemeral task state — that's what TodoWrite is for.
- Anything already obvious from `git log` or the source itself — the mesh is for what's *not* derivable from the code.
- LML-specific knowledge — this is a Rust repo; LML references belong elsewhere.
