# Crux Mesh — agent instructions

This repo dogfoods its own tool. A local mesh lives at the repo root (gitignored).

## At session start

Attach to the mesh before doing other work. Per [CRUX_AGENT_SPEC.md](CRUX_AGENT_SPEC.md) "Path A":

1. Call `mesh_status` with `mesh_path=.` — discovers the three members and reports health.
2. Call `mesh_query` with `query="<topic>"` and `mesh_path=.` when the user's request touches anything that might already live in the mesh.

If the `crux` MCP tool is not available in the current session, fall back to reading `.crux-mesh.json` and each member's `.crux.json` directly. Note the absence so the user can wire up the MCP server.

## The three cruxes

- **`policy/.crux.json`** — security/clearance rules and MCP server registrations. Read-mostly; only write when policy changes.
- **`code/.crux.json`** — knowledge about the Crux Mesh Rust codebase: modules, invariants, decisions, gotchas. Write `crux_add_node` here when you learn something durable about the code (a non-obvious constraint, a deliberate design choice, a fix and its reason). Reach for it via `mesh_query` before doing nontrivial work.
- **`coms/.crux.json`** — messages and channels. Post a `message` node (channel=`general`) when you want to leave a note for future sessions or another agent.

## What NOT to write to the mesh

- Ephemeral task state — that's what TodoWrite is for.
- Anything already obvious from `git log` or the source itself — the mesh is for what's *not* derivable from the code.
- LML-specific knowledge — this is a Rust repo; LML references belong elsewhere.
