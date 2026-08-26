# Mesh Write Integrity — Correction Instructions

`add_edges` accepts edges whose endpoints do not exist, stores them, and reports that it
checked. Nothing downstream detects the result: `verify` returns PASS and `load` reports the
raw edge count. A mesh can therefore accumulate fictional structure indefinitely while every
available integrity signal says it is healthy.

This document reproduces the behaviour, lists the defects in priority order, and specifies the
fixes. Please apply all of them.

**Observed against:** `crux-mesh 0.5.0` (binary built 2026-08-21 18:45), via the `crux --mcp`
stdio driver and the `crux` CLI.

**Reported from:** a production mesh (284 nodes, 667 edges), where this bit
three separate times in a single working session. Every occurrence was caught by a hand-written
Python pre-check that reads `.crux.json` and does set-membership on node names before calling
`add_edges` — i.e. the caller reimplemented the validation the tool claims in its own success
message.

---

## 1. Reproduction

Two valid nodes, then four edges: one valid, three with endpoints that do not exist.

```jsonc
// nodes
[{"name":"alpha","kind":"reference","summary":"test node A"},
 {"name":"beta", "kind":"reference","summary":"test node B"}]

// edges
[{"src":"alpha",       "dst":"beta",         "kind":"relates_to"},  // valid
 {"src":"alpha",       "dst":"NO_SUCH_DST",  "kind":"relates_to"},  // dst missing
 {"src":"NO_SUCH_SRC", "dst":"beta",         "kind":"relates_to"},  // src missing
 {"src":"NO_SUCH_SRC2","dst":"NO_SUCH_DST2", "kind":"relates_to"}]  // both missing
```

| Call | Reported | Actual |
|---|---|---|
| `add_nodes` | `2 node(s) added, 0 skipped` | correct |
| `add_edges` | `4 edge(s) added, 0 skipped (missing src/dst)` | **all 4 stored; 3 dangling** |
| `verify` | `Status: PASS` | never examined an edge |
| `crux load` | `2 nodes, 4 edges` | no integrity signal |

Neither `src` nor `dst` is validated. The `skipped` counter is not merely under-reporting — the
skip path never executes, so the figure is structurally always `0`.

---

## 2. Defects, in priority order

### 2.1 The success message asserts a check that does not exist — **fix this first**

```
Batch add complete: 4 edge(s) added, 0 skipped (missing src/dst)
```

The string names the exact failure mode it is not checking. A caller reading it concludes the
validation ran and found nothing wrong. That is strictly worse than silence: it manufactures
confidence, and it survives code review because it *looks* like diligence.

This is the cheapest fix in the document and the most valuable. Even with no validation added,
the message must not claim a skip count it did not compute.

**Rule: never emit a count you did not calculate.**

### 2.2 `add_edges` does not validate endpoints

Fail closed. An edge whose `src` or `dst` does not resolve to an existing node is rejected, not
stored.

### 2.3 Rejections must name the offenders, not count them

`"3 rejected"` forces the caller into a re-query to discover which. Return the offending names
and which side failed:

```jsonc
{
  "added": 1,
  "rejected": [
    {"index": 1, "src": "alpha",        "dst": "NO_SUCH_DST",  "reason": "dst not found"},
    {"index": 2, "src": "NO_SUCH_SRC",  "dst": "beta",         "reason": "src not found"},
    {"index": 3, "src": "NO_SUCH_SRC2", "dst": "NO_SUCH_DST2", "reason": "src not found, dst not found"}
  ]
}
```

Set the MCP `isError` flag when anything is rejected, so automated callers can branch without
parsing prose. Include `index` so the caller can map rejections back to its input array.

Decide and document whether a partially-valid batch is all-or-nothing or best-effort. Either is
defensible; silence is not. Given that meshes are written unattended, **all-or-nothing is the
safer default** — a partially-applied batch leaves the caller unsure what to retry.

### 2.4 Forward references need to be a deliberate, distinguishable state

There is a legitimate case for an edge preceding its node: batch pipelines that write edges and
nodes in separate passes. If that is to be supported, it must be **opt-in and visible**:

- `allow_forward_refs: true` on the call, defaulting to `false`
- edges admitted that way stored in a distinguishable state (`"pending"` / `"unresolved"`)
- a way to list and reconcile them

What must not persist is today's situation, where **a deliberate forward reference and a typo are
byte-identical in storage**. That is what makes the corruption undetectable after the fact.

### 2.5 `verify` reports PASS on a structurally broken graph

`verify` currently checks node payload hashes only, and is candid about its limits:

```
Status: PASS (nothing verifiable)
No node carries a re-derivable hash yet, so this run proves nothing about their contents.
```

But it returned `PASS` on a mesh where 75% of edges pointed at nothing, because it never looks at
edges at all. `verify` is where people go to ask "is this mesh sound?" — dangling-edge detection
is a single set-membership pass over `edges`, and belongs there.

Report dangling edges as a distinct, non-PASS category. Do not fold them into the content-hash
result; they are a different class of defect and a mesh can have one without the other.

### 2.6 `load` gives a cold reader no integrity signal

```
2 nodes, 4 edges, 0 modules
```

`load` is the first thing a fresh agent runs to orient itself. It should surface the problem:

```
2 nodes, 4 edges (3 dangling), 0 modules
```

An agent that reads "4 edges" has no reason to doubt them.

### 2.7 `verify` is not reachable from the CLI

`crux verify <path>` returns `Unknown command: verify`; it exists only over MCP. Anyone checking
mesh health from a shell or CI job cannot. Expose it.

### 2.8 `create` ignores `path`

Same family of bug — a parameter accepted and silently discarded:

```
crux action=create path=/tmp/scratch/edgetest/.crux.json name=edgetest kind=documentation
  -> Created crux 'edgetest' (documentation)
     File: <cwd>/.crux.json                                  <-- cwd, not the path given
```

The response even prints the path it used, which is the only reason it was noticed. In this case
it dropped a stray `.crux.json` into the root of an unrelated live project.

**To be clear about what this is not:** `create` does *not* clobber. Tested with a sentinel file
in place, it refuses correctly and names the consequence:

```
Error: Crux already exists at <cwd>/.crux.json. Overwriting discards all of its
nodes and edges; pass force=true to replace it.
```

That guard is exactly right. The problem is that **it guards the wrong file.** Because `path` is
ignored, the existence check runs against the working directory rather than the destination the
caller named. Two consequences follow:

- Passing `path` to a location that already holds a crux gives you a confusing "already exists"
  error about a file you never mentioned — or, if cwd is clean, silently creates the new crux in
  cwd while leaving your intended target untouched.
- The safety property everyone would assume — "`create` will not destroy the crux at the path I
  gave it" — holds only by accident, because it never writes there at all.

Either honour `path`, or reject the call when it is supplied and unsupported. Do not accept and
discard.

---

## 3. Suggested addition: a validate-only path

Callers currently have to pre-validate by reading `.crux.json` and doing set membership on node
names themselves. Make that a supported operation:

- `dry_run: true` on `add_edges`, returning exactly the rejection report it would produce, or
- a `validate` action that reports dangling edges, orphan nodes, and duplicate names

This also gives CI something to call.

---

## 4. Regression tests worth adding

1. `add_edges` with a missing `dst` → rejected, named in the response, **not** in `.crux.json`
2. `add_edges` with a missing `src` → same
3. `add_edges` with both missing → both sides named in one reason string
4. A partially-valid batch → asserts the documented all-or-nothing / best-effort behaviour
5. `verify` on a mesh with a hand-inserted dangling edge → **must not** return PASS
6. `load` on the same → dangling count present in the summary
7. `create` with an explicit `path` → file appears at that path, **not** in cwd
8. `create` with an explicit `path` whose target already exists, cwd clean → refuses; does not
   silently create in cwd (this is the case the current existence check misses)
9. **A message-content test**: assert the success string does not claim a skip count when no
   validation ran. Defect 2.1 is a string bug and only a string test will stop it recurring.

---

## 5. The through-line

Every defect above is one of two shapes:

- **input accepted and silently discarded** (2.2, 2.8)
- **a success signal emitted unconditionally** (2.1, 2.5, 2.6)

Together they are the worst combination for a knowledge graph that agents populate unattended and
later trust as ground truth: the corruption is invisible when written, invisible when verified,
and invisible in the summary the next agent reads. The mesh does not degrade loudly — it degrades
into confident fiction.

The reporting project's own working notes had already recorded this as a known hazard
(`gotcha-mesh-writes-report-success-while-discarding-your-input`) and the team still hit it three
more times in one session, because a documented workaround is not a fix. Prefer failing closed and
reporting precisely; a caller can always be given an explicit escape hatch, but it cannot recover
data it never knew was dropped.
