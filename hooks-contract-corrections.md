# Hooks Contract — Correction Instructions

The hooks contract you produced contains many incorrect element IDs, a few wrong class names, a wrong CSS custom property name, and several structural errors. This document lists every correction needed. Please apply all of them to the contract before it is used as a hand-off document.

The source files you should treat as authoritative are `helm-ui/index.html`, `helm-ui/helm.js`, `helm-ui/board.js`, and `helm-ui/graph.js`.

---

## 1. ID corrections — §1.1 App shell

Replace every incorrect ID in the table in §1.1 with the actual ID from the source:

| Replace this | With this |
|---|---|
| `refresh-btn` | `btn-refresh` |
| `crux-search` | `search-input` |
| `node-search` | `nf-query` |
| `kind-filter` | `nf-kind` |
| `status-filter` | `nf-status` |
| `tag-filter` | `nf-tag` |
| `sort-select` | `nf-sort` |
| `clear-filters` | `btn-nf-clear` |
| `font-smaller` | `btn-font-dec` |
| `font-larger` | `btn-font-inc` |
| `view-tabs` | `view-switcher` |

Also correct the row for the status/meta display element:
- Remove the row for `crux-meta`. The element that holds header status text is `#status-bar`. Its content is set via `statusBar.textContent`, not innerHTML. The format `<crux> · N nodes · M edges` is correct, but the ID is `status-bar`, not `crux-meta`.

Also correct the `view-tabs` / `view-switcher` description. JS does **not** iterate `querySelectorAll('#view-switcher > *')` or `children`. It uses `document.querySelectorAll('.view-btn')` to find all tab buttons regardless of container. The structural invariant in §6 that says "direct children must be the tab buttons" is wrong for the same reason — what matters is that each button has class `view-btn` and the correct `data-view` attribute, not its parent/child relationship.

Also add a new row to the §1.1 table for the node filter bar, which is hidden until a crux loads:

| ID | Element | Behavior |
|---|---|---|
| 🔒 `node-filter-bar` | `<div>` wrapping all four filter controls | Hidden (`style.display='none'`) until a crux is selected; revealed as `display:'flex'` after load. Must remain a single addressable element. |

---

## 2. ID corrections — §1.3 Inspector

The inspector fields described in this section contain multiple IDs that do not exist and several that describe the wrong element type. Apply the following corrections:

### Remove these rows — the elements don't exist as editable inputs
- `insp-name` — Name is rendered as a read-only `<div class="value">`. There is no input bound to it.
- `insp-kind` — Kind is rendered read-only. There is no input or select.
- `insp-module` — Module is rendered read-only. There is no input.
- `insp-security` — Classification is rendered read-only. There is no input.
- `insp-node-id` — Node ID is rendered read-only. There is no text node addressable by this ID.

### Correct these rows
- `insp-empty` → `inspector-empty`
- `insp-tags` → `insp-tags-wrap` (this is the container div; it holds `.kind-tag` chip spans plus an `<input id="insp-tag-add">` at the end)
- `insp-save` — This is **not an ID**. The save button is found via the class selector `.btn-save`. Update the row to reflect that.
- `insp-add-node` → `btn-add-node`
- `insp-add-edge` → `btn-add-edge`

### Add these missing rows
- `#inspector-body` — The actual write target. `helm.js` sets `inspectorBody.innerHTML` on every selection change. Must exist as a child of `#inspector` at all times.
- `#inspector-resizer` — A drag handle between the canvas and inspector. `mousedown` on it initiates a drag that sets the `--inspector-w` CSS custom property on `:root`. Must remain a sibling of `#inspector`.

---

## 3. ID corrections — §1.4 Action buttons

| Replace this | With this |
|---|---|
| `new-crux-btn` | `btn-new-crux` |
| `open-crux-btn` | `btn-open-crux` |
| `import-csv-btn` | `btn-import-csv` |
| `export-md-btn` | `btn-export-md` |

---

## 4. Structural correction — §2 `data-path`

Remove the `data-path` row entirely. Crux list items inside `#crux-list` do **not** have a `data-path` attribute. Click handling is wired via a closure at render time (`div.addEventListener('click', () => selectMember(m))`). There is no attribute-based dispatch.

What crux list items *do* have (add a new row for this):

| Attribute | On | Notes |
|---|---|---|
| 🔒 `data-view` | `.view-btn` buttons inside `#view-switcher` | Values: `graph` \| `board` \| `table` \| `timeline` \| `mcp`. Already listed — no change needed here. |

Also add:

| Attribute | On | Notes |
|---|---|---|
| 🔒 `data-tag` | `.tag-remove` buttons inside `#insp-tags-wrap` | Carries the tag string. Read by the click handler to identify which tag to remove. |
| 🔒 `data-mcp-tab` | `.mcp-tab` buttons inside `.mcp-tabs` | Values: `registered` \| `discovered` \| `external`. Read by the MCP tab-switching listener. |
| 🔒 `data-col` | `.tbl thead th` | Also used on table header cells (not just board), for sort-column identification. |

---

## 5. Class name correction — §3.1 crux list

The contract states `.selected` is toggled on `#crux-list` children. This is wrong. The active crux list item receives the class `.active`, not `.selected`. Update the `.active` row to read:

> `.active` — Toggled by `helm.js` on: the active view tab (`.view-btn`), the active crux list item (`.crux-item`), the active MCP tab (`.mcp-tab`), modal overlays when shown, and `#canvas-loader` when loading.

`.selected` is used only on `.board-card`, `.graph-node`, and `.graph-edge`.

---

## 6. Class name corrections — §3.4 Tag editor

| Replace this | With this |
|---|---|
| `.tag-chip` | `.kind-tag` |
| `<input class="tag-input">` | `<input id="insp-tag-add">` (no class; identified by ID) |

`.tag-remove` is correct — keep it.

Also correct the commit trigger description: tags are committed on **Enter or Tab**, not on Enter/blur.

---

## 7. CSS custom property correction — §4

| Replace this | With this |
|---|---|
| `--app-font-size` | `--ui-zoom` |

Add a second row for:

| Property | Set on | Read/written by | Notes |
|---|---|---|---|
| 🔒 `--inspector-w` | `:root` | Inspector resizer drag handler | Controls inspector panel width. Read as integer px on drag start; written on every drag move. |

---

## 8. Keyboard shortcuts correction — §5.2

The contract states "No global keyboard shortcuts found." This is incorrect. Replace that section with:

> Three keyboard shortcuts exist:
> - 🔒 **Cmd/Ctrl+K** — Opens the command palette (`#cmd-palette-overlay`). Handled via `document.addEventListener('keydown')`.
> - 🔒 **`/`** (forward-slash) — Focuses `#search-input` (sidebar crux filter), when focus is not already in a form field and the palette is not open.
> - 🔒 **F or R** (case-insensitive) — Fires `Graph.fitToView()` when the graph view is active and focus is not in a form field.
> - 🔒 **Escape** — Closes any open modal overlay or the command palette.
>
> The redesign may add new shortcuts but must not intercept these keystrokes when the described conditions are met.

---

## 9. API endpoint corrections — §7

Replace the listed endpoints with the actual ones:

| Replace this | With this |
|---|---|
| `GET /api/meshes` | `GET /api/known-meshes` (returns array of `{path, name}`) |
| *(missing)* | `GET /api/mesh` (returns the currently active mesh object) |
| `GET /api/meshes/<mesh>/cruxes` | Remove — there is no such endpoint |
| `GET /api/cruxes/<path>` | `GET /api/crux?path=<url-encoded-path>` |
| `POST /api/cruxes/<path>/nodes/<id>` | `POST /api/node/update` with JSON body `{crux_path, node_id, …fields}` |
| `POST /api/cruxes` (new crux) | `POST /api/crux/create` with body `{name, kind, source_path?}` |
| *(open crux)* | `POST /api/crux/join` with body `{path}` |
| *(import CSV)* | `POST /api/crux/import-csv` |
| *(mesh switch)* | `POST /api/switch-mesh` with body `{path}` |
| *(new mesh)* | `POST /api/create-mesh` with body `{name, path}` |
| *(add node)* | `POST /api/node/add` with body `{crux_path, name, kind, summary, tags}` |
| *(add edge)* | `POST /api/edge/add` with body `{crux_path, src, dst, kind}` |

Also correct the localStorage claim. Replace "Not used" with:

> Used. Two keys are written: `helm-zoom` (float, UI zoom level, read on init and written on each A−/A+ press) and `helm-update-dismissed-<version>` (flag set when the user dismisses the update banner for a given version).

---

## 10. Missing elements to add to the contract

The following elements exist in the real DOM and have JS-bound behavior. Add coverage for them so the redesign knows they must be preserved.

### New section: Command palette

Add a new sub-section (or rows in §1) for:

| ID | Element | Behavior |
|---|---|---|
| 🔒 `cmd-palette-overlay` | Full-screen overlay `<div>` | Shown/hidden by toggling `.active` class. Click on the overlay background closes it. |
| 🔒 `cmd-input` | `<input type="text">` inside the palette | Input events trigger debounced cross-crux node search. |
| 🔒 `cmd-results` | Container `<div>` | Written via innerHTML with result rows. |

Structural classes used inside the palette (add to §3.2):
- 🔒 `.cmd-result-row` — Each result item; gets `.cmd-selected` on keyboard/mouse focus; has `data-idx` attribute.
- 🔒 `.cmd-selected` — Toggled on the currently highlighted row.
- 🔒 `.cmd-group-label`, `.cmd-empty`, `.cmd-res-name`, `.cmd-res-kind`, `.cmd-res-meta` — Written by JS; only `cmd-result-row` and `cmd-selected` are queried back.

### Crux list item structure

Add a note that each crux list item rendered into `#crux-list` has:
- Class `crux-item kind-<crux_kind>` (e.g., `crux-item kind-codebase`).
- The active item has `.active` added.
- Child elements with classes `.crux-name`, `.crux-kind`, `.crux-status` (written by `renderCruxList`).

### Canvas shell elements

Add rows for:

| ID | Behavior |
|---|---|
| 🔒 `canvas` | Outer canvas wrapper. Not queried by JS after init, but is the layout parent of all five view containers. |
| 🔒 `canvas-empty` | Shown when no crux is selected (`style.display=''`); hidden when loading begins. |
| 🔒 `canvas-loader` | Spinner overlay. JS toggles `.active` class to show/hide it. |

### Modal overlays

The contract omits all modal overlays. These are shown/hidden by toggling `.active` on the overlay `<div>` (not `style.display`). Add a note that the redesign must preserve this pattern, and list the overlay IDs that JS addresses:

`modal-overlay`, `modal-new-mesh-overlay`, `modal-import-csv-overlay`, `modal-mcp-overlay`, `modal-open-crux-overlay`, `cmd-palette-overlay`

Each modal overlay also listens for a click on the backdrop (when `e.target === overlayEl`) to close itself.

### Inspector resizer

Already covered in the correction to §1.3 above. Ensure it appears in the final contract.

### Graph controls

Add rows for:

| ID | Behavior |
|---|---|
| 🔒 `btn-fit-view` | Click calls `Graph.fitToView()`. Lives inside `#graph-container`. |
| 🔒 `btn-reset-view` | Also calls `Graph.fitToView()`. Same container. |

These must remain inside or adjacent to `#graph-container` so they're visible only when the graph view is active.

### Update banner

Add a note:

> The update-check banner is injected dynamically into `document.body` as a `<div class="update-banner">` when a newer version is detected. It contains an `<a class="update-banner-dl">` (download link) and a `<button class="update-banner-dismiss">`. CSS must include global rules for these classes since the element is not in the static HTML.

---

## 11. View container visibility correction — §1.2 and §6

The contract says all five containers are toggled via `style.display`. This is only fully true for `#graph-container` and `#mcp-container`. The other three use **`.active` class** toggling, not `style.display`:

- `#board-container` — shown/hidden via `classList.add/remove('active')`
- `#table-container` — same
- `#timeline-container` — same

Update §1.2 to reflect this and ensure the CSS for those three containers hides them when `.active` is absent (e.g., `display: none` by default, `display: block/flex` when `.active`).
