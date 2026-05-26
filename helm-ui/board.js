// board.js — Kanban board and Table views for Helm
// Depends on graph.js being loaded first (uses Graph.kindColor).

const Board = (() => {
  // ── Board State ────────────────────────────────────────────────────────────
  let container, onSelect, saveCallback;
  let cruxData = null;
  let cruxPath = null;
  let groupBy = 'status';     // default: planning.status
  let selectedNodeId = null;

  // ── Table State ────────────────────────────────────────────────────────────
  let tableContainer = null;
  let tableOnSelect  = null;
  let tableData      = null;
  let tableSortCol   = 'name';
  let tableSortAsc   = true;
  let tableFilter    = '';
  let tableSelectedId = null;

  // ── Timeline State ─────────────────────────────────────────────────────────
  let timelineContainer = null;
  let timelineOnSelect  = null;
  let timelineData      = null;
  let timelineGroupBy   = 'kind';   // 'kind' | 'status'
  let timelineDateKey   = 'updated_at';
  let timelineSelectedId = null;
  let tlTooltipEl       = null;

  // ── Board Public API ───────────────────────────────────────────────────────
  function init(el, onNodeSelected, saveFn) {
    container = el;
    onSelect = onNodeSelected;
    saveCallback = saveFn;
  }

  function load(data, path) {
    cruxData = data;
    cruxPath = path;
    render();
  }

  function stop() {
    if (container) container.innerHTML = '';
    cruxData = null;
    cruxPath = null;
    selectedNodeId = null;
  }

  function setGroupBy(field) {
    groupBy = field;
    render();
  }

  // ── Table Public API ───────────────────────────────────────────────────────
  function initTable(el, onNodeSelected) {
    tableContainer = el;
    tableOnSelect  = onNodeSelected;
  }

  function loadTable(data) {
    tableData = data;
    renderTable();
  }

  // ── Board Rendering ────────────────────────────────────────────────────────
  function render() {
    container.innerHTML = '';
    if (!cruxData) return;

    const nodes = (cruxData.nodes || []).filter(n => !n.deleted_at);

    // Toolbar
    const toolbar = document.createElement('div');
    toolbar.className = 'board-toolbar';
    toolbar.innerHTML = `
      <label>Group by</label>
      <select class="board-groupby">
        <option value="status"${groupBy === 'status' ? ' selected' : ''}>Planning status</option>
        <option value="kind"${groupBy === 'kind' ? ' selected' : ''}>Kind</option>
        <option value="tags"${groupBy === 'tags' ? ' selected' : ''}>Tags</option>
      </select>`;
    toolbar.querySelector('.board-groupby').addEventListener('change', e => {
      groupBy = e.target.value;
      render();
    });
    container.appendChild(toolbar);

    if (nodes.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'board-empty';
      empty.textContent = 'No nodes in this crux';
      container.appendChild(empty);
      return;
    }

    // Compute columns
    const { columns, nodeToColumn } = computeColumns(nodes);

    // Columns container
    const colsEl = document.createElement('div');
    colsEl.className = 'board-columns';

    columns.forEach(colName => {
      const colNodes = nodes.filter(n => nodeToColumn(n) === colName);
      colsEl.appendChild(renderColumn(colName, colNodes));
    });

    container.appendChild(colsEl);
  }

  function computeColumns(nodes) {
    if (groupBy === 'status') {
      const KNOWN_ORDER = ['backlog', 'in-progress', 'done'];
      const statusSet = new Set();
      nodes.forEach(n => {
        const s = getNodeStatus(n);
        if (s) statusSet.add(s);
      });
      const known = KNOWN_ORDER.filter(s => statusSet.has(s));
      // Others alphabetically
      const others = Array.from(statusSet).filter(s => !KNOWN_ORDER.includes(s)).sort();
      others.forEach(s => known.push(s));
      const hasNone = nodes.some(n => !getNodeStatus(n));
      const columns = hasNone ? [...known, '(none)'] : known;
      const nodeToColumn = n => getNodeStatus(n) || '(none)';
      return { columns, nodeToColumn };
    }

    if (groupBy === 'kind') {
      const kindSet = new Set();
      nodes.forEach(n => kindSet.add(n.kind || 'unknown'));
      const columns = Array.from(kindSet).sort();
      const nodeToColumn = n => n.kind || 'unknown';
      return { columns, nodeToColumn };
    }

    // groupBy === 'tags'
    const tagSet = new Set();
    nodes.forEach(n => {
      if (n.tags && n.tags.length > 0) tagSet.add(n.tags[0]);
    });
    const tags = Array.from(tagSet).sort();
    const hasNoTag = nodes.some(n => !n.tags || n.tags.length === 0);
    const columns = hasNoTag ? [...tags, '(none)'] : tags;
    const nodeToColumn = n => (n.tags && n.tags.length > 0) ? n.tags[0] : '(none)';
    return { columns, nodeToColumn };
  }

  function getNodeStatus(n) {
    // Check planning.status first, then properties array
    if (n.planning && n.planning.status) return n.planning.status;
    if (n.properties && n.properties.length) {
      for (const p of n.properties) {
        if (typeof p === 'string' && p.startsWith('planning.status=')) {
          return p.slice('planning.status='.length).trim();
        }
      }
    }
    return null;
  }

  function renderColumn(colName, colNodes) {
    const col = document.createElement('div');
    col.className = 'board-column';
    col.dataset.col = colName;

    const header = document.createElement('div');
    header.className = 'board-column-header';
    header.innerHTML = `<span>${esc(colName)}</span><span class="board-column-count">${colNodes.length}</span>`;
    col.appendChild(header);

    const body = document.createElement('div');
    body.className = 'board-column-body';
    body.dataset.col = colName;

    colNodes.forEach(n => body.appendChild(renderCard(n)));

    // Drop zone events
    body.addEventListener('dragover', onDragOver);
    body.addEventListener('dragleave', onDragLeave);
    body.addEventListener('drop', e => onDrop(e, colName));

    col.appendChild(body);
    return col;
  }

  function renderCard(node) {
    const card = document.createElement('div');
    card.className = 'board-card';
    card.draggable = true;
    card.dataset.nodeId = node.node_id;
    if (node.node_id === selectedNodeId) card.classList.add('selected');

    const color = Graph.kindColor(node.kind);
    const kindGrad = `linear-gradient(180deg, color-mix(in oklab, ${color} 78%, white), color-mix(in oklab, ${color} 88%, black))`;
    const summary = node.summary ? node.summary.slice(0, 80) : '';

    card.innerHTML = `
      <div class="board-card-name">${esc(node.name)}</div>
      <span class="board-card-kind" style="background:${kindGrad}">${esc(node.kind)}</span>
      ${summary ? `<div class="board-card-summary">${esc(summary)}</div>` : ''}`;

    card.addEventListener('click', () => {
      container.querySelectorAll('.board-card.selected').forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      selectedNodeId = node.node_id;
      onSelect({ ...node, id: node.node_id });
    });

    card.addEventListener('dragstart', e => onDragStart(e, node));
    card.addEventListener('dragend', onDragEnd);

    return card;
  }

  // ── Drag-and-Drop ──────────────────────────────────────────────────────────
  let dragNodeId = null;
  let dragSourceCol = null;

  function onDragStart(e, node) {
    dragNodeId = node.node_id;
    dragSourceCol = nodeColumnName(node);
    e.dataTransfer.setData('text/plain', node.node_id);
    e.dataTransfer.effectAllowed = 'move';
    requestAnimationFrame(() => {
      const el = container.querySelector(`.board-card[data-node-id="${CSS.escape(dragNodeId)}"]`);
      if (el) el.classList.add('dragging');
    });
  }

  function onDragEnd() {
    container.querySelectorAll('.board-card.dragging').forEach(c => c.classList.remove('dragging'));
    container.querySelectorAll('.board-column-body.drag-over').forEach(b => b.classList.remove('drag-over'));
    dragNodeId = null;
    dragSourceCol = null;
  }

  function onDragOver(e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    e.currentTarget.classList.add('drag-over');
  }

  function onDragLeave(e) {
    if (!e.currentTarget.contains(e.relatedTarget)) {
      e.currentTarget.classList.remove('drag-over');
    }
  }

  async function onDrop(e, targetCol) {
    e.preventDefault();
    e.currentTarget.classList.remove('drag-over');

    const nodeId = e.dataTransfer.getData('text/plain') || dragNodeId;
    if (!nodeId || targetCol === dragSourceCol) return;

    const node = (cruxData.nodes || []).find(n => n.node_id === nodeId);
    if (!node) return;

    const updates = computeUpdates(node, targetCol);
    applyUpdates(node, updates);
    render();

    const ok = await saveCallback(cruxPath, nodeId, updates);
    if (!ok) {
      applyUpdates(node, reverseUpdates(node, updates));
      render();
    }
  }

  function nodeColumnName(node) {
    if (groupBy === 'status') return getNodeStatus(node) || '(none)';
    if (groupBy === 'kind')   return node.kind || 'unknown';
    return (node.tags && node.tags.length > 0) ? node.tags[0] : '(none)';
  }

  function computeUpdates(node, targetCol) {
    if (groupBy === 'tags') {
      const rest = (node.tags || []).slice(1);
      return { tags: targetCol === '(none)' ? rest : [targetCol, ...rest] };
    }
    if (groupBy === 'status') {
      return { status: targetCol === '(none)' ? '' : targetCol };
    }
    return { kind: targetCol };
  }

  function applyUpdates(node, updates) {
    if (updates.tags !== undefined) node.tags = updates.tags;
    if (updates.status !== undefined) {
      if (!node.planning) node.planning = {};
      node.planning.status = updates.status || null;
    }
    if (updates.kind !== undefined) node.kind = updates.kind;
  }

  function reverseUpdates() { return {}; }

  // ── Table Rendering ────────────────────────────────────────────────────────
  function renderTable() {
    if (!tableContainer) return;

    // If toolbar exists (view was already initialized), just refresh body.
    if (tableContainer.querySelector('.tbl-toolbar')) {
      renderTableBody();
      return;
    }

    tableContainer.innerHTML = '';

    // Toolbar with search input
    const toolbar = document.createElement('div');
    toolbar.className = 'tbl-toolbar';
    const searchEl = document.createElement('input');
    searchEl.type = 'text';
    searchEl.className = 'tbl-search';
    searchEl.placeholder = 'Filter by name or summary…';
    searchEl.value = tableFilter;
    let filterTimer = null;
    searchEl.addEventListener('input', () => {
      clearTimeout(filterTimer);
      filterTimer = setTimeout(() => {
        tableFilter = searchEl.value;
        renderTableBody();
      }, 150);
    });
    toolbar.appendChild(searchEl);
    tableContainer.appendChild(toolbar);

    // Scrollable body area
    const scrollEl = document.createElement('div');
    scrollEl.className = 'tbl-scroll';
    tableContainer.appendChild(scrollEl);

    renderTableBody();
  }

  function renderTableBody() {
    if (!tableContainer) return;
    const scrollEl = tableContainer.querySelector('.tbl-scroll');
    if (!scrollEl) return;

    if (!tableData) {
      scrollEl.innerHTML = '<div class="tbl-empty">No crux loaded.</div>';
      return;
    }

    const allNodes = (tableData.nodes || []).filter(n => !n.deleted_at);
    const q = tableFilter.trim().toLowerCase();
    const nodes = q
      ? allNodes.filter(n =>
          n.name.toLowerCase().includes(q) ||
          (n.summary || '').toLowerCase().includes(q))
      : allNodes;

    // Sort
    const sorted = [...nodes].sort((a, b) => {
      let va = '', vb = '';
      if (tableSortCol === 'name')    { va = a.name || '';    vb = b.name || ''; }
      if (tableSortCol === 'kind')    { va = a.kind || '';    vb = b.kind || ''; }
      if (tableSortCol === 'summary') { va = a.summary || ''; vb = b.summary || ''; }
      if (tableSortCol === 'tags')    { va = (a.tags || []).join(','); vb = (b.tags || []).join(','); }
      if (tableSortCol === 'created') { va = String(a.created_at || 0); vb = String(b.created_at || 0); }
      const cmp = va.localeCompare(vb);
      return tableSortAsc ? cmp : -cmp;
    });

    if (sorted.length === 0) {
      scrollEl.innerHTML = `<div class="tbl-empty">${q ? 'No nodes match your filter.' : 'No nodes in this crux.'}</div>`;
      return;
    }

    const cols = [
      { key: 'name',    label: 'Name' },
      { key: 'kind',    label: 'Kind' },
      { key: 'summary', label: 'Summary' },
      { key: 'tags',    label: 'Tags' },
      { key: 'created', label: 'Created' },
    ];

    let html = '<table class="tbl"><thead><tr>';
    cols.forEach(c => {
      let cls = '';
      if (tableSortCol === c.key) cls = tableSortAsc ? 'sort-asc' : 'sort-desc';
      html += `<th class="${cls}" data-col="${c.key}">${esc(c.label)}</th>`;
    });
    html += '</tr></thead><tbody>';

    sorted.forEach(n => {
      const summary = (n.summary || '').slice(0, 60);
      const tags    = (n.tags || []).join(', ');
      let created   = '';
      if (n.created_at) {
        created = new Date(n.created_at * 1000).toISOString().slice(0, 10);
      }
      const selCls = n.node_id === tableSelectedId ? ' class="tbl-selected"' : '';
      html += `<tr${selCls} data-node-id="${esc(n.node_id)}">
        <td class="tbl-name">${esc(n.name)}</td>
        <td class="tbl-kind">${esc(n.kind)}</td>
        <td class="tbl-summary">${esc(summary)}</td>
        <td class="tbl-tags">${esc(tags)}</td>
        <td class="tbl-created">${esc(created)}</td>
      </tr>`;
    });
    html += '</tbody></table>';
    scrollEl.innerHTML = html;

    // Header sort clicks
    scrollEl.querySelectorAll('.tbl thead th').forEach(th => {
      th.addEventListener('click', () => {
        const col = th.dataset.col;
        if (tableSortCol === col) tableSortAsc = !tableSortAsc;
        else { tableSortCol = col; tableSortAsc = true; }
        renderTableBody();
      });
    });

    // Row selection
    scrollEl.querySelectorAll('.tbl tbody tr').forEach(row => {
      row.addEventListener('click', () => {
        const nodeId = row.dataset.nodeId;
        const node   = (tableData.nodes || []).find(n => n.node_id === nodeId);
        if (!node) return;
        tableSelectedId = nodeId;
        scrollEl.querySelectorAll('.tbl tbody tr').forEach(r => r.classList.remove('tbl-selected'));
        row.classList.add('tbl-selected');
        if (tableOnSelect) tableOnSelect({ ...node, id: node.node_id });
      });
    });
  }

  // ── Timeline Public API ────────────────────────────────────────────────────
  function initTimeline(el, onNodeSelected) {
    timelineContainer = el;
    timelineOnSelect  = onNodeSelected;
    // Shared tooltip element — created once, lives on body
    if (!tlTooltipEl) {
      tlTooltipEl = document.createElement('div');
      tlTooltipEl.className = 'tl-tooltip';
      tlTooltipEl.style.display = 'none';
      document.body.appendChild(tlTooltipEl);
    }
  }

  function loadTimeline(data) {
    timelineData = data;
    timelineGroupBy = 'kind';
    timelineDateKey = 'updated_at';
    timelineSelectedId = null;
    renderTimeline();
  }

  function renderTimeline() {
    if (!timelineContainer) return;
    timelineContainer.innerHTML = '';

    if (!timelineData) {
      const empty = document.createElement('div');
      empty.className = 'tl-empty';
      empty.textContent = 'No crux loaded.';
      timelineContainer.appendChild(empty);
      return;
    }

    const allNodes = (timelineData.nodes || []).filter(n => !n.deleted_at);

    // --- Collect all date property keys that appear date-shaped ---
    const dateKeySet = new Set();
    const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
    allNodes.forEach(n => {
      (n.properties || []).forEach(p => {
        if (typeof p === 'string') {
          const eq = p.indexOf('=');
          if (eq > 0) {
            const val = p.slice(eq + 1).trim();
            if (DATE_RE.test(val)) dateKeySet.add(p.slice(0, eq).trim());
          }
        }
      });
    });
    const dateKeys = Array.from(dateKeySet).sort();

    // Find the most common date property key
    let defaultKey = 'updated_at';
    if (dateKeys.length > 0) {
      const counts = {};
      allNodes.forEach(n => {
        (n.properties || []).forEach(p => {
          if (typeof p === 'string') {
            const eq = p.indexOf('=');
            if (eq > 0) {
              const k = p.slice(0, eq).trim();
              if (dateKeySet.has(k)) counts[k] = (counts[k] || 0) + 1;
            }
          }
        });
      });
      let best = 0;
      for (const k of dateKeys) {
        if ((counts[k] || 0) > best) { best = counts[k]; defaultKey = k; }
      }
    }

    // Respect current selection if it's still valid
    if (timelineDateKey !== 'updated_at' && !dateKeySet.has(timelineDateKey)) {
      timelineDateKey = defaultKey;
    } else if (timelineDateKey === 'updated_at' && dateKeys.length > 0) {
      // Keep 'updated_at' as selected if user hasn't changed it
    }

    // --- Toolbar ---
    const toolbar = document.createElement('div');
    toolbar.className = 'tl-toolbar';

    const dateKeyOpts = `<option value="updated_at"${timelineDateKey === 'updated_at' ? ' selected' : ''}>Last updated</option>` +
      dateKeys.map(k => `<option value="${esc(k)}"${timelineDateKey === k ? ' selected' : ''}>${esc(k)}</option>`).join('');

    toolbar.innerHTML = `
      <label>Date</label>
      <select class="tl-date-key">${dateKeyOpts}</select>
      <label style="margin-left:14px">Group by</label>
      <select class="tl-groupby">
        <option value="kind"${timelineGroupBy === 'kind' ? ' selected' : ''}>Kind</option>
        <option value="status"${timelineGroupBy === 'status' ? ' selected' : ''}>Status</option>
      </select>`;
    toolbar.querySelector('.tl-date-key').addEventListener('change', e => {
      timelineDateKey = e.target.value;
      renderTimeline();
    });
    toolbar.querySelector('.tl-groupby').addEventListener('change', e => {
      timelineGroupBy = e.target.value;
      renderTimeline();
    });
    timelineContainer.appendChild(toolbar);

    // --- Resolve dates for each node ---
    function resolveDate(node) {
      if (timelineDateKey !== 'updated_at') {
        for (const p of (node.properties || [])) {
          if (typeof p === 'string') {
            const eq = p.indexOf('=');
            if (eq > 0 && p.slice(0, eq).trim() === timelineDateKey) {
              const val = p.slice(eq + 1).trim();
              if (DATE_RE.test(val)) return new Date(val + 'T00:00:00Z');
            }
          }
        }
      }
      // Fallback: updated_at
      if (node.planning && node.planning.updated_at) {
        return new Date(node.planning.updated_at * 1000);
      }
      return null;
    }

    const dated   = [];
    const undated = [];
    allNodes.forEach(n => {
      const d = resolveDate(n);
      if (d) dated.push({ node: n, date: d });
      else undated.push(n);
    });

    // --- Body ---
    const body = document.createElement('div');
    body.className = 'tl-body';
    timelineContainer.appendChild(body);

    if (dated.length === 0) {
      // All undated — show message + undated strip
      const msg = document.createElement('div');
      msg.className = 'tl-empty';
      msg.textContent = 'No date properties found — edit nodes to add date=YYYY-MM-DD in Properties.';
      body.appendChild(msg);
      if (undated.length) body.appendChild(renderUndatedStrip(undated));
      return;
    }

    // --- Time range ---
    const minMs = Math.min(...dated.map(d => d.date.getTime())) - 14 * 86400 * 1000;
    const maxMs = Math.max(...dated.map(d => d.date.getTime())) + 14 * 86400 * 1000;
    const rangeMs = maxMs - minMs || 1;

    function xPct(date) {
      return Math.max(0, Math.min(100, (date.getTime() - minMs) / rangeMs * 100));
    }

    // --- Group lanes ---
    const laneMap = new Map();
    dated.forEach(({ node, date }) => {
      const key = timelineGroupBy === 'status'
        ? (node.planning && node.planning.status) || '(none)'
        : (node.kind || 'unknown');
      if (!laneMap.has(key)) laneMap.set(key, []);
      laneMap.get(key).push({ node, date });
    });

    // Sort lane names
    const laneNames = Array.from(laneMap.keys()).sort();

    // --- Compute month ticks ---
    const monthTicks = [];
    const start = new Date(minMs);
    const cur = new Date(start.getUTCFullYear(), start.getUTCMonth(), 1);
    while (cur.getTime() <= maxMs) {
      monthTicks.push({
        date: new Date(cur),
        label: cur.toLocaleString('default', { month: 'short', year: '2-digit', timeZone: 'UTC' }),
        pct: xPct(cur),
      });
      cur.setUTCMonth(cur.getUTCMonth() + 1);
    }

    // --- Lanes ---
    const lanesEl = document.createElement('div');
    lanesEl.className = 'tl-lanes';

    laneNames.forEach(laneName => {
      const items = laneMap.get(laneName);
      const lane = document.createElement('div');
      lane.className = 'tl-lane';

      const label = document.createElement('div');
      label.className = 'tl-lane-label';
      label.title = laneName;
      label.textContent = laneName;
      lane.appendChild(label);

      const track = document.createElement('div');
      track.className = 'tl-lane-track';

      // Month grid lines inside this track
      monthTicks.forEach(tick => {
        const line = document.createElement('div');
        line.className = 'tl-month-line';
        line.style.left = tick.pct + '%';
        track.appendChild(line);
      });

      items.forEach(({ node, date }) => {
        const chip = document.createElement('div');
        chip.className = 'tl-chip';
        if (node.node_id === timelineSelectedId) chip.classList.add('tl-selected');
        chip.style.left = xPct(date) + '%';
        const tc = Graph.kindColor(node.kind);
        chip.style.background = `radial-gradient(circle at 35% 32%, color-mix(in oklab, ${tc} 70%, white), color-mix(in oklab, ${tc} 80%, black))`;

        chip.addEventListener('mouseenter', e => {
          const summary = (node.summary || '').slice(0, 60);
          const dateStr = date.toISOString().slice(0, 10);
          tlTooltipEl.innerHTML = `<strong>${esc(node.name)}</strong>${summary ? esc(summary) : ''}<div class="tl-tooltip-date">${esc(dateStr)}</div>`;
          tlTooltipEl.style.display = 'block';
          tlTooltipEl.style.left = (e.clientX + 14) + 'px';
          tlTooltipEl.style.top  = (e.clientY - 4) + 'px';
        });
        chip.addEventListener('mousemove', e => {
          tlTooltipEl.style.left = (e.clientX + 14) + 'px';
          tlTooltipEl.style.top  = (e.clientY - 4) + 'px';
        });
        chip.addEventListener('mouseleave', () => {
          tlTooltipEl.style.display = 'none';
        });
        chip.addEventListener('click', () => {
          timelineSelectedId = node.node_id;
          timelineContainer.querySelectorAll('.tl-chip').forEach(c => c.classList.remove('tl-selected'));
          timelineContainer.querySelectorAll('.tl-undated-chip').forEach(c => c.classList.remove('tl-selected'));
          chip.classList.add('tl-selected');
          if (timelineOnSelect) timelineOnSelect({ ...node, id: node.node_id });
        });

        track.appendChild(chip);
      });

      lane.appendChild(track);
      lanesEl.appendChild(lane);
    });

    body.appendChild(lanesEl);

    // --- X axis ---
    const axis = document.createElement('div');
    axis.className = 'tl-axis';
    monthTicks.forEach(tick => {
      const lbl = document.createElement('div');
      lbl.className = 'tl-month-tick';
      lbl.style.left = tick.pct + '%';
      lbl.textContent = tick.label;
      axis.appendChild(lbl);
    });
    body.appendChild(axis);

    // --- Undated strip ---
    if (undated.length) body.appendChild(renderUndatedStrip(undated));
  }

  function renderUndatedStrip(nodes) {
    const strip = document.createElement('div');
    strip.className = 'tl-undated-strip';
    nodes.forEach(node => {
      const chip = document.createElement('span');
      chip.className = 'tl-undated-chip';
      if (node.node_id === timelineSelectedId) chip.classList.add('tl-selected');
      const uc = Graph.kindColor(node.kind);
      chip.style.background = `linear-gradient(180deg, color-mix(in oklab, ${uc} 78%, white), color-mix(in oklab, ${uc} 88%, black))`;
      chip.textContent = node.name;
      chip.title = node.summary || '';
      chip.addEventListener('click', () => {
        timelineSelectedId = node.node_id;
        if (timelineContainer) {
          timelineContainer.querySelectorAll('.tl-chip').forEach(c => c.classList.remove('tl-selected'));
          timelineContainer.querySelectorAll('.tl-undated-chip').forEach(c => c.classList.remove('tl-selected'));
        }
        chip.classList.add('tl-selected');
        if (timelineOnSelect) timelineOnSelect({ ...node, id: node.node_id });
      });
      strip.appendChild(chip);
    });
    return strip;
  }

  // ── Utilities ──────────────────────────────────────────────────────────────
  function esc(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  return { init, load, stop, setGroupBy, initTable, loadTable, initTimeline, loadTimeline };
})();
