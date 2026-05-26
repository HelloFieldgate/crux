// graph.js — Force-directed SVG knowledge graph renderer
// Self-contained: no deps. Uses Velocity Verlet integration.

const Graph = (() => {
  // ── Configuration ──────────────────────────────────────────────────────────
  const CFG = {
    nodeRadius: 14,
    charge: 900,           // repulsion strength (positive = repulsion)
    linkDistance: 120,     // edge spring rest length
    linkStrength: 0.25,
    gravity: 0.04,
    velocityDecay: 0.82,   // fraction of velocity kept each step
    maxNodes: 600,
    ticksPerFrame: 3,
    alphaDecay: 0.018,     // per-frame cooling rate; sim stops when alpha < 0.001
    alphaMin: 0.001,
  };

  const IDLE_AMP_PX    = 3.5;
  const IDLE_PERIOD_MS = 7000;

  // Node colour by kind
  const KIND_COLOR = {
    'function':    '#5b7cf7',
    'process':     '#818cf8',
    'struct':      '#4ade80',
    'enum':        '#86efac',
    'module':      '#fb923c',
    'class':       '#fbbf24',
    'interface':   '#fde68a',
    'trait':       '#f87171',
    'constant':    '#94a3b8',
    'macro':       '#c084fc',
    'test':        '#67e8f9',
    'document':    '#a78bfa',
    'section':     '#c4b5fd',
    'record':      '#2dd4bf',
    'field':       '#5eead4',
    'table':       '#99f6e4',
    'person':      '#fca5a5',
    'policy':      '#f87171',
    'concept':     '#e2e4ed',
    'preference':  '#7c82a0',
    'default':     '#374151',
  };

  function kindColor(kind) {
    return KIND_COLOR[kind] || KIND_COLOR['default'];
  }

  // Edge stroke class by kind
  function edgeClass(kind) {
    const map = {
      calls: 'calls', imports: 'imports', data_flow: 'data_flow',
      reads: 'data_flow', writes: 'data_flow', transforms: 'data_flow',
      belongs_to_domain: 'belongs_to_domain',
      relates_to: 'relates_to', contradicts: 'relates_to',
      mesh_link: 'mesh_link',
    };
    return map[kind] || 'relates_to';
  }

  function ensureNodeGradients() {
    if (defs.querySelector('#nodeGrad-default')) return;
    Object.entries(KIND_COLOR).forEach(([kind, hex]) => {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'radialGradient');
      g.setAttribute('id', `nodeGrad-${kind}`);
      g.setAttribute('cx', '35%'); g.setAttribute('cy', '32%'); g.setAttribute('r', '75%');
      const s1 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
      s1.setAttribute('offset', '0%');
      s1.setAttribute('stop-color', `color-mix(in oklab, ${hex} 70%, white)`);
      const s2 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
      s2.setAttribute('offset', '100%');
      s2.setAttribute('stop-color', `color-mix(in oklab, ${hex} 80%, black)`);
      g.append(s1, s2);
      defs.appendChild(g);
    });
  }

  // ── State ──────────────────────────────────────────────────────────────────
  let svg, nodeGroup, edgeGroup, defs;
  let nodes = [], links = [];
  let nodeById = new Map();
  let rafId = null;
  let running = false;
  let alpha = 1.0;
  let vx = [], vy = [];
  let viewX = 0, viewY = 0, viewScale = 1;
  let selectedId = null;
  let onSelectNode = null, onSelectEdge = null;
  let isDragging = false, dragNode = null;
  let panStartX, panStartY, panOriginX, panOriginY;

  // Pending-drag state — promotes to active only when threshold met
  let pendingDragNode = null;
  let dragDownX = 0, dragDownY = 0;
  let dragHoldTimer = null;
  let didDrag = false;
  const DRAG_PX   = 4;
  const DRAG_HOLD = 150;

  function commitDrag(nd) {
    if (didDrag) return;
    didDrag    = true;
    isDragging = true;
    dragNode   = nd;
    nd.pinned  = true;
    alpha = Math.max(alpha, 0.3);
    if (!running) start();
  }

  // Edge-draw (Alt+drag) state
  let isEdgeDraw    = false;
  let edgeSrcNode   = null;
  let edgeHoverNode = null;
  let draftLine     = null;
  let draftGroup    = null;
  let onEdgeDraft   = null;   // callback(srcId, dstId) set from helm.js

  // ── Initialise SVG container ───────────────────────────────────────────────
  function init(container, onNode, onEdge, onEdgeDraftCb) {
    onSelectNode  = onNode;
    onSelectEdge  = onEdge;
    onEdgeDraft   = onEdgeDraftCb || null;

    container.innerHTML = '';

    svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '100%');
    container.appendChild(svg);

    // Arrow marker
    defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    const marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
    marker.setAttribute('id', 'arrow');
    marker.setAttribute('markerWidth', '8');
    marker.setAttribute('markerHeight', '8');
    marker.setAttribute('refX', '7');
    marker.setAttribute('refY', '3');
    marker.setAttribute('orient', 'auto');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M0,0 L0,6 L8,3 z');
    path.setAttribute('fill', '#4b5563');
    marker.appendChild(path);
    defs.appendChild(marker);
    svg.appendChild(defs);

    // Groups (edges behind nodes)
    edgeGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    nodeGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    svg.appendChild(edgeGroup);
    svg.appendChild(nodeGroup);

    // Draft edge overlay (on top of everything)
    draftGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    svg.appendChild(draftGroup);

    // Pan (only when not edge-drawing)
    svg.addEventListener('mousedown', e => {
      if (isEdgeDraw) return;
      if (e.target === svg || e.target === edgeGroup || e.target === nodeGroup) {
        isDragging  = true;
        dragNode    = null;
        panStartX   = e.clientX;
        panStartY   = e.clientY;
        panOriginX  = viewX;
        panOriginY  = viewY;
      }
    });
    svg.addEventListener('mousemove', e => {
      if (isEdgeDraw) {
        if (draftLine) {
          const pt = svgPoint(e);
          draftLine.setAttribute('x2', pt.x);
          draftLine.setAttribute('y2', pt.y);
        }
        return;
      }
      // Promote pending-drag to active if movement threshold exceeded
      if (pendingDragNode && !didDrag) {
        const dx = e.clientX - dragDownX;
        const dy = e.clientY - dragDownY;
        if (dx*dx + dy*dy > DRAG_PX * DRAG_PX) commitDrag(pendingDragNode);
      }
      if (!isDragging) return;
      if (dragNode) {
        const pt = svgPoint(e);
        dragNode.x = pt.x;
        dragNode.y = pt.y;
        dragNode.pinned = true;
        vx[dragNode._idx] = 0;
        vy[dragNode._idx] = 0;
      } else {
        viewX = panOriginX + (e.clientX - panStartX) / viewScale;
        viewY = panOriginY + (e.clientY - panStartY) / viewScale;
        applyTransform();
      }
    });

    function cancelEdgeDraw() {
      isEdgeDraw    = false;
      edgeSrcNode   = null;
      edgeHoverNode = null;
      draftGroup.innerHTML = '';
      draftLine     = null;
      svg.style.cursor = '';
    }

    svg.addEventListener('mouseup', e => {
      if (isEdgeDraw) {
        const srcId = edgeSrcNode ? edgeSrcNode.id : null;
        const dstId = edgeHoverNode && edgeHoverNode !== edgeSrcNode ? edgeHoverNode.id : null;
        cancelEdgeDraw();
        if (srcId && dstId && onEdgeDraft) onEdgeDraft(srcId, dstId);
        return;
      }
      clearTimeout(dragHoldTimer);
      pendingDragNode = null;
      isDragging = false;
      dragNode   = null;
      // didDrag left true until next mousedown so the click handler (fires after mouseup) sees it
    });
    svg.addEventListener('mouseleave', () => {
      if (isEdgeDraw) { cancelEdgeDraw(); return; }
      clearTimeout(dragHoldTimer);
      pendingDragNode = null;
      isDragging = false;
      dragNode   = null;
    });

    // Zoom
    svg.addEventListener('wheel', e => {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.1 : 0.9;
      const rect = svg.getBoundingClientRect();
      const mx = (e.clientX - rect.left) / viewScale - viewX;
      const my = (e.clientY - rect.top) / viewScale - viewY;
      viewScale = Math.min(4, Math.max(0.1, viewScale * factor));
      viewX = (e.clientX - rect.left) / viewScale - mx;
      viewY = (e.clientY - rect.top) / viewScale - my;
      applyTransform();
    }, { passive: false });
    ensureNodeGradients();
  }

  function applyTransform() {
    if (nodes.length) {
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      for (const n of nodes) {
        if (n.x < minX) minX = n.x; if (n.y < minY) minY = n.y;
        if (n.x > maxX) maxX = n.x; if (n.y > maxY) maxY = n.y;
      }
      const rect = svg.getBoundingClientRect();
      const margin = 60;
      const sMinX = (minX + viewX) * viewScale;
      const sMaxX = (maxX + viewX) * viewScale;
      const sMinY = (minY + viewY) * viewScale;
      const sMaxY = (maxY + viewY) * viewScale;
      if (sMaxX < margin)                  viewX += (margin - sMaxX) / viewScale;
      if (sMinX > rect.width  - margin)    viewX -= (sMinX - (rect.width  - margin)) / viewScale;
      if (sMaxY < margin)                  viewY += (margin - sMaxY) / viewScale;
      if (sMinY > rect.height - margin)    viewY -= (sMinY - (rect.height - margin)) / viewScale;
    }
    nodeGroup.setAttribute ('transform', `translate(${viewX},${viewY}) scale(${viewScale})`);
    edgeGroup.setAttribute ('transform', `translate(${viewX},${viewY}) scale(${viewScale})`);
    draftGroup.setAttribute('transform', `translate(${viewX},${viewY}) scale(${viewScale})`);
  }

  function svgPoint(e) {
    const rect = svg.getBoundingClientRect();
    return {
      x: (e.clientX - rect.left) / viewScale - viewX,
      y: (e.clientY - rect.top) / viewScale - viewY,
    };
  }

  // ── Load data ──────────────────────────────────────────────────────────────
  function load(cruxData, mesh) {
    stop();
    nodes = [];
    links = [];
    nodeById.clear();
    nodeGroup.innerHTML = '';
    edgeGroup.innerHTML = '';
    selectedId = null;

    const rawNodes = (cruxData.nodes || []).filter(n => !n.deleted_at);
    // Cap at maxNodes
    const subset = rawNodes.slice(0, CFG.maxNodes);

    const rect = svg.getBoundingClientRect();
    const cx = (rect.width  / 2) / viewScale - viewX;
    const cy = (rect.height / 2) / viewScale - viewY;

    subset.forEach((n, i) => {
      const angle = (i / Math.max(subset.length, 1)) * Math.PI * 2;
      const r = Math.min(200, 20 + subset.length * 2.5);
      nodes.push({
        _idx: i,
        id: n.node_id,
        name: n.name,
        kind: n.kind,
        summary: n.summary,
        tags: n.tags || [],
        properties: n.properties || [],
        planning: n.planning || {},
        security: n.security || {},
        module: n.module || '',
        x: cx + Math.cos(angle) * r,
        y: cy + Math.sin(angle) * r,
        pinned: false,
        raw: n,
        phase: Math.random() * Math.PI * 2,
        freqJitter: 0.85 + Math.random() * 0.3,
        _drawX: 0,
        _drawY: 0,
      });
      nodeById.set(n.node_id, nodes[i]);
    });

    // Peer crux name lookup from the mesh manifest
    const peerNameById = {};
    ((mesh && mesh.members) || []).forEach(m => { peerNameById[m.crux_id] = m.crux_name; });
    const currentCruxId = cruxData.crux_id || '';

    // Ghost nodes for outgoing cross-crux (mesh_link) edges, deduped by peer target
    const ghostByKey = new Map();

    (cruxData.edges || []).forEach((e, i) => {
      let src = nodeById.get(e.src) || findNodeByName(e.src);
      let dst = nodeById.get(e.dst) || findNodeByName(e.dst);

      if (src && !dst && (e.cross_crux || e.kind === 'mesh_link')) {
        const parsed = parseMeshLinkDst(e.dst);
        if (parsed && parsed.peerCruxId !== currentCruxId) {
          const key = `${parsed.peerCruxId}::${parsed.peerNodeName}`;
          if (!ghostByKey.has(key)) {
            const ghost = {
              _idx: nodes.length,
              id: `__external::${parsed.peerCruxId}::${parsed.peerNodeName}`,
              name: parsed.peerNodeName,
              kind: 'mesh_link',
              summary: '', tags: [], properties: [], planning: {}, security: {}, module: '',
              x: cx, y: cy,
              pinned: false,
              raw: { peer_crux_id: parsed.peerCruxId, peer_node_name: parsed.peerNodeName, edge: e },
              phase: Math.random() * Math.PI * 2,
              freqJitter: 0.85 + Math.random() * 0.3,
              _drawX: 0, _drawY: 0,
              isGhost: true,
              peerCruxId: parsed.peerCruxId,
              peerCruxName: peerNameById[parsed.peerCruxId] || (parsed.peerCruxId.slice(0, 15) + '…'),
              peerNodeName: parsed.peerNodeName,
            };
            nodes.push(ghost);
            ghostByKey.set(key, ghost);
          }
          dst = ghostByKey.get(key);
        } else if (!parsed) {
          console.warn('[crux] malformed mesh_link dst:', e.dst);
        }
      }

      if (src && dst) {
        links.push({ _idx: i, src, dst, kind: e.kind || 'relates_to', detail: e.detail || '', raw: e });
      }
    });

    vx = new Array(nodes.length).fill(0);
    vy = new Array(nodes.length).fill(0);
    alpha = 1.0;

    renderElements();
    start();
  }

  function findNodeByName(name) {
    return nodes.find(n => n.name === name) || null;
  }

  function parseMeshLinkDst(dst) {
    if (!dst || !dst.startsWith('sha256:')) return null;
    const rest = dst.slice('sha256:'.length);
    const sep = rest.indexOf(':');
    if (sep < 0) return null;
    return { peerCruxId: `sha256:${rest.slice(0, sep)}`, peerNodeName: rest.slice(sep + 1) };
  }

  // ── Render SVG elements ────────────────────────────────────────────────────
  function renderElements() {
    // Edges
    links.forEach(lk => {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.classList.add('graph-edge', edgeClass(lk.kind));
      path.addEventListener('click', e => { e.stopPropagation(); selectEdge(lk, path); });
      lk._el = path;
      edgeGroup.appendChild(path);
    });

    // Nodes
    nodes.forEach(nd => {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.classList.add('graph-node');
      if (nd.isGhost) g.classList.add('ghost');

      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('r', CFG.nodeRadius);
      if (nd.isGhost) {
        circle.setAttribute('fill', 'transparent');
        circle.setAttribute('stroke', 'var(--edge-mesh-link)');
      } else {
        const kindKey = KIND_COLOR[nd.kind] ? nd.kind : 'default';
        circle.setAttribute('fill', `url(#nodeGrad-${kindKey})`);
        circle.setAttribute('stroke', kindColor(nd.kind));
      }

      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      const shortName = nd.name.replace(/^@/, '').slice(0, 14);
      label.textContent = shortName;
      label.setAttribute('y', CFG.nodeRadius + 11);

      g.appendChild(circle);
      g.appendChild(label);

      if (nd.isGhost) {
        // Peer crux name badge shown above the ghost node
        const badge = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        badge.classList.add('peer-badge');
        badge.textContent = nd.peerCruxName;
        badge.setAttribute('y', -(CFG.nodeRadius + 4));
        g.appendChild(badge);

        // Ghosts are clickable (triggers drill-through in onNodeSelected), not draggable
        g.addEventListener('click', e => {
          e.stopPropagation();
          selectNode(nd, g);
        });
      } else {
        // Node drag / edge-draw
        g.addEventListener('mousedown', e => {
          e.stopPropagation();
          if (e.altKey && onEdgeDraft) {
            // Start edge-draw mode
            isEdgeDraw  = true;
            edgeSrcNode = nd;
            edgeHoverNode = null;
            svg.style.cursor = 'crosshair';
            const pt = svgPoint(e);
            draftLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            draftLine.setAttribute('stroke', '#5b7cf7');
            draftLine.setAttribute('stroke-width', '2');
            draftLine.setAttribute('stroke-dasharray', '6 3');
            draftLine.setAttribute('marker-end', 'url(#arrow)');
            draftLine.setAttribute('x1', nd.x); draftLine.setAttribute('y1', nd.y);
            draftLine.setAttribute('x2', pt.x); draftLine.setAttribute('y2', pt.y);
            draftGroup.appendChild(draftLine);
            return;
          }
          // Defer drag until threshold met (movement > 4px or hold > 150ms)
          pendingDragNode = nd;
          dragDownX = e.clientX;
          dragDownY = e.clientY;
          didDrag   = false;
          clearTimeout(dragHoldTimer);
          dragHoldTimer = setTimeout(() => {
            if (pendingDragNode === nd) commitDrag(nd);
          }, DRAG_HOLD);
        });
        g.addEventListener('mouseenter', () => {
          if (!isEdgeDraw || nd === edgeSrcNode) return;
          edgeHoverNode = nd;
          circle.setAttribute('stroke-width', '3.5');
          circle.setAttribute('stroke', '#fff');
        });
        g.addEventListener('mouseleave', () => {
          if (!isEdgeDraw || edgeHoverNode !== nd) return;
          edgeHoverNode = null;
          circle.setAttribute('stroke-width', '1.5');
          circle.setAttribute('stroke', kindColor(nd.kind));
        });
        g.addEventListener('dblclick', e => {
          e.stopPropagation();
          nd.pinned = !nd.pinned;
          g.style.opacity = nd.pinned ? '0.7' : '1';
        });
        g.addEventListener('click', e => {
          e.stopPropagation();
          if (!didDrag) selectNode(nd, g);
        });
      }

      nd._el = g;
      nodeGroup.appendChild(g);
    });

    // Deselect on background click
    svg.addEventListener('click', () => {
      clearSelection();
      if (onSelectNode) onSelectNode(null);
    });
  }

  // ── Selection ──────────────────────────────────────────────────────────────
  function selectNode(nd, el) {
    clearSelection();
    el.classList.add('selected');
    selectedId = nd.id;
    if (onSelectNode) onSelectNode(nd);
  }

  function selectEdge(lk, el) {
    clearSelection();
    el.classList.add('selected');
    if (onSelectEdge) onSelectEdge(lk);
  }

  function clearSelection() {
    document.querySelectorAll('.graph-node.selected').forEach(e => e.classList.remove('selected'));
    document.querySelectorAll('.graph-edge.selected').forEach(e => e.classList.remove('selected'));
    selectedId = null;
  }

  function selectByName(name) {
    const nd = findNodeByName(name);
    if (nd && nd._el) selectNode(nd, nd._el);
  }

  // ── Simulation ─────────────────────────────────────────────────────────────
  function start() {
    if (running) return;
    running = true;
    tick();
  }

  function stop() {
    running = false;
    if (rafId) cancelAnimationFrame(rafId);
    rafId = null;
  }

  function tick() {
    if (!running) return;
    if (alpha > CFG.alphaMin) {
      alpha = Math.max(0, alpha - CFG.alphaDecay);
      for (let t = 0; t < CFG.ticksPerFrame; t++) step();
    }
    draw(performance.now());
    rafId = requestAnimationFrame(tick);
  }

  function step() {
    const n = nodes.length;
    const ax = new Array(n).fill(0);
    const ay = new Array(n).fill(0);

    // Gravity toward center of current view
    const rect = svg.getBoundingClientRect();
    const cx = (rect.width  / 2) / viewScale - viewX;
    const cy = (rect.height / 2) / viewScale - viewY;

    for (let i = 0; i < n; i++) {
      ax[i] += (cx - nodes[i].x) * CFG.gravity;
      ay[i] += (cy - nodes[i].y) * CFG.gravity;
    }

    // Charge repulsion (O(n²), fine up to ~500 nodes)
    // charge is positive; formula ax[i] -= dx*force pushes i away from j ✓
    const minDist2 = CFG.nodeRadius * CFG.nodeRadius * 4; // clamp at 2×radius
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const dx = nodes[j].x - nodes[i].x;
        const dy = nodes[j].y - nodes[i].y;
        const dist2 = Math.max(dx * dx + dy * dy, minDist2);
        const force = CFG.charge / dist2;
        ax[i] -= dx * force;
        ay[i] -= dy * force;
        ax[j] += dx * force;
        ay[j] += dy * force;
      }
    }

    // Spring attraction along edges
    for (const lk of links) {
      const i = lk.src._idx, j = lk.dst._idx;
      const dx = nodes[j].x - nodes[i].x;
      const dy = nodes[j].y - nodes[i].y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist - CFG.linkDistance) * CFG.linkStrength;
      ax[i] += (dx / dist) * force;
      ay[i] += (dy / dist) * force;
      ax[j] -= (dx / dist) * force;
      ay[j] -= (dy / dist) * force;
    }

    // Integrate — forces scaled by alpha so energy decays as simulation cools
    for (let i = 0; i < n; i++) {
      if (nodes[i].pinned) continue;
      vx[i] = (vx[i] + ax[i] * alpha) * CFG.velocityDecay;
      vy[i] = (vy[i] + ay[i] * alpha) * CFG.velocityDecay;
      nodes[i].x += vx[i];
      nodes[i].y += vy[i];
    }
  }

  function draw(t) {
    const omega = (Math.PI * 2) / IDLE_PERIOD_MS;
    nodes.forEach(nd => {
      if (!nd.pinned && nd !== dragNode) {
        const phase = nd.phase + (t || 0) * omega * nd.freqJitter;
        nd._drawX = nd.x + Math.sin(phase)        * IDLE_AMP_PX;
        nd._drawY = nd.y + Math.cos(phase * 1.13) * IDLE_AMP_PX;
      } else {
        nd._drawX = nd.x;
        nd._drawY = nd.y;
      }
      nd._el.setAttribute('transform', `translate(${nd._drawX},${nd._drawY})`);
    });
    links.forEach(lk => {
      const s = lk.src, d = lk.dst;
      const dx = d._drawX - s._drawX, dy = d._drawY - s._drawY;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const r = CFG.nodeRadius;
      const x1 = s._drawX + (dx / dist) * r;
      const y1 = s._drawY + (dy / dist) * r;
      const x2 = d._drawX - (dx / dist) * (r + 8);
      const y2 = d._drawY - (dy / dist) * (r + 8);
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
      const ex = -(dy / dist), ey = dx / dist;
      const stretch = (dist - CFG.linkDistance) * 0.08;
      const cpx = mx + ex * stretch, cpy = my + ey * stretch;
      lk._el.setAttribute('d', `M ${x1} ${y1} Q ${cpx} ${cpy} ${x2} ${y2}`);
    });
  }

  function fitToView() {
    if (!nodes.length) { viewX = viewY = 0; viewScale = 1; applyTransform(); return; }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach(n => {
      if (n.x < minX) minX = n.x; if (n.y < minY) minY = n.y;
      if (n.x > maxX) maxX = n.x; if (n.y > maxY) maxY = n.y;
    });
    const pad = 60;
    const bw = Math.max(maxX - minX, 1) + pad * 2;
    const bh = Math.max(maxY - minY, 1) + pad * 2;
    const rect = svg.getBoundingClientRect();
    viewScale = Math.min(4, Math.max(0.1, Math.min(rect.width / bw, rect.height / bh)));
    const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
    viewX = (rect.width  / 2) / viewScale - cx;
    viewY = (rect.height / 2) / viewScale - cy;
    applyTransform();
    alpha = Math.max(alpha, 0.3);
    if (!running) start();
  }

  // ── Reset — re-layout nodes in a fresh circle + re-frame camera ──────────
  function resetGraph() {
    if (!nodes.length) return;
    const rect = svg.getBoundingClientRect();
    const cx = rect.width  / 2 / viewScale - viewX;
    const cy = rect.height / 2 / viewScale - viewY;
    const n  = nodes.length;
    const r  = Math.min(200, 20 + n * 2.5);
    nodes.forEach((nd, i) => {
      const angle = (i / Math.max(n, 1)) * Math.PI * 2;
      nd.x = cx + Math.cos(angle) * r;
      nd.y = cy + Math.sin(angle) * r;
      nd.pinned = false;
    });
    vx.fill(0);
    vy.fill(0);
    alpha = 1.0;
    if (!running) start();
    fitToView();
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  return { init, load, stop, kindColor, fitToView, reset: resetGraph, selectByName };
})();
