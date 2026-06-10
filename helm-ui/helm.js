// helm.js — Helm application logic
// Depends on graph.js being loaded first.

const Helm = (() => {
  // ── State ──────────────────────────────────────────────────────────────────
  let mesh = null;
  let activeMember = null;    // the selected MeshMember object
  let activeCrux = null;      // the loaded CruxDb object
  let filterText = '';
  let currentView = 'graph';  // 'graph' | 'board' | 'table' | 'timeline' | 'mcp'
  // CSV import wizard state
  let csvRawText = '';
  let csvHeaders = [];
  let csvRows = [];
  // UI zoom state (persisted in localStorage)
  let uiZoom = parseFloat(localStorage.getItem('helm-zoom') || '1');
  // Theme state: 'light' | 'dark' | 'auto'
  let uiTheme = localStorage.getItem('helm-theme') || 'auto';
  // Command palette state
  let cmdSelectedIdx = -1;
  let cmdSearchTimer = null;
  let cmdAllResults  = [];

  // ── DOM references ─────────────────────────────────────────────────────────
  const $ = id => document.getElementById(id);
  const statusBar        = $('status-bar');
  const cruxList         = $('crux-list');
  const searchInput      = $('search-input');
  const canvasEl         = $('canvas');
  const canvasEmpty      = $('canvas-empty');
  const canvasLoader     = $('canvas-loader');
  const inspectorBody    = $('inspector-body');
  const meshSelect       = $('mesh-select');
  const btnRefresh       = $('btn-refresh');
  // New crux modal
  const modalOverlay     = $('modal-overlay');
  const btnNewCrux       = $('btn-new-crux');
  const btnModalCancel   = $('btn-modal-cancel');
  const btnModalScan     = $('btn-modal-scan');
  const btnModalCreate   = $('btn-modal-create');
  const modalName        = $('modal-name');
  const modalKind        = $('modal-kind');
  const modalSource      = $('modal-source');
  const modalScanPreview = $('modal-scan-preview');
  const modalScanInfo    = $('modal-scan-info');
  const modalTemplate    = $('modal-template');
  const templatePreview  = $('template-preview');
  const modalAiDesc      = $('modal-ai-desc');
  const aiActions        = $('ai-actions');
  const btnAiGenerate    = $('btn-ai-generate');
  const btnAiCopy        = $('btn-ai-copy');
  const aiStatus         = $('ai-status');
  // Node filter bar
  const nodeFilterBar    = $('node-filter-bar');
  const nfQuery          = $('nf-query');
  const nfKind           = $('nf-kind');
  const nfStatus         = $('nf-status');
  const nfTag            = $('nf-tag');
  const nfSort           = $('nf-sort');
  const btnNfClear       = $('btn-nf-clear');
  // New mesh modal
  const modalNewMesh     = $('modal-new-mesh-overlay');
  const nmName           = $('nm-name');
  const nmPath           = $('nm-path');
  const nmError          = $('nm-error');
  const btnNmCancel      = $('btn-nm-cancel');
  const btnNmCreate      = $('btn-nm-create');
  // Font size controls
  const btnFontDec       = $('btn-font-dec');
  const btnFontInc       = $('btn-font-inc');
  const btnTheme         = $('btn-theme');
  // Open existing crux modal
  const btnOpenCrux      = $('btn-open-crux');
  const modalOpenOverlay = $('modal-open-crux-overlay');
  const openCruxPath     = $('open-crux-path');
  const openCruxError    = $('open-crux-error');
  const btnOpenCancel    = $('btn-open-cancel');
  const btnOpenConnect   = $('btn-open-connect');
  // Import CSV modal
  const btnImportCsv     = $('btn-import-csv');
  const btnExportMd      = $('btn-export-md');
  const modalCsvOverlay  = $('modal-import-csv-overlay');
  const csvFileInput     = $('csv-file-input');
  const csvPasteArea     = $('csv-paste-area');
  const csvStep1         = $('csv-step1');
  const csvStep2         = $('csv-step2');
  const csvStep1Error    = $('csv-step1-error');
  const csvColMapTable   = $('csv-col-map-table');
  const csvNodeKind      = $('csv-node-kind');
  const csvTargetCrux    = $('csv-target-crux');
  const csvNewNameField  = $('csv-new-name-field');
  const csvCruxName      = $('csv-crux-name');
  const csvPreviewTable  = $('csv-preview-table');
  const csvPreviewCount  = $('csv-preview-count');
  const csvImportStatus  = $('csv-import-status');
  const btnCsvCancel     = $('btn-csv-cancel');
  const btnCsvBack       = $('btn-csv-back');
  const btnCsvNext       = $('btn-csv-next');
  const btnCsvImport     = $('btn-csv-import');
  // Command palette
  const cmdPaletteOverlay = $('cmd-palette-overlay');
  const cmdInput          = $('cmd-input');
  const cmdResults        = $('cmd-results');
  // Graph controls
  const btnFitView        = $('btn-fit-view');
  const btnResetView      = $('btn-reset-view');

  // ── View switching ─────────────────────────────────────────────────────────
  function switchView(view) {
    currentView = view;
    document.querySelectorAll('.view-btn').forEach(b =>
      b.classList.toggle('active', b.dataset.view === view));
    const graphContainer    = $('graph-container');
    const boardContainer    = $('board-container');
    const tableContainer    = $('table-container');
    const timelineContainer = $('timeline-container');
    const mcpContainer      = $('mcp-container');
    const nodeFilterBar_    = $('node-filter-bar');
    if (view === 'mcp') {
      graphContainer.style.display = 'none';
      boardContainer.classList.remove('active');
      tableContainer.classList.remove('active');
      timelineContainer.classList.remove('active');
      mcpContainer.classList.add('active');
      if (nodeFilterBar_) nodeFilterBar_.style.display = 'none';
      Graph.stop();
      loadMcpServers();
    } else {
      mcpContainer.classList.remove('active');
      if (nodeFilterBar_) nodeFilterBar_.style.display = '';
      if (view === 'graph') {
        graphContainer.style.display = '';
        boardContainer.classList.remove('active');
        tableContainer.classList.remove('active');
        timelineContainer.classList.remove('active');
        if (activeCrux) applyNodeFilters();
      } else if (view === 'board') {
        graphContainer.style.display = 'none';
        boardContainer.classList.add('active');
        tableContainer.classList.remove('active');
        timelineContainer.classList.remove('active');
        Graph.stop();
        if (activeCrux && activeMember) applyNodeFilters();
      } else if (view === 'table') {
        graphContainer.style.display = 'none';
        boardContainer.classList.remove('active');
        tableContainer.classList.add('active');
        timelineContainer.classList.remove('active');
        Graph.stop();
        if (activeCrux) applyNodeFilters();
      } else if (view === 'timeline') {
        graphContainer.style.display = 'none';
        boardContainer.classList.remove('active');
        tableContainer.classList.remove('active');
        timelineContainer.classList.add('active');
        Graph.stop();
        if (activeCrux) applyNodeFilters();
      }
    }
  }

  // ── MCP Servers tab ────────────────────────────────────────────────────────
  async function loadMcpServers() {
    const wrap = $('mcp-table-wrap');
    wrap.innerHTML = '<div class="mcp-empty">Loading…</div>';
    const result = await api('GET', '/api/mcp/list');
    if (result.error) {
      wrap.innerHTML = `<div class="mcp-empty" style="color:var(--red)">${result.error}</div>`;
      return;
    }
    const servers = result.servers || [];
    if (servers.length === 0) {
      wrap.innerHTML = '<div class="mcp-empty">No MCP servers registered. Click "+ Register" to add one.</div>';
      return;
    }
    let html = `<table class="mcp-table">
      <thead><tr>
        <th>Alias</th><th>Transport</th><th>Clearance</th>
        <th>Allowed Tools</th><th>Rate Limit</th><th>Auth</th><th></th>
      </tr></thead><tbody>`;
    for (const s of servers) {
      const tBadge = s.transport === 'http' ? 'mcp-badge-http' : 'mcp-badge-stdio';
      const clLevel = { public: 'cl0', internal: 'cl1', confidential: 'cl2', restricted: 'cl3' }[s.required_clearance] || 'cl1';
      // OAuth auth status badge + buttons
      let authCell = '<span style="color:var(--text-dim);font-size:11px">—</span>';
      let authActions = '';
      if (s.auth === 'oauth2') {
        const statusClass = { authorized: 'mcp-badge-http', expired: 'mcp-badge-cl2', unauthorized: 'mcp-badge-cl3' }[s.auth_status] || 'mcp-badge-cl3';
        authCell = `<span class="mcp-badge ${statusClass}">${esc(s.auth_status || 'unauthorized')}</span>`;
        const btnLabel = s.auth_status === 'authorized' ? 'Re-authorize' : 'Authorize';
        authActions = `<button class="btn-authorize" onclick="Helm.oauthStart(${JSON.stringify(s.alias)})">${btnLabel}</button>`;
        if (s.auth_status === 'authorized' || s.auth_status === 'expired') {
          authActions += ` <button class="btn-revoke-token" onclick="Helm.oauthRevokeToken(${JSON.stringify(s.alias)})">Revoke Token</button>`;
        }
      }
      html += `<tr>
        <td><strong>${esc(s.alias)}</strong></td>
        <td><span class="mcp-badge ${tBadge}">${esc(s.transport)}</span></td>
        <td><span class="mcp-badge mcp-badge-${clLevel}">${esc(s.required_clearance || 'internal')}</span></td>
        <td>${esc(s.allowed_tools || '*')}</td>
        <td>${esc(s.rate_limit || '—')}</td>
        <td style="white-space:nowrap">${authCell} ${authActions}</td>
        <td><button class="btn-revoke" onclick="Helm.revokeMcp(${JSON.stringify(s.alias)})">Revoke</button></td>
      </tr>`;
    }
    html += '</tbody></table>';
    wrap.innerHTML = html;
  }

  async function revokeMcp(alias) {
    if (!confirm(`Revoke MCP server '${alias}'? This cannot be undone.`)) return;
    const result = await api('POST', '/api/mcp/revoke', { alias });
    if (result.error) { setStatus('Revoke failed: ' + result.error, true); return; }
    setStatus(`Revoked '${alias}'`);
    loadMcpServers();
  }

  // ── OAuth authorization management ─────────────────────────────────────────

  async function oauthStart(alias) {
    setStatus(`Starting OAuth authorization for '${alias}'…`);
    const result = await api('POST', '/api/mcp/oauth/start', { alias });
    if (result.error) { setStatus('OAuth start failed: ' + result.error, true); return; }
    const authUrl = result.auth_url;
    if (!authUrl) { setStatus('OAuth start failed: no auth_url returned', true); return; }
    // Open the authorization URL in a new tab; Helm will handle the redirect callback.
    window.open(authUrl, '_blank', 'noopener');
    setStatus(`Opened authorization URL for '${alias}' — complete in your browser, then refresh.`);
    // Poll for completion (up to 5 minutes, check every 3s)
    let polls = 0;
    const maxPolls = 100;
    const pollId = setInterval(async () => {
      polls++;
      if (polls > maxPolls) { clearInterval(pollId); return; }
      const listResult = await api('GET', '/api/mcp/list');
      if (listResult.error) return;
      const servers = listResult.servers || [];
      const srv = servers.find(s => s.alias === alias);
      if (srv && srv.auth_status === 'authorized') {
        clearInterval(pollId);
        setStatus(`'${alias}' authorized successfully.`);
        loadMcpServers();
      }
    }, 3000);
  }

  async function oauthRevokeToken(alias) {
    if (!confirm(`Revoke OAuth token for '${alias}'? The next call will require re-authorization.`)) return;
    const result = await api('POST', '/api/mcp/oauth/revoke', { alias });
    if (result.error) { setStatus('Token revoke failed: ' + result.error, true); return; }
    setStatus(`Token for '${alias}' revoked.`);
    loadMcpServers();
  }

  function openMcpRegisterModal() {
    $('mcp-alias').value = '';
    $('mcp-command').value = '';
    $('mcp-url').value = '';
    $('mcp-tools').value = '*';
    $('mcp-rate').value = '';
    $('mcp-reg-error').textContent = '';
    $('mcp-transport').value = 'stdio';
    $('mcp-command-field').style.display = '';
    $('mcp-url-field').style.display = 'none';
    $('modal-mcp-overlay').style.display = 'flex';
    $('mcp-alias').focus();
  }

  function closeMcpModal() {
    $('modal-mcp-overlay').style.display = 'none';
  }

  async function submitMcpRegister() {
    const alias     = $('mcp-alias').value.trim();
    const transport = $('mcp-transport').value;
    const command   = $('mcp-command').value.trim();
    const url       = $('mcp-url').value.trim();
    const clearance = $('mcp-clearance').value;
    const tools     = $('mcp-tools').value.trim();
    const rate      = $('mcp-rate').value.trim();
    if (!alias) { $('mcp-reg-error').textContent = 'Alias is required.'; return; }
    if (transport === 'stdio' && !command) { $('mcp-reg-error').textContent = 'Command is required for stdio transport.'; return; }
    if (transport === 'http'  && !url)     { $('mcp-reg-error').textContent = 'URL is required for http transport.'; return; }
    $('btn-mcp-submit').disabled = true;
    const result = await api('POST', '/api/mcp/register', {
      alias, transport, command, url,
      required_clearance: clearance,
      allowed_tools: tools,
      rate_limit: rate,
    });
    $('btn-mcp-submit').disabled = false;
    if (result.error) { $('mcp-reg-error').textContent = result.error; return; }
    closeMcpModal();
    setStatus(`Registered '${alias}'`);
    loadMcpServers();
  }

  // ── MCP Discovered sub-tab ────────────────────────────────────────────────
  let activeMcpTab = 'registered';

  function switchMcpTab(tab) {
    activeMcpTab = tab;
    document.querySelectorAll('.mcp-tab').forEach(b => {
      b.classList.toggle('active', b.dataset.mcpTab === tab);
    });
    $('mcp-table-wrap').classList.toggle('active',      tab === 'registered');
    $('mcp-discovered-wrap').classList.toggle('active', tab === 'discovered');
    $('mcp-external-wrap').classList.toggle('active',   tab === 'external');
    $('btn-mcp-register').style.display    = tab === 'registered' ? '' : 'none';
    $('btn-mcp-scan').style.display        = tab !== 'external'   ? '' : 'none';
    if (tab === 'discovered') loadDiscoveredMcp();
    if (tab === 'external')   loadExternalMcp();
  }

  async function loadDiscoveredMcp() {
    const wrap = $('mcp-discovered-wrap');
    wrap.innerHTML = '<div class="mcp-empty">Loading…</div>';
    const result = await api('GET', '/api/mcp/discovered');
    if (result.error) {
      wrap.innerHTML = `<div class="mcp-empty" style="color:var(--red)">${result.error}</div>`;
      return;
    }
    const servers = result.servers || [];
    if (servers.length === 0) {
      wrap.innerHTML = '<div class="mcp-empty">No pending discoveries. Click "⟳ Scan" to scan for new servers.</div>';
      return;
    }
    let html = `<table class="mcp-table">
      <thead><tr>
        <th>Alias</th><th>Transport</th><th>Source</th><th>Discovered</th><th>Clearance</th><th></th>
      </tr></thead><tbody>`;
    for (const s of servers) {
      const tBadge = s.transport === 'http' ? 'mcp-badge-http' : 'mcp-badge-stdio';
      const ts = s.discovered_at ? new Date(s.discovered_at * 1000).toLocaleString() : '—';
      html += `<tr>
        <td><strong>${esc(s.alias)}</strong></td>
        <td><span class="mcp-badge ${tBadge}">${esc(s.transport)}</span></td>
        <td><span class="mcp-badge mcp-badge-cl1">${esc(s.source || 'manifest')}</span></td>
        <td>${esc(ts)}</td>
        <td>${esc(s.required_clearance || 'internal')}</td>
        <td><button class="btn-primary" style="font-size:0.75rem;padding:2px 8px"
            onclick="Helm.approveMcp(${JSON.stringify(s.alias)})">Approve</button></td>
      </tr>`;
    }
    html += '</tbody></table>';
    wrap.innerHTML = html;
  }

  async function scanMcp() {
    const btn = $('btn-mcp-scan');
    btn.disabled = true;
    setStatus('Scanning…');
    const result = await api('POST', '/api/mcp/scan', {});
    btn.disabled = false;
    if (result.error) { setStatus('Scan failed: ' + result.error, true); return; }
    const n = result.discovered || 0;
    setStatus(`Scan complete — ${n} new server(s) staged for approval`);
    if (activeMcpTab === 'discovered') loadDiscoveredMcp();
    else switchMcpTab('discovered');
  }

  async function approveMcp(alias) {
    const result = await api('POST', '/api/mcp/approve', { alias });
    if (result.error) { setStatus('Approve failed: ' + result.error, true); return; }
    setStatus(`Approved '${alias}'`);
    loadDiscoveredMcp();
  }

  // ── MCP External sub-tab ──────────────────────────────────────────────────
  async function loadExternalMcp() {
    const wrap = $('mcp-external-wrap');
    wrap.innerHTML = '<div class="mcp-empty">Scanning host for external MCP servers…</div>';
    const result = await api('GET', '/api/mcp/external');
    if (result.error) {
      wrap.innerHTML = `<div class="mcp-empty" style="color:var(--red)">${result.error}</div>`;
      return;
    }
    const servers = result.servers || [];
    if (servers.length === 0) {
      wrap.innerHTML = '<div class="mcp-empty">No external MCP servers detected on this host.</div>';
      return;
    }
    let html = `<table class="mcp-table">
      <thead><tr>
        <th>Name</th><th>Source</th><th>Transport</th><th>Routed</th><th></th>
      </tr></thead><tbody>`;
    for (const s of servers) {
      const routedBadge = s.routed_via_crux
        ? '<span class="mcp-badge mcp-badge-cl1">routed</span>'
        : '<span class="mcp-badge mcp-badge-cl3">unrouted</span>';
      const actionBtn = s.routed_via_crux ? '' :
        `<button class="btn-primary" style="font-size:0.75rem;padding:2px 8px"
            onclick="Helm.routeExternal(${JSON.stringify(s.name)})">Route via Crux</button>`;
      html += `<tr>
        <td><strong>${esc(s.name)}</strong></td>
        <td>${esc(s.source_label)}</td>
        <td>${esc(s.transport)}</td>
        <td>${routedBadge}</td>
        <td>${actionBtn}</td>
      </tr>`;
      if (!s.routed_via_crux && s.instructions) {
        html += `<tr><td colspan="5"><pre class="mcp-instructions">${esc(s.instructions)}</pre></td></tr>`;
      }
    }
    html += '</tbody></table>';
    wrap.innerHTML = html;
  }

  async function routeExternal(name) {
    const result = await api('POST', '/api/mcp/route_external', { name });
    if (result.error) { setStatus('Route failed: ' + result.error, true); return; }
    setStatus(`Staged '${name}' for approval`);
    loadExternalMcp();
  }

  // ── Node filtering (client-side) ──────────────────────────────────────────
  function applyNodeFilters() {
    if (!activeCrux) return;
    const q      = nfQuery.value.trim().toLowerCase();
    const kind   = nfKind.value;
    const status = nfStatus.value;
    const tag    = nfTag.value.trim().toLowerCase();
    const sort   = nfSort.value;

    let nodes = (activeCrux.nodes || []).filter(n => !n.deleted_at);

    if (q) nodes = nodes.filter(n =>
      n.name.toLowerCase().includes(q) ||
      n.kind.toLowerCase().includes(q) ||
      (n.tags || []).some(t => t.toLowerCase().includes(q)) ||
      (n.summary || '').toLowerCase().includes(q));

    if (kind)   nodes = nodes.filter(n => n.kind === kind);
    if (status) nodes = nodes.filter(n => (n.planning && n.planning.status) === status);
    if (tag)    nodes = nodes.filter(n => (n.tags || []).some(t => t.toLowerCase() === tag));

    if (sort === 'name')     nodes.sort((a, b) => a.name.localeCompare(b.name));
    if (sort === 'priority') nodes.sort((a, b) => (a.planning && a.planning.priority != null ? a.planning.priority : 99) - (b.planning && b.planning.priority != null ? b.planning.priority : 99));
    if (sort === 'created')  nodes.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));

    const filtered = { ...activeCrux, nodes };
    if (currentView === 'graph') Graph.load(filtered);
    else if (currentView === 'board' && activeMember) Board.load(filtered, activeMember.path);
    else if (currentView === 'table') Board.loadTable(filtered);
    else if (currentView === 'timeline') Board.loadTimeline(filtered);
  }

  async function boardSaveNode(cruxPath, nodeId, updates) {
    const payload = { crux_path: cruxPath, node_id: nodeId, ...updates };
    const result = await api('POST', '/api/node/update', payload);
    if (result.error) { setStatus('Save failed: ' + result.error, true); return false; }
    setStatus('Saved');
    return true;
  }

  // ── AI bootstrap state ─────────────────────────────────────────────────────
  let aiProvider = 'none';

  async function checkAiConfig() {
    try {
      const cfg = await api('GET', '/api/ai/config');
      aiProvider = cfg.provider || 'none';
    } catch (_) { aiProvider = 'none'; }
  }

  // ── Bootstrap ──────────────────────────────────────────────────────────────
  function init() {
    Graph.init($('graph-container'), onNodeSelected, onEdgeSelected, onEdgeDraft);
    Board.init($('board-container'), onNodeSelected, boardSaveNode);
    Board.initTable($('table-container'), onNodeSelected);
    Board.initTimeline($('timeline-container'), onNodeSelected);
    loadKnownMeshes().then(() => loadMesh());
    checkAiConfig();

    document.querySelectorAll('.view-btn').forEach(btn => {
      btn.addEventListener('click', () => switchView(btn.dataset.view));
    });

    btnRefresh.addEventListener('click', loadMesh);
    btnNewCrux.addEventListener('click', () => showModal());
    btnModalCancel.addEventListener('click', hideModal);
    btnModalScan.addEventListener('click', doScan);
    btnModalCreate.addEventListener('click', doCreate);
    // Mesh switcher
    meshSelect.addEventListener('change', onMeshSelectChange);
    btnNmCancel.addEventListener('click', hideNewMeshModal);
    btnNmCreate.addEventListener('click', doCreateMesh);
    searchInput.addEventListener('input', () => {
      filterText = searchInput.value.toLowerCase();
      renderCruxList();
    });
    modalTemplate.addEventListener('change', () => {
      const tpl = TEMPLATES[modalTemplate.value];
      templatePreview.textContent = tpl ? tpl.description : '';
    });
    modalAiDesc.addEventListener('input', () => {
      const hasText = modalAiDesc.value.trim().length > 0;
      aiActions.style.display = hasText ? 'flex' : 'none';
      if (hasText) {
        btnAiGenerate.style.display = aiProvider !== 'none' ? '' : 'none';
      }
    });
    btnAiGenerate.addEventListener('click', doAiGenerate);
    btnAiCopy.addEventListener('click', doAiCopy);
    btnExportMd.addEventListener('click', exportMarkdown);
    // Font size controls
    applyZoom();
    btnFontDec.addEventListener('click', () => { uiZoom = Math.max(0.7, +(uiZoom - 0.1).toFixed(2)); applyZoom(); });
    btnFontInc.addEventListener('click', () => { uiZoom = Math.min(1.6, +(uiZoom + 0.1).toFixed(2)); applyZoom(); });
    // Theme toggle
    applyTheme();
    btnTheme.addEventListener('click', () => {
      const isDark = uiTheme === 'dark' ||
        (uiTheme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
      uiTheme = isDark ? 'light' : 'dark';
      applyTheme();
    });
    // Open existing crux
    btnOpenCrux.addEventListener('click', showOpenCruxModal);
    btnOpenCancel.addEventListener('click', hideOpenCruxModal);
    btnOpenConnect.addEventListener('click', doConnectCrux);
    // CSV import wizard
    btnImportCsv.addEventListener('click', showCsvModal);
    btnCsvCancel.addEventListener('click', hideCsvModal);
    btnCsvBack.addEventListener('click', showCsvStep1);
    btnCsvNext.addEventListener('click', doPreviewCsv);
    btnCsvImport.addEventListener('click', doImportCsv);
    csvFileInput.addEventListener('change', onCsvFileSelected);
    csvTargetCrux.addEventListener('change', () => {
      csvNewNameField.style.display = csvTargetCrux.value === '' ? '' : 'none';
    });

    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        hideModal(); hideNewMeshModal(); hideCsvModal(); hideOpenCruxModal();
        hideCmdPalette();
      }
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        showCmdPalette();
      }
      if (e.key === '/' && document.activeElement !== searchInput
          && !cmdPaletteOverlay.classList.contains('active')) {
        e.preventDefault(); searchInput.focus();
      }
      // Arrow key + Enter navigation inside palette
      if (cmdPaletteOverlay.classList.contains('active')) {
        if (e.key === 'ArrowDown') { e.preventDefault(); moveCmdSelection(1); }
        if (e.key === 'ArrowUp')   { e.preventDefault(); moveCmdSelection(-1); }
        if (e.key === 'Enter')     { e.preventDefault(); commitCmdSelection(); }
      }
    });

    // Graph controls — fit/reset view
    btnFitView  .addEventListener('click', () => Graph.fitToView());
    btnResetView.addEventListener('click', () => Graph.reset());
    document.addEventListener('keydown', e => {
      if (currentView !== 'graph') return;
      if (document.activeElement && /input|textarea|select/i.test(document.activeElement.tagName)) return;
      if (e.key === 'f' || e.key === 'F') Graph.fitToView();
      if (e.key === 'r' || e.key === 'R') Graph.reset();
    });

    cmdPaletteOverlay.addEventListener('click', e => {
      if (e.target === cmdPaletteOverlay) hideCmdPalette();
    });

    cmdInput.addEventListener('input', () => {
      clearTimeout(cmdSearchTimer);
      cmdSearchTimer = setTimeout(runCmdSearch, 150);
    });

    // Filter bar events (debounced for text inputs)
    let nfQueryTimer = null;
    nfQuery.addEventListener('input', () => {
      clearTimeout(nfQueryTimer);
      nfQueryTimer = setTimeout(applyNodeFilters, 150);
    });
    let nfTagTimer = null;
    nfTag.addEventListener('input', () => {
      clearTimeout(nfTagTimer);
      nfTagTimer = setTimeout(applyNodeFilters, 150);
    });
    nfKind.addEventListener('change', applyNodeFilters);
    nfStatus.addEventListener('change', applyNodeFilters);
    nfSort.addEventListener('change', applyNodeFilters);
    btnNfClear.addEventListener('click', () => {
      nfQuery.value = '';
      nfKind.value = '';
      nfStatus.value = '';
      nfTag.value = '';
      nfSort.value = '';
      applyNodeFilters();
    });

    // MCP Servers tab
    $('btn-mcp-register').addEventListener('click', openMcpRegisterModal);
    $('btn-mcp-refresh').addEventListener('click', () => {
      if (activeMcpTab === 'registered') loadMcpServers();
      else loadDiscoveredMcp();
    });
    $('btn-mcp-scan').addEventListener('click', scanMcp);
    document.querySelectorAll('.mcp-tab').forEach(b => {
      b.addEventListener('click', () => switchMcpTab(b.dataset.mcpTab));
    });
    $('btn-mcp-cancel').addEventListener('click', closeMcpModal);
    $('btn-mcp-submit').addEventListener('click', submitMcpRegister);
    $('mcp-transport').addEventListener('change', () => {
      const isHttp = $('mcp-transport').value === 'http';
      $('mcp-command-field').style.display = isHttp ? 'none' : '';
      $('mcp-url-field').style.display = isHttp ? '' : 'none';
    });
    $('modal-mcp-overlay').addEventListener('click', e => {
      if (e.target === $('modal-mcp-overlay')) closeMcpModal();
    });

    // Image lightbox
    initLightbox();

    // Check for updates in the background; show a dismissible banner if newer.
    setTimeout(checkForUpdates, 3000);
  }

  // ── Image lightbox ─────────────────────────────────────────────────────────
  function initLightbox() {
    const lb      = $('img-lightbox');
    const lbImg   = $('img-lightbox-img');
    const lbClose = $('img-lightbox-close');

    function open(src, alt) {
      lbImg.src = src;
      lbImg.alt = alt || '';
      lb.classList.remove('lb-closing');
      lb.classList.add('lb-open');
    }

    function close() {
      lb.classList.remove('lb-open');
      lb.classList.add('lb-closing');
      lb.addEventListener('animationend', () => {
        lb.classList.remove('lb-closing');
        lb.style.display = '';
      }, { once: true });
    }

    lbClose.addEventListener('click', close);
    lb.addEventListener('click', e => { if (e.target === lb) close(); });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && lb.classList.contains('lb-open')) close();
    });

    // Delegate clicks from inspector images
    $('inspector').addEventListener('click', e => {
      const img = e.target.closest('.insp-image');
      if (img) open(img.src, img.alt);
    });
  }

  // ── Update banner ──────────────────────────────────────────────────────────
  async function checkForUpdates() {
    let info;
    try {
      const r = await fetch('/api/update-check');
      info = await r.json();
    } catch { return; }
    if (!info || !info.latest) return;

    const dismissKey = `helm-update-dismissed-${info.latest}`;
    if (localStorage.getItem(dismissKey)) return;

    const banner = document.createElement('div');
    banner.className = 'update-banner';
    banner.innerHTML =
      `<span>Helm <strong>${info.latest}</strong> is available</span>` +
      `<a class="update-banner-dl" href="${info.url}" target="_blank">Download</a>` +
      `<button class="update-banner-dismiss" title="Dismiss">&#x2715;</button>`;
    banner.querySelector('.update-banner-dismiss').addEventListener('click', () => {
      localStorage.setItem(dismissKey, '1');
      banner.remove();
    });
    document.body.prepend(banner);
  }

  // ── API helpers ────────────────────────────────────────────────────────────
  async function api(method, path, body = null) {
    const opts = { method, headers: {} };
    if (body) { opts.body = JSON.stringify(body); opts.headers['Content-Type'] = 'application/json'; }
    const resp = await fetch(path, opts);
    const text = await resp.text();
    try { return JSON.parse(text); } catch { return { error: text }; }
  }

  function setStatus(msg, error = false) {
    statusBar.textContent = msg;
    statusBar.style.color = error ? 'var(--red)' : 'var(--text-dim)';
  }

  // ── Known meshes dropdown ─────────────────────────────────────────────────
  let knownMeshes = [];  // [{path, name}]

  async function loadKnownMeshes() {
    try {
      knownMeshes = await api('GET', '/api/known-meshes');
      if (!Array.isArray(knownMeshes)) knownMeshes = [];
      renderMeshDropdown(null);  // selected path unknown until loadMesh completes
    } catch (_) { knownMeshes = []; }
  }

  function renderMeshDropdown(activePath) {
    // Keep existing options list but rebuild; preserve active selection
    meshSelect.innerHTML = '';
    knownMeshes.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m.path;
      opt.textContent = m.name;
      if (activePath && m.path === activePath) opt.selected = true;
      meshSelect.appendChild(opt);
    });
    // Divider + New mesh option
    if (knownMeshes.length > 0) {
      const div = document.createElement('option');
      div.disabled = true;
      div.textContent = '──────────';
      meshSelect.appendChild(div);
    }
    const newOpt = document.createElement('option');
    newOpt.value = '__new__';
    newOpt.textContent = '+ New mesh…';
    newOpt.className = 'new-mesh-opt';
    meshSelect.appendChild(newOpt);
  }

  function onMeshSelectChange() {
    const val = meshSelect.value;
    if (val === '__new__') {
      // Reset to previous selection so dropdown doesn't stay on '+ New mesh…'
      renderMeshDropdown(mesh ? getMeshPath() : null);
      showNewMeshModal();
      return;
    }
    if (val && (!mesh || val !== getMeshPath())) {
      switchMesh(val);
    }
  }

  // Best-effort: find current mesh path from known list by matching name
  function getMeshPath() {
    if (!mesh) return null;
    const m = knownMeshes.find(k => k.name === mesh.mesh_name);
    return m ? m.path : null;
  }

  async function switchMesh(path) {
    setStatus('Switching…');
    Graph.stop();
    activeMember = null; activeCrux = null;
    canvasEmpty.style.display = '';
    const result = await api('POST', '/api/switch-mesh', { path });
    if (result.error) { setStatus(result.error, true); return; }
    await loadMesh();
  }

  // ── Load mesh ──────────────────────────────────────────────────────────────
  async function loadMesh() {
    setStatus('Loading…');
    try {
      mesh = await api('GET', '/api/mesh');
      if (mesh.error) { setStatus(mesh.error, true); return; }

      // Sync dropdown — add this mesh if not in known list yet
      const currentPath = getMeshPath() || '';
      if (currentPath && !knownMeshes.find(k => k.path === currentPath)) {
        knownMeshes.unshift({ path: currentPath, name: mesh.mesh_name });
      }
      renderMeshDropdown(currentPath);

      setStatus(`${mesh.members.length} member${mesh.members.length !== 1 ? 's' : ''}`);
      renderCruxList();
    } catch (e) {
      setStatus('Failed to load mesh', true);
    }
  }

  // ── Sidebar ────────────────────────────────────────────────────────────────
  function renderCruxList() {
    cruxList.innerHTML = '';
    if (!mesh) return;
    const members = filterText
      ? mesh.members.filter(m => m.crux_name.toLowerCase().includes(filterText) ||
                                  m.crux_kind.toLowerCase().includes(filterText))
      : mesh.members;
    members.forEach(m => {
      const div = document.createElement('div');
      div.className = `crux-item kind-${m.crux_kind}`;
      if (activeMember && activeMember.crux_id === m.crux_id) div.classList.add('active');
      div.innerHTML = `
        <div class="crux-item-content">
          <span class="crux-name">${esc(m.crux_name)}</span>
          <div class="crux-meta">
            <span class="crux-kind">${esc(m.crux_kind)}</span>
            <span class="crux-status" style="color:${statusColor(m.status)}">${esc(m.status)}</span>
          </div>
        </div>`;
      div.addEventListener('click', () => selectMember(m));
      cruxList.appendChild(div);
    });
  }

  function statusColor(s) {
    return s === 'online' ? 'var(--green)' : s === 'stale' ? 'var(--yellow)' : 'var(--text-dim)';
  }

  async function selectMember(member) {
    activeMember = member;
    activeCrux = null;
    renderCruxList();
    showLoader(true);
    canvasEmpty.style.display = 'none';
    nodeFilterBar.style.display = 'none';
    try {
      activeCrux = await api('GET', `/api/crux?path=${encodeURIComponent(member.path)}`);
      if (activeCrux.error) { setStatus(activeCrux.error, true); canvasEmpty.style.display = ''; showLoader(false); return; }

      // Populate kind dropdown from actual node kinds in this crux
      const kinds = [...new Set((activeCrux.nodes || [])
        .filter(n => !n.deleted_at)
        .map(n => n.kind)
        .filter(Boolean))].sort();
      nfKind.innerHTML = '<option value="">Kind</option>' +
        kinds.map(k => `<option value="${k}">${k}</option>`).join('');

      // Reset filter bar and show it
      nfQuery.value = ''; nfKind.value = ''; nfStatus.value = '';
      nfTag.value = ''; nfSort.value = '';
      nodeFilterBar.style.display = 'flex';

      if (currentView === 'graph') {
        Graph.load(activeCrux, mesh);
      } else if (currentView === 'board') {
        Board.load(activeCrux, member.path);
      } else if (currentView === 'table') {
        Board.loadTable(activeCrux);
      } else if (currentView === 'timeline') {
        Board.loadTimeline(activeCrux);
      }
      const n = (activeCrux.nodes || []).filter(x => !x.deleted_at).length;
      const e = (activeCrux.edges || []).length;
      setStatus(`${activeCrux.crux_name} · ${n} nodes · ${e} edges`);
    } catch (err) {
      setStatus('Error loading crux', true);
      canvasEmpty.style.display = '';
    }
    showLoader(false);
  }

  function showLoader(on) { canvasLoader.classList.toggle('active', on); }

  // ── Inspector ──────────────────────────────────────────────────────────────
  async function onNodeSelected(nd) {
    if (!nd) { inspectorBody.innerHTML = '<div id="inspector-empty">Click a node or edge to inspect it.</div>' + renderInspectorActions(); bindInspectorActions(); return; }

    if (nd.isGhost) {
      const member = (mesh && mesh.members || []).find(m => m.crux_id === nd.peerCruxId);
      inspectorBody.innerHTML = renderGhostInspector(nd, member);
      if (member) {
        await selectMember(member);
        Graph.selectByName(nd.peerNodeName);
      }
      return;
    }

    const editable = !!activeMember;
    inspectorBody.innerHTML = renderNodeInspector(nd, editable);
    if (editable) {
      const btn = inspectorBody.querySelector('.btn-save');
      if (btn) btn.addEventListener('click', () => saveNodeEdits(nd));

      // Status dropdown — save immediately on change
      const statusEl = $('insp-status');
      if (statusEl) {
        statusEl.addEventListener('change', () => {
          boardSaveNode(activeMember.path, nd.id, { status: statusEl.value });
        });
      }

      // Priority input — save on blur
      const prioEl = $('insp-priority');
      if (prioEl) {
        prioEl.addEventListener('blur', () => {
          boardSaveNode(activeMember.path, nd.id, { priority: prioEl.value });
        });
      }

      // Tag chip editor — remove buttons and add input
      const tagsWrap = $('insp-tags-wrap');
      if (tagsWrap) {
        tagsWrap.addEventListener('click', e => {
          const btn = e.target.closest('.tag-remove');
          if (!btn) return;
          const tag = btn.dataset.tag;
          const currentTags = Array.from(tagsWrap.querySelectorAll('.kind-tag'))
            .map(el => el.querySelector('.tag-remove') ? el.querySelector('.tag-remove').dataset.tag : null)
            .filter(Boolean)
            .filter(t => t !== tag);
          boardSaveNode(activeMember.path, nd.id, { tags: currentTags });
          // Remove chip from DOM immediately
          btn.closest('.kind-tag').remove();
        });

        const addInput = $('insp-tag-add');
        if (addInput) {
          const commitTag = () => {
            const val = addInput.value.trim();
            if (!val) return;
            const currentTags = Array.from(tagsWrap.querySelectorAll('.kind-tag'))
              .map(el => el.querySelector('.tag-remove') ? el.querySelector('.tag-remove').dataset.tag : null)
              .filter(Boolean);
            if (!currentTags.includes(val)) {
              const newTags = [...currentTags, val];
              boardSaveNode(activeMember.path, nd.id, { tags: newTags });
              // Add chip to DOM immediately
              const chip = document.createElement('span');
              chip.className = 'kind-tag';
              chip.innerHTML = `${esc(val)}<button class="tag-remove" data-tag="${escAttr(val)}">×</button>`;
              tagsWrap.insertBefore(chip, addInput);
            }
            addInput.value = '';
          };
          addInput.addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); commitTag(); }
          });
        }
      }
    }
    bindInspectorActions();
  }

  function onEdgeSelected(lk) {
    inspectorBody.innerHTML = renderEdgeInspector(lk);
  }

  function onEdgeDraft(srcId, dstId) {
    if (!activeCrux || !activeMember) return;
    const srcNode = (activeCrux.nodes || []).find(n => n.node_id === srcId);
    const dstNode = (activeCrux.nodes || []).find(n => n.node_id === dstId);
    if (!srcNode || !dstNode) return;
    showEdgeDraftPopup(srcNode, dstNode);
  }

  function showEdgeDraftPopup(srcNode, dstNode) {
    const kindOpts = EDGE_KINDS.map(k => `<option value="${k}">${k}</option>`).join('');
    inspectorBody.innerHTML = `
      <div class="section-title">New Edge</div>
      <div class="field"><label>From</label>
        <div class="value">${esc(srcNode.name)}</div></div>
      <div class="field"><label>To</label>
        <div class="value">${esc(dstNode.name)}</div></div>
      <div class="field"><label>Kind</label>
        <select id="draft-edge-kind">${kindOpts}</select></div>
      <div class="add-form-buttons">
        <button class="btn-save"   id="btn-draft-save">Add Edge</button>
        <button class="btn-cancel" id="btn-draft-cancel">Cancel</button>
      </div>`;
    $('btn-draft-cancel').addEventListener('click', () => onNodeSelected(null));
    $('btn-draft-save').addEventListener('click', async () => {
      const kind = $('draft-edge-kind').value;
      $('btn-draft-save').disabled = true;
      const result = await api('POST', '/api/edge/add', {
        crux_path: activeMember.path,
        src: srcNode.name,
        dst: dstNode.name,
        kind,
      });
      if (result.error) {
        setStatus('Add failed: ' + result.error, true);
        $('btn-draft-save').disabled = false;
        return;
      }
      setStatus('Edge added');
      selectMember(activeMember);
    });
  }

  function exportMarkdown() {
    if (!activeCrux || !activeMember) { setStatus('No crux loaded', true); return; }
    const nodes = (activeCrux.nodes || []).filter(n => !n.deleted_at);
    const edges = (activeCrux.edges || []);
    const name  = activeMember.crux_name;
    const kind  = activeMember.crux_kind;

    let md = `# ${name}\n\n`;
    md += `**Kind:** ${kind}  \n`;
    md += `**Exported:** ${new Date().toISOString().slice(0, 10)}  \n`;
    md += `**Nodes:** ${nodes.length}  **Edges:** ${edges.length}\n\n---\n\n`;

    // Nodes grouped by kind
    const byKind = {};
    for (const n of nodes) {
      (byKind[n.kind] = byKind[n.kind] || []).push(n);
    }
    md += `## Nodes\n\n`;
    for (const k of Object.keys(byKind).sort()) {
      md += `### ${k}\n\n`;
      for (const n of byKind[k]) {
        md += `**${n.name}**`;
        if (n.summary) md += ` — ${n.summary}`;
        md += `\n`;
        if (n.tags && n.tags.length) md += `*Tags:* ${n.tags.join(', ')}  \n`;
        if (n.planning) {
          const p = n.planning;
          const pf = [];
          if (p.status)   pf.push(`status: ${p.status}`);
          if (p.priority) pf.push(`priority: ${p.priority}`);
          if (pf.length)  md += `*Planning:* ${pf.join(', ')}  \n`;
        }
        if (n.properties && n.properties.length) {
          for (const prop of n.properties) {
            md += `*${prop.key}:* ${prop.value}  \n`;
          }
        }
        md += `\n`;
      }
    }

    if (edges.length) {
      md += `---\n\n## Edges\n\n`;
      for (const e of edges) {
        md += `- **${e.src}** →[${e.kind}]→ **${e.dst}**`;
        if (e.detail) md += ` *(${e.detail})*`;
        md += `\n`;
      }
      md += `\n`;
    }

    const blob = new Blob([md], { type: 'text/markdown' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `${name}.md`;
    a.click();
    URL.revokeObjectURL(url);
    setStatus('Exported ' + name + '.md');
  }

  function renderNodeInspector(nd, editable) {
    const planStatus = nd.planning && nd.planning.status ? nd.planning.status : '';
    const planPrio   = nd.planning && nd.planning.priority != null ? nd.planning.priority : '';
    const classification = nd.security && nd.security.classification ? nd.security.classification : '—';
    const tags = nd.tags || [];
    let html = `
      <div class="field"><label>Name</label><div class="value">${esc(nd.name)}</div></div>
      <div class="field"><label>Kind</label><div class="value">${esc(nd.kind)}</div></div>
      <div class="field"><label>Module</label><div class="value">${esc(nd.module || '—')}</div></div>
      <hr class="divider">
      <div class="field"><label>Summary</label>`;
    if (editable) {
      html += `<textarea id="insp-summary">${escAttr(nd.summary || '')}</textarea>`;
    } else {
      html += `<div class="value">${esc(nd.summary || '—')}</div>`;
    }
    html += `</div>`;

    // Tags — chip editor when editable, static when not
    html += `<div class="field"><label>Tags</label><div class="value" id="insp-tags-wrap">`;
    if (editable) {
      tags.forEach(t => {
        html += `<span class="kind-tag">${esc(t)}<button class="tag-remove" data-tag="${escAttr(t)}">×</button></span>`;
      });
      html += `<input id="insp-tag-add" placeholder="+ tag" style="width:70px;background:transparent;border:1px solid var(--border-soft);border-radius:4px;color:var(--text);font-family:var(--font-mono);font-size:var(--fs-11);padding:1px 5px;outline:none" autocomplete="off">`;
    } else if (tags.length) {
      tags.forEach(t => { html += `<span class="kind-tag">${esc(t)}</span>`; });
    } else {
      html += `<span style="color:var(--text-mute)">—</span>`;
    }
    html += `</div></div>`;

    const imgProps   = (nd.properties || []).filter(p => p.startsWith('image='));
    const otherProps = (nd.properties || []).filter(p => !p.startsWith('image='));
    if (imgProps.length) {
      imgProps.forEach(p => {
        const imgPath = p.slice(6);
        html += `<div class="insp-image-wrap"><img class="insp-image" src="/api/file?path=${encodeURIComponent(imgPath)}" alt="${esc(imgPath)}"></div>`;
      });
    }
    if (otherProps.length || editable) {
      html += `<div class="field"><label>Properties</label>`;
      if (editable) {
        html += `<textarea id="insp-properties">${escAttr(otherProps.join('\n'))}</textarea>`;
      } else {
        html += `<div class="value">`;
        otherProps.forEach(p => { html += `<span class="kind-tag">${esc(p)}</span>`; });
        html += `</div>`;
      }
      html += `</div>`;
    }

    html += `<hr class="divider">
      <div class="section-title">Planning</div>`;

    if (editable) {
      const statusOpts = ['', 'backlog', 'in-progress', 'review', 'done', 'blocked']
        .map(v => `<option value="${v}"${v === planStatus ? ' selected' : ''}>${v === '' ? '—' : v}</option>`)
        .join('');
      html += `<div class="field"><label>Status</label>
        <select id="insp-status">${statusOpts}</select></div>`;
      html += `<div class="field"><label>Priority</label>
        <input id="insp-priority" type="number" min="1" max="99" placeholder="—" value="${esc(String(planPrio))}"></div>`;
    } else {
      html += `<div class="field"><label>Status</label><div class="value">${esc(planStatus || '—')}</div></div>`;
      html += `<div class="field"><label>Priority</label><div class="value">${planPrio !== '' ? planPrio : '—'}</div></div>`;
    }

    html += `<hr class="divider">
      <div class="field"><label>Security</label><div class="value">${esc(classification)}</div></div>
      <div class="field"><label>Node ID</label><div class="value" style="font-size:var(--fs-10);color:var(--text-dim)">${esc(nd.id)}</div></div>`;
    if (editable) {
      html += `<button class="btn-save">Save changes</button>`;
    }
    html += renderInspectorActions();
    return html;
  }

  function renderGhostInspector(nd, member) {
    const peerInMesh = !!member;
    const detail = nd.raw && nd.raw.edge && nd.raw.edge.detail;
    return `
      <div class="field"><label>Name</label><div class="value">${esc(nd.peerNodeName)}</div></div>
      <div class="field"><label>Kind</label><div class="value" style="color:var(--edge-mesh-link)">cross-crux reference</div></div>
      <hr class="divider">
      <div class="field"><label>Peer crux</label><div class="value">${peerInMesh
        ? `<span>${esc(nd.peerCruxName)}</span>`
        : `<span style="color:var(--text-mute)">${esc(nd.peerCruxName)}</span>
           <div style="font-size:var(--fs-10);color:var(--red);margin-top:2px">Peer crux not in this mesh</div>`
      }</div></div>
      <div class="field"><label>Peer crux ID</label><div class="value" style="font-size:var(--fs-10);color:var(--text-dim);font-family:var(--font-mono)">${esc(nd.peerCruxId)}</div></div>
      ${detail ? `<div class="field"><label>Edge detail</label><div class="value">${esc(detail)}</div></div>` : ''}
      ${peerInMesh ? '<div style="font-size:var(--fs-11);color:var(--text-mute);margin-top:8px">Navigating to peer crux…</div>' : ''}
    `;
  }

  function renderEdgeInspector(lk) {
    return `
      <div class="field"><label>Kind</label><div class="value">${esc(lk.kind)}</div></div>
      <div class="field"><label>From</label><div class="value">${esc(lk.src.name)}</div></div>
      <div class="field"><label>To</label><div class="value">${esc(lk.dst.name)}</div></div>
      ${lk.detail ? `<div class="field"><label>Detail</label><div class="value">${esc(lk.detail)}</div></div>` : ''}
      <div class="field"><label>Edge ID</label><div class="value" style="font-size:var(--fs-10);color:var(--text-dim)">${esc(lk.raw.edge_id || '')}</div></div>`;
  }

  async function saveNodeEdits(nd) {
    const summaryEl  = $('insp-summary');
    const propsEl    = $('insp-properties');
    const payload = {
      crux_path: activeMember.path,
      node_id: nd.id,
    };
    if (summaryEl) payload.summary = summaryEl.value;
    if (propsEl) payload.properties = propsEl.value.split('\n').map(s => s.trim()).filter(Boolean);
    const result = await api('POST', '/api/node/update', payload);
    if (result.error) { setStatus('Save failed: ' + result.error, true); return; }
    setStatus('Saved');
    // Refresh crux to reflect changes
    selectMember(activeMember);
  }

  // ── Domain templates ───────────────────────────────────────────────────────
  const TEMPLATES = {
    'project-tracker': {
      description: '5 task nodes (Todo/In Progress/Done) + 1 milestone, wired with planning edges',
      nodes: [
        { name: 'task-1', kind: 'task', summary: 'First task to complete',   tags: ['Todo'] },
        { name: 'task-2', kind: 'task', summary: 'Second task in progress',  tags: ['In Progress'] },
        { name: 'task-3', kind: 'task', summary: 'Third task in progress',   tags: ['In Progress'] },
        { name: 'task-4', kind: 'task', summary: 'Fourth task complete',     tags: ['Done'] },
        { name: 'task-5', kind: 'task', summary: 'Fifth task complete',      tags: ['Done'] },
        { name: 'v1',     kind: 'milestone', summary: 'Version 1 milestone', tags: [] },
      ],
      edges: [
        { src: 'task-1', dst: 'v1', kind: 'belongs_to_domain' },
        { src: 'task-2', dst: 'v1', kind: 'belongs_to_domain' },
        { src: 'task-3', dst: 'v1', kind: 'belongs_to_domain' },
        { src: 'task-4', dst: 'v1', kind: 'belongs_to_domain' },
        { src: 'task-5', dst: 'v1', kind: 'belongs_to_domain' },
      ],
    },
    'contacts-crm': {
      description: '3 person nodes + 2 company nodes, persons linked to their companies',
      nodes: [
        { name: 'Alice',  kind: 'person',  summary: 'Primary contact',   tags: [] },
        { name: 'Bob',    kind: 'person',  summary: 'Secondary contact', tags: [] },
        { name: 'Carol',  kind: 'person',  summary: 'Executive contact', tags: [] },
        { name: 'Acme',   kind: 'company', summary: 'Main client',       tags: [] },
        { name: 'Globex', kind: 'company', summary: 'Partner company',   tags: [] },
      ],
      edges: [
        { src: 'Alice', dst: 'Acme',   kind: 'belongs_to_domain' },
        { src: 'Bob',   dst: 'Acme',   kind: 'belongs_to_domain' },
        { src: 'Carol', dst: 'Globex', kind: 'belongs_to_domain' },
      ],
    },
    'knowledge-base': {
      description: '4 concept nodes + 1 index node, each concept linked to the index',
      nodes: [
        { name: 'concept-1', kind: 'concept', summary: 'First key concept',          tags: [] },
        { name: 'concept-2', kind: 'concept', summary: 'Second key concept',         tags: [] },
        { name: 'concept-3', kind: 'concept', summary: 'Third key concept',          tags: [] },
        { name: 'concept-4', kind: 'concept', summary: 'Fourth key concept',         tags: [] },
        { name: 'index',     kind: 'index',   summary: 'Master index of all concepts', tags: [] },
      ],
      edges: [
        { src: 'concept-1', dst: 'index', kind: 'relates_to' },
        { src: 'concept-2', dst: 'index', kind: 'relates_to' },
        { src: 'concept-3', dst: 'index', kind: 'relates_to' },
        { src: 'concept-4', dst: 'index', kind: 'relates_to' },
      ],
    },
    'incident-log': {
      description: '1 incident + 2 root-cause nodes + 1 resolution, fully wired',
      nodes: [
        { name: 'incident-1',   kind: 'incident',   summary: 'Production outage or notable event',   tags: [] },
        { name: 'root-cause-1', kind: 'root-cause', summary: 'Primary contributing factor',          tags: [] },
        { name: 'root-cause-2', kind: 'root-cause', summary: 'Secondary contributing factor',        tags: [] },
        { name: 'resolution-1', kind: 'resolution', summary: 'How the incident was resolved',        tags: [] },
      ],
      edges: [
        { src: 'incident-1',   dst: 'root-cause-1', kind: 'relates_to' },
        { src: 'incident-1',   dst: 'root-cause-2', kind: 'relates_to' },
        { src: 'root-cause-1', dst: 'resolution-1', kind: 'produces' },
        { src: 'root-cause-2', dst: 'resolution-1', kind: 'produces' },
      ],
    },
  };

  async function seedTemplate(cruxPath, templateName) {
    const tpl = TEMPLATES[templateName];
    if (!tpl) return;
    for (const node of tpl.nodes) {
      await api('POST', '/api/node/add', {
        crux_path: cruxPath, name: node.name, kind: node.kind,
        summary: node.summary, tags: node.tags,
      });
    }
    for (const edge of tpl.edges) {
      await api('POST', '/api/edge/add', {
        crux_path: cruxPath, src: edge.src, dst: edge.dst, kind: edge.kind,
      });
    }
  }

  // ── Inspector actions (Add Node / Add Edge) ────────────────────────────────
  const EDGE_KINDS = ['calls','imports','contains','extends','implements',
    'data_flow','reads','writes','transforms','produces',
    'relates_to','contradicts','supersedes','exemplifies',
    'belongs_to_domain','tagged','mesh_link'];

  function renderInspectorActions() {
    if (!activeMember) return '';
    return `<div class="inspector-actions">
      <button class="btn-add" id="btn-add-node">+ Node</button>
      <button class="btn-add" id="btn-add-edge">+ Edge</button>
    </div>`;
  }

  function bindInspectorActions() {
    const btnNode = $('btn-add-node');
    const btnEdge = $('btn-add-edge');
    if (btnNode) btnNode.addEventListener('click', showAddNodeForm);
    if (btnEdge) btnEdge.addEventListener('click', showAddEdgeForm);
  }

  function showAddNodeForm() {
    inspectorBody.innerHTML = `
      <div class="section-title">Add Node</div>
      <div class="field"><label>Name</label><input id="an-name" placeholder="node-name" /></div>
      <div class="field"><label>Kind</label><input id="an-kind" placeholder="concept" /></div>
      <div class="field"><label>Summary</label><textarea id="an-summary" style="min-height:50px"></textarea></div>
      <div class="add-form-buttons">
        <button class="btn-save" id="btn-an-save">Add</button>
        <button class="btn-cancel" id="btn-an-cancel">Cancel</button>
      </div>`;
    $('btn-an-cancel').addEventListener('click', () => onNodeSelected(null));
    $('btn-an-save').addEventListener('click', async () => {
      const name    = $('an-name').value.trim();
      const kind    = $('an-kind').value.trim() || 'concept';
      const summary = $('an-summary').value.trim();
      if (!name) { setStatus('Name is required', true); return; }
      $('btn-an-save').disabled = true;
      const result = await api('POST', '/api/node/add', {
        crux_path: activeMember.path, name, kind, summary,
      });
      if (result.error) { setStatus('Add failed: ' + result.error, true); $('btn-an-save').disabled = false; return; }
      setStatus('Node added');
      selectMember(activeMember);
    });
  }

  function showAddEdgeForm() {
    const nodes = (activeCrux && activeCrux.nodes || []).filter(n => !n.deleted_at);
    const opts = nodes.map(n => `<option value="${esc(n.name)}">${esc(n.name)}</option>`).join('');
    const kindOpts = EDGE_KINDS.map(k => `<option value="${k}">${k}</option>`).join('');
    inspectorBody.innerHTML = `
      <div class="section-title">Add Edge</div>
      <div class="field"><label>From</label><select id="ae-src">${opts}</select></div>
      <div class="field"><label>To</label><select id="ae-dst">${opts}</select></div>
      <div class="field"><label>Kind</label><select id="ae-kind">${kindOpts}</select></div>
      <div class="add-form-buttons">
        <button class="btn-save" id="btn-ae-save">Add</button>
        <button class="btn-cancel" id="btn-ae-cancel">Cancel</button>
      </div>`;
    $('btn-ae-cancel').addEventListener('click', () => onNodeSelected(null));
    $('btn-ae-save').addEventListener('click', async () => {
      const src  = $('ae-src').value;
      const dst  = $('ae-dst').value;
      const kind = $('ae-kind').value;
      if (!src || !dst) { setStatus('src and dst are required', true); return; }
      $('btn-ae-save').disabled = true;
      const result = await api('POST', '/api/edge/add', {
        crux_path: activeMember.path, src, dst, kind,
      });
      if (result.error) { setStatus('Add failed: ' + result.error, true); $('btn-ae-save').disabled = false; return; }
      setStatus('Edge added');
      selectMember(activeMember);
    });
  }

  // ── Modal: New Crux ────────────────────────────────────────────────────────
  function showModal() {
    modalName.value = ''; modalSource.value = '';
    modalTemplate.value = ''; templatePreview.textContent = '';
    modalAiDesc.value = ''; aiActions.style.display = 'none'; aiStatus.textContent = '';
    modalScanPreview.style.display = 'none';
    modalOverlay.classList.add('active');
    modalName.focus();
  }

  function hideModal() { modalOverlay.classList.remove('active'); }

  async function doScan() {
    const src = modalSource.value.trim();
    if (!src) { alert('Enter a source directory first.'); return; }
    btnModalScan.disabled = true;
    btnModalScan.textContent = 'Scanning…';
    try {
      const result = await api('POST', '/api/crux/generate', { source_path: src });
      if (result.error) { alert('Scan error: ' + result.error); return; }
      modalScanPreview.style.display = '';
      modalScanInfo.textContent = `${result.total} file(s) found`;
    } finally {
      btnModalScan.disabled = false;
      btnModalScan.textContent = 'Scan';
    }
  }

  async function doCreate() {
    const name = modalName.value.trim();
    if (!name) { alert('Name is required.'); return; }
    const templateName = modalTemplate.value;
    const description  = modalAiDesc.value.trim();
    btnModalCreate.disabled = true;
    btnModalCreate.textContent = 'Creating…';
    try {
      const payload = { name, kind: modalKind.value };
      const src = modalSource.value.trim();
      if (src) payload.source_path = src;
      const result = await api('POST', '/api/crux/create', payload);
      if (result.error) { alert('Error: ' + result.error); return; }
      await loadMesh();
      const newMember = mesh && mesh.members.find(m => m.crux_name === name);

      if (description && newMember) {
        // AI bootstrap takes priority over template seeding.
        await doAiBootstrap(newMember.path, description, name);
        await loadMesh();
      } else if (newMember && templateName) {
        await seedTemplate(newMember.path, templateName);
        await loadMesh();
      }

      hideModal();
      if (newMember) selectMember(newMember);
    } finally {
      btnModalCreate.disabled = false;
      btnModalCreate.textContent = 'Create';
    }
  }

  // Called by the "Generate with AI" button (before create).
  async function doAiGenerate() {
    const name = modalName.value.trim();
    if (!name) { alert('Name is required.'); return; }
    const description = modalAiDesc.value.trim();
    if (!description) return;

    btnAiGenerate.disabled = true;
    aiStatus.textContent = 'Creating crux…';
    try {
      const createResult = await api('POST', '/api/crux/create', { name, kind: modalKind.value });
      if (createResult.error) { aiStatus.textContent = 'Error: ' + createResult.error; return; }
      await loadMesh();
      const newMember = mesh && mesh.members.find(m => m.crux_name === name);
      if (!newMember) { aiStatus.textContent = 'Error: crux not found after creation'; return; }

      await doAiBootstrap(newMember.path, description, name);
      await loadMesh();
      hideModal();
      selectMember(newMember);
    } finally {
      btnAiGenerate.disabled = false;
    }
  }

  // Shared bootstrap logic: POSTs to /api/ai/bootstrap and handles both response modes.
  async function doAiBootstrap(cruxPath, description, cruxName) {
    aiStatus.textContent = 'Generating with AI…';
    const result = await api('POST', '/api/ai/bootstrap', { crux_path: cruxPath, description });
    if (result.mode === 'copy-prompt') {
      try { await navigator.clipboard.writeText(result.prompt); } catch (_) {}
      aiStatus.textContent = 'Prompt copied — paste into Claude Code to seed this crux.';
    } else if (result.ok) {
      aiStatus.textContent = `Added ${result.nodes_added} nodes, ${result.edges_added} edges.`;
    } else {
      aiStatus.textContent = 'AI error: ' + (result.error || 'unknown');
    }
  }

  // "Copy Prompt" button — copies the bootstrap prompt without creating the crux.
  async function doAiCopy() {
    const description = modalAiDesc.value.trim();
    if (!description) return;
    const name = modalName.value.trim() || 'my-crux';
    const prompt =
      `Bootstrap crux '${name}'\nDescription: ${description}\n\n` +
      `Node kinds: task, concept, person, document, record, milestone, module\n` +
      `Edge kinds: relates_to, contains, produces, belongs_to_domain, reads, writes\n\n` +
      `Generate 6–15 nodes. Call \`crux add_nodes\` then \`crux add_edges\`.\n` +
      `Node format: [{"name":"...", "kind":"...", "summary":"...", "tags":"tag1,tag2"}]\n` +
      `Edge format: [{"src":"...", "dst":"...", "kind":"..."}]`;
    try {
      await navigator.clipboard.writeText(prompt);
      aiStatus.textContent = 'Prompt copied to clipboard!';
      setTimeout(() => { aiStatus.textContent = ''; }, 3000);
    } catch (_) {
      aiStatus.textContent = 'Copy failed — check clipboard permissions.';
    }
  }

  // ── New Mesh modal ─────────────────────────────────────────────────────────
  function showNewMeshModal() {
    nmName.value = ''; nmPath.value = ''; nmError.textContent = '';
    modalNewMesh.classList.add('active');
    nmName.focus();
  }

  function hideNewMeshModal() { modalNewMesh.classList.remove('active'); }

  async function doCreateMesh() {
    const name = nmName.value.trim();
    const path = nmPath.value.trim();
    if (!name) { nmError.textContent = 'Name is required.'; return; }
    if (!path) { nmError.textContent = 'Directory is required.'; return; }
    nmError.textContent = '';
    btnNmCreate.disabled = true; btnNmCreate.textContent = 'Creating…';
    try {
      const result = await api('POST', '/api/create-mesh', { name, path });
      if (result.error) { nmError.textContent = result.error; return; }
      hideNewMeshModal();
      knownMeshes.unshift({ path, name });
      await loadMesh();
    } finally {
      btnNmCreate.disabled = false; btnNmCreate.textContent = 'Create Mesh';
    }
  }

  // ── Font size & theme ─────────────────────────────────────────────────────

  function applyZoom() {
    document.documentElement.style.setProperty('--ui-zoom', String(uiZoom));
    localStorage.setItem('helm-zoom', String(uiZoom));
  }

  function applyTheme() {
    const html = document.documentElement;
    if (uiTheme === 'dark') {
      html.setAttribute('data-theme', 'dark');
    } else if (uiTheme === 'light') {
      html.setAttribute('data-theme', 'light');
    } else {
      html.removeAttribute('data-theme');
    }
    localStorage.setItem('helm-theme', uiTheme);
    const isDark = uiTheme === 'dark' ||
      (uiTheme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    if (btnTheme) btnTheme.textContent = isDark ? '☀' : '☾';
  }

  // ── Connect existing crux ─────────────────────────────────────────────────

  function showOpenCruxModal() {
    openCruxPath.value = '';
    openCruxError.textContent = '';
    btnOpenConnect.disabled = false;
    btnOpenConnect.textContent = 'Connect';
    modalOpenOverlay.classList.add('active');
    openCruxPath.focus();
  }

  function hideOpenCruxModal() {
    modalOpenOverlay.classList.remove('active');
  }

  async function doConnectCrux() {
    const path = openCruxPath.value.trim();
    if (!path) { openCruxError.textContent = 'Enter a path.'; return; }
    btnOpenConnect.disabled = true;
    btnOpenConnect.textContent = 'Connecting…';
    openCruxError.textContent = '';
    try {
      const result = await api('POST', '/api/crux/join', { path });
      if (result.error) {
        openCruxError.textContent = result.error;
        btnOpenConnect.disabled = false;
        btnOpenConnect.textContent = 'Connect';
        return;
      }
      hideOpenCruxModal();
      await loadMesh();
    } catch (e) {
      openCruxError.textContent = 'Connection failed.';
      btnOpenConnect.disabled = false;
      btnOpenConnect.textContent = 'Connect';
    }
  }

  // ── CSV Import Wizard ─────────────────────────────────────────────────────

  function showCsvModal() {
    csvRawText = ''; csvHeaders = []; csvRows = [];
    csvPasteArea.value = ''; csvFileInput.value = '';
    csvStep1Error.textContent = '';
    csvImportStatus.textContent = '';
    csvImportStatus.style.color = 'var(--text-dim)';
    // Populate target crux dropdown from mesh members
    csvTargetCrux.innerHTML = '<option value="">— Create new crux —</option>';
    if (mesh && mesh.members) {
      mesh.members.forEach(m => {
        const opt = document.createElement('option');
        opt.value = m.path; opt.textContent = m.crux_name;
        csvTargetCrux.appendChild(opt);
      });
    }
    if (activeMember) {
      csvTargetCrux.value = activeMember.path;
      csvNewNameField.style.display = 'none';
    } else {
      csvNewNameField.style.display = '';
    }
    showCsvStep1();
    modalCsvOverlay.classList.add('active');
  }

  function hideCsvModal() {
    modalCsvOverlay.classList.remove('active');
  }

  function showCsvStep1() {
    csvStep1.style.display = ''; csvStep2.style.display = 'none';
    btnCsvBack.style.display = 'none'; btnCsvNext.style.display = '';
    btnCsvImport.style.display = 'none';
  }

  function onCsvFileSelected(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => { csvPasteArea.value = ev.target.result; };
    reader.readAsText(file, 'UTF-8');
  }

  function doPreviewCsv() {
    const text = csvPasteArea.value.trim();
    if (!text) { csvStep1Error.textContent = 'No CSV content.'; return; }
    csvStep1Error.textContent = '';
    const parsed = parseClientCsv(text);
    if (parsed.length < 2) {
      csvStep1Error.textContent = 'Need at least a header row and one data row.';
      return;
    }
    csvRawText = text;
    csvHeaders = parsed[0];
    csvRows = parsed.slice(1).filter(r => r.some(v => v.trim()));

    // Build column-mapping table
    csvColMapTable.innerHTML = buildColMapTable(csvHeaders, csvRows[0] || []);
    csvColMapTable.querySelectorAll('.csv-field-select')
      .forEach(s => s.addEventListener('change', updateCsvPreview));

    updateCsvPreview();

    csvStep2.style.display = ''; csvStep1.style.display = 'none';
    btnCsvBack.style.display = ''; btnCsvNext.style.display = 'none';
    btnCsvImport.style.display = '';
    csvPreviewCount.textContent = `(first 3 of ${csvRows.length} rows)`;
  }

  /** Client-side RFC 4180 CSV parser. Returns array of rows (each row = array of strings). */
  function parseClientCsv(text) {
    const rows = [];
    let cur = [], field = '', inQuote = false;
    const len = text.length;
    for (let i = 0; i < len; i++) {
      const c = text[i];
      if (inQuote) {
        if (c === '"') {
          if (i + 1 < len && text[i + 1] === '"') { field += '"'; i++; }
          else inQuote = false;
        } else { field += c; }
      } else {
        if (c === '"') { inQuote = true; }
        else if (c === ',') { cur.push(field.trim()); field = ''; }
        else if (c === '\n' || (c === '\r' && text[i + 1] === '\n')) {
          if (c === '\r') i++;
          cur.push(field.trim()); field = '';
          if (cur.some(v => v)) rows.push(cur);
          cur = [];
        } else { field += c; }
      }
    }
    cur.push(field.trim());
    if (cur.some(v => v)) rows.push(cur);
    return rows;
  }

  /** Build column-mapping table HTML. */
  function buildColMapTable(headers, sample) {
    const ROLES = ['property', 'name', 'kind', 'summary', 'tags', 'skip'];
    let html = '<table class="csv-map-table"><thead><tr>'
      + '<th>Column</th><th>Sample</th><th>Field</th></tr></thead><tbody>';
    headers.forEach((h, i) => {
      const sv = sample[i] || '';
      const hl = h.toLowerCase();
      let def = 'property';
      if (hl === 'name' || hl === 'title' || hl === 'id' || hl === 'subject') def = 'name';
      else if (hl === 'kind' || hl === 'type' || hl === 'category') def = 'kind';
      else if (hl === 'summary' || hl === 'description' || hl === 'notes') def = 'summary';
      else if (hl === 'tags' || hl === 'labels' || hl === 'keywords') def = 'tags';
      const opts = ROLES.map(r =>
        `<option value="${r}"${r === def ? ' selected' : ''}>${r}</option>`).join('');
      html += `<tr><td class="csv-col-name">${esc(h)}</td>`
        + `<td class="csv-col-sample">${esc(sv.substring(0, 40))}</td>`
        + `<td><select class="csv-field-select" data-col="${i}">${opts}</select></td></tr>`;
    });
    html += '</tbody></table>';
    return html;
  }

  /** Render preview of first 3 rows using current dropdown selections. */
  function updateCsvPreview() {
    const selects = csvColMapTable.querySelectorAll('.csv-field-select');
    const roles = Array.from(selects).map(s => s.value);
    const visibleCols = roles.map((r, i) => r !== 'skip' ? i : -1).filter(i => i >= 0);
    if (!csvRows.length) { csvPreviewTable.innerHTML = ''; return; }
    const preview = csvRows.slice(0, 3);
    let html = '<table class="csv-preview"><thead><tr>'
      + visibleCols.map(i =>
          `<th>${esc(csvHeaders[i])}<br><span style="color:var(--text-dim)">${roles[i]}</span></th>`
        ).join('')
      + '</tr></thead><tbody>';
    preview.forEach(row => {
      html += '<tr>' + visibleCols.map(i =>
        `<td>${esc((row[i] || '').substring(0, 50))}</td>`
      ).join('') + '</tr>';
    });
    html += '</tbody></table>';
    csvPreviewTable.innerHTML = html;
  }

  async function doImportCsv() {
    btnCsvImport.disabled = true;
    csvImportStatus.style.color = 'var(--text-dim)';
    csvImportStatus.textContent = 'Importing…';
    const selects = csvColMapTable.querySelectorAll('.csv-field-select');
    const column_mappings = Array.from(selects)
      .map((s, i) => ({ column: csvHeaders[i], field: s.value }))
      .filter(m => m.field !== 'property');

    const payload = {
      crux_path: csvTargetCrux.value || '',
      crux_name: csvCruxName.value.trim() || 'CSV Import',
      csv_content: csvRawText,
      column_mappings,
      node_kind: csvNodeKind.value.trim() || 'record',
    };

    const result = await api('POST', '/api/crux/import-csv', payload);
    if (result.error) {
      csvImportStatus.style.color = 'var(--red)';
      csvImportStatus.textContent = 'Error: ' + result.error;
      btnCsvImport.disabled = false;
      return;
    }
    csvImportStatus.style.color = 'var(--green)';
    csvImportStatus.textContent = `Imported ${result.nodes_added} node${result.nodes_added === 1 ? '' : 's'}.`;
    setTimeout(() => {
      hideCsvModal();
      if (activeMember) selectMember(activeMember);
      else loadMesh();
    }, 1200);
  }

  // ── Command Palette ────────────────────────────────────────────────────────
  function showCmdPalette() {
    cmdInput.value = '';
    cmdResults.innerHTML = '';
    cmdAllResults = [];
    cmdSelectedIdx = -1;
    cmdPaletteOverlay.classList.add('active');
    cmdInput.focus();
    renderCmdQuickJump();
  }

  function hideCmdPalette() {
    cmdPaletteOverlay.classList.remove('active');
    clearTimeout(cmdSearchTimer);
  }

  function renderCmdQuickJump() {
    if (!mesh || !mesh.members || !mesh.members.length) {
      cmdResults.innerHTML = '<div class="cmd-empty">No cruxes in mesh.</div>';
      return;
    }
    cmdAllResults = mesh.members.map(m => ({ type: 'crux', member: m }));
    let html = '<div class="cmd-group-label">Jump to crux</div>';
    cmdAllResults.forEach((r, i) => {
      html += `<div class="cmd-result-row${i === 0 ? ' cmd-selected' : ''}" data-idx="${i}">
        <span class="cmd-res-name">${esc(r.member.crux_name)}</span>
        <span class="cmd-res-meta">${esc(r.member.crux_kind)}</span>
      </div>`;
    });
    cmdResults.innerHTML = html;
    cmdSelectedIdx = 0;
    bindCmdResultClicks();
  }

  async function runCmdSearch() {
    const q = cmdInput.value.trim();
    if (!q) { renderCmdQuickJump(); return; }
    if (!mesh || !mesh.members.length) return;

    cmdResults.innerHTML = '<div class="cmd-empty">Searching…</div>';
    cmdAllResults = [];
    cmdSelectedIdx = -1;

    const queries = mesh.members.map(m =>
      api('GET', `/api/crux/query?path=${encodeURIComponent(m.path)}&q=${encodeURIComponent(q)}&limit=6`)
        .then(nodes => Array.isArray(nodes) ? nodes.map(n => ({ type: 'node', node: n, member: m })) : [])
        .catch(() => [])
    );

    const perCrux = await Promise.all(queries);
    cmdAllResults = perCrux.flat();

    if (!cmdAllResults.length) {
      cmdResults.innerHTML = `<div class="cmd-empty">No results for "${esc(q)}"</div>`;
      return;
    }

    let html = '';
    perCrux.forEach((results, ci) => {
      if (!results.length) return;
      html += `<div class="cmd-group-label">${esc(mesh.members[ci].crux_name)}</div>`;
      results.forEach(r => {
        const idx = cmdAllResults.indexOf(r);
        html += `<div class="cmd-result-row" data-idx="${idx}">
          <span class="cmd-res-kind">${esc(r.node.kind)}</span>
          <span class="cmd-res-name">${esc(r.node.name)}</span>
          <span class="cmd-res-meta">${esc((r.node.summary || '').substring(0, 60))}</span>
        </div>`;
      });
    });
    cmdResults.innerHTML = html;
    cmdSelectedIdx = -1;
    bindCmdResultClicks();
  }

  function bindCmdResultClicks() {
    cmdResults.querySelectorAll('.cmd-result-row').forEach(row => {
      row.addEventListener('mouseenter', () => {
        cmdSelectedIdx = parseInt(row.dataset.idx, 10);
        updateCmdHighlight();
      });
      row.addEventListener('click', () => {
        cmdSelectedIdx = parseInt(row.dataset.idx, 10);
        commitCmdSelection();
      });
    });
  }

  function moveCmdSelection(delta) {
    if (!cmdAllResults.length) return;
    cmdSelectedIdx = Math.max(0, Math.min(cmdAllResults.length - 1, cmdSelectedIdx + delta));
    updateCmdHighlight();
    const row = cmdResults.querySelector(`.cmd-result-row[data-idx="${cmdSelectedIdx}"]`);
    if (row) row.scrollIntoView({ block: 'nearest' });
  }

  function updateCmdHighlight() {
    cmdResults.querySelectorAll('.cmd-result-row').forEach(row => {
      row.classList.toggle('cmd-selected', parseInt(row.dataset.idx, 10) === cmdSelectedIdx);
    });
  }

  function commitCmdSelection() {
    if (cmdSelectedIdx < 0 || cmdSelectedIdx >= cmdAllResults.length) return;
    const r = cmdAllResults[cmdSelectedIdx];
    hideCmdPalette();
    selectMember(r.member);
  }

  // ── Utilities ──────────────────────────────────────────────────────────────
  function esc(s) {
    return String(s || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
  function escAttr(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;')
      .replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  return { init, revokeMcp, approveMcp, routeExternal, oauthStart, oauthRevokeToken };
})();

document.addEventListener('DOMContentLoaded', Helm.init);

// Inspector resize handle
(function() {
  const resizer = document.getElementById('inspector-resizer');
  if (!resizer) return;
  let dragging = false, startX = 0, startW = 0;
  const root = document.documentElement;

  resizer.addEventListener('mousedown', e => {
    dragging = true;
    startX = e.clientX;
    startW = parseInt(getComputedStyle(root).getPropertyValue('--inspector-w'), 10);
    resizer.classList.add('dragging');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });
  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    const delta = startX - e.clientX;
    const newW = Math.max(200, Math.min(700, startW + delta));
    root.style.setProperty('--inspector-w', newW + 'px');
  });
  document.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    resizer.classList.remove('dragging');
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  });
})();
