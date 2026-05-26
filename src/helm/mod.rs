//! Helm — browser-based Crux Mesh manager.
//!
//! Exposes a minimal HTTP server on `127.0.0.1:8111` serving the Helm UI
//! and a JSON API backed directly by the `crux_mesh` library.

pub mod api;
pub mod assets;
pub mod http;
pub mod update_check;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::helm::http::{parse_request, write_response, Response};
use crate::helm::api::{
    handle_add_edge, handle_add_node, handle_create_crux, handle_generate_preview,
    handle_get_crux, handle_get_file, handle_get_known_meshes, handle_get_mesh, handle_import_csv,
    handle_query_crux, handle_switch_mesh, handle_create_mesh_init, handle_update_node,
    handle_ai_config, handle_ai_bootstrap,
    handle_mcp_list, handle_mcp_register, handle_mcp_revoke,
    handle_mcp_discovered, handle_mcp_scan, handle_mcp_approve,
    handle_mcp_external, handle_mcp_route_external,
};
use crate::helm::assets::{BOARD_JS, CRUX_ICON, CRUX_ICON_SVG, GRAPH_JS, HELM_CSS, HELM_JS, INDEX_HTML};
use crate::json::json_escape;

pub const PORT: u16 = 8111;

// ── Setup page (served when no mesh is configured) ────────────────────────────

const SETUP_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Helm Setup</title>
  <link rel="stylesheet" href="/helm.css">
  <style>
    body { display:flex; align-items:center; justify-content:center; height:100vh; }
    .setup-card { width:460px; }
    .setup-card h1 { font-size:20px; margin-bottom:16px; }
    .setup-tabs { display:flex; gap:4px; margin-bottom:20px; }
    .setup-tab { flex:1; padding:7px 0; font-size:13px; background:var(--surface1);
                 border:1px solid var(--border); border-radius:6px; cursor:pointer;
                 color:var(--text-dim); transition:background 0.1s, color 0.1s; }
    .setup-tab.active { background:var(--accent); color:#fff; border-color:var(--accent); }
    .setup-pane { display:none; }
    .setup-pane.active { display:block; }
    .setup-pane p { color:var(--text-dim); font-size:13px; margin-bottom:16px; line-height:1.6; }
    #err-open, #err-new { color:var(--red); font-size:12px; min-height:18px; margin:6px 0; }
    code { background:var(--surface2); border-radius:3px; padding:1px 5px; font:inherit; }
  </style>
</head>
<body>
  <div class="setup-card">
    <h1>Helm</h1>
    <div class="setup-tabs">
      <button class="setup-tab active" onclick="show_tab('open')">Open existing</button>
      <button class="setup-tab"        onclick="show_tab('new')">Create new</button>
    </div>

    <div id="pane-open" class="setup-pane active">
      <p>Enter the path to a directory that contains a <code>.crux-mesh.json</code> file.</p>
      <div class="field">
        <label>Mesh directory</label>
        <input id="open-path" type="text" placeholder="/path/to/your/project" autofocus>
      </div>
      <div id="err-open"></div>
      <button class="btn-primary" id="btn-open" onclick="open_mesh()">Open Mesh</button>
    </div>

    <div id="pane-new" class="setup-pane">
      <p>Choose a name and a directory. The directory will be created if it doesn't exist.</p>
      <div class="field">
        <label>Mesh name</label>
        <input id="new-name" type="text" placeholder="my-project">
      </div>
      <div class="field">
        <label>Directory</label>
        <input id="new-path" type="text" placeholder="/path/to/new/directory">
      </div>
      <div id="err-new"></div>
      <button class="btn-primary" id="btn-new" onclick="create_mesh()">Create Mesh</button>
    </div>
  </div>
  <script>
    function show_tab(tab) {
      document.querySelectorAll('.setup-tab').forEach((el, i) =>
        el.classList.toggle('active', (tab === 'open') ? i === 0 : i === 1));
      document.getElementById('pane-open').classList.toggle('active', tab === 'open');
      document.getElementById('pane-new').classList.toggle('active',  tab === 'new');
      document.getElementById(tab === 'open' ? 'open-path' : 'new-name').focus();
    }
    async function open_mesh() {
      const path = document.getElementById('open-path').value.trim();
      if (!path) return;
      const btn = document.getElementById('btn-open');
      btn.disabled = true; btn.textContent = 'Opening\u2026';
      const r = await fetch('/api/setup', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({path})
      });
      const d = await r.json();
      if (d.ok) { window.location.href = '/'; return; }
      document.getElementById('err-open').textContent = d.error || 'Unknown error';
      btn.disabled = false; btn.textContent = 'Open Mesh';
    }
    async function create_mesh() {
      const name = document.getElementById('new-name').value.trim();
      const path = document.getElementById('new-path').value.trim();
      const err  = document.getElementById('err-new');
      if (!name) { err.textContent = 'Name is required'; return; }
      if (!path) { err.textContent = 'Directory is required'; return; }
      const btn = document.getElementById('btn-new');
      btn.disabled = true; btn.textContent = 'Creating\u2026';
      const r = await fetch('/api/create-mesh', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name, path})
      });
      const d = await r.json();
      if (d.ok) { window.location.href = '/'; return; }
      err.textContent = d.error || 'Unknown error';
      btn.disabled = false; btn.textContent = 'Create Mesh';
    }
    document.getElementById('open-path').addEventListener('keydown', e => {
      if (e.key === 'Enter') open_mesh();
    });
  </script>
</body>
</html>"#;

// ── Server ────────────────────────────────────────────────────────────────────

/// Start the Helm HTTP server and block, serving requests on `127.0.0.1:PORT`.
///
/// `initial_mesh` may be `None` when no mesh is found at launch; in that case
/// the setup page is served until the user provides a path via `/api/setup`.
pub fn serve(initial_mesh: Option<PathBuf>) {
    update_check::spawn_update_check();

    let addr = format!("127.0.0.1:{}", PORT);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("helm: cannot bind {} — is another helm already running? ({})", addr, e);
            std::process::exit(1);
        }
    };
    eprintln!("Helm listening on http://{}", addr);

    // Open the browser after the port is bound so it's always ready.
    let url = format!("http://{}", addr);
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        open_browser(&url);
    });

    // Persist the initial mesh so it appears in the dropdown on next launch.
    if let Some(ref root) = initial_mesh {
        save_last_mesh(root);
    }
    let mesh_root: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(initial_mesh));

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let _ = stream.set_nodelay(true);
                let mesh_root = Arc::clone(&mesh_root);
                thread::spawn(move || {
                    let req = match parse_request(&mut stream) {
                        Some(r) => r,
                        None => return,
                    };
                    let resp = {
                        let mut guard = mesh_root.lock().unwrap();
                        route(&req, &mut guard)
                    };
                    write_response(&mut stream, resp);
                });
            }
            Err(_) => {}
        }
    }
}

fn route(req: &crate::helm::http::Request, mesh_root: &mut Option<PathBuf>) -> Response {
    let path  = req.path.as_str();
    let method = req.method.as_str();

    // Static assets — always available
    match (method, path) {
        ("GET", "/helm.js")        => return Response::ok_js(HELM_JS),
        ("GET", "/graph.js")       => return Response::ok_js(GRAPH_JS),
        ("GET", "/board.js")       => return Response::ok_js(BOARD_JS),
        ("GET", "/helm.css")       => return Response::ok_css(HELM_CSS),
        ("GET", "/crux_icon.png")  => return Response::ok_png(CRUX_ICON),
        ("GET", "/crux_icon.svg")  => return Response::ok_svg(CRUX_ICON_SVG),
        _ => {}
    }

    // Endpoints that can mutate mesh_root — must come before the root borrow below
    if method == "POST" && path == "/api/setup" {
        return handle_setup(req, mesh_root);
    }
    if method == "POST" && path == "/api/switch-mesh" {
        return handle_switch_mesh(req, mesh_root);
    }
    if method == "POST" && path == "/api/create-mesh" {
        return handle_create_mesh_init(req, mesh_root);
    }
    if method == "GET" && path == "/api/known-meshes" {
        return handle_get_known_meshes();
    }
    if method == "GET" && path == "/api/update-check" {
        let body = update_check::update_check_json();
        return Response::ok_json(body);
    }

    // Root: serve setup page if no mesh is configured yet
    if method == "GET" && path == "/" {
        return match mesh_root {
            Some(_) => Response::ok_html(INDEX_HTML),
            None    => Response::ok_html(SETUP_HTML),
        };
    }

    // All remaining routes require a mesh
    let root = match mesh_root {
        Some(r) => r.as_path(),
        None    => return Response::server_error("no mesh configured — open http://127.0.0.1:8111 to set one up"),
    };

    match (method, path) {
        ("GET",  "/api/mesh")           => handle_get_mesh(root),
        ("GET",  "/api/file")           => handle_get_file(root, req),
        ("GET",  "/api/crux")           => handle_get_crux(root, req),
        ("GET",  "/api/crux/query")     => handle_query_crux(root, req),
        ("POST", "/api/node/update")    => handle_update_node(root, req),
        ("POST", "/api/node/add")       => handle_add_node(root, req),
        ("POST", "/api/edge/add")       => handle_add_edge(root, req),
        ("POST", "/api/crux/create")     => handle_create_crux(root, req),
        ("POST", "/api/crux/generate")  => handle_generate_preview(req),
        ("POST", "/api/crux/import-csv") => handle_import_csv(root, req),
        ("GET",  "/api/ai/config")      => handle_ai_config(),
        ("POST", "/api/ai/bootstrap")   => handle_ai_bootstrap(root, req),
        ("GET",  "/api/mcp/list")       => handle_mcp_list(root),
        ("POST", "/api/mcp/register")   => handle_mcp_register(root, req),
        ("POST", "/api/mcp/revoke")     => handle_mcp_revoke(root, req),
        ("GET",  "/api/mcp/discovered")    => handle_mcp_discovered(root),
        ("POST", "/api/mcp/scan")          => handle_mcp_scan(root),
        ("POST", "/api/mcp/approve")       => handle_mcp_approve(root, req),
        ("GET",  "/api/mcp/external")      => handle_mcp_external(root),
        ("POST", "/api/mcp/route_external")=> handle_mcp_route_external(root, req),
        ("POST", "/api/crux/join")          => handle_join_crux(root, req),
        _ => Response::not_found(),
    }
}

fn handle_join_crux(mesh_root: &Path, req: &crate::helm::http::Request) -> Response {
    use crate::json::extract_string_value;
    use crate::mesh::join_mesh;

    let body = req.body_str();
    let crux_path = match extract_string_value(body, "path") {
        Some(p) => p,
        None => return Response::bad_request("missing 'path'"),
    };
    match join_mesh(mesh_root, crux_path.trim()) {
        Ok(_)  => Response::ok_json("{\"ok\":true}".to_string()),
        Err(e) => Response::bad_request(&e),
    }
}

// ── Setup handler ─────────────────────────────────────────────────────────────

fn handle_setup(req: &crate::helm::http::Request, mesh_root: &mut Option<PathBuf>) -> Response {
    use crate::json::extract_string_value;
    use crate::mesh::load_mesh;

    let body = req.body_str();
    let raw_path = match extract_string_value(body, "path") {
        Some(p) => p,
        None => return Response::bad_request("missing 'path'"),
    };

    let candidate = PathBuf::from(raw_path.trim());

    // Accept either the dir containing .crux-mesh.json or the file itself
    let mesh_dir = if candidate.join(".crux-mesh.json").exists() {
        candidate
    } else if candidate.file_name().map(|n| n == ".crux-mesh.json").unwrap_or(false) {
        candidate.parent().unwrap_or(&candidate).to_path_buf()
    } else {
        return Response::server_error(&format!(
            "no .crux-mesh.json found in {}",
            json_escape(&raw_path)
        ));
    };

    // Validate it actually loads
    if let Err(e) = load_mesh(&mesh_dir) {
        return Response::server_error(&e);
    }

    // Persist and activate
    save_last_mesh(&mesh_dir);
    *mesh_root = Some(mesh_dir);

    Response::ok_json("{\"ok\": true}".to_string())
}

// ── Last-mesh persistence ─────────────────────────────────────────────────────

fn config_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    Some(PathBuf::from(home).join(".config").join("helm"))
}

pub fn load_last_mesh() -> Option<PathBuf> {
    let text = std::fs::read_to_string(config_dir()?.join("last_mesh")).ok()?;
    let t = text.trim();
    if t.is_empty() { None } else { Some(PathBuf::from(t)) }
}

pub fn save_last_mesh(mesh_root: &Path) {
    if let Some(dir) = config_dir() {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("last_mesh"), mesh_root.to_string_lossy().as_bytes());
    }
    add_known_mesh(mesh_root);
}

/// Return all known mesh paths, most-recently-used first.
pub fn load_known_meshes() -> Vec<PathBuf> {
    let path = match config_dir() {
        Some(d) => d.join("known_meshes"),
        None => return Vec::new(),
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.join(".crux-mesh.json").exists())
        .collect()
}

/// Add a mesh path to the known-meshes list (deduped, most-recent first).
pub fn add_known_mesh(mesh_root: &Path) {
    let Some(dir) = config_dir() else { return };
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("known_meshes");
    let canonical = mesh_root.to_string_lossy().to_string();
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut lines: Vec<&str> = existing.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != canonical.as_str())
        .collect();
    lines.insert(0, &canonical);
    let _ = std::fs::write(&path, lines.join("\n") + "\n");
}

// ── Browser launch ────────────────────────────────────────────────────────────

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open")
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd").args(["/c", "start", url]).spawn();
}
