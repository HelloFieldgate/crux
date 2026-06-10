//! Helm API handlers.
//!
//! Each function takes the mesh root path, a parsed Request, and returns a Response.

use std::fmt::Write as FmtWrite;
use std::path::{Path, PathBuf};

use crate::helm::http::{Request, Response};
use crate::json::{extract_string_value, json_escape, json_opt_str, json_str_array, extract_json_objects_from_array};
use crate::mesh::{load_mesh, MeshManifest};
use crate::schema::{
    load_crux_db, save_crux_db, serialize_crux_db, CruxEdge, CruxNode, EdgeKind,
    NodeSchema, PlanningMetadata, SecurityMetadata, generate_node_id, generate_edge_id,
    now_unix,
};

// ===========================================================================
// Path resolution
// ===========================================================================

/// Resolve a member path to an absolute crux directory.
///
/// `member_path` may be:
/// - An absolute path (starts with `/`) → used as-is
/// - A relative path → joined with `mesh_root`
///
/// The resolved path is a directory that should contain `.crux.json`.
pub fn resolve_crux_dir(mesh_root: &Path, member_path: &str) -> PathBuf {
    let p = Path::new(member_path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        mesh_root.join(member_path)
    }
}

// ===========================================================================
// GET /api/mesh
// ===========================================================================

/// Return the mesh manifest as JSON, with private keys stripped.
pub fn handle_get_mesh(mesh_root: &Path) -> Response {
    match load_mesh(mesh_root) {
        Ok(manifest) => Response::ok_json(serialize_mesh_for_ui(&manifest, mesh_root)),
        Err(e) => Response::server_error(&e),
    }
}

fn serialize_mesh_for_ui(manifest: &MeshManifest, mesh_root: &Path) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("{\n");
    let _ = writeln!(out, "  \"mesh_name\": {},", json_escape(&manifest.mesh_name));
    let _ = writeln!(out, "  \"mesh_id\": {},", json_escape(&manifest.mesh_id));
    let _ = writeln!(out, "  \"mesh_version\": {},", manifest.mesh_version);
    let _ = writeln!(out, "  \"created_at\": {},", manifest.created_at);

    out.push_str("  \"members\": [");
    for (i, m) in manifest.members.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("\n    {");
        let _ = write!(out, "\"crux_id\": {},", json_escape(&m.crux_id));
        let _ = write!(out, " \"crux_name\": {},", json_escape(&m.crux_name));
        let _ = write!(out, " \"crux_kind\": {},", json_escape(m.crux_kind.as_str()));
        let _ = write!(out, " \"path\": {},", json_escape(&m.path));
        let _ = write!(out, " \"status\": {},", json_escape(&m.status));
        let _ = write!(out, " \"last_seen\": {},", m.last_seen);
        let _ = write!(out, " \"replica_group\": {},", json_opt_str(&m.replica_group));
        let _ = write!(out, " \"cluster\": {}", json_opt_str(&m.cluster));

        // Compute the resolved absolute path for the frontend
        let crux_dir = resolve_crux_dir(mesh_root, &m.path);
        let _ = write!(out, ", \"abs_path\": {}", json_escape(&crux_dir.to_string_lossy()));
        out.push('}');
    }
    out.push_str("\n  ],\n");

    out.push_str("  \"cross_edges\": [");
    for (i, ce) in manifest.cross_edges.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"src_crux\": {}, \"dst_crux\": {}, \"edge_count\": {}, \"last_synced\": {}}}",
            json_escape(&ce.src_crux),
            json_escape(&ce.dst_crux),
            ce.edge_count,
            ce.last_synced
        );
    }
    out.push_str("],\n");

    let _ = writeln!(
        out,
        "  \"default_classification\": {}",
        json_escape(&manifest.security.default_classification)
    );
    out.push('}');
    out
}

// ===========================================================================
// GET /api/crux?path=X
// ===========================================================================

/// Return a full crux as JSON. `path` is a member path (relative or absolute).
pub fn handle_get_crux(mesh_root: &Path, req: &Request) -> Response {
    let member_path = match req.query.get("path") {
        Some(p) => p.clone(),
        None => return Response::bad_request("missing 'path' query parameter"),
    };
    let crux_dir = resolve_crux_dir(mesh_root, &member_path);
    match load_crux_db(&crux_dir) {
        Ok(db) => Response::ok_json(serialize_crux_db(&db)),
        Err(e) => Response::server_error(&e),
    }
}

// ===========================================================================
// GET /api/crux/query?path=X&q=Y
// ===========================================================================

/// Filter nodes with structured query params.
/// Accepts: path (required), q, kind, status, tag, property, since, sort, limit.
pub fn handle_query_crux(mesh_root: &Path, req: &Request) -> Response {
    let member_path = match req.query.get("path") {
        Some(p) => p.clone(),
        None => return Response::bad_request("missing 'path' query parameter"),
    };
    let filter = crate::query::NodeFilter::from_query_params(&req.query);
    let crux_dir = resolve_crux_dir(mesh_root, &member_path);

    match load_crux_db(&crux_dir) {
        Ok(db) => {
            let mut matching: Vec<&CruxNode> = db
                .nodes
                .iter()
                .filter(|n| filter.matches(n))
                .collect();
            filter.apply_sort(&mut matching);
            let matching: Vec<&CruxNode> = matching.into_iter().take(filter.limit).collect();

            let mut out = String::from("[");
            for (i, n) in matching.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serialize_node_compact(n));
            }
            out.push(']');
            Response::ok_json(out)
        }
        Err(e) => Response::server_error(&e),
    }
}

fn serialize_node_compact(n: &CruxNode) -> String {
    let mut out = String::from("{");
    let _ = write!(out, "\"node_id\": {},", json_escape(&n.node_id));
    let _ = write!(out, " \"name\": {},", json_escape(&n.name));
    let _ = write!(out, " \"kind\": {},", json_escape(&n.kind));
    let _ = write!(out, " \"module\": {},", json_escape(&n.module));
    let _ = write!(out, " \"summary\": {},", json_escape(&n.summary));
    let _ = write!(out, " \"tags\": {},", json_str_array(&n.tags));
    let _ = write!(out, " \"properties\": {},", json_str_array(&n.properties));
    // planning: status + priority (needed for client-side filtering and display)
    let status_json = match &n.planning.status {
        Some(s) => json_escape(s),
        None => "null".to_string(),
    };
    let priority_json = match n.planning.priority {
        Some(p) => p.to_string(),
        None => "null".to_string(),
    };
    let _ = write!(out, " \"planning\": {{\"status\": {}, \"priority\": {}}},", status_json, priority_json);
    // updated_at from planning (closest available timestamp on nodes)
    let updated_at_json = match n.planning.updated_at {
        Some(ts) => ts.to_string(),
        None => "null".to_string(),
    };
    let _ = write!(out, " \"updated_at\": {}", updated_at_json);
    out.push('}');
    out
}

// ===========================================================================
// POST /api/node/update  { crux_path, node_id, summary?, tags?, properties? }
// ===========================================================================

pub fn handle_update_node(mesh_root: &Path, req: &Request) -> Response {
    let body = req.body_str();
    let crux_path = match extract_string_value(body, "crux_path") {
        Some(p) => p,
        None => return Response::bad_request("missing 'crux_path'"),
    };
    let node_id = match extract_string_value(body, "node_id") {
        Some(id) => id,
        None => return Response::bad_request("missing 'node_id'"),
    };
    let crux_dir = resolve_crux_dir(mesh_root, &crux_path);

    let mut db = match load_crux_db(&crux_dir) {
        Ok(db) => db,
        Err(e) => return Response::server_error(&e),
    };

    let node = match db.nodes.iter_mut().find(|n| n.node_id == node_id) {
        Some(n) => n,
        None => return Response::bad_request("node not found"),
    };

    if let Some(summary) = extract_string_value(body, "summary") {
        node.summary = summary;
    }
    if let Some(kind) = extract_string_value(body, "kind") {
        node.kind = kind;
    }

    // tags: JSON array of strings — simple extraction
    if let Some(tags_raw) = extract_array_value(body, "tags") {
        node.tags = tags_raw;
    }
    if let Some(props_raw) = extract_array_value(body, "properties") {
        node.properties = props_raw;
    }

    // Planning fields
    if let Some(status) = extract_string_value(body, "status") {
        node.planning.status = if status.is_empty() { None } else { Some(status) };
    }
    if let Some(p_str) = extract_string_value(body, "priority") {
        node.planning.priority = p_str.parse::<u8>().ok();
    }

    db.header.last_modified_at = now_unix();

    match save_crux_db(&db, &crux_dir) {
        Ok(()) => Response::ok_json("{\"ok\": true}".to_string()),
        Err(e) => Response::server_error(&e),
    }
}

// ===========================================================================
// POST /api/node/add  { crux_path, name, kind, summary, tags?, module? }
// ===========================================================================

pub fn handle_add_node(mesh_root: &Path, req: &Request) -> Response {
    let body = req.body_str();
    let crux_path = match extract_string_value(body, "crux_path") {
        Some(p) => p,
        None => return Response::bad_request("missing 'crux_path'"),
    };
    let name = match extract_string_value(body, "name") {
        Some(n) => n,
        None => return Response::bad_request("missing 'name'"),
    };
    let kind = extract_string_value(body, "kind").unwrap_or_else(|| "concept".to_string());
    let summary = extract_string_value(body, "summary").unwrap_or_default();
    let module = extract_string_value(body, "module").unwrap_or_default();
    let tags = extract_array_value(body, "tags").unwrap_or_default();

    let crux_dir = resolve_crux_dir(mesh_root, &crux_path);
    let mut db = match load_crux_db(&crux_dir) {
        Ok(db) => db,
        Err(e) => return Response::server_error(&e),
    };

    let content_hash = format!("sha256:{:x}", now_unix());
    let node_id = generate_node_id(&name, &content_hash);
    let node = CruxNode {
        node_id: node_id.clone(),
        name,
        kind,
        module,
        summary,
        schema: NodeSchema::empty(),
        tags,
        reach: Vec::new(),
        properties: Vec::new(),
        warnings: Vec::new(),
        planning: PlanningMetadata::empty(),
        security: SecurityMetadata {
            classification: "internal".to_string(),
            redact_below: None,
        },
        content_hash,
        deleted_at: None,
    };

    db.nodes.push(node);
    db.header.last_modified_at = now_unix();

    match save_crux_db(&db, &crux_dir) {
        Ok(()) => Response::ok_json(format!("{{\"ok\": true, \"node_id\": {}}}", json_escape(&node_id))),
        Err(e) => Response::server_error(&e),
    }
}

// ===========================================================================
// POST /api/edge/add  { crux_path, src, dst, kind, detail? }
// ===========================================================================

pub fn handle_add_edge(mesh_root: &Path, req: &Request) -> Response {
    let body = req.body_str();
    let crux_path = match extract_string_value(body, "crux_path") {
        Some(p) => p,
        None => return Response::bad_request("missing 'crux_path'"),
    };
    let src = match extract_string_value(body, "src") {
        Some(s) => s,
        None => return Response::bad_request("missing 'src'"),
    };
    let dst = match extract_string_value(body, "dst") {
        Some(d) => d,
        None => return Response::bad_request("missing 'dst'"),
    };
    let kind_str = extract_string_value(body, "kind").unwrap_or_else(|| "relates_to".to_string());
    let detail = extract_string_value(body, "detail").unwrap_or_default();

    let edge_kind = EdgeKind::from_str(&kind_str);
    let crux_dir = resolve_crux_dir(mesh_root, &crux_path);
    let mut db = match load_crux_db(&crux_dir) {
        Ok(db) => db,
        Err(e) => return Response::server_error(&e),
    };

    let edge_id = generate_edge_id(&src, &dst, &kind_str);
    let edge = CruxEdge {
        edge_id: edge_id.clone(),
        src,
        dst,
        kind: edge_kind,
        weight: 1.0,
        detail,
        cross_crux: false,
        binding: String::new(),
        created_at: now_unix(),
        dangling: false,
    };

    db.edges.push(edge);
    db.header.last_modified_at = now_unix();

    match save_crux_db(&db, &crux_dir) {
        Ok(()) => Response::ok_json(format!("{{\"ok\": true, \"edge_id\": {}}}", json_escape(&edge_id))),
        Err(e) => Response::server_error(&e),
    }
}

// ===========================================================================
// POST /api/crux/create  { name, kind, source_path }
// ===========================================================================

pub fn handle_create_crux(mesh_root: &Path, req: &Request) -> Response {
    use crate::adapters::scanner::{generate_dir, GroupingStrategy};
    use crate::mesh::join_mesh;
    use crate::schema::{create_crux_db, CruxKind};

    let body = req.body_str();
    let name = match extract_string_value(body, "name") {
        Some(n) => n,
        None => return Response::bad_request("missing 'name'"),
    };
    let kind_str =
        extract_string_value(body, "kind").unwrap_or_else(|| "codebase".to_string());
    let source_path = extract_string_value(body, "source_path");

    let crux_kind = CruxKind::from_str(&kind_str);
    let crux_dir = mesh_root.join(&name);

    // If source_path given, generate from directory scan; otherwise create empty
    if let Some(src) = source_path {
        let src_path = Path::new(&src);
        let result = generate_dir(
            src_path,
            &crux_dir,
            &name,
            GroupingStrategy::Flat,
            None,
            None,
            None,
        );
        match result {
            Err(e) => return Response::server_error(&e),
            Ok(_) => {}
        }
    } else {
        // Create empty crux
        let db = create_crux_db(&name, crux_kind, "helm");
        if let Err(e) = save_crux_db(&db, &crux_dir) {
            return Response::server_error(&e);
        }
    }

    // Join to mesh
    match join_mesh(mesh_root, &name) {
        Ok(_) => Response::ok_json(format!("{{\"ok\": true, \"crux_name\": {}}}", json_escape(&name))),
        Err(e) => Response::server_error(&e),
    }
}

// ===========================================================================
// POST /api/crux/generate  { source_path, name? }  — dry-run scan preview
// ===========================================================================

pub fn handle_generate_preview(req: &Request) -> Response {
    use crate::adapters::scanner::scan_directory;

    let body = req.body_str();
    let source_path = match extract_string_value(body, "source_path") {
        Some(p) => p,
        None => return Response::bad_request("missing 'source_path'"),
    };

    let src = Path::new(&source_path);
    match scan_directory(src, Some(3), &[]) {
        Ok(result) => {
            let mut out = String::from("{\"files\": [");
            for (i, f) in result.files.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(
                    out,
                    "{{\"path\": {}, \"kind\": {}, \"size\": {}}}",
                    json_escape(&f.relative_path),
                    json_escape(f.kind.as_str()),
                    f.size_bytes
                );
            }
            let _ = write!(out, "], \"total\": {}}}", result.files.len());
            Response::ok_json(out)
        }
        Err(e) => Response::server_error(&e),
    }
}

// ===========================================================================
// Helper: extract a JSON array of strings from a body
// ===========================================================================

// ===========================================================================
// GET /api/known-meshes
// ===========================================================================

/// Return all known mesh paths as a JSON array of {path, name} objects.
pub fn handle_get_known_meshes() -> Response {
    use crate::helm::load_known_meshes;
    use crate::mesh::load_mesh;

    let known = load_known_meshes();
    let mut out = String::from("[");
    let mut first = true;
    for mesh_dir in &known {
        let name = match load_mesh(mesh_dir) {
            Ok(m) => m.mesh_name,
            Err(_) => continue,
        };
        if !first { out.push(','); }
        first = false;
        let _ = write!(
            out,
            "{{\"path\": {}, \"name\": {}}}",
            json_escape(&mesh_dir.to_string_lossy()),
            json_escape(&name)
        );
    }
    out.push(']');
    Response::ok_json(out)
}

// ===========================================================================
// POST /api/switch-mesh  { path }
// ===========================================================================

/// Switch to a different mesh. Updates the live mesh_root and persists last_mesh.
pub fn handle_switch_mesh(req: &Request, mesh_root: &mut Option<PathBuf>) -> Response {
    use crate::helm::{add_known_mesh, save_last_mesh};

    let body = req.body_str();
    let raw_path = match extract_string_value(body, "path") {
        Some(p) => p,
        None => return Response::bad_request("missing 'path'"),
    };
    let candidate = PathBuf::from(raw_path.trim());
    if !candidate.join(".crux-mesh.json").exists() {
        return Response::server_error(&format!(
            "no .crux-mesh.json found in {}",
            candidate.display()
        ));
    }
    if let Err(e) = load_mesh(&candidate) {
        return Response::server_error(&e);
    }
    save_last_mesh(&candidate);
    add_known_mesh(&candidate);
    *mesh_root = Some(candidate);
    Response::ok_json("{\"ok\": true}".to_string())
}

// ===========================================================================
// POST /api/create-mesh  { name, path }
// ===========================================================================

/// Create a new mesh (with auto-generated policy crux) at the given directory.
pub fn handle_create_mesh_init(req: &Request, mesh_root: &mut Option<PathBuf>) -> Response {
    use crate::helm::{add_known_mesh, save_last_mesh};
    use crate::mesh::init_mesh;

    let body = req.body_str();
    let name = match extract_string_value(body, "name") {
        Some(n) => n,
        None => return Response::bad_request("missing 'name'"),
    };
    let raw_path = match extract_string_value(body, "path") {
        Some(p) => p,
        None => return Response::bad_request("missing 'path'"),
    };
    let mesh_dir = PathBuf::from(raw_path.trim());
    if let Err(e) = std::fs::create_dir_all(&mesh_dir) {
        return Response::server_error(&format!("cannot create directory: {}", e));
    }
    match init_mesh(&name, &mesh_dir) {
        Ok(_) => {
            save_last_mesh(&mesh_dir);
            add_known_mesh(&mesh_dir);
            *mesh_root = Some(mesh_dir.clone());
            Response::ok_json(format!(
                "{{\"ok\": true, \"name\": {}, \"path\": {}}}",
                json_escape(&name),
                json_escape(&mesh_dir.to_string_lossy())
            ))
        }
        Err(e) => Response::server_error(&e),
    }
}

// ===========================================================================
// Helper: extract a JSON string array `"key": ["a", "b"]` from body text.
// ===========================================================================

/// Extract a JSON string array `"key": ["a", "b"]` from body text.
fn extract_array_value(body: &str, key: &str) -> Option<Vec<String>> {
    let pattern = format!("\"{}\"", key);
    let pos = body.find(&pattern)?;
    let after_key = &body[pos + pattern.len()..];
    let colon = after_key.find(':')? + 1;
    let after_colon = after_key[colon..].trim_start();
    if !after_colon.starts_with('[') {
        return None;
    }
    let bracket_end = after_colon.find(']')?;
    let inner = &after_colon[1..bracket_end];

    let items: Vec<String> = inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Some(items)
}

// ===========================================================================
// GET /api/file?path=<relative-path>
// ===========================================================================

/// Serve a file relative to the mesh root (e.g. assets/image.png).
/// Rejects absolute paths and any path containing `..` components.
/// Symlinks within the mesh tree (e.g. mesh/assets -> ../assets) are permitted.
pub fn handle_get_file(mesh_root: &Path, req: &Request) -> Response {
    let rel = match req.query.get("path") {
        Some(p) => p.clone(),
        None => return Response::bad_request("missing 'path' query parameter"),
    };

    // Reject absolute paths and any `..` traversal (catches both raw and
    // percent-decoded forms since query parsing already URL-decodes values).
    if rel.starts_with('/') || rel.contains("..") {
        return Response::bad_request("path traversal not allowed");
    }

    let candidate = mesh_root.join(&rel);
    let data = match std::fs::read(&candidate) {
        Ok(d) => d,
        Err(_) => return Response::not_found(),
    };

    let ext = candidate.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    let content_type: &'static str = match ext.as_str() {
        "png"  => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif"  => "image/gif",
        "svg"  => "image/svg+xml",
        "webp" => "image/webp",
        "pdf"  => "application/pdf",
        _      => "application/octet-stream",
    };

    Response { status: 200, content_type, body: data }
}

// ===========================================================================
// GET /api/ai/config
// ===========================================================================

/// Returns the active LLM provider: "anthropic", "ollama", or "none".
pub fn handle_ai_config() -> Response {
    let provider = if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        "anthropic"
    } else if std::env::var("OLLAMA_URL").is_ok() {
        "ollama"
    } else {
        "none"
    };
    Response::ok_json(format!("{{\"provider\":{}}}", json_escape(provider)))
}

// ===========================================================================
// POST /api/ai/bootstrap  { crux_path, description }
// ===========================================================================

const BOOTSTRAP_SYSTEM_PROMPT: &str = "\
You are seeding a knowledge graph called a crux. \
Respond with ONLY valid JSON — no prose, no markdown fences.\n\
Schema: {\"nodes\":[{\"name\":\"...\",\"kind\":\"...\",\"summary\":\"one sentence\",\"tags\":\"tag1,tag2\"}],\
\"edges\":[{\"src\":\"node name\",\"dst\":\"node name\",\"kind\":\"edge kind\"}]}\n\
Node kinds: task, concept, person, document, record, milestone, module\n\
Edge kinds: relates_to, contains, produces, belongs_to_domain, supersedes, reads, writes\n\
Use 6-15 nodes. For tasks use tags=\"Todo\". Keep names 2-4 words. No duplicate names.";

pub fn handle_ai_bootstrap(mesh_root: &Path, req: &Request) -> Response {
    let body = req.body_str();
    let crux_path = match extract_string_value(body, "crux_path") {
        Some(p) => p,
        None => return Response::bad_request("missing 'crux_path'"),
    };
    let description = match extract_string_value(body, "description") {
        Some(d) => d,
        None => return Response::bad_request("missing 'description'"),
    };

    let crux_dir = resolve_crux_dir(mesh_root, &crux_path);

    // If no LLM configured, return a copy-prompt response.
    let has_anthropic = std::env::var("ANTHROPIC_API_KEY").is_ok();
    let has_ollama    = std::env::var("OLLAMA_URL").is_ok();

    if !has_anthropic && !has_ollama {
        // Build the same prompt that the MCP bootstrap action returns so the
        // user can paste it into Claude Code.
        let crux_name = match load_crux_db(&crux_dir) {
            Ok(db) => db.header.crux_name,
            Err(_) => crux_path.clone(),
        };
        let prompt = format!(
            "Bootstrap crux '{}' at: {}\n\
             Description: {}\n\n\
             ## Node kinds\n\
             task, concept, person, document, record, milestone, module, channel\n\n\
             ## Edge kinds\n\
             relates_to, contains, produces, belongs_to_domain, supersedes, reads, writes\n\n\
             Generate 6–15 nodes and appropriate edges for the description above.\n\
             Call `crux add_nodes` with path=\"{}\" and a nodes JSON array.\n\
             Then call `crux add_edges` with path=\"{}\" and an edges JSON array.\n\n\
             Node format: [{{\"name\":\"short name\",\"kind\":\"kind\",\"summary\":\"one sentence\",\"tags\":\"tag1,tag2\"}}]\n\
             Edge format: [{{\"src\":\"node name\",\"dst\":\"node name\",\"kind\":\"edge kind\"}}]\n\
             Keep names short (2–4 words). For tasks use tags=\"Todo\".",
            crux_name, crux_path, description, crux_path, crux_path
        );
        return Response::ok_json(format!(
            "{{\"mode\":\"copy-prompt\",\"prompt\":{}}}",
            json_escape(&prompt)
        ));
    }

    // Call the LLM.
    let user_msg = format!("Create a crux for: {}", description);
    let llm_result = if has_anthropic {
        let key = std::env::var("ANTHROPIC_API_KEY").unwrap();
        call_llm_anthropic(&key, &user_msg)
    } else {
        let url = std::env::var("OLLAMA_URL").unwrap();
        let model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3".to_string());
        call_llm_ollama(&url, &model, &user_msg)
    };

    let llm_output = match llm_result {
        Ok(s) => s,
        Err(e) => return Response::server_error(&format!("LLM call failed: {}", e)),
    };

    match seed_from_llm_response(mesh_root, &crux_path, &llm_output) {
        Ok((nodes_added, edges_added)) => Response::ok_json(format!(
            "{{\"ok\":true,\"nodes_added\":{},\"edges_added\":{}}}",
            nodes_added, edges_added
        )),
        Err(e) => Response::server_error(&format!("Seeding failed: {}", e)),
    }
}

// ===========================================================================
// POST /api/crux/import-csv
// Body: { crux_name, csv_content, column_mappings?, node_kind?, crux_path? }
// ===========================================================================

/// Import CSV rows as nodes into an existing or new crux.
///
/// - `crux_name`       — name for the crux (used when creating a new one)
/// - `csv_content`     — full CSV text (RFC 4180, UTF-8) — required
/// - `column_mappings` — JSON array of `{"column":"ColName","field":"name|kind|summary|tags|skip"}`
/// - `node_kind`       — default node kind (default: `"record"`)
/// - `crux_path`       — path to existing crux to merge into; absent → create new
pub fn handle_import_csv(mesh_root: &Path, req: &Request) -> Response {
    use crate::adapters::csv::{CsvAdapter, ColumnMap};
    use crate::adapters::AdapterConfig;
    use crate::mesh::join_mesh;

    let body = req.body_str();

    let crux_name = extract_string_value(body, "crux_name")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "CSV Import".to_string());

    let csv_content = match extract_string_value(body, "csv_content") {
        Some(c) if !c.is_empty() => c,
        _ => return Response::bad_request("missing 'csv_content'"),
    };

    let node_kind = extract_string_value(body, "node_kind")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "record".to_string());

    // Parse column_mappings: [{"column":"Name","field":"name"}, ...]
    let mut col_map: ColumnMap = ColumnMap::new();
    if let Some(key_pos) = body.find("\"column_mappings\"") {
        let after_key = &body[key_pos + 17..]; // skip "column_mappings"
        if let Some(arr_start) = after_key.find('[') {
            let arr_text = &after_key[arr_start..];
            for obj in extract_json_objects_from_array(arr_text) {
                if let (Some(col), Some(field)) = (
                    extract_string_value(&obj, "column"),
                    extract_string_value(&obj, "field"),
                ) {
                    col_map.insert(col, field);
                }
            }
        }
    }

    // Resolve crux directory
    let crux_path_raw = extract_string_value(body, "crux_path").unwrap_or_default();
    let crux_dir = if crux_path_raw.is_empty() {
        // New crux: sanitise name → directory name
        let safe_name: String = crux_name.to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
            .collect();
        mesh_root.join(&safe_name)
    } else {
        resolve_crux_dir(mesh_root, &crux_path_raw)
    };

    let config = AdapterConfig {
        name: crux_name.clone(),
        origin: "csv".to_string(),
        default_classification: Some("internal".to_string()),
        default_module: None,
        schema_hints: col_map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    };

    let imported_db = match CsvAdapter::generate_with_map(&csv_content, &config, &col_map, &node_kind) {
        Ok(db) => db,
        Err(e) => return Response::bad_request(&e),
    };

    let nodes_added = imported_db.nodes.len();

    // Merge into existing crux, or create new
    if crux_dir.join(".crux.json").exists() {
        let mut existing = match load_crux_db(&crux_dir) {
            Ok(db) => db,
            Err(e) => return Response::server_error(&e),
        };
        existing.nodes.extend(imported_db.nodes);
        if let Err(e) = save_crux_db(&existing, &crux_dir) {
            return Response::server_error(&e);
        }
    } else {
        if let Err(e) = std::fs::create_dir_all(&crux_dir) {
            return Response::server_error(&format!("Cannot create crux dir: {}", e));
        }
        if let Err(e) = save_crux_db(&imported_db, &crux_dir) {
            return Response::server_error(&e);
        }
        if let Err(e) = join_mesh(mesh_root, crux_dir.to_str().unwrap_or("")) {
            return Response::server_error(&e);
        }
    }

    let crux_path_out = crux_dir.to_string_lossy();
    Response::ok_json(format!(
        "{{\"ok\":true,\"nodes_added\":{},\"crux_path\":{},\"crux_name\":{}}}",
        nodes_added,
        json_escape(&crux_path_out),
        json_escape(&crux_name),
    ))
}

// ===========================================================================
// LLM call helpers
// ===========================================================================

fn call_llm_anthropic(api_key: &str, user_msg: &str) -> Result<String, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let payload = format!(
        "{{\"model\":\"claude-haiku-4-5-20251001\",\"max_tokens\":1024,\
         \"system\":{},\"messages\":[{{\"role\":\"user\",\"content\":{}}}]}}",
        json_escape(BOOTSTRAP_SYSTEM_PROMPT),
        json_escape(user_msg)
    );

    let mut child = Command::new("curl")
        .args([
            "-s", "--max-time", "30",
            "-X", "POST",
            "https://api.anthropic.com/v1/messages",
            "-H", &format!("x-api-key: {}", api_key),
            "-H", "anthropic-version: 2023-06-01",
            "-H", "content-type: application/json",
            "-d", "@-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl spawn failed: {}", e))?;

    if let Some(stdin) = child.stdin.take() {
        let mut stdin = stdin;
        stdin.write_all(payload.as_bytes())
            .map_err(|e| format!("curl write failed: {}", e))?;
    }

    let output = child.wait_with_output()
        .map_err(|e| format!("curl wait failed: {}", e))?;
    let text = String::from_utf8_lossy(&output.stdout).to_string();

    // Anthropic response: {"content":[{"type":"text","text":"..."}],...}
    // Find the "text" value inside the first content object.
    let content_start = text.find("\"content\"").ok_or_else(|| format!("No content in response: {}", &text[..text.len().min(300)]))?;
    let after_content = &text[content_start..];
    extract_string_value(after_content, "text")
        .ok_or_else(|| format!("Could not extract text from response: {}", &text[..text.len().min(300)]))
}

fn call_llm_ollama(base_url: &str, model: &str, user_msg: &str) -> Result<String, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let prompt = format!("{}\n\nUser: {}", BOOTSTRAP_SYSTEM_PROMPT, user_msg);
    let payload = format!(
        "{{\"model\":{},\"prompt\":{},\"stream\":false}}",
        json_escape(model),
        json_escape(&prompt)
    );
    let url = format!("{}/api/generate", base_url.trim_end_matches('/'));

    let mut child = Command::new("curl")
        .args(["-s", "--max-time", "60", "-X", "POST", &url,
               "-H", "content-type: application/json", "-d", "@-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl spawn failed: {}", e))?;

    if let Some(stdin) = child.stdin.take() {
        let mut stdin = stdin;
        stdin.write_all(payload.as_bytes())
            .map_err(|e| format!("curl write failed: {}", e))?;
    }

    let output = child.wait_with_output()
        .map_err(|e| format!("curl wait failed: {}", e))?;
    let text = String::from_utf8_lossy(&output.stdout).to_string();

    extract_string_value(&text, "response")
        .ok_or_else(|| format!("Could not extract response from ollama output: {}", &text[..text.len().min(300)]))
}

// ===========================================================================
// Seed a crux from LLM JSON output
// ===========================================================================

/// Parse `{"nodes":[...],"edges":[...]}` from LLM output and add them to the crux.
fn seed_from_llm_response(mesh_root: &Path, crux_path: &str, llm_output: &str) -> Result<(usize, usize), String> {
    // Strip markdown code fences if present.
    let stripped = llm_output.trim();
    let json_text = if let Some(start) = stripped.find('{') {
        // Find the matching closing brace (last `}` at depth 1).
        let s = &stripped[start..];
        let mut depth = 0usize;
        let mut end = s.len();
        let mut in_str = false;
        let mut escaped = false;
        for (i, c) in s.char_indices() {
            if escaped { escaped = false; continue; }
            if c == '\\' && in_str { escaped = true; continue; }
            if c == '"' { in_str = !in_str; continue; }
            if in_str { continue; }
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 { end = i + 1; break; }
                }
                _ => {}
            }
        }
        &s[..end]
    } else {
        return Err("No JSON object found in LLM response".to_string());
    };

    let crux_dir = resolve_crux_dir(mesh_root, crux_path);
    let mut db = load_crux_db(&crux_dir)?;
    let now = now_unix();
    let mut nodes_added = 0usize;
    let mut edges_added = 0usize;

    // Parse nodes array.
    if let Some(nodes_start) = json_text.find("\"nodes\"") {
        let after = &json_text[nodes_start + 7..];
        if let Some(arr_start) = after.find('[') {
            let arr_text = &after[arr_start..];
            for obj in extract_json_objects_from_array(arr_text) {
                let name = extract_string_value(&obj, "name").unwrap_or_default();
                if name.is_empty() { continue; }
                let kind = extract_string_value(&obj, "kind").unwrap_or_else(|| "concept".to_string());
                let summary = extract_string_value(&obj, "summary").unwrap_or_default();
                let tags_str = extract_string_value(&obj, "tags").unwrap_or_default();
                let tags: Vec<String> = tags_str.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                let content_hash = format!("sha256:{:x}", now);
                let node_id = generate_node_id(&name, &content_hash);
                db.nodes.push(CruxNode {
                    node_id,
                    name,
                    kind,
                    module: String::new(),
                    summary,
                    schema: NodeSchema::empty(),
                    tags,
                    reach: Vec::new(),
                    properties: Vec::new(),
                    warnings: Vec::new(),
                    planning: PlanningMetadata::empty(),
                    security: SecurityMetadata {
                        classification: "internal".to_string(),
                        redact_below: None,
                    },
                    content_hash,
                    deleted_at: None,
                });
                nodes_added += 1;
            }
        }
    }

    // Parse edges array.
    if let Some(edges_start) = json_text.find("\"edges\"") {
        let after = &json_text[edges_start + 7..];
        if let Some(arr_start) = after.find('[') {
            let arr_text = &after[arr_start..];
            for obj in extract_json_objects_from_array(arr_text) {
                let src = extract_string_value(&obj, "src").unwrap_or_default();
                let dst = extract_string_value(&obj, "dst").unwrap_or_default();
                if src.is_empty() || dst.is_empty() { continue; }
                let kind_str = extract_string_value(&obj, "kind").unwrap_or_else(|| "relates_to".to_string());
                let edge_kind = EdgeKind::from_str(&kind_str);
                let edge_id = generate_edge_id(&src, &dst, &kind_str);
                db.edges.push(CruxEdge {
                    edge_id,
                    src,
                    dst,
                    kind: edge_kind,
                    weight: 1.0,
                    detail: String::new(),
                    cross_crux: false,
                    binding: String::new(),
                    created_at: now,
                    dangling: false,
                });
                edges_added += 1;
            }
        }
    }

    db.header.last_modified_at = now;
    save_crux_db(&db, &crux_dir)?;
    Ok((nodes_added, edges_added))
}

// ===========================================================================
// MCP Server management (GET /api/mcp/list, POST /api/mcp/register, POST /api/mcp/revoke)
// ===========================================================================

pub fn handle_mcp_list(mesh_root: &Path) -> Response {
    use crate::mesh::load_mcp_registrations;
    let regs = load_mcp_registrations(mesh_root);
    let mut out = String::from("[");
    for (i, r) in regs.iter().enumerate() {
        if i > 0 { out.push(','); }
        let auth_status = if r.auth == "oauth2" {
            let s = crate::oauth::auth_status(&r.alias);
            json_escape(&s.status)
        } else {
            json_escape("none")
        };
        let _ = write!(
            out,
            r#"{{"alias":{},"transport":{},"required_clearance":{},"allowed_tools":{},"rate_limit":{},"audit_required":{},"auth":{},"auth_status":{}}}"#,
            json_escape(&r.alias),
            json_escape(r.transport.as_str()),
            json_escape(r.required_clearance.as_str()),
            json_escape(&r.allowed_tools),
            match &r.rate_limit { Some(rl) => json_escape(rl), None => "null".to_string() },
            r.audit_required,
            json_escape(&r.auth),
            auth_status,
        );
    }
    out.push(']');
    Response::ok_json(format!("{{\"servers\":{}}}", out))
}

// ===========================================================================
// POST /api/mcp/oauth/start  { alias }
// ===========================================================================

/// Start a Helm browser OAuth flow for `alias`.
///
/// Performs endpoint discovery, generates PKCE params, stores the pending
/// state (keyed by alias) in `PENDING_OAUTH`, and returns the authorization
/// URL. The authorization server should redirect to
/// `GET /oauth/callback?alias=<alias>&code=<code>&state=<state>`.
pub fn handle_mcp_oauth_start(
    mesh_root: &Path,
    req: &Request,
    helm_port: u16,
    pending: &std::sync::Mutex<std::collections::HashMap<String, crate::oauth::PendingOAuth>>,
) -> Response {
    use crate::mesh::load_mcp_registrations;
    let body = req.body_str();
    let alias = match extract_string_value(body, "alias") {
        Some(a) => a,
        None => return Response::bad_request("missing 'alias'"),
    };
    // Load the registration
    let regs = load_mcp_registrations(mesh_root);
    let reg = match regs.iter().find(|r| r.alias == alias) {
        Some(r) => r,
        None => return Response::bad_request(&format!("no registration found for alias '{}'", alias)),
    };
    if reg.auth != "oauth2" {
        return Response::bad_request(&format!(
            "'{}' has auth='{}' — only oauth2 registrations can be authorized",
            alias, reg.auth
        ));
    }
    let oauth_reg = crate::oauth::OAuthReg::from_schema(reg);
    match crate::oauth::helm_oauth_start(&alias, &oauth_reg, helm_port) {
        Ok((auth_url, pending_state)) => {
            if let Ok(mut map) = pending.lock() {
                map.insert(alias.clone(), pending_state);
            }
            Response::ok_json(format!("{{\"ok\":true,\"auth_url\":{}}}", json_escape(&auth_url)))
        }
        Err(e) => Response::server_error(&e),
    }
}

// ===========================================================================
// GET /oauth/callback?alias=X&code=Y&state=Z
// ===========================================================================

/// Complete a Helm OAuth flow from the AS callback redirect.
///
/// Looks up the pending state for `alias`, validates `state`, exchanges the
/// code for tokens, and serves an HTML success page.
pub fn handle_oauth_callback(
    mesh_root: &Path,
    req: &Request,
    pending: &std::sync::Mutex<std::collections::HashMap<String, crate::oauth::PendingOAuth>>,
) -> Response {
    let alias = match req.query.get("alias") {
        Some(a) => a.clone(),
        None => return Response::bad_request("missing 'alias' query parameter"),
    };
    let code = match req.query.get("code") {
        Some(c) => c.clone(),
        None => return html_error_page("Authorization failed: no code in callback."),
    };
    let state = match req.query.get("state") {
        Some(s) => s.clone(),
        None => return html_error_page("Authorization failed: no state in callback."),
    };
    // Clone the pending state without removing it yet — the token exchange
    // may fail transiently, and we want the user to be able to retry the
    // callback without restarting the full authorization flow.
    let pending_state = match pending.lock().ok().and_then(|m| m.get(&alias).cloned()) {
        Some(p) => p,
        None => return html_error_page(&format!(
            "Authorization failed: no pending flow for alias '{}'. Did it time out?", alias
        )),
    };
    match crate::oauth::helm_oauth_complete(&pending_state, &code, &state, Some(mesh_root)) {
        Ok(_) => {
            // Exchange succeeded — now remove the pending state.
            let _ = pending.lock().ok().map(|mut m| m.remove(&alias));
            Response {
                status: 200,
                content_type: "text/html",
                body: HTML_OAUTH_SUCCESS.as_bytes().to_vec(),
            }
        }
        Err(e) => html_error_page(&format!("Authorization failed: {}", e)),
    }
}

const HTML_OAUTH_SUCCESS: &str = "\
<!DOCTYPE html><html><head><meta charset=\"UTF-8\">\
<title>Authorization Successful</title>\
<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0a0a0b;color:#e2e8f0}\
.card{text-align:center;padding:40px;background:#18181b;border:1px solid #27272a;border-radius:12px}\
h2{color:#4ade80;margin:0 0 12px}p{color:#a1a1aa;margin:0}</style>\
</head><body><div class=\"card\">\
<h2>Authorization Successful</h2>\
<p>You may close this tab and return to Helm.</p>\
</div></body></html>";

fn html_error_page(msg: &str) -> Response {
    let body = format!(
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Authorization Failed</title>\
         <style>body{{font-family:system-ui,sans-serif;display:flex;align-items:center;\
         justify-content:center;height:100vh;margin:0;background:#0a0a0b;color:#e2e8f0}}\
         .card{{text-align:center;padding:40px;background:#18181b;\
         border:1px solid #27272a;border-radius:12px}}\
         h2{{color:#f87171;margin:0 0 12px}}p{{color:#a1a1aa;margin:0}}</style>\
         </head><body><div class=\"card\">\
         <h2>Authorization Failed</h2><p>{}</p>\
         </div></body></html>",
        msg
    );
    Response { status: 400, content_type: "text/html", body: body.into_bytes() }
}

// ===========================================================================
// POST /api/mcp/oauth/revoke  { alias }
// ===========================================================================

/// Revoke (delete) the stored OAuth token for `alias`.
pub fn handle_mcp_oauth_revoke(mesh_root: &Path, req: &Request) -> Response {
    let _ = mesh_root; // unused — token store is per-alias, not per-mesh
    let body = req.body_str();
    let alias = match extract_string_value(body, "alias") {
        Some(a) => a,
        None => return Response::bad_request("missing 'alias'"),
    };
    match crate::oauth::revoke_token(&alias) {
        Ok(()) => Response::ok_json(format!(
            "{{\"ok\":true,\"message\":{}}}",
            json_escape(&format!("Token for '{}' revoked — next call will require re-authorization.", alias))
        )),
        Err(e) => Response::server_error(&e),
    }
}

pub fn handle_mcp_register(mesh_root: &Path, req: &Request) -> Response {
    let body = req.body_str();
    let alias     = extract_string_value(body, "alias").unwrap_or_default();
    let transport = extract_string_value(body, "transport").unwrap_or_default();
    let command   = extract_string_value(body, "command").unwrap_or_default();
    let url       = extract_string_value(body, "url").unwrap_or_default();
    let clearance = extract_string_value(body, "required_clearance")
        .unwrap_or_else(|| "internal".to_string());
    let tools     = extract_string_value(body, "allowed_tools")
        .unwrap_or_else(|| "*".to_string());
    let rate      = extract_string_value(body, "rate_limit").unwrap_or_default();
    let oauth     = crate::schema::OAuthConfig {
        auth:                   extract_string_value(body, "auth").unwrap_or_else(|| "none".to_string()),
        client_id:              extract_string_value(body, "oauth_client_id").unwrap_or_default(),
        scopes:                 extract_string_value(body, "oauth_scopes").unwrap_or_default(),
        discovery_url:          extract_string_value(body, "oauth_discovery_url").unwrap_or_default(),
        authorization_endpoint: extract_string_value(body, "oauth_authorization_endpoint").unwrap_or_default(),
        token_endpoint:         extract_string_value(body, "oauth_token_endpoint").unwrap_or_default(),
        registration_endpoint:  extract_string_value(body, "oauth_registration_endpoint").unwrap_or_default(),
    };

    match crate::mesh::mesh_register_mcp(
        mesh_root, &alias, &transport, &command, &url, &clearance, &tools, &rate, &oauth,
    ) {
        Ok(msg) => Response::ok_json(format!("{{\"ok\":true,\"message\":{}}}", json_escape(&msg))),
        Err(e)  => Response::server_error(&e),
    }
}

pub fn handle_mcp_revoke(mesh_root: &Path, req: &Request) -> Response {
    let body = req.body_str();
    let alias = match extract_string_value(body, "alias") {
        Some(a) => a,
        None => return Response::bad_request("missing 'alias'"),
    };
    match crate::mesh::mesh_revoke_mcp(mesh_root, &alias) {
        Ok(msg) => Response::ok_json(format!("{{\"ok\":true,\"message\":{}}}", json_escape(&msg))),
        Err(e)  => Response::server_error(&e),
    }
}

pub fn handle_mcp_discovered(mesh_root: &Path) -> Response {
    use crate::mesh::load_discovered_mcp;
    let regs = load_discovered_mcp(mesh_root);
    let mut out = String::from("[");
    for (i, r) in regs.iter().enumerate() {
        if i > 0 { out.push(','); }
        let _ = write!(
            out,
            r#"{{"alias":{},"transport":{},"required_clearance":{},"source":{},"discovered_at":{}}}"#,
            json_escape(&r.alias),
            json_escape(r.transport.as_str()),
            json_escape(r.required_clearance.as_str()),
            json_escape(&r.source),
            r.discovered_at.map(|t| t.to_string()).unwrap_or_else(|| "null".to_string()),
        );
    }
    out.push(']');
    Response::ok_json(format!("{{\"servers\":{}}}", out))
}

pub fn handle_mcp_scan(mesh_root: &Path) -> Response {
    match crate::mesh::mesh_discover(mesh_root) {
        Ok(report) => Response::ok_json(format!(
            "{{\"ok\":true,\"discovered\":{}}}",
            report.added.len(),
        )),
        Err(e) => Response::server_error(&e),
    }
}

pub fn handle_mcp_approve(mesh_root: &Path, req: &Request) -> Response {
    let body = req.body_str();
    let alias = match extract_string_value(body, "alias") {
        Some(a) => a,
        None => return Response::bad_request("missing 'alias'"),
    };
    match crate::mesh::mesh_approve_mcp(mesh_root, &alias) {
        Ok(msg) => Response::ok_json(format!("{{\"ok\":true,\"message\":{}}}", json_escape(&msg))),
        Err(e)  => Response::server_error(&e),
    }
}

pub fn handle_mcp_external(mesh_root: &Path) -> Response {
    let detected = match crate::mcp_detect::detect_external_mcp(mesh_root) {
        Ok(d)  => d,
        Err(e) => return Response::server_error(&e),
    };
    let mut out = String::from("[");
    for (i, d) in detected.iter().enumerate() {
        if i > 0 { out.push(','); }
        let instructions = if !d.routed_via_crux {
            format!(
                "SECURITY WARNING: '{}' is configured in {} but is NOT routed through the Crux policy router.\\n\\nTo route: mesh route_external --name {}",
                d.name,
                d.source_path.display(),
                d.name,
            )
        } else {
            String::new()
        };
        let _ = write!(
            out,
            r#"{{"name":{},"source_label":{},"transport":{},"routed_via_crux":{},"instructions":{}}}"#,
            json_escape(&d.name),
            json_escape(&d.source_label),
            json_escape(&d.transport),
            d.routed_via_crux,
            json_escape(&instructions),
        );
    }
    out.push(']');
    Response::ok_json(format!("{{\"servers\":{}}}", out))
}

pub fn handle_mcp_route_external(mesh_root: &Path, req: &Request) -> Response {
    let body = req.body_str();
    let name = match extract_string_value(body, "name") {
        Some(n) => n,
        None => return Response::bad_request("missing 'name'"),
    };
    let detected = match crate::mcp_detect::detect_external_mcp(mesh_root) {
        Ok(d)  => d,
        Err(e) => return Response::server_error(&e),
    };
    let det = match detected.iter().find(|d| d.name == name) {
        Some(d) => d,
        None    => return Response::bad_request(&format!("'{}' not found in detected servers", name)),
    };
    if det.routed_via_crux {
        return Response::ok_json(format!(
            "{{\"ok\":true,\"message\":{}}}",
            json_escape(&format!("'{}' is already routed via Crux", name))
        ));
    }
    let source = format!("detect:{}", det.source_label);
    match crate::mesh::mesh_register_mcp_with_source(
        mesh_root, &det.name, &det.transport,
        &det.command, &det.url, "internal", "*", "", &source,
        &crate::schema::OAuthConfig::default(),
    ) {
        Ok(msg) => Response::ok_json(format!("{{\"ok\":true,\"message\":{}}}", json_escape(&msg))),
        Err(e)  => Response::server_error(&e),
    }
}
