//! MCP server — JSON-RPC 2.0 over stdio.
//!
//! Provides 3 unified tools:
//!   crux — all crux CRUD operations (action param)
//!   mesh — all mesh operations (action param)
//!   pkg  — all package manager operations (action param)
//!
//! Legacy tool names (crux_create, crux_load, crux_query, crux_add_node, etc.)
//! are still accepted as backward-compat aliases.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use crate::adapters::{AdapterConfig, CruxAdapter};
use crate::adapters::scanner::{GroupingStrategy, scan_directory, generate_dir};
use crate::audit::{AuditLog, AuditEvent, AuditEventKind};
use crate::json::{extract_bool_value, extract_string_value, extract_string_array, json_escape, extract_json_objects_from_array};
use crate::mesh;
use crate::schema;

// ===========================================================================
// Tool definitions
// ===========================================================================

/// Unified tool definitions for the 3 consolidated tools.
/// Legacy names (crux_create, mesh_init, etc.) are handled as aliases in handle_tool_call.
const UNIFIED_TOOLS: &[(&str, &str, &str)] = &[
    (
        "crux",
        concat!(
            "Unified crux knowledge graph tool. action is required.\n",
            "  create        — create a new .crux.json (requires name; optional kind, origin)\n",
            "  load          — load and summarize a crux (requires path)\n",
            "  query         — filter nodes with structured fields (requires path; optional query/filter_kind/filter_status/tag/property/since/sort/limit)\n",
            "                   query=substring  filter_kind=exact  filter_status=exact  tag=exact(case-insensitive)\n",
            "                   property=key=val|key>N|key<N  since=YYYY-MM-DD  sort=priority|name|created  limit=N\n",
            "                   Note: 'since' filters by planning.updated_at; nodes without it are excluded\n",
            "  add_node      — add a single node (requires path, name; optional kind/module/summary/tags/classification)\n",
            "  add_nodes     — add multiple nodes from JSON array (requires path, nodes)\n",
            "  add_edge      — add an edge between nodes (requires path, src, dst; optional kind, detail)\n",
            "  add_edges     — add multiple edges from JSON array (requires path, edges; optional allow_forward_refs)\n",
            "                   All-or-nothing: if any edge names a node that does not exist the whole\n",
            "                   batch is rejected and every offender is named. Pass allow_forward_refs=true\n",
            "                   to store unresolved edges as dangling instead.\n",
            "  update_node   — update summary/tags/properties/status/priority/depends (requires path, name)\n",
            "  remove_node   — soft-delete a node (requires path, name)\n",
            "  generate      — generate crux from text input via auto-adapter (requires name, input)\n",
            "  scan          — scan directory for file manifest (requires path)\n",
            "  generate_dir  — auto-generate cruxes from directory grouped by type (requires source_path, output_path, mesh_name)\n",
            "  verify        — verify content hashes (requires path)\n",
            "  resolve       — resolve node source reference to file location (requires path, node_name)\n",
            "  extract       — extract original source content for a node (requires path, node_name)\n",
            "  enrich        — enrich nodes with computed metadata (requires path; optional operations, lml_bin)\n",
            "  bootstrap     — scaffold a crux from a natural-language description (requires path, description)"
        ),
        r#"{"type":"object","properties":{"action":{"type":"string","description":"create|load|query|add_node|add_nodes|add_edge|add_edges|update_node|remove_node|generate|scan|generate_dir|verify|resolve|extract|enrich|bootstrap"},"path":{"type":"string","description":"Path to crux file or directory"},"name":{"type":"string","description":"Node or crux name"},"kind":{"type":"string","description":"Crux or node kind"},"origin":{"type":"string","description":"Origin identifier (for create)"},"query":{"type":"string","description":"Substring filter on name/kind/tags/summary (for query)"},"filter_kind":{"type":"string","description":"Exact node kind filter (for query)"},"filter_status":{"type":"string","description":"Exact planning.status filter: Todo|In Progress|Done|Blocked (for query)"},"tag":{"type":"string","description":"Exact tag match, case-insensitive (for query)"},"property":{"type":"string","description":"Property filter: key=value, key>N, or key<N (for query)"},"since":{"type":"string","description":"Filter by planning.updated_at >= date: YYYY-MM-DD or unix timestamp (for query)"},"sort":{"type":"string","description":"Sort order: priority|name|created (for query)"},"limit":{"type":"integer","description":"Max results (for query, default 50)"},"module":{"type":"string","description":"Module or namespace (for add_node)"},"summary":{"type":"string","description":"Node summary"},"tags":{"type":"string","description":"Comma-separated tags"},"classification":{"type":"string","description":"Security classification: public|internal|confidential|restricted"},"nodes":{"type":"string","description":"JSON array of node objects (for add_nodes)"},"src":{"type":"string","description":"Source node name (for add_edge/add_edges)"},"dst":{"type":"string","description":"Destination node name (for add_edge)"},"detail":{"type":"string","description":"Edge detail (for add_edge)"},"edges":{"type":"string","description":"JSON array of edge objects (for add_edges)"},"allow_forward_refs":{"type":"boolean","description":"Allow add_edges to store edges whose endpoints do not exist yet, flagged as dangling (default false; batch is otherwise all-or-nothing)"},"properties":{"type":"string","description":"Properties to append as key=value,... (for update_node)"},"status":{"type":"string","description":"Planning status (for update_node)"},"priority":{"type":"string","description":"Planning priority 1-5 (for update_node)"},"depends":{"type":"string","description":"Comma-separated dependencies (for update_node)"},"node_name":{"type":"string","description":"Node name (for resolve/extract actions)"},"input":{"type":"string","description":"Input text (for generate action)"},"format":{"type":"string","description":"Format hint: auto|markdown|plaintext|manual (for generate)"},"source_path":{"type":"string","description":"Source directory (for generate_dir)"},"output_path":{"type":"string","description":"Output directory (for generate_dir)"},"mesh_name":{"type":"string","description":"Mesh name prefix (for generate_dir)"},"strategy":{"type":"string","description":"Grouping strategy: by_kind|by_directory|flat (for generate_dir)"},"operations":{"type":"string","description":"Comma-separated operations for enrich: reach,lint,schema,functions"},"lml_bin":{"type":"string","description":"Path to lml binary (for enrich lint operation)"},"description":{"type":"string","description":"Natural-language description of what to track (for bootstrap)"}},"required":["action"]}"#,
    ),
    (
        "mesh",
        concat!(
            "Unified mesh management tool. action is required.\n",
            "  init           — create a new .crux-mesh.json (requires name; optional path)\n",
            "  join           — add a crux to the mesh (requires crux_path; optional mesh_path)\n",
            "  leave          — remove a crux from the mesh (requires identifier; optional mesh_path)\n",
            "  status         — show mesh health, members, connectivity (optional mesh_path)\n",
            "  query          — filter nodes across all mesh members (optional query/filter_kind/filter_status/tag/property/since/sort/limit; optional mesh_path)\n",
            "  build          — init + join all cruxes from a directory (requires name, crux_dir; optional output_dir)\n",
            "  diff           — show changes since a timestamp (requires since; optional mesh_path)\n",
            "  create_cluster — create an access-control cluster (requires name; optional classification, policy, mesh_path)\n",
            "  assign_cluster    — assign a crux to a cluster (requires identifier, cluster; optional mesh_path)\n",
            "  register_mcp      — register an external MCP server in the policy crux (requires alias, transport; optional command, url, required_clearance, allowed_tools, rate_limit, auth, oauth_client_id, oauth_scopes, oauth_discovery_url, oauth_authorization_endpoint, oauth_token_endpoint, oauth_registration_endpoint, mesh_path)\n",
            "  list_mcp_servers  — list all active MCP server registrations (optional mesh_path)\n",
            "  revoke_mcp        — soft-delete an MCP server registration by alias (requires alias; optional mesh_path)\n",
            "  push              — copy nodes+edges from src into dst, filtering by clearance (requires src, dst; optional mesh_path)\n",
            "  pull              — copy nodes+edges from src into dst, filtering by clearance (requires src, dst; optional mesh_path)\n",
            "  auth_status       — show OAuth token status for a registered alias: authorized/expired/unauthorized (requires alias; optional mesh_path)\n",
            "  trigger_auth      — run PKCE authorization-code flow for an OAuth2 alias; prints auth URL, waits for browser callback (requires alias; optional mesh_path)\n",
            "  oauth_revoke      — delete stored OAuth token for an alias from the encrypted token store (requires alias)"
        ),
        r#"{"type":"object","properties":{"action":{"type":"string","description":"init|join|leave|status|query|build|diff|create_cluster|assign_cluster|register_mcp|list_mcp_servers|revoke_mcp|push|pull|auth_status|trigger_auth|oauth_revoke"},"name":{"type":"string","description":"Mesh or cluster name"},"path":{"type":"string","description":"Directory path (for init)"},"crux_path":{"type":"string","description":"Path to crux to join (for join)"},"mesh_path":{"type":"string","description":"Mesh directory (defaults to searching from cwd)"},"identifier":{"type":"string","description":"Crux name or ID (for leave/assign_cluster)"},"query":{"type":"string","description":"Substring filter on name/kind/tags/summary (for query)"},"filter_kind":{"type":"string","description":"Exact node kind filter (for query)"},"filter_status":{"type":"string","description":"Exact planning.status filter (for query)"},"tag":{"type":"string","description":"Exact tag match, case-insensitive (for query)"},"property":{"type":"string","description":"Property filter: key=value, key>N, or key<N (for query)"},"sort":{"type":"string","description":"Sort order: priority|name|created (for query)"},"limit":{"type":"integer","description":"Max results (for query, default 50)"},"crux_dir":{"type":"string","description":"Directory of cruxes to join (for build)"},"output_dir":{"type":"string","description":"Where to create mesh manifest (for build)"},"since":{"type":"integer","description":"Unix timestamp for diff (0 = all)"},"classification":{"type":"string","description":"Security classification (for create_cluster)"},"policy":{"type":"string","description":"Cross-cluster policy: allow|deny|filtered (for create_cluster)"},"cluster":{"type":"string","description":"Cluster name (for assign_cluster)"},"alias":{"type":"string","description":"Unique routing key for the MCP server (for register_mcp/revoke_mcp)"},"transport":{"type":"string","description":"Transport: stdio or http (for register_mcp)"},"command":{"type":"string","description":"Argv string for stdio transport (for register_mcp)"},"url":{"type":"string","description":"Base URL for http transport (for register_mcp)"},"required_clearance":{"type":"string","description":"Minimum caller clearance: public|internal|confidential|restricted (for register_mcp)"},"allowed_tools":{"type":"string","description":"Comma-separated tool names to forward, or * for all (for register_mcp)"},"rate_limit":{"type":"string","description":"Optional rate limit: N/W = max N calls per W-second window, e.g. 60/60 (for register_mcp)"},"auth":{"type":"string","description":"Authentication: none (default) or oauth2 (for register_mcp)"},"oauth_client_id":{"type":"string","description":"OAuth 2.1 client ID (for register_mcp with auth=oauth2)"},"oauth_scopes":{"type":"string","description":"Space-separated OAuth scopes per RFC 6749 §3.3 (for register_mcp with auth=oauth2)"},"oauth_discovery_url":{"type":"string","description":"RFC 9728/8414 authorization server metadata URL (for register_mcp with auth=oauth2)"},"oauth_authorization_endpoint":{"type":"string","description":"Explicit authorization endpoint, used when oauth_discovery_url is empty (for register_mcp with auth=oauth2)"},"oauth_token_endpoint":{"type":"string","description":"Token endpoint (for register_mcp with auth=oauth2)"},"oauth_registration_endpoint":{"type":"string","description":"Dynamic Client Registration endpoint per RFC 7591 (for register_mcp with auth=oauth2)"},"src":{"type":"string","description":"Source crux name, id, or path (for push/pull)"},"dst":{"type":"string","description":"Destination crux name, id, or path (for push/pull)"}},"required":["action"]}"#,
    ),
    (
        "pkg",
        concat!(
            "Package manager tool. action is required.\n",
            "  search  — search registry for functions/modules (requires query, registry_path)\n",
            "  publish — publish a package to the registry (requires name, source_dir, registry_path)\n",
            "  install — install a package from registry (requires package_name, registry_path, project_path)\n",
            "  deps    — show dependency tree (requires project_path)\n",
            "  audit   — verify integrity of installed packages (requires project_path)\n",
            "  update  — check for updates (requires project_path, registry_path)"
        ),
        r#"{"type":"object","properties":{"action":{"type":"string","description":"search|publish|install|deps|audit|update"},"query":{"type":"string","description":"Search query (for search)"},"registry_path":{"type":"string","description":"Path to registry mesh directory"},"name":{"type":"string","description":"Package name (for publish)"},"source_dir":{"type":"string","description":"Directory with LML source files (for publish)"},"publisher":{"type":"string","description":"Publisher identifier (for publish, default: agent)"},"package_name":{"type":"string","description":"Package name to install (for install)"},"project_path":{"type":"string","description":"Path to project directory (for install/deps/audit/update)"},"limit":{"type":"integer","description":"Max results (for search, default 20)"}},"required":["action"]}"#,
    ),
];

// Keep legacy TOOLS const for backward compat reference only (not used in tools/list).
#[allow(dead_code)]
const TOOLS: &[(&str, &str, &str)] = &[
    (
        "crux_create",
        "Create a new crux (.crux.json) in the current directory",
        r#"{"type":"object","properties":{"name":{"type":"string","description":"Name for the crux"},"kind":{"type":"string","description":"Crux kind: codebase|documentation|preferences|organization|skillset|api|dataset|custom","default":"codebase"},"origin":{"type":"string","description":"Origin identifier (e.g. rust, markdown, manual)","default":"manual"}},"required":["name"]}"#,
    ),
    (
        "crux_load",
        "Load a crux and return its summary",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory containing .crux.json"}},"required":["path"]}"#,
    ),
    (
        "crux_query",
        "Query nodes in a crux by name, kind, or tag substring",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory"},"query":{"type":"string","description":"Substring filter on name/kind/tags/summary"},"filter_kind":{"type":"string","description":"Exact node kind"},"filter_status":{"type":"string","description":"Exact planning.status"},"tag":{"type":"string","description":"Exact tag match"},"property":{"type":"string","description":"Property filter: key=val, key>N, key<N"},"since":{"type":"string","description":"Filter by planning.updated_at >= YYYY-MM-DD"},"sort":{"type":"string","description":"priority|name|created"},"limit":{"type":"integer","description":"Max results (default 50)"}},"required":["path"]}"#,
    ),
    (
        "mesh_init",
        "Create a new mesh manifest (.crux-mesh.json)",
        r#"{"type":"object","properties":{"name":{"type":"string","description":"Name for the mesh"},"path":{"type":"string","description":"Directory path (defaults to current directory)"}},"required":["name"]}"#,
    ),
    (
        "mesh_join",
        "Add a crux to the mesh (triggers introduction protocol)",
        r#"{"type":"object","properties":{"crux_path":{"type":"string","description":"Path to the crux (relative to mesh root)"},"mesh_path":{"type":"string","description":"Mesh directory (defaults to searching from current directory)"}},"required":["crux_path"]}"#,
    ),
    (
        "mesh_leave",
        "Remove a crux from the mesh",
        r#"{"type":"object","properties":{"identifier":{"type":"string","description":"Crux name or ID to remove"},"mesh_path":{"type":"string","description":"Mesh directory (defaults to searching from current directory)"}},"required":["identifier"]}"#,
    ),
    (
        "mesh_status",
        "Show mesh health: members, connectivity, cross-edges",
        r#"{"type":"object","properties":{"mesh_path":{"type":"string","description":"Mesh directory (defaults to searching from current directory)"}}}"#,
    ),
    (
        "mesh_query",
        "Query nodes across all mesh members by name, kind, or tag",
        r#"{"type":"object","properties":{"query":{"type":"string","description":"Filter string (matches name, kind, or tag)"},"mesh_path":{"type":"string","description":"Mesh directory (defaults to searching from current directory)"},"limit":{"type":"integer","description":"Max results to return (default: 50)"}},"required":["query"]}"#,
    ),
    (
        "crux_add_node",
        "Add a node to an existing crux",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory"},"name":{"type":"string","description":"Node name"},"kind":{"type":"string","description":"Node kind: function|struct|module|class|document|record|preference|etc","default":"function"},"module":{"type":"string","description":"Module or namespace"},"summary":{"type":"string","description":"Short description of the node"},"tags":{"type":"string","description":"Comma-separated tags"},"classification":{"type":"string","description":"Security classification: public|internal|confidential|restricted","default":"internal"}},"required":["path","name"]}"#,
    ),
    (
        "crux_add_edge",
        "Add an edge between two nodes in a crux",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory"},"src":{"type":"string","description":"Source node name"},"dst":{"type":"string","description":"Destination node name"},"kind":{"type":"string","description":"Edge kind: calls|imports|contains|extends|implements|data_flow|reads|writes|transforms|produces|relates_to|contradicts|supersedes","default":"relates_to"},"detail":{"type":"string","description":"Optional detail about the relationship"}},"required":["path","src","dst"]}"#,
    ),
    (
        "crux_remove_node",
        "Soft-delete a node from a crux (marks deleted_at, preserves history)",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory"},"name":{"type":"string","description":"Node name to remove"}},"required":["path","name"]}"#,
    ),
    (
        "crux_generate",
        "Generate a crux from input text using the auto-adapter",
        r#"{"type":"object","properties":{"name":{"type":"string","description":"Name for the generated crux"},"input":{"type":"string","description":"Input text to generate from (markdown, plaintext, CSV, JSON, etc.)"},"format":{"type":"string","description":"Format hint: auto|markdown|plaintext|manual|csv","default":"auto"},"path":{"type":"string","description":"Directory to save the crux (defaults to current directory)"},"column_mappings":{"type":"string","description":"CSV only: JSON array of column→field mappings, e.g. [{\"column\":\"Name\",\"field\":\"name\"},{\"column\":\"Type\",\"field\":\"kind\"}]. Fields: name|kind|summary|tags|skip|property"},"node_kind":{"type":"string","description":"CSV only: default node kind for rows without an explicit kind mapping (default: record)"}},"required":["name","input"]}"#,
    ),
    (
        "mesh_create_cluster",
        "Create a named access-control cluster in the mesh",
        r#"{"type":"object","properties":{"name":{"type":"string","description":"Cluster name"},"classification":{"type":"string","description":"Security classification for this cluster","default":"internal"},"policy":{"type":"string","description":"Cross-cluster policy: allow|deny|filtered","default":"allow"},"mesh_path":{"type":"string","description":"Mesh directory (defaults to searching from current directory)"}},"required":["name"]}"#,
    ),
    (
        "mesh_assign_cluster",
        "Assign a crux to a cluster",
        r#"{"type":"object","properties":{"identifier":{"type":"string","description":"Crux name or ID"},"cluster":{"type":"string","description":"Cluster name to assign to"},"mesh_path":{"type":"string","description":"Mesh directory (defaults to searching from current directory)"}},"required":["identifier","cluster"]}"#,
    ),
    // --- Agentic intelligence tools ---
    (
        "crux_scan",
        "Recursively scan a directory and return a manifest of discovered files with detected types",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Directory to scan"},"max_depth":{"type":"integer","description":"Maximum recursion depth (omit for unlimited)"},"extensions":{"type":"string","description":"Comma-separated list of extensions to include (omit for all)"}},"required":["path"]}"#,
    ),
    (
        "crux_generate_dir",
        "Scan a directory and automatically generate cruxes grouped by content type",
        r#"{"type":"object","properties":{"source_path":{"type":"string","description":"Directory to scan for content"},"output_path":{"type":"string","description":"Directory where crux subdirectories will be created"},"mesh_name":{"type":"string","description":"Name prefix for generated cruxes"},"strategy":{"type":"string","description":"Grouping strategy: by_kind|by_directory|flat","default":"by_kind"},"device_id":{"type":"string","description":"Device or drive identifier for provenance tracking"},"classification":{"type":"string","description":"Default security classification for all nodes","default":"internal"},"max_depth":{"type":"integer","description":"Maximum directory scan depth"}},"required":["source_path","output_path","mesh_name"]}"#,
    ),
    (
        "crux_add_nodes_batch",
        "Add multiple nodes to a crux in a single call",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory"},"nodes":{"type":"string","description":"JSON array of node objects: [{name,kind,module?,summary?,tags?,properties?,classification?}]"}},"required":["path","nodes"]}"#,
    ),
    (
        "crux_add_edges_batch",
        "Add multiple edges to a crux in a single call",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory"},"edges":{"type":"string","description":"JSON array of edge objects: [{src,dst,kind?,detail?}]"}},"required":["path","edges"]}"#,
    ),
    (
        "crux_update_node",
        "Update an existing node's summary, tags, properties, classification, or planning metadata (status/priority/depends)",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory"},"name":{"type":"string","description":"Node name to update"},"summary":{"type":"string","description":"New summary"},"tags":{"type":"string","description":"New comma-separated tags (replaces existing)"},"properties":{"type":"string","description":"Additional properties to append as 'key=value' comma-separated"},"classification":{"type":"string","description":"New security classification"},"status":{"type":"string","description":"Planning status: open, resolved, todo, wip, done, new, promoted, rejected"},"priority":{"type":"string","description":"Planning priority 1-5 (1=highest)"},"depends":{"type":"string","description":"Comma-separated node names this node depends on"}},"required":["path","name"]}"#,
    ),
    (
        "crux_enrich",
        "Enrich nodes with computed metadata. Operations: reach (transitive deps), lint (Argus warnings), schema (public API signatures), functions (create function-level nodes). For lint, also pass lml_bin.",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory"},"operations":{"type":"string","description":"Comma-separated operations: reach, lint, schema, functions, metrics, traps, lifecycle (default: reach)"},"lml_bin":{"type":"string","description":"Path to the lml binary (required for lint operation)"},"memory_file":{"type":"string","description":"Path to MEMORY.md (required for traps operation)"}},"required":["path"]}"#,
    ),
    (
        "crux_verify",
        "Verify content hashes for all nodes in a crux to detect tampering",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory"}},"required":["path"]}"#,
    ),
    (
        "mesh_build",
        "Init a mesh and join all cruxes from a directory in one step",
        r#"{"type":"object","properties":{"name":{"type":"string","description":"Mesh name"},"crux_dir":{"type":"string","description":"Directory containing crux subdirectories to join"},"output_dir":{"type":"string","description":"Where to create the mesh manifest (defaults to crux_dir)"}},"required":["name","crux_dir"]}"#,
    ),
    (
        "mesh_diff",
        "Show what changed in the mesh since a given timestamp",
        r#"{"type":"object","properties":{"since":{"type":"integer","description":"Unix timestamp — show members/nodes added after this time (0 = all)"},"mesh_path":{"type":"string","description":"Mesh directory (defaults to searching from current directory)"}},"required":["since"]}"#,
    ),
    (
        "crux_resolve",
        "Resolve a node's source reference to its current file location and byte range",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory"},"node_name":{"type":"string","description":"Name of the node to resolve"}},"required":["path","node_name"]}"#,
    ),
    (
        "crux_extract",
        "Extract the original source content for a node (reads bytes from the source file)",
        r#"{"type":"object","properties":{"path":{"type":"string","description":"Path to the crux file or directory"},"node_name":{"type":"string","description":"Name of the node to extract content for"}},"required":["path","node_name"]}"#,
    ),
    // --- Package manager tools ---
    (
        "pkg_search",
        "Search the package registry for functions/modules. Supports domain:X, tag:X, effect:X filters and free-text terms",
        r#"{"type":"object","properties":{"query":{"type":"string","description":"Search query (e.g. 'domain:crypto hash tag:security')"},"registry_path":{"type":"string","description":"Path to the registry mesh directory"},"limit":{"type":"integer","description":"Max results (default: 20)"}},"required":["query","registry_path"]}"#,
    ),
    (
        "pkg_publish",
        "Publish a package to the registry. Package = crux spec + LML source files + metadata",
        r#"{"type":"object","properties":{"name":{"type":"string","description":"Package name"},"source_dir":{"type":"string","description":"Directory containing LML source files"},"registry_path":{"type":"string","description":"Path to the registry mesh directory"},"publisher":{"type":"string","description":"Publisher identifier (default: 'agent')"}},"required":["name","source_dir","registry_path"]}"#,
    ),
    (
        "pkg_install",
        "Install a package from the registry into the project's deps/ directory",
        r#"{"type":"object","properties":{"package_name":{"type":"string","description":"Name of the package to install"},"registry_path":{"type":"string","description":"Path to the registry mesh directory"},"project_path":{"type":"string","description":"Path to the project directory"}},"required":["package_name","registry_path","project_path"]}"#,
    ),
    (
        "pkg_deps",
        "Show the dependency tree for a project",
        r#"{"type":"object","properties":{"project_path":{"type":"string","description":"Path to the project directory"}},"required":["project_path"]}"#,
    ),
    (
        "pkg_audit",
        "Verify integrity of all installed packages (content hash checks)",
        r#"{"type":"object","properties":{"project_path":{"type":"string","description":"Path to the project directory"}},"required":["project_path"]}"#,
    ),
    (
        "pkg_update",
        "Check for available updates to installed packages",
        r#"{"type":"object","properties":{"project_path":{"type":"string","description":"Path to the project directory"},"registry_path":{"type":"string","description":"Path to the registry mesh directory"}},"required":["project_path","registry_path"]}"#,
    ),
];

// ===========================================================================
// JSON-RPC 2.0 helpers
// ===========================================================================

/// Build a `tools/call` result, setting the MCP `isError` flag when the tool
/// failed. Without it a caller has to pattern-match on prose to tell a rejection
/// from a success, which is exactly the branch automated writers get wrong.
fn json_rpc_tool_result(id: &str, content: &str, is_error: bool) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":{}}}],\"isError\":{}}}}}",
        id,
        json_escape(content),
        is_error
    )
}

fn json_rpc_error(id: &str, code: i32, message: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":{},\"message\":{}}}}}",
        id,
        code,
        json_escape(message)
    )
}

fn json_rpc_result_raw(id: &str, raw_json: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
        id, raw_json
    )
}

// ===========================================================================
// Tool dispatch
// ===========================================================================

fn handle_tools_list(id: &str) -> String {
    let mut tools_json = String::from("[");
    for (i, (name, desc, schema)) in UNIFIED_TOOLS.iter().enumerate() {
        if i > 0 {
            tools_json.push(',');
        }
        tools_json.push_str(&format!(
            "{{\"name\":{},\"description\":{},\"inputSchema\":{}}}",
            json_escape(name),
            json_escape(desc),
            schema
        ));
    }
    tools_json.push(']');
    json_rpc_result_raw(id, &format!("{{\"tools\":{}}}", tools_json))
}

fn handle_tool_call(id: &str, name: &str, args: &str) -> String {
    let result = dispatch_tool(name, args);
    match result {
        Ok(text) => json_rpc_tool_result(id, &text, false),
        Err(e) => json_rpc_tool_result(id, &format!("Error: {}", e), true),
    }
}

/// Resolve the action for unified or legacy tool names, then dispatch.
fn dispatch_tool(name: &str, args: &str) -> Result<String, String> {
    // Map legacy names to (unified_tool, action).
    let action: String = match name {
        // Unified tools: read action from args.
        "crux" | "mesh" | "pkg" => {
            extract_string_value(args, "action")
                .ok_or_else(|| format!("Missing required parameter: action (tool: {})", name))?
        }
        // crux_ legacy aliases
        "crux_create"       => "create".into(),
        "crux_load"         => "load".into(),
        "crux_query"        => "query".into(),
        "crux_add_node"     => "add_node".into(),
        "crux_add_nodes_batch" => "add_nodes".into(),
        "crux_add_edge"     => "add_edge".into(),
        "crux_add_edges_batch" => "add_edges".into(),
        "crux_update_node"  => "update_node".into(),
        "crux_remove_node"  => "remove_node".into(),
        "crux_generate"     => "generate".into(),
        "crux_scan"         => "scan".into(),
        "crux_generate_dir" => "generate_dir".into(),
        "crux_verify"       => "verify".into(),
        "crux_resolve"      => "resolve".into(),
        "crux_extract"      => "extract".into(),
        "crux_enrich"       => "enrich".into(),
        "crux_bootstrap"    => "bootstrap".into(),
        // mesh_ legacy aliases
        "mesh_init"           => "init".into(),
        "mesh_join"           => "join".into(),
        "mesh_leave"          => "leave".into(),
        "mesh_status"         => "status".into(),
        "mesh_query"          => "query".into(),
        "mesh_build"          => "build".into(),
        "mesh_diff"           => "diff".into(),
        "mesh_create_cluster" => "create_cluster".into(),
        "mesh_assign_cluster" => "assign_cluster".into(),
        // pkg_ legacy aliases
        "pkg_search"  => "search".into(),
        "pkg_publish" => "publish".into(),
        "pkg_install" => "install".into(),
        "pkg_deps"    => "deps".into(),
        "pkg_audit"   => "audit".into(),
        "pkg_update"  => "update".into(),
        _ => return Err(format!("Unknown tool: {}", name)),
    };

    // Determine which unified tool this belongs to (for legacy aliases, infer from prefix).
    let tool_prefix = if name == "crux" || name.starts_with("crux_") { "crux" }
        else if name == "mesh" || name.starts_with("mesh_") { "mesh" }
        else { "pkg" };

    match (tool_prefix, action.as_str()) {
        // crux actions
        ("crux", "create")       => tool_crux_create(args),
        ("crux", "load")         => tool_crux_load(args),
        ("crux", "query")        => tool_crux_query(args),
        ("crux", "add_node")     => tool_crux_add_node(args),
        ("crux", "add_nodes")    => tool_crux_add_nodes_batch(args),
        ("crux", "add_edge")     => tool_crux_add_edge(args),
        ("crux", "add_edges")    => tool_crux_add_edges_batch(args),
        ("crux", "update_node")  => tool_crux_update_node(args),
        ("crux", "remove_node")  => tool_crux_remove_node(args),
        ("crux", "generate")     => tool_crux_generate(args),
        ("crux", "scan")         => tool_crux_scan(args),
        ("crux", "generate_dir") => tool_crux_generate_dir(args),
        ("crux", "verify")       => tool_crux_verify(args),
        ("crux", "resolve")      => tool_crux_resolve(args),
        ("crux", "extract")      => tool_crux_extract(args),
        ("crux", "enrich")       => tool_crux_enrich(args),
        ("crux", "bootstrap")    => tool_crux_bootstrap(args),
        // mesh actions
        ("mesh", "init")           => tool_mesh_init(args),
        ("mesh", "join")           => tool_mesh_join(args),
        ("mesh", "leave")          => tool_mesh_leave(args),
        ("mesh", "status")         => tool_mesh_status(args),
        ("mesh", "query")          => tool_mesh_query(args),
        ("mesh", "build")          => tool_mesh_build(args),
        ("mesh", "diff")           => tool_mesh_diff(args),
        ("mesh", "create_cluster") => tool_mesh_create_cluster(args),
        ("mesh", "assign_cluster") => tool_mesh_assign_cluster(args),
        ("mesh", "register_mcp")     => tool_mesh_register_mcp(args),
        ("mesh", "list_mcp_servers") => tool_mesh_list_mcp_servers(args),
        ("mesh", "revoke_mcp")       => tool_mesh_revoke_mcp(args),
        ("mesh", "push")             => tool_mesh_push(args),
        ("mesh", "pull")             => tool_mesh_pull(args),
        ("mesh", "auth_status")      => tool_mesh_auth_status(args),
        ("mesh", "trigger_auth")     => tool_mesh_trigger_auth(args),
        ("mesh", "oauth_revoke")     => tool_mesh_oauth_revoke(args),
        ("mesh", "verify")           => tool_mesh_verify(args),
        ("mesh", "discover")         => tool_mesh_discover(args),
        ("mesh", "list_discovered")  => tool_mesh_list_discovered(args),
        ("mesh", "approve_mcp")      => tool_mesh_approve_mcp(args),
        ("mesh", "detect_external")  => tool_mesh_detect_external(args),
        ("mesh", "route_external")   => tool_mesh_route_external(args),
        // pkg actions
        ("pkg", "search")  => tool_pkg_search(args),
        ("pkg", "publish") => tool_pkg_publish(args),
        ("pkg", "install") => tool_pkg_install(args),
        ("pkg", "deps")    => tool_pkg_deps(args),
        ("pkg", "audit")   => tool_pkg_audit(args),
        ("pkg", "update")  => tool_pkg_update(args),
        _ => Err(format!("Unknown action '{}' for tool '{}'", action, tool_prefix)),
    }
}

// ===========================================================================
// Tool implementations
// ===========================================================================

fn resolve_working_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Refuse to create a crux over an existing one unless `force`.
///
/// `save_crux_db` is an unconditional write and creation always targets the
/// working directory, so calling create where a crux already lives silently
/// discarded every node and edge in it. `mesh::init_mesh` has always guarded
/// its manifest this way; the CLI's `crux create` carries the same guard.
fn check_create_conflict(dir: &std::path::Path, force: bool) -> Result<(), String> {
    let existing = dir.join(".crux.json");
    if existing.exists() && !force {
        return Err(format!(
            "Crux already exists at {}. Overwriting discards all of its nodes and edges; \
             pass force=true to replace it.",
            existing.display()
        ));
    }
    Ok(())
}

fn tool_crux_create(args: &str) -> Result<String, String> {
    let name = extract_string_value(args, "name")
        .ok_or_else(|| "Missing required parameter: name".to_string())?;
    let kind_str = extract_string_value(args, "kind").unwrap_or_else(|| "codebase".to_string());
    let origin = extract_string_value(args, "origin").unwrap_or_else(|| "manual".to_string());

    let kind = schema::CruxKind::from_str(&kind_str);
    let db = schema::create_crux_db(&name, kind, &origin);
    let cwd = resolve_working_dir();
    check_create_conflict(&cwd, extract_bool_value(args, "force").unwrap_or(false))?;
    schema::save_crux_db(&db, &cwd)?;

    Ok(format!(
        "Created crux '{}' ({})\nID: {}\nFile: {}",
        name,
        kind_str,
        db.header.crux_id,
        cwd.join(".crux.json").display()
    ))
}

fn tool_crux_load(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let path = PathBuf::from(&path_str);
    let db = schema::load_crux_db(&path)?;
    Ok(schema::format_crux_summary(&db, None))
}

fn tool_crux_query(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;

    let filter = crate::query::NodeFilter::from_args(args);

    let path = PathBuf::from(&path_str);
    let db = schema::load_crux_db(&path)?;

    let mut matched: Vec<&schema::CruxNode> = db
        .nodes
        .iter()
        .filter(|n| filter.matches(n))
        .collect();
    filter.apply_sort(&mut matched);
    let total = matched.len();
    let matched: Vec<&schema::CruxNode> = matched.into_iter().take(filter.limit).collect();

    if matched.is_empty() {
        return Ok(format!("No nodes found matching filters: {}.", filter.describe()));
    }

    let truncated = total > filter.limit;
    let mut out = format!(
        "Found {} node(s) [filters: {}]{}:\n",
        total,
        filter.describe(),
        if truncated { format!(" (showing first {})", filter.limit) } else { String::new() }
    );
    for n in &matched {
        out.push_str(&format!(
            "  {} ({}) — {}\n",
            n.name, n.kind, n.summary
        ));
        if !n.tags.is_empty() {
            out.push_str(&format!("    tags: {}\n", n.tags.join(", ")));
        }
        // Show planning metadata when present
        let has_status = n.planning.status.is_some();
        let has_priority = n.planning.priority.is_some();
        if has_status || has_priority {
            let status_str = n.planning.status.as_deref().unwrap_or("-");
            let priority_str = n.planning.priority
                .map(|p| format!("P{}", p))
                .unwrap_or_default();
            let planning_parts: Vec<&str> = [
                if has_status { status_str } else { "" },
                if has_priority { &priority_str } else { "" },
            ].iter().filter(|s| !s.is_empty()).copied().collect();
            out.push_str(&format!("    planning: {}\n", planning_parts.join(", ")));
        }
        if !n.schema.outputs.is_empty() {
            out.push_str(&format!("    api: {} exported functions ({})\n",
                n.schema.outputs.len(),
                n.schema.outputs.iter().take(4)
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>().join(", ")
                    + if n.schema.outputs.len() > 4 { ", ..." } else { "" }
            ));
        }
        if !n.reach.is_empty() {
            out.push_str(&format!("    reach: {} nodes ({})\n",
                n.reach.len(),
                n.reach.iter().take(4).cloned().collect::<Vec<_>>().join(", ")
                    + if n.reach.len() > 4 { ", ..." } else { "" }
            ));
        }
        if !n.warnings.is_empty() {
            out.push_str(&format!("    warnings: {} ({})\n",
                n.warnings.len(),
                n.warnings.iter().take(2)
                    .map(|w| w.splitn(3, ' ').nth(2).unwrap_or(w).chars().take(60).collect::<String>())
                    .collect::<Vec<_>>().join("; ")
                    + if n.warnings.len() > 2 { "..." } else { "" }
            ));
        }
        // Show non-file properties
        let display_props: Vec<&String> = n.properties.iter()
            .filter(|p| !p.starts_with("file="))
            .collect();
        if !display_props.is_empty() {
            out.push_str(&format!("    properties: {}\n",
                display_props.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("; ")));
        }
    }
    Ok(out)
}

fn tool_mesh_init(args: &str) -> Result<String, String> {
    let name = extract_string_value(args, "name")
        .ok_or_else(|| "Missing required parameter: name".to_string())?;
    let dir = match extract_string_value(args, "path") {
        Some(p) => PathBuf::from(p),
        None => resolve_working_dir(),
    };

    let manifest = mesh::init_mesh(&name, &dir)?;
    Ok(format!(
        "Initialized mesh '{}'\nID: {}\nFile: {}",
        name,
        manifest.mesh_id,
        dir.join(mesh::MESH_MANIFEST_FILE).display()
    ))
}

fn tool_mesh_join(args: &str) -> Result<String, String> {
    let crux_path = extract_string_value(args, "crux_path")
        .ok_or_else(|| "Missing required parameter: crux_path".to_string())?;
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd)
                .ok_or_else(|| "No mesh found. Run mesh_init first.".to_string())?
        }
    };

    let manifest = mesh::join_mesh(&mesh_dir, &crux_path)?;
    let member = manifest.members.last().unwrap();
    let audit_log = AuditLog::for_crux(&mesh_dir);
    let _ = audit_log.append(AuditEvent {
        timestamp: crate::schema::now_unix(),
        event: AuditEventKind::MeshJoined,
        crux_id: manifest.mesh_id.clone(),
        subject: member.crux_name.clone(),
        actor: None,
        detail: Some(format!("kind={}", member.crux_kind.as_str())),
        ..Default::default()
    });
    let mut result = format!(
        "Joined '{}' ({}) to mesh '{}'\nMembers: {}",
        member.crux_name,
        member.crux_kind.as_str(),
        manifest.mesh_name,
        manifest.members.len()
    );
    if !manifest.cross_edges.is_empty() {
        let total: usize = manifest.cross_edges.iter().map(|ce| ce.edge_count).sum();
        result.push_str(&format!("\nCross-edges discovered: {}", total));
    }
    Ok(result)
}

fn tool_mesh_leave(args: &str) -> Result<String, String> {
    let identifier = extract_string_value(args, "identifier")
        .ok_or_else(|| "Missing required parameter: identifier".to_string())?;
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd)
                .ok_or_else(|| "No mesh found.".to_string())?
        }
    };

    let manifest = mesh::leave_mesh(&mesh_dir, &identifier)?;
    let audit_log = AuditLog::for_crux(&mesh_dir);
    let _ = audit_log.append(AuditEvent {
        timestamp: crate::schema::now_unix(),
        event: AuditEventKind::MeshLeft,
        crux_id: manifest.mesh_id.clone(),
        subject: identifier.clone(),
        actor: None,
        detail: None,
        ..Default::default()
    });
    Ok(format!(
        "Removed '{}' from mesh '{}'\nRemaining members: {}",
        identifier,
        manifest.mesh_name,
        manifest.members.len()
    ))
}

fn tool_mesh_status(args: &str) -> Result<String, String> {
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd)
                .ok_or_else(|| "No mesh found.".to_string())?
        }
    };

    let mut manifest = mesh::load_mesh(&mesh_dir)?;
    mesh::check_member_health(&mut manifest, &mesh_dir);
    Ok(mesh::mesh_status_text(&manifest))
}

fn tool_mesh_verify(args: &str) -> Result<String, String> {
    use crate::audit::{AuditLog, AUDIT_LOG_FILE};
    use std::fmt::Write as FmtWrite;

    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd)
                .ok_or_else(|| "No mesh found.".to_string())?
        }
    };

    let manifest = mesh::load_mesh(&mesh_dir)?;
    let mut out = String::new();
    let _ = writeln!(out, "Mesh: {} ({})", manifest.mesh_name, manifest.mesh_id);
    let _ = writeln!(out, "Verifying audit chains for {} member(s):", manifest.members.len());

    let mut total_ok = 0usize;
    let mut total_err = 0usize;

    for member in &manifest.members {
        let crux_dir = mesh_dir.join(&member.path);
        let log_path = crux_dir.join(AUDIT_LOG_FILE);

        if !log_path.exists() {
            let _ = writeln!(out, "  [SKIP] {} — no audit log", member.crux_name);
            continue;
        }

        let log = AuditLog::with_id(log_path, &member.crux_id);
        let priv_key = member.mesh_private_key.clone();
        let crux_id = member.crux_id.clone();

        let result = log.verify_chain(&|id| {
            if id == crux_id { Some(priv_key.clone()) } else { None }
        });

        match result {
            Ok(n) => {
                let _ = writeln!(out, "  [OK]   {} — {n} event(s) verified", member.crux_name);
                total_ok += n;
            }
            Err(e) => {
                let _ = writeln!(out, "  [FAIL] {} — seq {} {:?}: {}", member.crux_name, e.at_seq, e.kind, e.detail);
                total_err += 1;
            }
        }
    }

    // --- MCP registration self-sig check ---
    let policy_member = manifest.members.iter()
        .find(|m| m.crux_kind == schema::CruxKind::Policy);
    if let Some(pm) = policy_member {
        let policy_dir = mesh_dir.join(&pm.path);
        if let Ok(policy_db) = schema::load_crux_db(&policy_dir) {
            let regs = schema::parse_all_mcp_server_registrations(&policy_db);
            if !regs.is_empty() {
                let _ = writeln!(out, "\nChecking {} MCP registration self-sig(s):", regs.len());
                for reg in &regs {
                    if reg.public_key.is_empty() {
                        let _ = writeln!(out, "  [SKIP] {} — no self-sig", reg.alias);
                        continue;
                    }
                    let sig_hex = reg.public_key.split(';')
                        .find_map(|p| p.strip_prefix("sig=").map(|v| v.to_string()))
                        .unwrap_or_default();
                    let pk_hex = reg.public_key.split(';')
                        .find_map(|p| p.strip_prefix("pk=").map(|v| v.to_string()))
                        .unwrap_or_default();
                    let sig_bytes = crate::crypto::hex_to_bytes(&sig_hex).unwrap_or_default();
                    let pk_bytes = crate::crypto::hex_to_bytes(&pk_hex).unwrap_or_default();
                    let canonical = format!(
                        "{}\x1f{}\x1f{}\x1f{}",
                        reg.alias, reg.transport.as_str(), reg.url, reg.required_clearance.as_str()
                    );
                    let hash_vec = crate::crypto::sha256(canonical.as_bytes());
                    let hash: [u8; 32] = match hash_vec.try_into() {
                        Ok(a) => a,
                        Err(_) => {
                            let _ = writeln!(out, "  [FAIL] {} — hash error", reg.alias);
                            total_err += 1;
                            continue;
                        }
                    };
                    if crate::crypto::wots_verify_raw(&pk_bytes, &hash, &sig_bytes) {
                        let _ = writeln!(out, "  [OK]   {} — self-sig valid", reg.alias);
                    } else {
                        let _ = writeln!(out, "  [FAIL] {} — self-sig invalid", reg.alias);
                        total_err += 1;
                    }
                }
            }
        }
    }

    let _ = writeln!(out, "\nTotal: {total_ok} event(s) verified; {total_err} chain error(s).");
    if total_err == 0 {
        Ok(out)
    } else {
        Err(out)
    }
}

fn tool_mesh_discover(args: &str) -> Result<String, String> {
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };
    let report = mesh::mesh_discover(&mesh_dir)?;
    let mut out = String::new();
    if !report.added.is_empty() {
        out.push_str(&format!("Added: {}\n", report.added.join(", ")));
    }
    if !report.updated.is_empty() {
        out.push_str(&format!("Updated: {}\n", report.updated.join(", ")));
    }
    if !report.skipped.is_empty() {
        out.push_str(&format!("Skipped (unchanged): {}\n", report.skipped.join(", ")));
    }
    if !report.errors.is_empty() {
        out.push_str(&format!("Errors:\n  {}\n", report.errors.join("\n  ")));
    }
    if out.is_empty() {
        out.push_str("No manifests found in .crux-discovery/");
    }
    Ok(out)
}

fn tool_mesh_list_discovered(args: &str) -> Result<String, String> {
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };
    let proposed = mesh::load_discovered_mcp(&mesh_dir);
    if proposed.is_empty() {
        return Ok("No pending MCP server proposals.".to_string());
    }
    let mut out = format!("{:<20} {:<8} {:<30} {:<10}\n", "ALIAS", "TRANSPORT", "COMMAND/URL", "SOURCE");
    for r in &proposed {
        let cmd_or_url = if r.command.is_empty() { r.url.as_str() } else { r.command.as_str() };
        out.push_str(&format!("{:<20} {:<8} {:<30} {:<10}\n",
            r.alias, r.transport.as_str(), cmd_or_url, r.source));
    }
    Ok(out)
}

fn tool_mesh_approve_mcp(args: &str) -> Result<String, String> {
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };
    let alias = extract_string_value(args, "alias")
        .ok_or_else(|| "Missing required parameter: alias".to_string())?;
    mesh::mesh_approve_mcp(&mesh_dir, &alias)
}

fn tool_mesh_detect_external(args: &str) -> Result<String, String> {
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };
    let detected = crate::mcp_detect::detect_external_mcp(&mesh_dir)?;
    if detected.is_empty() {
        return Ok("No external MCP servers detected.".to_string());
    }
    let mut out = format!("{:<24} {:<20} {:<8} {:<6}\n", "NAME", "SOURCE", "TRANSPORT", "ROUTED");
    for d in &detected {
        out.push_str(&format!("{:<24} {:<20} {:<8} {}\n",
            d.name, d.source_label, d.transport,
            if d.routed_via_crux { "yes" } else { "NO ⚠" }));
    }
    let unrouted: Vec<&crate::mcp_detect::DetectedMcp> = detected.iter()
        .filter(|d| !d.routed_via_crux).collect();
    if !unrouted.is_empty() {
        out.push('\n');
        for d in &unrouted {
            out.push_str(&remediation_instructions(d));
            out.push('\n');
        }
    }
    Ok(out)
}

fn remediation_instructions(det: &crate::mcp_detect::DetectedMcp) -> String {
    format!(
        "SECURITY WARNING: '{name}' is configured in {path} but is NOT routed\n\
through the Crux policy router. The router cannot enforce clearance,\n\
audit, redaction, or rate limits on this server.\n\
\n\
To route through Crux:\n\
  1. Run: mesh route_external --name {name}\n\
  2. Run: mesh approve_mcp --alias {name}\n\
  3. In {path}, replace the \"{name}\" entry with:\n\
       {{ \"command\": \"<crux_router_path>\",\n\
         \"args\": [\"--policy-router\", \"--proxy\", \"{name}\"] }}\n\
  4. Restart <client_app>.",
        name = det.name,
        path = det.source_path.display(),
    )
}

fn tool_mesh_route_external(args: &str) -> Result<String, String> {
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };
    let name = extract_string_value(args, "name")
        .ok_or_else(|| "Missing required parameter: name".to_string())?;

    // Look up the server in the detected list
    let detected = crate::mcp_detect::detect_external_mcp(&mesh_dir)?;
    let det = detected.iter().find(|d| d.name == name)
        .ok_or_else(|| format!("'{}' not found in detected external MCP servers", name))?;

    if det.routed_via_crux {
        return Ok(format!("'{}' is already routed via the Crux policy router.", name));
    }

    // Stage as proposed registration
    let clearance = "internal";
    let tools = "*";
    let rate = "";
    let source = format!("detect:{}", det.source_label);
    mesh::mesh_register_mcp_with_source(
        &mesh_dir, &det.name, &det.transport,
        &det.command, &det.url, clearance, tools, rate, &source,
        &crate::schema::OAuthConfig::default(),
    )?;
    Ok(format!(
        "Staged '{}' as a proposed registration (status=proposed, source={}).\n\
Run: mesh approve_mcp --alias {} to activate.",
        name, source, name
    ))
}

fn tool_mesh_query(args: &str) -> Result<String, String> {
    let filter = crate::query::NodeFilter::from_args(args);
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd)
                .ok_or_else(|| "No mesh found.".to_string())?
        }
    };

    let manifest = mesh::load_mesh(&mesh_dir)?;
    let results = mesh::mesh_query(&manifest, &mesh_dir, &filter);
    let display_query = filter.query.as_deref().unwrap_or("");
    let mut out = mesh::format_mesh_query_results(&results, display_query);
    // Append the current mesh-wide VectorClock so clients can use it for
    // subsequent diff_clock calls.
    let clock = mesh::mesh_current_clock(&manifest, &mesh_dir);
    out.push_str(&format!("\nClock: {}", clock.to_json_inline()));
    Ok(out)
}

fn tool_crux_add_node(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let name = extract_string_value(args, "name")
        .ok_or_else(|| "Missing required parameter: name".to_string())?;
    let kind = extract_string_value(args, "kind").unwrap_or_else(|| "function".to_string());
    let module = extract_string_value(args, "module").unwrap_or_default();
    let summary = extract_string_value(args, "summary").unwrap_or_default();
    let classification =
        extract_string_value(args, "classification").unwrap_or_else(|| "internal".to_string());
    let tags: Vec<String> = extract_string_value(args, "tags")
        .map(|t| {
            t.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let path = PathBuf::from(&path_str);
    let mut db = schema::load_crux_db(&path)?;

    if db.nodes.iter().any(|n| n.name == name && n.deleted_at.is_none()) {
        return Err(format!("Node '{}' already exists", name));
    }

    let node_id = format!(
        "sha256:{}",
        crate::crypto::sha256_hex(format!("node:{}:{}", db.header.crux_id, name).as_bytes())
    );
    let mut node = schema::CruxNode {
        node_id: node_id.clone(),
        name: name.clone(),
        kind: kind.clone(),
        module,
        summary,
        schema: schema::NodeSchema::empty(),
        tags,
        reach: Vec::new(),
        properties: Vec::new(),
        warnings: Vec::new(),
        planning: schema::PlanningMetadata {
                updated_at: Some(crate::crypto::now_unix()),
                ..schema::PlanningMetadata::empty()
            },
        security: schema::SecurityMetadata {
            classification,
            redact_below: None,
        },
        content_hash: String::new(),
        deleted_at: None,
    };
    // Hash the node we actually built, so no field can be forgotten here.
    node.content_hash = schema::node_content_hash(&node);
    db.nodes.push(node);

    schema::save_crux_db(&db, &path)?;
    Ok(format!(
        "Added node '{}' ({}) to crux '{}'\nNode ID: {}",
        name, kind, db.header.crux_name, node_id
    ))
}

fn tool_crux_add_edge(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let src = extract_string_value(args, "src")
        .ok_or_else(|| "Missing required parameter: src".to_string())?;
    let dst = extract_string_value(args, "dst")
        .ok_or_else(|| "Missing required parameter: dst".to_string())?;
    let kind_str =
        extract_string_value(args, "kind").unwrap_or_else(|| "relates_to".to_string());
    let detail = extract_string_value(args, "detail").unwrap_or_default();

    let path = PathBuf::from(&path_str);
    let mut db = schema::load_crux_db(&path)?;

    if !db.nodes.iter().any(|n| n.name == src && n.deleted_at.is_none()) {
        return Err(format!("Source node '{}' not found", src));
    }
    if !db.nodes.iter().any(|n| n.name == dst && n.deleted_at.is_none()) {
        return Err(format!("Destination node '{}' not found", dst));
    }

    let edge_id = format!(
        "sha256:{}",
        crate::crypto::sha256_hex(
            format!("edge:{}:{}:{}", db.header.crux_id, src, dst).as_bytes()
        )
    );
    let edge_kind = schema::EdgeKind::from_str(&kind_str);

    db.edges.push(schema::CruxEdge {
        edge_id: edge_id.clone(),
        src: src.clone(),
        dst: dst.clone(),
        kind: edge_kind,
        weight: 1.0,
        detail,
        cross_crux: false,
        binding: String::new(),
        created_at: crate::crypto::now_unix(),
        dangling: false,
    });

    schema::save_crux_db(&db, &path)?;
    Ok(format!(
        "Added edge {} --[{}]--> {} in crux '{}'\nEdge ID: {}",
        src, kind_str, dst, db.header.crux_name, edge_id
    ))
}

fn tool_crux_remove_node(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let name = extract_string_value(args, "name")
        .ok_or_else(|| "Missing required parameter: name".to_string())?;

    let path = PathBuf::from(&path_str);
    let mut db = schema::load_crux_db(&path)?;

    let crux_name = db.header.crux_name.clone();
    let node = db
        .nodes
        .iter_mut()
        .find(|n| n.name == name && n.deleted_at.is_none())
        .ok_or_else(|| format!("Node '{}' not found or already deleted", name))?;

    node.deleted_at = Some(crate::crypto::now_unix());

    schema::save_crux_db(&db, &path)?;
    Ok(format!("Soft-deleted node '{}' from crux '{}'", name, crux_name))
}

fn tool_crux_generate(args: &str) -> Result<String, String> {
    let name = extract_string_value(args, "name")
        .ok_or_else(|| "Missing required parameter: name".to_string())?;
    let format = extract_string_value(args, "format").unwrap_or_else(|| "auto".to_string());
    let dir = match extract_string_value(args, "path") {
        Some(p) => PathBuf::from(p),
        None => resolve_working_dir(),
    };

    // Support either inline `input` text OR `file_path` pointing to a file on disk.
    let input = if let Some(file_path) = extract_string_value(args, "file_path") {
        std::fs::read_to_string(&file_path)
            .map_err(|e| format!("Cannot read '{}': {}", file_path, e))?
    } else {
        extract_string_value(args, "input")
            .ok_or_else(|| "Missing required parameter: input or file_path".to_string())?
    };

    let config = AdapterConfig::new(&name, &format);
    let db = match format.as_str() {
        "markdown" => crate::adapters::markdown::MarkdownAdapter.generate(&input, &config)?,
        "plaintext" => crate::adapters::plaintext::PlaintextAdapter.generate(&input, &config)?,
        "manual" => crate::adapters::manual::ManualAdapter.generate(&input, &config)?,
        "csv" => {
            use crate::adapters::csv::{CsvAdapter, ColumnMap};
            let mut col_map = ColumnMap::new();
            if let Some(key_pos) = args.find("\"column_mappings\"") {
                let after_key = &args[key_pos + 17..];
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
            let node_kind = extract_string_value(args, "node_kind")
                .unwrap_or_else(|| "record".to_string());
            CsvAdapter::generate_with_map(&input, &config, &col_map, &node_kind)?
        }
        _ => crate::adapters::auto::AutoAdapter.generate(&input, &config)?,
    };

    schema::save_crux_db(&db, &dir)?;
    Ok(format!(
        "Generated crux '{}' ({} nodes, {} edges)\nFile: {}",
        name,
        db.nodes.len(),
        db.edges.len(),
        dir.join(".crux.json").display()
    ))
}

fn tool_mesh_create_cluster(args: &str) -> Result<String, String> {
    let cluster_name = extract_string_value(args, "name")
        .ok_or_else(|| "Missing required parameter: name".to_string())?;
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };
    let classification =
        extract_string_value(args, "classification").unwrap_or_else(|| "internal".to_string());
    let policy = extract_string_value(args, "policy").unwrap_or_else(|| "allow".to_string());

    mesh::create_cluster(&mesh_dir, &cluster_name, &classification, &policy)?;
    let manifest = mesh::load_mesh(&mesh_dir)?;
    let audit_log = AuditLog::for_crux(&mesh_dir);
    let _ = audit_log.append(AuditEvent {
        timestamp: crate::schema::now_unix(),
        event: AuditEventKind::NodeAdded,
        crux_id: manifest.mesh_id.clone(),
        subject: format!("cluster:{}", cluster_name),
        actor: None,
        detail: Some(format!("classification={}, policy={}", classification, policy)),
        ..Default::default()
    });
    Ok(format!(
        "Created cluster '{}' (classification: {}, cross-cluster: {})",
        cluster_name, classification, policy
    ))
}

fn tool_mesh_assign_cluster(args: &str) -> Result<String, String> {
    let identifier = extract_string_value(args, "identifier")
        .ok_or_else(|| "Missing required parameter: identifier".to_string())?;
    let cluster_name = extract_string_value(args, "cluster")
        .ok_or_else(|| "Missing required parameter: cluster".to_string())?;
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };

    let manifest = mesh::assign_cluster(&mesh_dir, &identifier, &cluster_name)?;
    let member_name = manifest
        .members
        .iter()
        .find(|m| m.crux_name == identifier || m.crux_id == identifier)
        .map(|m| m.crux_name.clone())
        .unwrap_or_else(|| identifier.clone());
    let audit_log = AuditLog::for_crux(&mesh_dir);
    let _ = audit_log.append(AuditEvent {
        timestamp: crate::schema::now_unix(),
        event: AuditEventKind::NodeUpdated,
        crux_id: manifest.mesh_id.clone(),
        subject: member_name.clone(),
        actor: None,
        detail: Some(format!("cluster={}", cluster_name)),
        ..Default::default()
    });
    Ok(format!(
        "Assigned '{}' to cluster '{}' in mesh '{}'",
        member_name, cluster_name, manifest.mesh_name
    ))
}

fn tool_mesh_register_mcp(args: &str) -> Result<String, String> {
    let alias = extract_string_value(args, "alias")
        .ok_or_else(|| "Missing required parameter: alias".to_string())?;
    let transport = extract_string_value(args, "transport")
        .ok_or_else(|| "Missing required parameter: transport".to_string())?;
    let command = extract_string_value(args, "command").unwrap_or_default();
    let url = extract_string_value(args, "url").unwrap_or_default();
    let required_clearance = extract_string_value(args, "required_clearance")
        .unwrap_or_else(|| "internal".to_string());
    let allowed_tools = extract_string_value(args, "allowed_tools")
        .unwrap_or_else(|| "*".to_string());
    let rate_limit = extract_string_value(args, "rate_limit").unwrap_or_default();
    let oauth = crate::schema::OAuthConfig {
        auth: extract_string_value(args, "auth").unwrap_or_else(|| "none".to_string()),
        client_id: extract_string_value(args, "oauth_client_id").unwrap_or_default(),
        scopes: extract_string_value(args, "oauth_scopes").unwrap_or_default(),
        discovery_url: extract_string_value(args, "oauth_discovery_url").unwrap_or_default(),
        authorization_endpoint: extract_string_value(args, "oauth_authorization_endpoint").unwrap_or_default(),
        token_endpoint: extract_string_value(args, "oauth_token_endpoint").unwrap_or_default(),
        registration_endpoint: extract_string_value(args, "oauth_registration_endpoint").unwrap_or_default(),
    };
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };

    let result = mesh::mesh_register_mcp(
        &mesh_dir, &alias, &transport, &command, &url,
        &required_clearance, &allowed_tools, &rate_limit, &oauth,
    )?;

    let manifest = mesh::load_mesh(&mesh_dir)?;
    let audit_log = AuditLog::for_crux(&mesh_dir);
    let _ = audit_log.append(AuditEvent {
        timestamp: crate::schema::now_unix(),
        event: AuditEventKind::NodeAdded,
        crux_id: manifest.mesh_id.clone(),
        subject: format!("mcp_server_registration:{}", alias),
        actor: None,
        detail: Some(format!("transport={}, clearance={}", transport, required_clearance)),
        ..Default::default()
    });

    Ok(result)
}

fn tool_mesh_list_mcp_servers(args: &str) -> Result<String, String> {
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };
    mesh::mesh_list_mcp_servers(&mesh_dir)
}

fn tool_mesh_revoke_mcp(args: &str) -> Result<String, String> {
    let alias = extract_string_value(args, "alias")
        .ok_or_else(|| "Missing required parameter: alias".to_string())?;
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };
    let result = mesh::mesh_revoke_mcp(&mesh_dir, &alias)?;
    let manifest = mesh::load_mesh(&mesh_dir)?;
    let audit_log = AuditLog::for_crux(&mesh_dir);
    let _ = audit_log.append(AuditEvent {
        timestamp: crate::schema::now_unix(),
        event: AuditEventKind::NodeDeleted,
        crux_id: manifest.mesh_id.clone(),
        subject: format!("mcp_server_registration:{}", alias),
        actor: None,
        detail: Some("soft-delete via revoke_mcp".to_string()),
        ..Default::default()
    });
    Ok(result)
}

fn tool_mesh_push(args: &str) -> Result<String, String> {
    let src = extract_string_value(args, "src")
        .ok_or_else(|| "Missing required parameter: src".to_string())?;
    let dst = extract_string_value(args, "dst")
        .ok_or_else(|| "Missing required parameter: dst".to_string())?;
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };
    let clearance = std::env::var("CRUX_CALLER_CLEARANCE")
        .map(|v| mesh::SecurityLevel::from_str(&v))
        .unwrap_or(mesh::SecurityLevel::Internal);
    let result = mesh::mesh_push(&mesh_dir, &src, &dst, clearance)?;

    let manifest = mesh::load_mesh(&mesh_dir)?;
    let audit_log = AuditLog::for_crux(&mesh_dir);
    let _ = audit_log.append(AuditEvent {
        timestamp: crate::schema::now_unix(),
        event: AuditEventKind::NodeAdded,
        crux_id: manifest.mesh_id.clone(),
        subject: format!("replicate:push:{}→{}", src, dst),
        actor: None,
        detail: Some(result.clone()),
        ..Default::default()
    });
    Ok(result)
}

fn tool_mesh_pull(args: &str) -> Result<String, String> {
    let src = extract_string_value(args, "src")
        .ok_or_else(|| "Missing required parameter: src".to_string())?;
    let dst = extract_string_value(args, "dst")
        .ok_or_else(|| "Missing required parameter: dst".to_string())?;
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };
    let clearance = std::env::var("CRUX_CALLER_CLEARANCE")
        .map(|v| mesh::SecurityLevel::from_str(&v))
        .unwrap_or(mesh::SecurityLevel::Internal);
    let result = mesh::mesh_pull(&mesh_dir, &src, &dst, clearance)?;

    let manifest = mesh::load_mesh(&mesh_dir)?;
    let audit_log = AuditLog::for_crux(&mesh_dir);
    let _ = audit_log.append(AuditEvent {
        timestamp: crate::schema::now_unix(),
        event: AuditEventKind::NodeAdded,
        crux_id: manifest.mesh_id.clone(),
        subject: format!("replicate:pull:{}→{}", src, dst),
        actor: None,
        detail: Some(result.clone()),
        ..Default::default()
    });
    Ok(result)
}

// ===========================================================================
// OAuth management tools (Phase 7)
// ===========================================================================

fn tool_mesh_auth_status(args: &str) -> Result<String, String> {
    let alias = extract_string_value(args, "alias")
        .ok_or_else(|| "Missing required parameter: alias".to_string())?;
    let status = crate::oauth::auth_status(&alias);
    let mut out = format!("alias: {}\nstatus: {}", status.alias, status.status);
    if let Some(exp) = status.expires_at {
        let now = crate::schema::now_unix();
        if exp > now {
            let secs = exp - now;
            out.push_str(&format!("\nexpires_in: {}s (~{}m)", secs, secs / 60));
        } else {
            out.push_str(&format!("\nexpired_since: {}s ago", now - exp));
        }
    }
    if let Some(sc) = &status.scopes {
        out.push_str(&format!("\nscopes: {}", sc));
    }
    Ok(out)
}

fn tool_mesh_trigger_auth(args: &str) -> Result<String, String> {
    let alias = extract_string_value(args, "alias")
        .ok_or_else(|| "Missing required parameter: alias".to_string())?;

    // Resolve mesh_dir and load the registration
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };
    let policy_crux_dir = {
        let manifest = mesh::load_mesh(&mesh_dir)?;
        let pm = manifest.members.iter()
            .find(|m| m.crux_kind == schema::CruxKind::Policy)
            .ok_or_else(|| "No policy crux in mesh".to_string())?;
        mesh_dir.join(&pm.path)
    };
    let policy_db = schema::load_crux_db(&policy_crux_dir)?;
    let all_regs = schema::parse_all_mcp_server_registrations(&policy_db);
    let reg = all_regs.iter()
        .find(|r| r.alias == alias)
        .ok_or_else(|| format!("No registration found for alias '{}'", alias))?;

    if reg.auth != "oauth2" {
        return Err(format!(
            "Registration '{}' has auth='{}' — must be 'oauth2' to use trigger_auth",
            alias, reg.auth
        ));
    }

    let oauth_reg = crate::oauth::OAuthReg::from_schema(reg);
    // Paste fallback params
    let preauth_code     = extract_string_value(args, "code");
    let preauth_state    = extract_string_value(args, "state");
    let preauth_verifier = extract_string_value(args, "code_verifier");
    let preauth_redirect = extract_string_value(args, "redirect_uri");

    crate::oauth::authorize(
        &alias,
        &oauth_reg,
        preauth_code.as_deref(),
        preauth_state.as_deref(),
        preauth_verifier.as_deref(),
        preauth_redirect.as_deref(),
        Some(&mesh_dir),
    )
}

fn tool_mesh_oauth_revoke(args: &str) -> Result<String, String> {
    let alias = extract_string_value(args, "alias")
        .ok_or_else(|| "Missing required parameter: alias".to_string())?;
    crate::oauth::revoke_token(&alias)?;
    Ok(format!("OAuth token for '{}' revoked — next call will require re-authorization.", alias))
}

// ===========================================================================
// Agentic intelligence tools
// ===========================================================================

fn tool_crux_scan(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let max_depth = extract_string_value(args, "max_depth")
        .and_then(|s| s.parse::<usize>().ok());
    let extensions: Vec<String> = extract_string_value(args, "extensions")
        .map(|s| s.split(',').map(|e| e.trim().to_string()).filter(|e| !e.is_empty()).collect())
        .unwrap_or_default();

    let result = scan_directory(
        &PathBuf::from(&path_str),
        max_depth,
        &extensions,
    )?;

    let mut out = format!("{}\n\n", result.summary());
    out.push_str(&result.to_json());
    Ok(out)
}

fn tool_crux_generate_dir(args: &str) -> Result<String, String> {
    let source_path = extract_string_value(args, "source_path")
        .ok_or_else(|| "Missing required parameter: source_path".to_string())?;
    let output_path = extract_string_value(args, "output_path")
        .ok_or_else(|| "Missing required parameter: output_path".to_string())?;
    let mesh_name = extract_string_value(args, "mesh_name")
        .ok_or_else(|| "Missing required parameter: mesh_name".to_string())?;

    let strategy = GroupingStrategy::from_str(
        &extract_string_value(args, "strategy").unwrap_or_else(|| "by_kind".to_string())
    );
    let device_id = extract_string_value(args, "device_id");
    let classification = extract_string_value(args, "classification");
    let max_depth = extract_string_value(args, "max_depth")
        .and_then(|s| s.parse::<usize>().ok());

    let result = generate_dir(
        &PathBuf::from(&source_path),
        &PathBuf::from(&output_path),
        &mesh_name,
        strategy,
        device_id.as_deref(),
        classification.as_deref(),
        max_depth,
    )?;

    let mut out = result.summary.clone();
    out.push_str("\n\nCreated cruxes:");
    for (name, path) in &result.cruxes {
        out.push_str(&format!("\n  {} → {}", name, path.display()));
    }
    if !result.skipped.is_empty() {
        out.push_str(&format!("\n\nSkipped {} file(s) (binary/image/document — metadata-only nodes added):", result.skipped.len()));
        for f in result.skipped.iter().take(10) {
            out.push_str(&format!("\n  {}", f.relative_path));
        }
        if result.skipped.len() > 10 {
            out.push_str(&format!("\n  ... and {} more", result.skipped.len() - 10));
        }
    }
    Ok(out)
}

fn tool_crux_add_nodes_batch(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let nodes_json = extract_string_value(args, "nodes")
        .ok_or_else(|| "Missing required parameter: nodes".to_string())?;

    let path = PathBuf::from(&path_str);
    let mut db = schema::load_crux_db(&path)?;

    // Parse the nodes array — each element is a JSON object
    let mut added = 0usize;
    let mut skipped = 0usize;

    // Walk the JSON array manually
    let trimmed = nodes_json.trim();
    if !trimmed.starts_with('[') {
        return Err("nodes must be a JSON array".to_string());
    }

    // Extract each node object from the array
    let node_objects = extract_json_objects_from_array(trimmed);

    for obj in &node_objects {
        let name = match extract_string_value(obj, "name") {
            Some(n) => n,
            None => { skipped += 1; continue; }
        };

        // Skip duplicates
        if db.nodes.iter().any(|n| n.name == name && n.deleted_at.is_none()) {
            skipped += 1;
            continue;
        }

        let kind = extract_string_value(obj, "kind").unwrap_or_else(|| "record".to_string());
        let module = extract_string_value(obj, "module").unwrap_or_default();
        let summary = extract_string_value(obj, "summary").unwrap_or_default();
        let classification = extract_string_value(obj, "classification")
            .unwrap_or_else(|| "internal".to_string());
        let tags: Vec<String> = extract_string_value(obj, "tags")
            .map(|t| t.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        let properties: Vec<String> = extract_string_array(obj, "properties");

        let node_id = format!(
            "sha256:{}",
            crate::crypto::sha256_hex(format!("node:{}:{}", db.header.crux_id, name).as_bytes())
        );
        let content_hash = format!(
            "sha256:{}",
            crate::crypto::sha256_hex(format!("{}:{}", name, summary).as_bytes())
        );

        db.nodes.push(schema::CruxNode {
            node_id,
            name,
            kind,
            module,
            summary,
            schema: schema::NodeSchema::empty(),
            tags,
            reach: Vec::new(),
            properties,
            warnings: Vec::new(),
            planning: schema::PlanningMetadata {
                updated_at: Some(crate::crypto::now_unix()),
                ..schema::PlanningMetadata::empty()
            },
            security: schema::SecurityMetadata { classification, redact_below: None },
            content_hash,
            deleted_at: None,
        });
        added += 1;
    }

    schema::save_crux_db(&db, &path)?;
    Ok(format!(
        "Batch add complete: {} node(s) added, {} skipped (already exist or missing name)",
        added, skipped
    ))
}

/// Batch-add edges, rejecting any whose endpoints do not resolve.
///
/// All-or-nothing by default: if any edge in the batch is invalid, nothing is
/// written and the caller gets every offender named. A partially-applied batch
/// leaves an unattended writer unsure what to retry, so the safer default is to
/// apply none of it.
///
/// `allow_forward_refs=true` is the deliberate escape hatch for pipelines that
/// write edges before their nodes: unresolved edges are then admitted and stored
/// with `dangling: true`, which `verify` and `load` report. Without the flag a
/// typo and an intentional forward reference are indistinguishable once written.
fn tool_crux_add_edges_batch(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let edges_json = extract_string_value(args, "edges")
        .ok_or_else(|| "Missing required parameter: edges".to_string())?;
    let allow_forward_refs = extract_bool_value(args, "allow_forward_refs").unwrap_or(false);

    let path = PathBuf::from(&path_str);
    let mut db = schema::load_crux_db(&path)?;

    let trimmed = edges_json.trim();
    if !trimmed.starts_with('[') {
        return Err("edges must be a JSON array".to_string());
    }

    let edge_objects = extract_json_objects_from_array(trimmed);

    // Pass 1: resolve and classify every edge before writing any of them.
    struct Pending {
        src: String,
        dst: String,
        kind: String,
        detail: String,
        unresolved: bool,
    }
    let mut pending: Vec<Pending> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();
    let mut forward_refs: Vec<String> = Vec::new();

    for (index, obj) in edge_objects.iter().enumerate() {
        let src = extract_string_value(obj, "src");
        let dst = extract_string_value(obj, "dst");

        // A missing src/dst *key* is malformed input, distinct from a key that
        // names a node which does not exist.
        let (src, dst) = match (src, dst) {
            (Some(s), Some(d)) => (s, d),
            (s, d) => {
                let mut missing = Vec::new();
                if s.is_none() { missing.push("src"); }
                if d.is_none() { missing.push("dst"); }
                rejected.push(format!(
                    "  [{}] {} --> {}: missing required field(s): {}",
                    index,
                    s.as_deref().unwrap_or("<no src>"),
                    d.as_deref().unwrap_or("<no dst>"),
                    missing.join(", ")
                ));
                continue;
            }
        };

        let sides = schema::DanglingSides {
            src_missing: !schema::node_exists(&db, &src),
            dst_missing: !schema::node_exists(&db, &dst),
        };
        let unresolved = sides.src_missing || sides.dst_missing;

        if unresolved && !allow_forward_refs {
            rejected.push(format!("  [{}] {} --> {}: {}", index, src, dst, sides.reason()));
            continue;
        }
        if unresolved {
            forward_refs.push(format!("  [{}] {} --> {}: {}", index, src, dst, sides.reason()));
        }

        pending.push(Pending {
            src,
            dst,
            kind: extract_string_value(obj, "kind").unwrap_or_else(|| "relates_to".to_string()),
            detail: extract_string_value(obj, "detail").unwrap_or_default(),
            unresolved,
        });
    }

    if !rejected.is_empty() {
        return Err(format!(
            "Batch rejected: {} of {} edge(s) invalid. No edges were written.\n{}\n\n\
             Add the missing nodes first, or pass allow_forward_refs=true to store\n\
             unresolved edges as dangling (reported by verify and load).",
            rejected.len(),
            edge_objects.len(),
            rejected.join("\n")
        ));
    }

    // Pass 2: every edge validated, so the write cannot leave a partial batch.
    for edge in &pending {
        let edge_id = format!(
            "sha256:{}",
            crate::crypto::sha256_hex(
                format!("edge:{}:{}:{}", db.header.crux_id, edge.src, edge.dst).as_bytes()
            )
        );

        db.edges.push(schema::CruxEdge {
            edge_id,
            src: edge.src.clone(),
            dst: edge.dst.clone(),
            kind: schema::EdgeKind::from_str(&edge.kind),
            weight: 1.0,
            detail: edge.detail.clone(),
            cross_crux: edge.unresolved,
            binding: String::new(),
            created_at: crate::crypto::now_unix(),
            dangling: edge.unresolved,
        });
    }

    schema::save_crux_db(&db, &path)?;

    let mut out = format!(
        "Batch add complete: {} edge(s) added, all endpoints resolved.",
        pending.len()
    );
    if !forward_refs.is_empty() {
        out = format!(
            "Batch add complete: {} edge(s) added, {} stored as dangling forward reference(s):\n{}",
            pending.len(),
            forward_refs.len(),
            forward_refs.join("\n")
        );
    }
    Ok(out)
}

fn tool_crux_update_node(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let name = extract_string_value(args, "name")
        .ok_or_else(|| "Missing required parameter: name".to_string())?;

    let path = PathBuf::from(&path_str);
    let mut db = schema::load_crux_db(&path)?;

    let node = db
        .nodes
        .iter_mut()
        .find(|n| n.name == name && n.deleted_at.is_none())
        .ok_or_else(|| format!("Node '{}' not found or deleted", name))?;

    let mut updated_fields = Vec::new();

    if let Some(summary) = extract_string_value(args, "summary") {
        node.summary = summary;
        updated_fields.push("summary");
    }
    if let Some(tags_str) = extract_string_value(args, "tags") {
        node.tags = tags_str.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        updated_fields.push("tags");
    }
    if let Some(classification) = extract_string_value(args, "classification") {
        node.security.classification = classification;
        updated_fields.push("classification");
    }
    if let Some(props_str) = extract_string_value(args, "properties") {
        // Append new properties
        let new_props: Vec<String> = props_str.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.contains('='))
            .collect();
        node.properties.extend(new_props);
        updated_fields.push("properties");
    }
    if let Some(status) = extract_string_value(args, "status") {
        node.planning.status = Some(status);
        updated_fields.push("status");
    }
    if let Some(priority_str) = extract_string_value(args, "priority") {
        if let Ok(p) = priority_str.trim().parse::<u8>() {
            node.planning.priority = Some(p);
            updated_fields.push("priority");
        }
    }
    if let Some(depends_str) = extract_string_value(args, "depends") {
        node.planning.depends = depends_str.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        updated_fields.push("depends");
    }

    if !updated_fields.is_empty() {
        node.planning.updated_at = Some(crate::crypto::now_unix());
    }

    if updated_fields.is_empty() {
        return Ok(format!("No fields to update for node '{}'", name));
    }

    // Re-bless the content hash: this is an authoring edit, so the new payload
    // is by definition the correct one. (Mechanical load-and-save paths must NOT
    // do this — see schema::node_content_hash.)
    node.content_hash = schema::node_content_hash(node);

    schema::save_crux_db(&db, &path)?;
    Ok(format!(
        "Updated node '{}': {}",
        name,
        updated_fields.join(", ")
    ))
}

fn tool_crux_enrich(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let ops_str = extract_string_value(args, "operations")
        .unwrap_or_else(|| "reach".to_string());
    let ops: Vec<&str> = ops_str.split(',').map(|s| s.trim()).collect();

    let path = PathBuf::from(&path_str);
    let mut db = schema::load_crux_db(&path)?;
    let mut log: Vec<String> = Vec::new();

    if ops.contains(&"reach") {
        let before: usize = db.nodes.iter()
            .filter(|n| n.deleted_at.is_none() && !n.reach.is_empty())
            .count();
        schema::compute_reach(&mut db);
        let after: usize = db.nodes.iter()
            .filter(|n| n.deleted_at.is_none() && !n.reach.is_empty())
            .count();
        log.push(format!("reach: {}/{} nodes now have reach data (was {})",
            after,
            db.nodes.iter().filter(|n| n.deleted_at.is_none()).count(),
            before));
    }

    if ops.contains(&"lint") {
        let lml_bin = extract_string_value(args, "lml_bin")
            .unwrap_or_else(|| "lml".to_string());
        let mut lint_count = 0usize;
        let mut error_count = 0usize;

        let dir_path = if path.is_dir() { path.clone() } else {
            path.parent().unwrap_or(&path).to_path_buf()
        };

        // Build a filename → full path index by walking the source tree
        let mut file_index: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        if let Ok(walker) = std::fs::read_dir(&dir_path) {
            fn walk_dir(
                dir: &std::path::Path,
                idx: &mut std::collections::HashMap<String, String>,
                depth: usize,
            ) {
                if depth > 4 { return; }
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_dir() {
                            let name = p.file_name().unwrap_or_default().to_string_lossy();
                            if !name.starts_with('.') && name != "target" {
                                walk_dir(&p, idx, depth + 1);
                            }
                        } else if p.extension().and_then(|e| e.to_str()) == Some("lml") {
                            let fname = p.file_name().unwrap_or_default()
                                .to_string_lossy().to_string();
                            // Prefer shallower paths (first wins)
                            idx.entry(fname).or_insert_with(|| p.to_string_lossy().to_string());
                        }
                    }
                }
            }
            drop(walker);
            walk_dir(&dir_path, &mut file_index, 0);
        }

        // Collect module nodes with .lml extension
        let targets: Vec<String> = db.nodes.iter()
            .filter(|n| n.deleted_at.is_none() && n.kind == "module" && n.name.ends_with(".lml"))
            .map(|n| n.name.clone())
            .collect();

        for node_name in targets {
            // Resolve file path: prefer explicit file= property, then index lookup
            let explicit = db.nodes.iter()
                .find(|n| n.name == node_name)
                .and_then(|n| n.properties.iter().find(|p| p.starts_with("file=")).map(|p| p[5..].to_string()));

            let full_path = match explicit.or_else(|| file_index.get(&node_name).cloned()) {
                Some(p) => p,
                None => continue,
            };

            // Annotate the file= property if not already set
            if let Some(node) = db.nodes.iter_mut()
                .find(|n| n.name == node_name && n.deleted_at.is_none())
            {
                if !node.properties.iter().any(|p| p.starts_with("file=")) {
                    node.properties.push(format!("file={}", full_path));
                }
            }

            let result = std::process::Command::new(&lml_bin)
                .args(["--lint", &full_path])
                .output();

            match result {
                Ok(out) => {
                    let text = String::from_utf8_lossy(&out.stdout).to_string();
                    let findings: Vec<String> = text.lines()
                        .filter(|l| l.contains("[WARN]") || l.contains("[ERROR]"))
                        .map(|l| l.trim().to_string())
                        .collect();
                    if let Some(node) = db.nodes.iter_mut()
                        .find(|n| n.name == node_name && n.deleted_at.is_none())
                    {
                        node.warnings = findings;
                        lint_count += 1;
                    }
                }
                Err(_) => { error_count += 1; }
            }
        }
        log.push(format!("lint: {} nodes linted, {} errors", lint_count, error_count));
    }

    if ops.contains(&"schema") {
        let dir_path = if path.is_dir() { path.clone() } else {
            path.parent().unwrap_or(&path).to_path_buf()
        };

        // Pass 1: collect all .lml files and the IMPORT lists they receive
        // public_api: filename (bare) -> set of fn names imported from it by other files
        let mut public_api: std::collections::HashMap<String, std::collections::HashSet<String>> =
            std::collections::HashMap::new();

        fn collect_lml_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>, depth: usize) {
            if depth > 4 { return; }
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        let n = p.file_name().unwrap_or_default().to_string_lossy();
                        if !n.starts_with('.') && n != "target" { collect_lml_files(&p, out, depth + 1); }
                    } else if p.extension().and_then(|e| e.to_str()) == Some("lml") {
                        out.push(p);
                    }
                }
            }
        }

        let mut all_lml: Vec<std::path::PathBuf> = Vec::new();
        collect_lml_files(&dir_path, &mut all_lml, 0);

        // For each file, scan its IMPORT statements
        for lml_path in &all_lml {
            let src = match std::fs::read_to_string(lml_path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for line in src.lines() {
                let trimmed = line.trim();
                if !trimmed.starts_with("IMPORT") { continue; }
                // Extract the filename from IMPORT "./foo.lml" [...] or IMPORT [*]
                let fname = if let Some(start) = trimmed.find("\"./") {
                    let rest = &trimmed[start + 3..];
                    rest.split('"').next().map(|s| s.to_string())
                } else { None };
                let fname = match fname { Some(f) => f, None => continue };

                // Find the function list: between [ and ]
                // Skip wildcard [*] — will collect all names later
                let bracket_start = match trimmed.find('[') { Some(i) => i, None => continue };
                let list_src = &trimmed[bracket_start..];
                if list_src.starts_with("[*]") { continue; } // wildcard: skip selective tracking

                // Multi-line imports: read subsequent lines until ]
                let mut full_list = list_src.to_string();
                if !full_list.contains(']') {
                    // Need more lines — re-scan src from this position
                    let mut found_import_start = false;
                    for l2 in src.lines() {
                        if l2.trim() == trimmed { found_import_start = true; continue; }
                        if found_import_start {
                            full_list.push(' ');
                            full_list.push_str(l2.trim());
                            if l2.contains(']') { break; }
                        }
                    }
                }

                // Extract @fn_names from the list
                let entry = public_api.entry(fname).or_default();
                for word in full_list.split_whitespace() {
                    let w = word.trim_matches(|c| c == '[' || c == ']' || c == ',');
                    if w.starts_with('@') {
                        entry.insert(w.to_string());
                    }
                }
            }
        }

        // Handle wildcard IMPORT [*]: add ALL functions from that file as public
        for lml_path in &all_lml {
            let src = match std::fs::read_to_string(lml_path) { Ok(s) => s, Err(_) => continue };
            for line in src.lines() {
                let t = line.trim();
                if !t.starts_with("IMPORT") { continue; }
                if !t.contains("[*]") { continue; }
                let fname = if let Some(start) = t.find("\"./") {
                    let rest = &t[start + 3..];
                    rest.split('"').next().map(|s| s.to_string())
                } else { None };
                let fname = match fname { Some(f) => f, None => continue };

                // Find and read the target file, collect all FN names
                let target = all_lml.iter().find(|p| {
                    p.file_name().map(|n| n.to_string_lossy().to_string()).as_deref() == Some(&fname)
                });
                if let Some(tp) = target {
                    if let Ok(tsrc) = std::fs::read_to_string(tp) {
                        let entry = public_api.entry(fname).or_default();
                        for tl in tsrc.lines() {
                            let tt = tl.trim();
                            if tt.starts_with("FN @") {
                                let fn_name = tt.splitn(2, '[').next()
                                    .unwrap_or("").trim()
                                    .splitn(2, ' ').nth(1)
                                    .unwrap_or("").trim().to_string();
                                if fn_name.starts_with('@') { entry.insert(fn_name); }
                            }
                        }
                    }
                }
            }
        }

        // Pass 2: for each .lml module node, parse its FN declarations
        // and populate schema for functions in its public API
        let mut schema_count = 0usize;
        let targets: Vec<(String, String)> = db.nodes.iter()
            .filter(|n| n.deleted_at.is_none() && n.kind == "module" && n.name.ends_with(".lml"))
            .map(|n| {
                let file_prop = n.properties.iter()
                    .find(|p| p.starts_with("file="))
                    .map(|p| p[5..].to_string())
                    .unwrap_or_default();
                (n.name.clone(), file_prop)
            })
            .filter(|(_, fp)| !fp.is_empty())
            .collect();

        for (node_name, file_path) in targets {
            let bare_name = node_name.clone();
            let api_set = match public_api.get(&bare_name) {
                Some(s) => s.clone(),
                None => continue, // no file imports from this module
            };
            if api_set.is_empty() { continue; }

            let src = match std::fs::read_to_string(&file_path) { Ok(s) => s, Err(_) => continue };

            // Parse FN declarations: "FN @name [@p1 @p2 ...] -> @ret"
            let mut fn_decls: Vec<(Vec<schema::SchemaSlot>, schema::SchemaSlot)> = Vec::new();
            let mut fn_names_ordered: Vec<String> = Vec::new();
            for line in src.lines() {
                let t = line.trim();
                if t.starts_with("FN @") {
                    // FN @name [@p1 @p2] -> @ret
                    let after_fn = &t[3..]; // "@name [@p1...] -> @ret"
                    let fn_name = after_fn.split(|c| c == ' ' || c == '[')
                        .next().unwrap_or("").trim().to_string();
                    if !fn_name.starts_with('@') { continue; }

                    let params: Vec<schema::SchemaSlot> = {
                        let bracket = after_fn.find('[').and_then(|s| {
                            after_fn[s..].find(']').map(|e| &after_fn[s+1..s+e])
                        });
                        match bracket {
                            Some(inner) => inner.split_whitespace()
                                .filter(|w| w.starts_with('@'))
                                .map(|w| schema::SchemaSlot {
                                    name: w.to_string(),
                                    type_str: "?".to_string(),
                                })
                                .collect(),
                            None => Vec::new(),
                        }
                    };

                    let ret: schema::SchemaSlot = {
                        let ret_name = after_fn.find("-> @")
                            .map(|i| after_fn[i+3..].trim().split_whitespace().next().unwrap_or("@result").to_string())
                            .unwrap_or_else(|| "@result".to_string());
                        schema::SchemaSlot { name: ret_name, type_str: "?".to_string() }
                    };

                    if api_set.contains(&fn_name) {
                        fn_names_ordered.push(fn_name.clone());
                        fn_decls.push((params, ret));
                    }
                }
            }

            if fn_decls.is_empty() { continue; }

            // Build consolidated schema: inputs = first public fn's params (entry point),
            // outputs = all public fn names as schema slots (API surface listing)
            // Use the first fn alphabetically as the "primary entry", list all as outputs
            let mut sorted: Vec<(String, Vec<schema::SchemaSlot>, schema::SchemaSlot)> =
                fn_names_ordered.into_iter().zip(fn_decls.into_iter())
                    .map(|(n, (p, r))| (n, p, r))
                    .collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));

            // inputs: params of primary function (longest param list = likely entry point)
            let primary = sorted.iter().max_by_key(|(_, p, _)| p.len());
            let inputs = primary.map(|(_, p, _)| p.clone()).unwrap_or_default();

            // outputs: one slot per exported function name
            let outputs: Vec<schema::SchemaSlot> = sorted.iter()
                .map(|(name, params, ret)| schema::SchemaSlot {
                    name: name.clone(),
                    type_str: format!("({}) -> {}", params.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", "), ret.name),
                })
                .collect();

            if let Some(node) = db.nodes.iter_mut()
                .find(|n| n.name == node_name && n.deleted_at.is_none())
            {
                node.schema.inputs = inputs;
                node.schema.outputs = outputs;
                schema_count += 1;
            }
        }
        log.push(format!("schema: {} nodes enriched with API schema", schema_count));
    }

    if ops.contains(&"functions") {
        let dir_path = if path.is_dir() { path.clone() } else {
            path.parent().unwrap_or(&path).to_path_buf()
        };
        const FN_NODE_CAP: usize = 15;

        // Walk all .lml files
        fn collect_lml2(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>, depth: usize) {
            if depth > 4 { return; }
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        let n = p.file_name().unwrap_or_default().to_string_lossy();
                        if !n.starts_with('.') && n != "target" { collect_lml2(&p, out, depth + 1); }
                    } else if p.extension().and_then(|e| e.to_str()) == Some("lml") {
                        out.push(p);
                    }
                }
            }
        }
        let mut all_lml2: Vec<std::path::PathBuf> = Vec::new();
        collect_lml2(&dir_path, &mut all_lml2, 0);

        // Build: selective_api[module_filename] -> {fn_name -> import_count}
        // (count = number of distinct files that selectively import this fn)
        let mut selective_api: std::collections::HashMap<String, std::collections::HashMap<String, usize>> =
            std::collections::HashMap::new();

        for lml_path in &all_lml2 {
            let importer = lml_path.file_name().unwrap_or_default().to_string_lossy().to_string();
            let src = match std::fs::read_to_string(lml_path) { Ok(s) => s, Err(_) => continue };
            for line in src.lines() {
                let t = line.trim();
                if !t.starts_with("IMPORT") { continue; }
                if t.contains("[*]") { continue; } // skip wildcard
                let fname = if let Some(s) = t.find("\"./") {
                    t[s+3..].split('"').next().map(|s| s.to_string())
                } else { None };
                let fname = match fname { Some(f) => f, None => continue };
                // Collect fn names from the import block (may span multiple lines)
                let bracket = t.find('[').map(|i| &t[i..]);
                let list = match bracket { Some(b) => b, None => continue };
                let mut full = list.to_string();
                if !full.contains(']') {
                    let mut found = false;
                    for l2 in src.lines() {
                        if l2.trim() == t { found = true; continue; }
                        if found { full.push(' '); full.push_str(l2.trim()); if l2.contains(']') { break; } }
                    }
                }
                let module_entry = selective_api.entry(fname).or_default();
                for word in full.split_whitespace() {
                    let w = word.trim_matches(|c| c == '[' || c == ']' || c == ',');
                    if w.starts_with('@') && w != importer.as_str() {
                        *module_entry.entry(w.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }

        // Build fn_signatures map from source files: fn_name -> (params, ret)
        // For each module node in the db that has a file= property
        let mut fn_signatures: std::collections::HashMap<String, (Vec<String>, String)> =
            std::collections::HashMap::new();
        for node in db.nodes.iter().filter(|n| n.deleted_at.is_none() && n.kind == "module") {
            let file_path_opt = node.properties.iter()
                .find(|p| p.starts_with("file="))
                .map(|p| p[5..].to_string());
            let file_path = match file_path_opt { Some(f) => f, None => continue };
            let src = match std::fs::read_to_string(&file_path) { Ok(s) => s, Err(_) => continue };
            for line in src.lines() {
                let t = line.trim();
                if !t.starts_with("FN @") { continue; }
                let after = &t[3..];
                let fn_name = after.split(|c| c == ' ' || c == '[')
                    .next().unwrap_or("").trim().to_string();
                if !fn_name.starts_with('@') { continue; }
                let params: Vec<String> = after.find('[').and_then(|s|
                    after[s..].find(']').map(|e| &after[s+1..s+e])
                ).map(|inner| inner.split_whitespace()
                    .filter(|w| w.starts_with('@'))
                    .map(|w| w.to_string()).collect()
                ).unwrap_or_default();
                let ret = after.find("-> @").map(|i|
                    after[i+3..].trim().split_whitespace().next().unwrap_or("@result").to_string()
                ).unwrap_or_else(|| "@result".to_string());
                fn_signatures.insert(fn_name, (params, ret));
            }
        }

        // For each module node, pick top FN_NODE_CAP functions and create nodes + edges
        let now = crate::crypto::now_unix();
        let mut nodes_added = 0usize;
        let mut edges_added = 0usize;

        let module_names: Vec<String> = db.nodes.iter()
            .filter(|n| n.deleted_at.is_none() && n.kind == "module")
            .map(|n| n.name.clone())
            .collect();

        for module_name in &module_names {
            let bare = module_name.clone();
            let fn_counts = match selective_api.get(&bare) {
                Some(m) => m, None => continue,
            };
            if fn_counts.is_empty() { continue; }

            // Sort: import_count desc, then name_len asc, then alpha
            let mut ranked: Vec<(&String, usize)> = fn_counts.iter()
                .map(|(n, c)| (n, *c)).collect();
            ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.len().cmp(&b.0.len())).then(a.0.cmp(b.0)));
            let top: Vec<&String> = ranked.iter().take(FN_NODE_CAP).map(|(n, _)| *n).collect();

            for fn_name in top {
                // Skip if node already exists
                if db.nodes.iter().any(|n| n.name == *fn_name && n.deleted_at.is_none()
                    && n.properties.iter().any(|p| p == &format!("function.module={}", bare)))
                { continue; }

                let (params, ret) = fn_signatures.get(fn_name.as_str())
                    .cloned()
                    .unwrap_or_default();
                let import_count = fn_counts.get(fn_name.as_str()).copied().unwrap_or(0);

                let node_id = format!("sha256:{}", crate::crypto::sha256_hex(
                    format!("node:{}:{}", db.header.crux_id, fn_name).as_bytes()
                ));
                let content_hash = format!("sha256:{}", crate::crypto::sha256_hex(fn_name.as_bytes()));

                let mut properties = vec![
                    format!("function.module={}", bare),
                    format!("function.params={}", params.join(", ")),
                    format!("function.returns={}", ret),
                    format!("function.import_count={}", import_count),
                ];
                if let Some(fp) = db.nodes.iter().find(|n| n.name == bare)
                    .and_then(|n| n.properties.iter().find(|p| p.starts_with("file=")).map(|p| p.clone()))
                {
                    properties.push(fp);
                }

                let summary = if params.is_empty() {
                    format!("() -> {}", ret)
                } else {
                    format!("({}) -> {}", params.join(", "), ret)
                };

                db.nodes.push(schema::CruxNode {
                    node_id,
                    name: fn_name.clone(),
                    kind: "function".to_string(),
                    module: bare.clone(),
                    summary,
                    schema: schema::NodeSchema::empty(),
                    tags: vec!["lml".to_string()],
                    reach: Vec::new(),
                    properties,
                    warnings: Vec::new(),
                    planning: schema::PlanningMetadata {
                        updated_at: Some(now),
                        ..schema::PlanningMetadata::empty()
                    },
                    security: schema::SecurityMetadata::internal(),
                    content_hash,
                    deleted_at: None,
                });
                nodes_added += 1;

                // contains edge: module -> function
                let edge_id = format!("sha256:{}", crate::crypto::sha256_hex(
                    format!("edge:{}:{}:contains", bare, fn_name).as_bytes()
                ));
                if !db.edges.iter().any(|e| e.src == bare && e.dst == *fn_name && matches!(e.kind, schema::EdgeKind::Contains)) {
                    db.edges.push(schema::CruxEdge {
                        edge_id,
                        src: bare.clone(),
                        dst: fn_name.clone(),
                        kind: schema::EdgeKind::Contains,
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

        // Chunk 2: relates_to edges from bug nodes to function nodes
        let bug_names: Vec<String> = db.nodes.iter()
            .filter(|n| n.deleted_at.is_none() && n.kind == "bug")
            .map(|n| n.name.clone())
            .collect();

        for bug_name in &bug_names {
            let bug_fn = db.nodes.iter()
                .find(|n| n.name == *bug_name)
                .and_then(|n| n.properties.iter()
                    .find(|p| p.starts_with("bug.function="))
                    .map(|p| p[13..].to_string()));
            let fn_name = match bug_fn { Some(f) => f, None => continue };
            // Only link if we created a node for this function
            if !db.nodes.iter().any(|n| n.name == fn_name && n.kind == "function" && n.deleted_at.is_none()) { continue; }
            let edge_id = format!("sha256:{}", crate::crypto::sha256_hex(
                format!("edge:{}:{}:relates_to", bug_name, fn_name).as_bytes()
            ));
            if !db.edges.iter().any(|e| e.src == *bug_name && e.dst == fn_name) {
                db.edges.push(schema::CruxEdge {
                    edge_id,
                    src: bug_name.clone(),
                    dst: fn_name.clone(),
                    kind: schema::EdgeKind::RelatesTo,
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

        // Chunk 2: calls edges between function nodes
        // Build set of all function node names for fast lookup
        let fn_node_names: std::collections::HashSet<String> = db.nodes.iter()
            .filter(|n| n.deleted_at.is_none() && n.kind == "function")
            .map(|n| n.name.clone())
            .collect();

        for lml_path in &all_lml2 {
            let src = match std::fs::read_to_string(lml_path) { Ok(s) => s, Err(_) => continue };
            let mut current_fn: Option<String> = None;
            for line in src.lines() {
                let t = line.trim();
                // Track current function
                if t.starts_with("FN @") {
                    let fn_name = t[3..].split(|c| c == ' ' || c == '[')
                        .next().unwrap_or("").trim().to_string();
                    current_fn = if fn_node_names.contains(&fn_name) { Some(fn_name) } else { None };
                    continue;
                }
                let caller = match &current_fn { Some(f) => f, None => continue };
                // Look for CALL @fn_name patterns
                if !t.contains("CALL @") { continue; }
                for word in t.split_whitespace() {
                    let w = if word.starts_with('@') { word }
                            else if word == "CALL" { continue }
                            else { continue };
                    // Only plain @name (no path separators)
                    if !w.starts_with('@') || !fn_node_names.contains(w) { continue; }
                    if w == caller { continue; } // no self-edges
                    let edge_id = format!("sha256:{}", crate::crypto::sha256_hex(
                        format!("edge:{}:{}:calls", caller, w).as_bytes()
                    ));
                    if !db.edges.iter().any(|e| e.src == *caller && e.dst == w) {
                        db.edges.push(schema::CruxEdge {
                            edge_id,
                            src: caller.clone(),
                            dst: w.to_string(),
                            kind: schema::EdgeKind::Calls,
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
        }

        log.push(format!("functions: {} function nodes added, {} edges added", nodes_added, edges_added));
    }

    if ops.contains(&"metrics") {
        let mut metrics_count = 0usize;

        // Gather integration test counts by example filename stem
        // Look for tests/integration.rs relative to the crux path
        let dir_path = if path.is_dir() { path.clone() } else {
            path.parent().unwrap_or(&path).to_path_buf()
        };
        let mut test_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut compiled_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        let integration_rs = dir_path.join("tests").join("integration.rs");
        if let Ok(src) = std::fs::read_to_string(&integration_rs) {
            for line in src.lines() {
                let t = line.trim();
                // run("filename.lml") → count for that file
                if let Some(start) = t.find("run(\"") {
                    let rest = &t[start + 5..];
                    if let Some(end) = rest.find('"') {
                        let fname = &rest[..end];
                        // Map test file → source module:
                        // rt_X_lib_test.lml → rt_X_lib.lml
                        // other_test.lml → other.lml (strip _test)
                        let module = if fname.ends_with("_test.lml") {
                            format!("{}.lml", &fname[..fname.len() - 9])
                        } else {
                            fname.to_string()
                        };
                        *test_counts.entry(module).or_insert(0) += 1;
                    }
                }
                // test_compiled_* → compiled test for that example
                if t.contains("compile_and_run(\"") {
                    if let Some(start) = t.find("compile_and_run(\"") {
                        let rest = &t[start + 17..];
                        if let Some(end) = rest.find('"') {
                            let fname = rest[..end].to_string();
                            *compiled_counts.entry(fname).or_insert(0) += 1;
                        }
                    }
                }
            }
        }

        // For each module node with a file= property, compute metrics
        let node_names: Vec<String> = db.nodes.iter()
            .filter(|n| n.deleted_at.is_none() && n.kind == "module")
            .map(|n| n.name.clone())
            .collect();

        for node_name in &node_names {
            let file_path_opt = db.nodes.iter()
                .find(|n| n.name == *node_name)
                .and_then(|n| n.properties.iter().find(|p| p.starts_with("file=")).map(|p| p[5..].to_string()));
            let file_path = match file_path_opt { Some(f) => f, None => continue };

            let (line_count, fn_count) = if let Ok(src) = std::fs::read_to_string(&file_path) {
                let lines = src.lines().count();
                let fns = src.lines().filter(|l| l.trim().starts_with("FN @")).count();
                (lines, fns)
            } else { continue };

            let test_count = test_counts.get(node_name.as_str()).copied().unwrap_or(0);
            let compiled_count = compiled_counts.get(node_name.as_str()).copied().unwrap_or(0);

            // Remove any existing metrics properties and replace
            if let Some(node) = db.nodes.iter_mut()
                .find(|n| n.name == *node_name && n.deleted_at.is_none())
            {
                node.properties.retain(|p| !p.starts_with("metrics."));
                node.properties.push(format!("metrics.lines={}", line_count));
                node.properties.push(format!("metrics.functions={}", fn_count));
                if test_count > 0 {
                    node.properties.push(format!("metrics.tests={}", test_count));
                }
                if compiled_count > 0 {
                    node.properties.push(format!("metrics.compiled_tests={}", compiled_count));
                }
                metrics_count += 1;
            }
        }
        log.push(format!("metrics: {} module nodes updated", metrics_count));
    }

    if ops.contains(&"traps") {
        let memory_file = extract_string_value(args, "memory_file")
            .unwrap_or_default();
        if memory_file.is_empty() {
            log.push("traps: skipped (memory_file param required)".to_string());
        } else if let Ok(mem_src) = std::fs::read_to_string(&memory_file) {
            // Parse "key traps: (N) **Name**: description" from MEMORY.md bullet lines
            // Each bullet may contain multiple traps as (1) ... (2) ...
            let mut trap_map: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new(); // module_name -> trap strings

            // Known module names to look for in trap text
            let module_names: Vec<String> = db.nodes.iter()
                .filter(|n| n.deleted_at.is_none() && n.kind == "module")
                .map(|n| n.name.clone())
                .collect();

            for line in mem_src.lines() {
                let t = line.trim();
                if !t.contains("key trap") { continue; }

                // Find trap items: "(N) **Name**: description" or "**Name**: description"
                // Split on numbered pattern "; (N)" or "(N)"
                let trap_text = if let Some(idx) = t.find("key traps:") {
                    &t[idx + 10..]
                } else if let Some(idx) = t.find("key trap:") {
                    &t[idx + 9..]
                } else { continue };

                // Extract individual trap descriptions between numbered markers
                // Pattern: (1) text... (2) text... (3) text...
                let mut traps: Vec<String> = Vec::new();
                let mut current = String::new();
                let mut chars = trap_text.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '(' {
                        // Check if this is a numbered marker like (1), (2)...
                        let mut num = String::new();
                        while let Some(&nc) = chars.peek() {
                            if nc.is_ascii_digit() { num.push(nc); chars.next(); }
                            else { break; }
                        }
                        if !num.is_empty() && chars.peek() == Some(&')') {
                            chars.next(); // consume ')'
                            if !current.trim().is_empty() {
                                traps.push(current.trim().to_string());
                            }
                            current = String::new();
                        } else {
                            current.push('(');
                            current.push_str(&num);
                        }
                    } else {
                        current.push(c);
                    }
                }
                if !current.trim().is_empty() {
                    traps.push(current.trim().to_string());
                }

                // For each trap, find mentioned modules and extract a short label
                for trap in &traps {
                    // Extract name from **Name**: pattern
                    let label = if let Some(s) = trap.find("**") {
                        let rest = &trap[s + 2..];
                        rest.find("**").map(|e| rest[..e].to_string())
                            .unwrap_or_else(|| rest.chars().take(40).collect())
                    } else {
                        trap.chars().take(60).collect::<String>()
                    };

                    // Get short description: text after "**: " up to first ";", ".", or 80 chars
                    let desc = if let Some(idx) = trap.find("**: ") {
                        let d = &trap[idx + 4..];
                        let end = d.find(';').or_else(|| d.find(". "))
                            .unwrap_or_else(|| d.len().min(80));
                        d[..end].trim().to_string()
                    } else {
                        trap.chars().take(80).collect()
                    };
                    let entry = format!("**{}**: {}", label, desc);

                    // Find which modules this trap relates to
                    let mut matched_any = false;
                    for mname in &module_names {
                        if trap.contains(mname.as_str()) {
                            trap_map.entry(mname.clone()).or_default().push(entry.clone());
                            matched_any = true;
                        }
                    }
                    // If no module matched but line mentions general patterns, attach to codegen/lower
                    if !matched_any && (trap.contains("CALL") || trap.contains("codegen") || trap.contains("emit")) {
                        trap_map.entry("codegen.lml".to_string()).or_default().push(entry);
                    }
                }
            }

            // Write traps as properties onto module nodes
            let mut trap_nodes = 0usize;
            for (module_name, traps) in &trap_map {
                if let Some(node) = db.nodes.iter_mut()
                    .find(|n| n.name == *module_name && n.deleted_at.is_none())
                {
                    node.properties.retain(|p| !p.starts_with("trap."));
                    for (i, trap) in traps.iter().enumerate() {
                        // Truncate to 200 chars to keep property manageable
                        let truncated: String = trap.chars().take(200).collect();
                        node.properties.push(format!("trap.{}={}", i + 1, truncated));
                    }
                    trap_nodes += 1;
                }
            }
            let total_traps: usize = trap_map.values().map(|v| v.len()).sum();
            log.push(format!("traps: {} traps across {} module nodes", total_traps, trap_nodes));
        } else {
            log.push(format!("traps: could not read memory_file '{}'", memory_file));
        }
    }

    // -----------------------------------------------------------------------
    // lifecycle: tag modules as archivable (legacy Rust), permanent (always-compiled Rust),
    //            or active (LML self-hosted)
    // -----------------------------------------------------------------------
    if ops.contains(&"lifecycle") {
        // Rust modules gated behind #[cfg(feature = "legacy")] → archivable
        // LML self-hosted modules (examples/self_host_v2/) → active
        // Always-compiled Rust modules (runtime, codegen, etc.) → permanent
        let archivable_rust = [
            "src/interpreter.rs", "src/parser.rs", "src/lexer.rs",
            "src/typeck.rs", "src/lower.rs", "src/codegen.rs",
            "src/ast.rs", "src/ast_bridge.rs", "src/expand.rs",
            "src/resolve.rs", "src/module.rs", "src/lint.rs",
            "src/graph_model.rs",
        ];
        let permanent_rust = [
            "src/runtime.rs", "src/bigint.rs", "src/value.rs",
            "src/types.rs", "src/value_ops.rs", "src/runtime_quant.rs",
            "src/codegen_nvptx.rs", "src/codegen_metal.rs",
        ];
        let lml_v2_prefix = "examples/self_host_v2/";

        let lc_dir = if path.is_dir() { path.clone() } else {
            path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
        };
        let mut lc_updated = 0usize;
        for node in db.nodes.iter_mut() {
            if node.deleted_at.is_some() { continue; }
            let file_prop = node.properties.iter()
                .find(|p| p.starts_with("file="))
                .map(|p| p[5..].to_string());
            let lifecycle = if let Some(ref fp) = file_prop {
                let rel = fp.trim_start_matches(&format!("{}/", lc_dir.display()));
                if archivable_rust.iter().any(|s| rel.ends_with(s)) {
                    Some("archivable")
                } else if permanent_rust.iter().any(|s| rel.ends_with(s)) {
                    Some("permanent")
                } else if rel.contains(lml_v2_prefix) {
                    Some("active")
                } else if rel.ends_with(".lml") {
                    Some("active")
                } else {
                    None
                }
            } else {
                // Fall back to name-based matching for nodes without file= property
                let name = &node.name;
                let archivable_names = [
                    "interpreter.rs", "parser.rs", "lexer.rs", "typeck.rs",
                    "lower.rs", "codegen.rs", "ast.rs", "ast_bridge.rs",
                    "expand.rs", "resolve.rs", "module.rs", "lint.rs",
                    "graph_model.rs",
                ];
                let permanent_names = [
                    "runtime.rs", "bigint.rs", "value.rs", "types.rs",
                    "value_ops.rs", "runtime_quant.rs", "codegen_nvptx.rs",
                    "codegen_metal.rs", "mcp.rs",
                ];
                if archivable_names.iter().any(|s| name == s) {
                    Some("archivable")
                } else if permanent_names.iter().any(|s| name == s) {
                    Some("permanent")
                } else {
                    None
                }
            };
            if let Some(lc) = lifecycle {
                node.properties.retain(|p| !p.starts_with("lifecycle="));
                node.properties.push(format!("lifecycle={}", lc));
                lc_updated += 1;
            }
        }
        log.push(format!("lifecycle: {} nodes tagged", lc_updated));
    }

    schema::save_crux_db(&db, &path)?;
    Ok(log.join("\n"))
}

fn tool_crux_bootstrap(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let description = extract_string_value(args, "description")
        .ok_or_else(|| "Missing required parameter: description".to_string())?;

    // Load the crux to confirm it exists and get its name.
    let dir = PathBuf::from(&path_str);
    let db = schema::load_crux_db(&dir)
        .map_err(|e| format!("Cannot load crux at '{}': {}", path_str, e))?;

    Ok(format!(
        "Bootstrap crux '{}' at: {}\n\
         Description: {}\n\n\
         ## Node kinds (pick best fit per item)\n\
         task, concept, person, document, record, milestone, module, channel\n\n\
         ## Edge kinds\n\
         relates_to, contains, produces, belongs_to_domain, supersedes, reads, writes\n\n\
         ## Instructions\n\
         Generate 6–15 nodes and appropriate edges for the description above.\n\
         Call `crux add_nodes` with path=\"{}\" and a nodes JSON array.\n\
         Then call `crux add_edges` with path=\"{}\" and an edges JSON array.\n\n\
         ## Node format\n\
         [{{\"name\":\"short name\",\"kind\":\"kind\",\"summary\":\"one sentence\",\"tags\":\"tag1,tag2\"}}]\n\n\
         ## Edge format\n\
         [{{\"src\":\"node name\",\"dst\":\"node name\",\"kind\":\"edge kind\"}}]\n\n\
         Keep names short (2–4 words). For tasks use tags=\"Todo\". Do not add a node for the crux itself.",
        db.header.crux_name, path_str, description, path_str, path_str
    ))
}

/// Check a crux's integrity along two independent axes.
///
/// Node content hashes and edge referential integrity are separate classes of
/// defect — a crux can have either without the other — so they are reported as
/// separate sections with their own status, and the overall status is a PASS
/// only when both are. Dangling edges are recomputed from live node membership
/// rather than read from the stored `dangling` flag, so hand-edited files and
/// edges orphaned by a later node deletion are caught too.
fn tool_crux_verify(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;

    let path = PathBuf::from(&path_str);
    let db = schema::load_crux_db(&path)?;

    let total = db.nodes.iter().filter(|n| n.deleted_at.is_none()).count();
    let mut verified = 0usize;
    let mut unverifiable = 0usize;
    let mut absent = 0usize;
    let mut mismatched = Vec::new();
    let mut malformed = Vec::new();

    for node in db.nodes.iter().filter(|n| n.deleted_at.is_none()) {
        match schema::check_node_hash(node) {
            schema::HashStatus::Verified => verified += 1,
            schema::HashStatus::Unverifiable => unverifiable += 1,
            schema::HashStatus::Absent => absent += 1,
            schema::HashStatus::Mismatch => mismatched.push(node.name.clone()),
            schema::HashStatus::Malformed => malformed.push(node.name.clone()),
        }
    }

    let mut out = format!(
        "Integrity check for crux '{}'\n\n  \
         CONTENT (node payload hashes)\n  \
         Nodes checked:            {}\n  \
         Verified (payload intact): {}\n  \
         Unverifiable (pre-{} hash): {}\n  \
         No hash stored:            {}",
        db.header.crux_name, total, verified, schema::CRUX_HASH_PREFIX, unverifiable, absent
    );

    let content_ok = mismatched.is_empty() && malformed.is_empty();

    if content_ok {
        if verified == 0 && total > 0 {
            out.push_str(
                "\n  Status: PASS (nothing verifiable)\n\n  \
                 No node carries a re-derivable hash yet, so this run proves nothing about\n  \
                 their contents. Nodes acquire one as they are next written via add_node or\n  \
                 update_node; until then a PASS here is not an integrity guarantee.",
            );
        } else {
            out.push_str("\n  Status: PASS");
            if unverifiable > 0 || absent > 0 {
                out.push_str(&format!(
                    "\n\n  {} of {} nodes could not be checked — their content_hash predates\n  \
                     this check (a name-only hash, an adapter digest, or a Helm timestamp) and\n  \
                     cannot be re-derived. They are re-blessed on their next authoring edit.",
                    unverifiable + absent,
                    total
                ));
            }
        }
    } else {
        out.push_str(&format!(
            "\n  Status: FAIL — {} mismatched, {} malformed",
            mismatched.len(),
            malformed.len()
        ));
        if !mismatched.is_empty() {
            out.push_str(
                "\n\n  MISMATCH — the payload changed after it was authored. Something wrote\n  \
                 these nodes without going through add_node/update_node, or corrupted them\n  \
                 in transit:",
            );
            for n in &mismatched {
                out.push_str(&format!("\n    {}", n));
            }
        }
        if !malformed.is_empty() {
            out.push_str("\n\n  MALFORMED — content_hash is not a recognisable hash:");
            for n in &malformed {
                out.push_str(&format!("\n    {}", n));
            }
        }
    }

    // Referential integrity — a distinct defect class from content hashes.
    let dangling = schema::dangling_edges(&db);
    let edges_ok = dangling.is_empty();

    out.push_str(&format!(
        "\n\n  REFERENTIAL (edge endpoints)\n  \
         Edges checked:            {}\n  \
         Dangling:                 {}",
        db.edges.len(),
        dangling.len()
    ));

    if edges_ok {
        out.push_str("\n  Status: PASS");
    } else {
        out.push_str(&format!(
            "\n  Status: FAIL — {} edge(s) point at nodes that do not exist\n\n  \
             DANGLING — these edges assert structure the graph cannot support. A query\n  \
             that follows them finds nothing, and a reader counting edges is counting\n  \
             claims, not relationships:",
            dangling.len()
        ));
        for (edge, sides) in &dangling {
            out.push_str(&format!(
                "\n    {} --[{}]--> {}  ({})",
                edge.src,
                edge.kind.as_str(),
                edge.dst,
                sides.reason()
            ));
        }
    }

    out.push_str(&format!(
        "\n\n  Overall: {}",
        if content_ok && edges_ok { "PASS" } else { "FAIL" }
    ));

    Ok(out)
}

fn tool_mesh_build(args: &str) -> Result<String, String> {
    let name = extract_string_value(args, "name")
        .ok_or_else(|| "Missing required parameter: name".to_string())?;
    let crux_dir_str = extract_string_value(args, "crux_dir")
        .ok_or_else(|| "Missing required parameter: crux_dir".to_string())?;
    let crux_dir = PathBuf::from(&crux_dir_str);

    let output_dir = match extract_string_value(args, "output_dir") {
        Some(p) => PathBuf::from(p),
        None => crux_dir.clone(),
    };

    // Init the mesh
    let manifest = mesh::init_mesh(&name, &output_dir)?;
    let mut joined = 0usize;
    let mut errors = Vec::new();

    // Find all subdirectories in crux_dir that contain a .crux.json
    let entries = std::fs::read_dir(&crux_dir)
        .map_err(|e| format!("Cannot read '{}': {}", crux_dir.display(), e))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let crux_file = path.join(".crux.json");
        if !crux_file.exists() {
            continue;
        }
        // Use relative path from output_dir
        let rel = path.strip_prefix(&output_dir)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string_lossy().to_string());

        match mesh::join_mesh(&output_dir, &rel) {
            Ok(_) => joined += 1,
            Err(e) => errors.push(format!("  {} — {}", rel, e)),
        }
    }

    let mut out = format!(
        "Built mesh '{}'\n  ID: {}\n  Cruxes joined: {}",
        name, manifest.mesh_id, joined
    );
    if !errors.is_empty() {
        out.push_str(&format!("\n  Errors ({}):", errors.len()));
        for e in &errors {
            out.push_str(&format!("\n{}", e));
        }
    }
    // Show cross-edge discovery summary
    let updated_manifest = mesh::load_mesh(&output_dir)?;
    let cross_total: usize = updated_manifest.cross_edges.iter().map(|ce| ce.edge_count).sum();
    if cross_total > 0 {
        out.push_str(&format!("\n  Cross-crux edges discovered: {}", cross_total));
    }
    Ok(out)
}

fn tool_mesh_diff(args: &str) -> Result<String, String> {
    let mesh_dir = match extract_string_value(args, "mesh_path") {
        Some(p) => PathBuf::from(p),
        None => {
            let cwd = resolve_working_dir();
            mesh::find_mesh(&cwd).ok_or_else(|| "No mesh found.".to_string())?
        }
    };

    let manifest = mesh::load_mesh(&mesh_dir)?;

    // Prefer vector-clock diff; fall back to timestamp diff.
    if let Some(clock_json) = extract_string_value(args, "since_clock") {
        let since_vc = crate::propagation::VectorClock::parse_inline(&clock_json)
            .map_err(|e| format!("Invalid since_clock: {e}"))?;
        let events = mesh::diff_clock(&manifest, &mesh_dir, &since_vc);
        let current_clock = mesh::mesh_current_clock(&manifest, &mesh_dir);

        let mut out = format!(
            "Audit diff for '{}' since clock {}\n",
            manifest.mesh_name, clock_json
        );
        out.push_str(&format!("  New events: {}\n", events.len()));
        for e in &events {
            out.push_str(&format!(
                "  [{}] seq={} {} {}\n",
                e.event.as_str(), e.seq, e.crux_id, e.subject
            ));
        }
        out.push_str(&format!("Current clock: {}", current_clock.to_json_inline()));
        return Ok(out);
    }

    // Legacy timestamp path
    let since: u64 = extract_string_value(args, "since")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let new_members: Vec<&mesh::MeshMember> = manifest.members.iter()
        .filter(|m| m.last_seen > since || since == 0)
        .collect();

    let mut new_nodes_total = 0usize;
    let mut node_details = Vec::new();

    for member in &manifest.members {
        let crux_path = mesh_dir.join(&member.path);
        if let Ok(db) = schema::load_crux_db(&crux_path) {
            let new_in_crux: Vec<&schema::CruxNode> = db.nodes.iter()
                .filter(|n| n.deleted_at.is_none())
                .collect();
            new_nodes_total += new_in_crux.len();
            node_details.push(format!("  {} ({} nodes)", member.crux_name, new_in_crux.len()));
        }
    }

    let cross_total: usize = manifest.cross_edges.iter().map(|ce| ce.edge_count).sum();

    let mut out = format!(
        "Mesh diff for '{}' (since timestamp: {})\n",
        manifest.mesh_name, since
    );
    out.push_str(&format!("  Total members: {}\n", manifest.members.len()));
    out.push_str(&format!("  Members in range: {}\n", new_members.len()));
    out.push_str(&format!("  Total nodes: {}\n", new_nodes_total));
    out.push_str(&format!("  Cross-crux edges: {}\n", cross_total));
    out.push_str(&format!("  Current clock: {}\n", mesh::mesh_current_clock(&manifest, &mesh_dir).to_json_inline()));
    out.push_str("\nNode breakdown by crux:");
    for detail in &node_details {
        out.push_str(&format!("\n{}", detail));
    }

    Ok(out)
}

fn tool_crux_resolve(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let node_name = extract_string_value(args, "node_name")
        .ok_or_else(|| "Missing required parameter: node_name".to_string())?;

    let path = PathBuf::from(&path_str);
    let db = schema::load_crux_db(&path)?;

    let node = db
        .nodes
        .iter()
        .find(|n| n.name == node_name && n.deleted_at.is_none())
        .ok_or_else(|| format!("Node '{}' not found or deleted", node_name))?;

    // Extract all source_ref.* properties
    let mut uri = String::new();
    let mut device_id = String::new();
    let mut volume_label = String::new();
    let mut relative_path = String::new();
    let mut byte_offset: u64 = 0;
    let mut byte_length: u64 = 0;
    let mut record_index: Option<u64> = None;
    let mut record_delimiter = String::new();
    let mut row: Option<u64> = None;

    for prop in &node.properties {
        if let Some(val) = prop.strip_prefix("source_ref.uri=") {
            uri = val.to_string();
        } else if let Some(val) = prop.strip_prefix("source_ref.device_id=") {
            device_id = val.to_string();
        } else if let Some(val) = prop.strip_prefix("source_ref.volume_label=") {
            volume_label = val.to_string();
        } else if let Some(val) = prop.strip_prefix("source_ref.relative_path=") {
            relative_path = val.to_string();
        } else if let Some(val) = prop.strip_prefix("source_ref.byte_offset=") {
            byte_offset = val.parse().unwrap_or(0);
        } else if let Some(val) = prop.strip_prefix("source_ref.byte_length=") {
            byte_length = val.parse().unwrap_or(0);
        } else if let Some(val) = prop.strip_prefix("source_ref.record_index=") {
            record_index = val.parse().ok();
        } else if let Some(val) = prop.strip_prefix("source_ref.record_delimiter=") {
            record_delimiter = val.to_string();
        } else if let Some(val) = prop.strip_prefix("source_ref.row=") {
            row = val.parse().ok();
        }
    }

    if uri.is_empty() && relative_path.is_empty() {
        return Ok(format!(
            "Node '{}' has no source reference (not generated by the filesystem scanner)",
            node_name
        ));
    }

    let resolved = source_ref_resolve_path(&uri, &volume_label, &relative_path);
    let accessible = resolved
        .as_deref()
        .map(|p| std::path::Path::new(p).exists())
        .unwrap_or(false);

    let mut out = format!("Source reference for node '{}'\n", node_name);
    if !uri.is_empty() {
        out.push_str(&format!("  URI:            {}\n", uri));
    }
    if !device_id.is_empty() {
        out.push_str(&format!("  Device ID:      {}\n", device_id));
    }
    if !volume_label.is_empty() {
        out.push_str(&format!("  Volume label:   {}\n", volume_label));
    }
    if !relative_path.is_empty() {
        out.push_str(&format!("  Relative path:  {}\n", relative_path));
    }
    if let Some(ref rp) = resolved {
        out.push_str(&format!("  Resolved path:  {}\n", rp));
    }
    out.push_str(&format!("  Accessible:     {}\n", if accessible { "yes" } else { "no — source not mounted" }));
    out.push_str(&format!("  Byte offset:    {}\n", byte_offset));
    out.push_str(&format!("  Byte length:    {}\n", byte_length));
    if let Some(ri) = record_index {
        out.push_str(&format!("  Record index:   {} (0-based)\n", ri));
    }
    if !record_delimiter.is_empty() {
        out.push_str(&format!("  Delimiter:      {:?}\n", record_delimiter));
    }
    if let Some(r) = row {
        out.push_str(&format!("  Row:            {} (1-based, excluding header)\n", r));
    }

    Ok(out)
}

fn tool_crux_extract(args: &str) -> Result<String, String> {
    let path_str = extract_string_value(args, "path")
        .ok_or_else(|| "Missing required parameter: path".to_string())?;
    let node_name = extract_string_value(args, "node_name")
        .ok_or_else(|| "Missing required parameter: node_name".to_string())?;

    let path = PathBuf::from(&path_str);
    let db = schema::load_crux_db(&path)?;

    let node = db
        .nodes
        .iter()
        .find(|n| n.name == node_name && n.deleted_at.is_none())
        .ok_or_else(|| format!("Node '{}' not found or deleted", node_name))?;

    let mut uri = String::new();
    let mut volume_label = String::new();
    let mut relative_path = String::new();
    let mut byte_offset: u64 = 0;
    let mut byte_length: u64 = 0;

    for prop in &node.properties {
        if let Some(val) = prop.strip_prefix("source_ref.uri=") {
            uri = val.to_string();
        } else if let Some(val) = prop.strip_prefix("source_ref.volume_label=") {
            volume_label = val.to_string();
        } else if let Some(val) = prop.strip_prefix("source_ref.relative_path=") {
            relative_path = val.to_string();
        } else if let Some(val) = prop.strip_prefix("source_ref.byte_offset=") {
            byte_offset = val.parse().unwrap_or(0);
        } else if let Some(val) = prop.strip_prefix("source_ref.byte_length=") {
            byte_length = val.parse().unwrap_or(0);
        }
    }

    let resolved = source_ref_resolve_path(&uri, &volume_label, &relative_path)
        .ok_or_else(|| {
            let loc = if !uri.is_empty() { &uri } else { &relative_path };
            format!("Source file for '{}' is not accessible. Last known: {}", node_name, loc)
        })?;

    const MAX_BYTES: usize = 1_048_576; // 1 MB cap

    let content = if byte_length > 0 {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(&resolved)
            .map_err(|e| format!("Cannot open '{}': {}", resolved, e))?;
        file.seek(SeekFrom::Start(byte_offset))
            .map_err(|e| format!("Cannot seek in '{}': {}", resolved, e))?;
        let read_len = (byte_length as usize).min(MAX_BYTES);
        let mut buf = vec![0u8; read_len];
        let n = file.read(&mut buf)
            .map_err(|e| format!("Cannot read '{}': {}", resolved, e))?;
        buf.truncate(n);
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        let raw = std::fs::read_to_string(&resolved)
            .map_err(|e| format!("Cannot read '{}': {}", resolved, e))?;
        if raw.len() > MAX_BYTES {
            format!("{}…[truncated at 1MB]", &raw[..MAX_BYTES])
        } else {
            raw
        }
    };

    let truncated = content.len() >= MAX_BYTES;
    let mut out = format!(
        "Content for node '{}'\nSource: {}\nBytes: [{}, {}]\n",
        node_name, resolved, byte_offset, byte_offset + byte_length
    );
    if truncated {
        out.push_str("Note: content truncated at 1MB\n");
    }
    out.push_str("---\n");
    out.push_str(&content);
    Ok(out)
}

/// Try to resolve a source_ref to an actual filesystem path.
///
/// Resolution order:
/// 1. `file://` URI — strip prefix, check if path exists
/// 2. `/Volumes/{volume_label}/{relative_path}` (macOS convention)
/// 3. `/mnt/{volume_label}/{relative_path}` (Linux convention)
fn source_ref_resolve_path(uri: &str, volume_label: &str, relative_path: &str) -> Option<String> {
    // 1. Direct URI
    if let Some(file_path) = uri.strip_prefix("file://") {
        if std::path::Path::new(file_path).exists() {
            return Some(file_path.to_string());
        }
    }
    // 2. macOS volume mount
    if !volume_label.is_empty() && !relative_path.is_empty() {
        let candidate = format!("/Volumes/{}/{}", volume_label, relative_path);
        if std::path::Path::new(&candidate).exists() {
            return Some(candidate);
        }
    }
    // 3. Linux volume mount
    if !volume_label.is_empty() && !relative_path.is_empty() {
        let candidate = format!("/mnt/{}/{}", volume_label, relative_path);
        if std::path::Path::new(&candidate).exists() {
            return Some(candidate);
        }
    }
    None
}

// ===========================================================================
// JSON array extraction helper
// ===========================================================================

// extract_json_objects_from_array is in crate::json (string-aware version)

// ===========================================================================
// Resources handlers (Phase 5)
// ===========================================================================

const AGENT_SPEC_URI: &str = "crux://spec/agent";
const ROUTER_SPEC_URI: &str = "crux://spec/router";

fn handle_resources_list(id: &str) -> String {
    let resources = format!(
        r#"[{{"uri":{},"name":"Crux Agent Spec","description":"Complete specification for LLM agents building cruxes","mimeType":"text/markdown"}},{{"uri":{},"name":"Crux Router Spec","description":"Policy Router reference: registration, clearance, rate limiting, injection scanning, audit log","mimeType":"text/markdown"}}]"#,
        json_escape(AGENT_SPEC_URI),
        json_escape(ROUTER_SPEC_URI)
    );
    json_rpc_result_raw(id, &format!("{{\"resources\":{}}}", resources))
}

fn handle_resources_read(id: &str, uri: &str) -> String {
    if uri == AGENT_SPEC_URI {
        let spec = include_str!("../CRUX_AGENT_SPEC.md");
        json_rpc_result_raw(
            id,
            &format!(
                r#"{{"contents":[{{"uri":{},"mimeType":"text/markdown","text":{}}}]}}"#,
                json_escape(AGENT_SPEC_URI),
                json_escape(spec)
            ),
        )
    } else if uri == ROUTER_SPEC_URI {
        let spec = include_str!("../CRUX_ROUTER_SPEC.md");
        json_rpc_result_raw(
            id,
            &format!(
                r#"{{"contents":[{{"uri":{},"mimeType":"text/markdown","text":{}}}]}}"#,
                json_escape(ROUTER_SPEC_URI),
                json_escape(spec)
            ),
        )
    } else {
        json_rpc_error(id, -32002, &format!("Resource not found: {}", uri))
    }
}

// ===========================================================================
// Initialize response
// ===========================================================================

fn handle_initialize(id: &str) -> String {
    let mut instructions = String::from(
        "Crux Mesh is a distributed knowledge graph for LLM agents. \
         Read the full specification with resources/read uri=crux://spec/agent. \
         To join an existing mesh: mesh_status \u{2192} mesh_query \u{2192} crux_load \u{2192} crux_resolve/crux_extract. \
         To start new: crux_create \u{2192} crux_add_node \u{2192} crux_add_edge \u{2192} mesh_init \u{2192} mesh_join. \
         For bulk ingestion from a filesystem: crux_scan \u{2192} crux_generate_dir \u{2192} mesh_build \u{2192} mesh_query \u{2192} crux_extract.",
    );

    // On session start, scan known client configs for MCP servers that bypass
    // the policy router. Inject a warning into instructions so any LLM client
    // sees it immediately \u2014 no CLAUDE.md or manual setup required.
    let cwd = resolve_working_dir();
    if let Some(mesh_dir) = mesh::find_mesh(&cwd) {
        if let Ok(detected) = crate::mcp_detect::detect_external_mcp(&mesh_dir) {
            let unrouted: Vec<&str> = detected
                .iter()
                .filter(|d| !d.routed_via_crux)
                .map(|d| d.name.as_str())
                .collect();
            if !unrouted.is_empty() {
                instructions.push_str(&format!(
                    " \u{26A0} SECURITY: {} MCP server(s) are active but not routed \
                     through the Crux policy router: [{}]. \
                     Call `mesh detect_external` for details and remediation steps.",
                    unrouted.len(),
                    unrouted.join(", "),
                ));
            }
        }
    }

    let result = format!(
        r#"{{"protocolVersion":"2024-11-05","capabilities":{{"tools":{{"listChanged":false}},"resources":{{"listChanged":false}}}},"serverInfo":{{"name":"crux-mesh","version":"{}"}},"instructions":{}}}"#,
        env!("CARGO_PKG_VERSION"),
        json_escape(&instructions),
    );
    json_rpc_result_raw(id, &result)
}

// ===========================================================================
// MCP server main loop
// ===========================================================================

/// Run the MCP server: reads JSON-RPC 2.0 from stdin, writes to stdout.
pub fn run_mcp_server() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Extract id
        let id = extract_id(trimmed);

        // Extract method
        let method = extract_string_value(trimmed, "method");

        let response = match method.as_deref() {
            Some("initialize") => handle_initialize(&id),
            Some("notifications/initialized") => continue, // no response needed
            Some("tools/list") => handle_tools_list(&id),
            Some("tools/call") => {
                let tool_name = extract_tool_name(trimmed);
                let arguments = extract_arguments(trimmed);
                handle_tool_call(&id, &tool_name, &arguments)
            }
            Some("resources/list") => handle_resources_list(&id),
            Some("resources/read") => {
                let uri = extract_string_value(trimmed, "uri").unwrap_or_default();
                handle_resources_read(&id, &uri)
            }
            Some(m) => json_rpc_error(&id, -32601, &format!("Method not found: {}", m)),
            None => json_rpc_error(&id, -32600, "Invalid request: missing method"),
        };

        let _ = writeln!(stdout, "{}", response);
        let _ = stdout.flush();
    }
}

// ===========================================================================
// JSON extraction helpers
// ===========================================================================

/// Extract the "id" field (as a raw JSON value string).
fn extract_id(text: &str) -> String {
    // Look for "id": <number or string>
    if let Some(idx) = text.find("\"id\"") {
        let after = &text[idx + 4..];
        if let Some(colon) = after.find(':') {
            let val_start = &after[colon + 1..].trim_start();
            if let Some(inner) = val_start.strip_prefix('"') {
                // String id
                if let Some(end) = inner.find('"') {
                    return val_start[..end + 2].to_string();
                }
            } else {
                // Numeric id
                let num: String = val_start
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '-')
                    .collect();
                if !num.is_empty() {
                    return num;
                }
            }
        }
    }
    "null".to_string()
}

/// Extract the tool name from a tools/call request.
fn extract_tool_name(text: &str) -> String {
    // Look for "name" inside "params"
    if let Some(params_idx) = text.find("\"params\"") {
        let params_text = &text[params_idx..];
        extract_string_value(params_text, "name").unwrap_or_default()
    } else {
        String::new()
    }
}

/// Extract the "arguments" object from a tools/call request as raw text.
fn extract_arguments(text: &str) -> String {
    if let Some(idx) = text.find("\"arguments\"") {
        let after = &text[idx + 11..];
        if let Some(colon) = after.find(':') {
            let val_start = &after[colon + 1..].trim_start();
            if val_start.starts_with('{') {
                // Find matching brace
                let mut depth = 0;
                for (i, c) in val_start.char_indices() {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                return val_start[..=i].to_string();
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    "{}".to_string()
}

// ===========================================================================
// Package manager tool implementations
// ===========================================================================

fn extract_int_value(args: &str, key: &str) -> Option<usize> {
    // Simple integer extraction from JSON
    let needle = format!("\"{}\":", key);
    let idx = args.find(&needle)?;
    let rest = &args[idx + needle.len()..];
    let rest = rest.trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn tool_pkg_search(args: &str) -> Result<String, String> {
    let query = extract_string_value(args, "query")
        .ok_or_else(|| "Missing required parameter: query".to_string())?;
    let registry_path = extract_string_value(args, "registry_path")
        .ok_or_else(|| "Missing required parameter: registry_path".to_string())?;
    let limit = extract_int_value(args, "limit").unwrap_or(20);

    use crate::package;
    let reg = std::path::Path::new(&registry_path);
    let results = package::search_registry(reg, &query, Some(limit))?;
    Ok(package::format_search_results(&results, &query))
}

fn tool_pkg_publish(args: &str) -> Result<String, String> {
    let source_dir = extract_string_value(args, "source_dir")
        .or_else(|| extract_string_value(args, "name"))
        .ok_or_else(|| "Missing required parameter: source_dir".to_string())?;
    let registry_path = extract_string_value(args, "registry_path")
        .ok_or_else(|| "Missing required parameter: registry_path".to_string())?;

    use crate::package;
    let src = std::path::Path::new(&source_dir);
    let reg = std::path::Path::new(&registry_path);
    let hash = package::publish_package(src, reg)?;
    Ok(format!("Published to registry.\nContent hash: {}", hash))
}

fn tool_pkg_install(args: &str) -> Result<String, String> {
    let package_name = extract_string_value(args, "package_name")
        .ok_or_else(|| "Missing required parameter: package_name".to_string())?;
    let registry_path = extract_string_value(args, "registry_path")
        .ok_or_else(|| "Missing required parameter: registry_path".to_string())?;
    let project_path = extract_string_value(args, "project_path")
        .ok_or_else(|| "Missing required parameter: project_path".to_string())?;

    use crate::package;
    let reg = std::path::Path::new(&registry_path);
    let proj = std::path::Path::new(&project_path);
    let result = package::install_package(&package_name, proj, reg)?;
    Ok(package::format_install_result(&result))
}

fn tool_pkg_deps(args: &str) -> Result<String, String> {
    let project_path = extract_string_value(args, "project_path")
        .ok_or_else(|| "Missing required parameter: project_path".to_string())?;

    use crate::package;
    let proj = std::path::Path::new(&project_path);
    let deps = package::get_dep_tree(proj)?;
    Ok(package::format_dep_tree(&deps))
}

fn tool_pkg_audit(args: &str) -> Result<String, String> {
    let project_path = extract_string_value(args, "project_path")
        .ok_or_else(|| "Missing required parameter: project_path".to_string())?;

    use crate::package;
    let proj = std::path::Path::new(&project_path);
    let result = package::audit_packages(proj)?;
    Ok(package::format_audit_result(&result))
}

fn tool_pkg_update(args: &str) -> Result<String, String> {
    let project_path = extract_string_value(args, "project_path")
        .ok_or_else(|| "Missing required parameter: project_path".to_string())?;
    let registry_path = extract_string_value(args, "registry_path")
        .ok_or_else(|| "Missing required parameter: registry_path".to_string())?;

    use crate::package;
    let proj = std::path::Path::new(&project_path);
    let reg = std::path::Path::new(&registry_path);
    let updates = package::check_updates(proj, reg)?;
    Ok(package::format_updates(&updates))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_id_numeric() {
        let req = r#"{"jsonrpc":"2.0","id":42,"method":"initialize"}"#;
        assert_eq!(extract_id(req), "42");
    }

    #[test]
    fn test_extract_id_string() {
        let req = r#"{"jsonrpc":"2.0","id":"abc","method":"initialize"}"#;
        assert_eq!(extract_id(req), "\"abc\"");
    }

    #[test]
    fn test_extract_tool_name() {
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mesh_status","arguments":{}}}"#;
        assert_eq!(extract_tool_name(req), "mesh_status");
    }

    #[test]
    fn test_extract_arguments() {
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crux_create","arguments":{"name":"test","kind":"codebase"}}}"#;
        let args = extract_arguments(req);
        assert!(args.contains("\"name\""));
        assert!(args.contains("\"test\""));
        assert!(args.contains("\"kind\""));
    }

    #[test]
    fn test_handle_initialize() {
        let resp = handle_initialize("1");
        assert!(resp.contains("\"protocolVersion\""));
        assert!(resp.contains("crux-mesh"));
    }

    #[test]
    fn test_handle_tools_list() {
        let resp = handle_tools_list("2");
        // Consolidated tools: 3 unified names
        assert!(resp.contains("\"crux\""), "missing crux tool: {}", &resp[..200]);
        assert!(resp.contains("\"mesh\""), "missing mesh tool: {}", &resp[..200]);
        assert!(resp.contains("\"pkg\""),  "missing pkg tool: {}", &resp[..200]);
        // Action enum descriptions should mention legacy actions
        assert!(resp.contains("create"), "crux tool should list create action");
        assert!(resp.contains("init"),   "mesh tool should list init action");
    }

    #[test]
    fn test_create_conflict_guard() {
        let dir = std::env::temp_dir().join("crux_mcp_test_create_conflict");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Empty directory: nothing to clobber.
        assert!(check_create_conflict(&dir, false).is_ok());

        let db = schema::create_crux_db("keeper", schema::CruxKind::Codebase, "manual");
        schema::save_crux_db(&db, &dir).unwrap();

        let err = check_create_conflict(&dir, false).unwrap_err();
        assert!(err.contains("already exists"), "got: {}", err);
        assert!(err.contains("force=true"), "error should name the escape hatch: {}", err);

        // force=true is the deliberate override.
        assert!(check_create_conflict(&dir, true).is_ok());

        // The guard must not have touched the existing crux.
        assert_eq!(schema::load_crux_db(&dir).unwrap().header.crux_name, "keeper");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_crux_create() {
        let dir = std::env::temp_dir().join("crux_mcp_test_create");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // We need to be in the temp dir for create to work
        let args = format!(r#"{{"name":"mcp-test","kind":"api"}}"#);
        // Instead of changing cwd, test via direct crux_create with explicit path
        let kind = schema::CruxKind::from_str("api");
        let db = schema::create_crux_db("mcp-test", kind, "manual");
        schema::save_crux_db(&db, &dir).unwrap();

        // Verify it was created
        let loaded = schema::load_crux_db(&dir).unwrap();
        assert_eq!(loaded.header.crux_name, "mcp-test");

        // Test the query tool on it
        let result = tool_crux_load(&format!(
            r#"{{"path":"{}"}}"#,
            dir.display()
        ));
        assert!(result.is_ok());
        assert!(result.unwrap().contains("mcp-test"));

        let _ = args; // suppress unused warning
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_crux_query() {
        let dir = std::env::temp_dir().join("crux_mcp_test_query");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut db = schema::create_crux_db("query-test", schema::CruxKind::Codebase, "rust");
        db.nodes.push(schema::CruxNode {
            node_id: "sha256:n1".to_string(),
            name: "@process_data".to_string(),
            kind: "function".to_string(),
            module: "main".to_string(),
            summary: "Process input data".to_string(),
            schema: schema::NodeSchema::empty(),
            tags: vec!["io".to_string(), "data".to_string()],
            reach: Vec::new(),
            properties: Vec::new(),
            warnings: Vec::new(),
            planning: schema::PlanningMetadata {
                updated_at: Some(crate::crypto::now_unix()),
                ..schema::PlanningMetadata::empty()
            },
            security: schema::SecurityMetadata::internal(),
            content_hash: String::new(),
            deleted_at: None,
        });
        schema::save_crux_db(&db, &dir).unwrap();

        let result = tool_crux_query(&format!(
            r#"{{"path":"{}","query":"data"}}"#,
            dir.display()
        ));
        assert!(result.is_ok());
        let text = result.unwrap();
        assert!(text.contains("@process_data"));
        assert!(text.contains("1 node(s)"));

        // Query that matches nothing
        let result = tool_crux_query(&format!(
            r#"{{"path":"{}","query":"zzz_nonexistent"}}"#,
            dir.display()
        ));
        assert!(result.is_ok());
        assert!(result.unwrap().contains("No nodes found matching filters"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_mesh_init() {
        let dir = std::env::temp_dir().join("crux_mcp_test_mesh_init");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let result = tool_mesh_init(&format!(
            r#"{{"name":"mcp-mesh","path":"{}"}}"#,
            dir.display()
        ));
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Initialized mesh 'mcp-mesh'"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_mesh_status() {
        let dir = std::env::temp_dir().join("crux_mcp_test_mesh_status");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        mesh::init_mesh("status-mesh", &dir).unwrap();

        let result = tool_mesh_status(&format!(r#"{{"mesh_path":"{}"}}"#, dir.display()));
        assert!(result.is_ok());
        assert!(result.unwrap().contains("status-mesh"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_mesh_verify_clean_chain() {
        let dir = std::env::temp_dir().join("crux_mcp_test_mesh_verify");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        mesh::init_mesh("verify-mesh", &dir).unwrap();

        // Verify on a fresh mesh (no audit events yet) — should report 0 events ok
        let result = tool_mesh_verify(&format!(r#"{{"mesh_path":"{}"}}"#, dir.display()));
        assert!(result.is_ok(), "mesh verify must succeed on clean mesh: {:?}", result);
        let out = result.unwrap();
        assert!(out.contains("verify-mesh"), "output must name the mesh");
        assert!(out.contains("0 chain error"), "must report no chain errors");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_verify_checks_registration_self_sig() {
        let dir = std::env::temp_dir().join("crux_mcp_test_verify_selfsig");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        mesh::init_mesh("selfsig-mesh", &dir).unwrap();
        mesh::mesh_register_mcp(&dir, "sig-server", "stdio", "my-tool --mcp", "", "internal", "*", "", &crate::schema::OAuthConfig::default()).unwrap();

        let result = tool_mesh_verify(&format!(r#"{{"mesh_path":"{}"}}"#, dir.display()));
        assert!(result.is_ok(), "mesh verify should succeed: {:?}", result);
        let out = result.unwrap();
        assert!(out.contains("self-sig valid"), "expected self-sig valid in output, got:\n{out}");
        assert!(out.contains("sig-server"), "expected alias in output");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_dispatch_unknown() {
        let resp = handle_tool_call("1", "nonexistent_tool", "{}");
        assert!(resp.contains("Unknown tool"));
    }

    #[test]
    fn test_json_rpc_error_format() {
        let err = json_rpc_error("1", -32601, "Method not found");
        assert!(err.contains("\"code\":-32601"));
        assert!(err.contains("Method not found"));
    }

    #[test]
    fn test_tool_crux_add_node() {
        let dir = std::env::temp_dir().join("crux_mcp_test_add_node");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let db = schema::create_crux_db("add-node-test", schema::CruxKind::Codebase, "rust");
        schema::save_crux_db(&db, &dir).unwrap();

        let result = tool_crux_add_node(&format!(
            r#"{{"path":"{}","name":"@my_func","kind":"function","module":"src/lib","summary":"Does stuff","tags":"io,network"}}"#,
            dir.display()
        ));
        assert!(result.is_ok(), "{:?}", result);
        let text = result.unwrap();
        assert!(text.contains("@my_func"));

        // Reload and verify
        let loaded = schema::load_crux_db(&dir).unwrap();
        assert_eq!(loaded.nodes.len(), 1);
        assert_eq!(loaded.nodes[0].name, "@my_func");
        assert_eq!(loaded.nodes[0].tags, vec!["io", "network"]);

        // Duplicate should fail
        let dup = tool_crux_add_node(&format!(
            r#"{{"path":"{}","name":"@my_func","kind":"function"}}"#,
            dir.display()
        ));
        assert!(dup.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_crux_add_edge() {
        let dir = std::env::temp_dir().join("crux_mcp_test_add_edge");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let db = schema::create_crux_db("edge-test", schema::CruxKind::Codebase, "rust");
        schema::save_crux_db(&db, &dir).unwrap();

        // Add nodes first
        tool_crux_add_node(&format!(
            r#"{{"path":"{}","name":"@caller","kind":"function"}}"#,
            dir.display()
        ))
        .unwrap();
        tool_crux_add_node(&format!(
            r#"{{"path":"{}","name":"@callee","kind":"function"}}"#,
            dir.display()
        ))
        .unwrap();

        // Add edge
        let result = tool_crux_add_edge(&format!(
            r#"{{"path":"{}","src":"@caller","dst":"@callee","kind":"calls","detail":"on every request"}}"#,
            dir.display()
        ));
        assert!(result.is_ok(), "{:?}", result);

        let loaded = schema::load_crux_db(&dir).unwrap();
        assert_eq!(loaded.edges.len(), 1);
        assert_eq!(loaded.edges[0].src, "@caller");
        assert_eq!(loaded.edges[0].dst, "@callee");
        assert_eq!(loaded.edges[0].kind, schema::EdgeKind::Calls);

        // Edge with missing src should fail
        let bad = tool_crux_add_edge(&format!(
            r#"{{"path":"{}","src":"@nonexistent","dst":"@callee","kind":"calls"}}"#,
            dir.display()
        ));
        assert!(bad.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Set up a crux with two live nodes, `alpha` and `beta`.
    fn edge_fixture(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("crux_mcp_test_{}", tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let db = schema::create_crux_db("edge-test", schema::CruxKind::Codebase, "rust");
        schema::save_crux_db(&db, &dir).unwrap();
        for n in ["alpha", "beta"] {
            tool_crux_add_node(&format!(
                r#"{{"path":"{}","name":"{}","kind":"reference"}}"#,
                dir.display(),
                n
            ))
            .unwrap();
        }
        dir
    }

    /// Build add_edges arguments. `edges` is declared as a string in the tool
    /// schema, so the array has to be JSON-encoded into it.
    fn edges_args(dir: &std::path::Path, extra: &str, edges: &str) -> String {
        format!(
            r#"{{"path":"{}"{},"edges":"{}"}}"#,
            dir.display(),
            extra,
            edges.replace('\\', "\\\\").replace('"', "\\\"")
        )
    }

    #[test]
    fn test_add_edges_rejects_missing_dst() {
        let dir = edge_fixture("edges_missing_dst");

        let result = tool_crux_add_edges_batch(&edges_args(
            &dir,
            "",
            r#"[{"src":"alpha","dst":"NO_SUCH_DST","kind":"relates_to"}]"#,
        ));

        let err = result.expect_err("edge with missing dst must be rejected");
        assert!(err.contains("NO_SUCH_DST"), "offender must be named: {}", err);
        assert!(err.contains("dst not found"), "side must be named: {}", err);

        // Nothing reached the file.
        assert_eq!(schema::load_crux_db(&dir).unwrap().edges.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_add_edges_rejects_missing_src() {
        let dir = edge_fixture("edges_missing_src");

        let result = tool_crux_add_edges_batch(&edges_args(
            &dir,
            "",
            r#"[{"src":"NO_SUCH_SRC","dst":"beta","kind":"relates_to"}]"#,
        ));

        let err = result.expect_err("edge with missing src must be rejected");
        assert!(err.contains("NO_SUCH_SRC"), "offender must be named: {}", err);
        assert!(err.contains("src not found"), "side must be named: {}", err);

        assert_eq!(schema::load_crux_db(&dir).unwrap().edges.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_add_edges_names_both_missing_sides_in_one_reason() {
        let dir = edge_fixture("edges_both_missing");

        let err = tool_crux_add_edges_batch(&edges_args(
            &dir,
            "",
            r#"[{"src":"NO_SRC","dst":"NO_DST","kind":"relates_to"}]"#,
        ))
        .expect_err("edge with both endpoints missing must be rejected");

        assert!(
            err.contains("src not found, dst not found"),
            "both sides must appear in one reason string: {}",
            err
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_add_edges_partial_batch_is_all_or_nothing() {
        let dir = edge_fixture("edges_partial");

        // One valid edge, three invalid — the documented behaviour is that the
        // valid one is NOT applied, so the caller can retry the whole array.
        let err = tool_crux_add_edges_batch(&edges_args(
            &dir,
            "",
            r#"[{"src":"alpha","dst":"beta","kind":"relates_to"},
                {"src":"alpha","dst":"NO_SUCH_DST","kind":"relates_to"},
                {"src":"NO_SUCH_SRC","dst":"beta","kind":"relates_to"},
                {"src":"NO_SUCH_SRC2","dst":"NO_SUCH_DST2","kind":"relates_to"}]"#,
        ))
        .expect_err("a partially-valid batch must be rejected whole");

        assert!(err.contains("3 of 4"), "counts must be reported: {}", err);
        assert!(err.contains("No edges were written"), "{}", err);
        // Every offender named, with its input index.
        for name in ["NO_SUCH_DST", "NO_SUCH_SRC", "NO_SUCH_SRC2", "NO_SUCH_DST2"] {
            assert!(err.contains(name), "{} must be named: {}", name, err);
        }
        for idx in ["[1]", "[2]", "[3]"] {
            assert!(err.contains(idx), "index {} must be reported: {}", idx, err);
        }

        assert_eq!(schema::load_crux_db(&dir).unwrap().edges.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_add_edges_success_message_claims_only_what_it_checked() {
        let dir = edge_fixture("edges_message");

        let msg = tool_crux_add_edges_batch(&edges_args(
            &dir,
            "",
            r#"[{"src":"alpha","dst":"beta","kind":"relates_to"}]"#,
        ))
        .unwrap();

        assert!(msg.contains("1 edge(s) added"), "{}", msg);
        // Regression guard for the original defect: the success string advertised
        // a "skipped (missing src/dst)" count that no validation had produced.
        assert!(
            !msg.contains("skipped"),
            "must not report a skip count it did not compute: {}",
            msg
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_add_edges_forward_refs_are_opt_in_and_marked() {
        let dir = edge_fixture("edges_forward_refs");

        let msg = tool_crux_add_edges_batch(&edges_args(
            &dir,
            r#","allow_forward_refs":true"#,
            r#"[{"src":"alpha","dst":"LATER","kind":"relates_to"}]"#,
        ))
        .unwrap();
        assert!(msg.contains("dangling forward reference"), "{}", msg);
        assert!(msg.contains("LATER"), "{}", msg);

        // Admitted, but stored in a state that is distinguishable from a resolved edge.
        let loaded = schema::load_crux_db(&dir).unwrap();
        assert_eq!(loaded.edges.len(), 1);
        assert!(loaded.edges[0].dangling);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_verify_fails_on_hand_inserted_dangling_edge() {
        let dir = edge_fixture("verify_dangling");

        // Insert the edge behind the tool's back, exactly as a foreign writer or
        // a hand edit would — no `dangling` flag set anywhere in the file.
        let mut db = schema::load_crux_db(&dir).unwrap();
        db.edges.push(schema::CruxEdge {
            edge_id: "sha256:test".to_string(),
            src: "alpha".to_string(),
            dst: "GHOST".to_string(),
            kind: schema::EdgeKind::RelatesTo,
            weight: 1.0,
            detail: String::new(),
            cross_crux: false,
            binding: String::new(),
            created_at: 0,
            dangling: false,
        });
        schema::save_crux_db(&db, &dir).unwrap();

        let out = tool_crux_verify(&format!(r#"{{"path":"{}"}}"#, dir.display())).unwrap();

        assert!(out.contains("Overall: FAIL"), "must not pass: {}", out);
        assert!(out.contains("GHOST"), "offender must be named: {}", out);
        assert!(out.contains("REFERENTIAL"), "{}", out);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_summary_reports_dangling_count() {
        let dir = edge_fixture("load_dangling");

        tool_crux_add_edges_batch(&edges_args(
            &dir,
            r#","allow_forward_refs":true"#,
            r#"[{"src":"alpha","dst":"beta"},{"src":"alpha","dst":"GHOST"}]"#,
        ))
        .unwrap();

        let out = tool_crux_load(&format!(r#"{{"path":"{}"}}"#, dir.display())).unwrap();
        assert!(
            out.contains("2 edges (1 dangling)"),
            "a cold reader must see the dangling count: {}",
            out
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_call_sets_is_error_on_failure() {
        let dir = edge_fixture("is_error_flag");

        let ok = handle_tool_call(
            "1",
            "crux",
            &edges_args(&dir, r#","action":"add_edges""#, r#"[{"src":"alpha","dst":"beta"}]"#),
        );
        assert!(ok.contains("\"isError\":false"), "{}", ok);

        let bad = handle_tool_call(
            "1",
            "crux",
            &edges_args(&dir, r#","action":"add_edges""#, r#"[{"src":"alpha","dst":"GHOST"}]"#),
        );
        assert!(
            bad.contains("\"isError\":true"),
            "rejection must be branchable without parsing prose: {}",
            bad
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_crux_remove_node() {
        let dir = std::env::temp_dir().join("crux_mcp_test_remove_node");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let db = schema::create_crux_db("remove-test", schema::CruxKind::Codebase, "rust");
        schema::save_crux_db(&db, &dir).unwrap();

        tool_crux_add_node(&format!(
            r#"{{"path":"{}","name":"@to_delete","kind":"function"}}"#,
            dir.display()
        ))
        .unwrap();

        let result = tool_crux_remove_node(&format!(
            r#"{{"path":"{}","name":"@to_delete"}}"#,
            dir.display()
        ));
        assert!(result.is_ok(), "{:?}", result);

        let loaded = schema::load_crux_db(&dir).unwrap();
        assert!(loaded.nodes[0].deleted_at.is_some());

        // Removing again should fail
        let dup = tool_crux_remove_node(&format!(
            r#"{{"path":"{}","name":"@to_delete"}}"#,
            dir.display()
        ));
        assert!(dup.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_crux_generate_markdown() {
        let dir = std::env::temp_dir().join("crux_mcp_test_generate");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let md = "# Introduction\nWelcome to the project.\n## Installation\nRun cargo install.\n";
        let result = tool_crux_generate(&format!(
            r#"{{"name":"test-docs","input":{},"format":"markdown","path":"{}"}}"#,
            crate::json::json_escape(md),
            dir.display()
        ));
        assert!(result.is_ok(), "{:?}", result);

        let loaded = schema::load_crux_db(&dir).unwrap();
        assert_eq!(loaded.nodes.len(), 2);
        assert_eq!(loaded.nodes[0].name, "Introduction");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_mesh_create_and_assign_cluster() {
        let dir = std::env::temp_dir().join("crux_mcp_test_cluster");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        mesh::init_mesh("cluster-mesh", &dir).unwrap();

        let crux_dir = dir.join("my-crux");
        std::fs::create_dir_all(&crux_dir).unwrap();
        let db = schema::create_crux_db("my-crux", schema::CruxKind::Codebase, "rust");
        schema::save_crux_db(&db, &crux_dir).unwrap();
        mesh::join_mesh(&dir, "my-crux").unwrap();

        let create = tool_mesh_create_cluster(&format!(
            r#"{{"name":"engineering","classification":"internal","policy":"allow","mesh_path":"{}"}}"#,
            dir.display()
        ));
        assert!(create.is_ok(), "{:?}", create);

        let assign = tool_mesh_assign_cluster(&format!(
            r#"{{"identifier":"my-crux","cluster":"engineering","mesh_path":"{}"}}"#,
            dir.display()
        ));
        assert!(assign.is_ok(), "{:?}", assign);
        assert!(assign.unwrap().contains("engineering"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_handle_resources_list() {
        let resp = handle_resources_list("1");
        assert!(resp.contains("crux://spec/agent"), "resp: {}", resp);
        assert!(resp.contains("Crux Agent Spec"), "resp: {}", resp);
        assert!(resp.contains("crux://spec/router"), "resp: {}", resp);
        assert!(resp.contains("Crux Router Spec"), "resp: {}", resp);
    }

    #[test]
    fn test_handle_resources_read_spec() {
        let resp = handle_resources_read("1", "crux://spec/agent");
        assert!(resp.contains("crux://spec/agent"));
        assert!(resp.contains("Crux Agent Spec"));
    }

    #[test]
    fn test_handle_resources_read_router_spec() {
        let resp = handle_resources_read("1", "crux://spec/router");
        assert!(resp.contains("crux://spec/router"), "resp: {}", resp);
        assert!(resp.contains("Policy Router"), "resp: {}", resp);
        assert!(resp.contains("rate_limit"), "resp: {}", resp);
    }

    #[test]
    fn test_handle_resources_read_unknown() {
        let resp = handle_resources_read("1", "crux://nonexistent");
        assert!(resp.contains("Resource not found"));
    }

    #[test]
    fn test_tool_pkg_publish_and_search() {
        let dir = std::env::temp_dir().join("crux_mcp_test_pkg_pub_search");
        let _ = std::fs::remove_dir_all(&dir);

        // Set up registry
        let registry_dir = dir.join("registry");
        std::fs::create_dir_all(&registry_dir).unwrap();
        mesh::init_mesh("mcp-pkg-registry", &registry_dir).unwrap();

        // Create a package to publish
        let pkg_dir = dir.join("my-lib");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let mut db = schema::create_crux_db("my-lib", schema::CruxKind::Codebase, "lml");
        db.nodes.push(schema::CruxNode {
            node_id: "sha256:n1".to_string(),
            name: "@helper_fn".to_string(),
            kind: "function".to_string(),
            module: "lib.lml".to_string(),
            summary: "A helper function".to_string(),
            schema: schema::NodeSchema::empty(),
            tags: vec!["util".to_string()],
            reach: Vec::new(),
            properties: Vec::new(),
            warnings: Vec::new(),
            planning: schema::PlanningMetadata::done(),
            security: schema::SecurityMetadata::internal(),
            content_hash: String::new(),
            deleted_at: None,
        });
        schema::save_crux_db(&db, &pkg_dir).unwrap();

        // Publish via MCP tool
        let result = tool_pkg_publish(&format!(
            r#"{{"source_dir":"{}","registry_path":"{}"}}"#,
            pkg_dir.display(),
            registry_dir.display()
        ));
        assert!(result.is_ok(), "pkg_publish failed: {:?}", result);
        let text = result.unwrap();
        assert!(text.contains("Published"));

        // Search via MCP tool
        let result = tool_pkg_search(&format!(
            r#"{{"query":"helper","registry_path":"{}"}}"#,
            registry_dir.display()
        ));
        assert!(result.is_ok(), "pkg_search failed: {:?}", result);
        let text = result.unwrap();
        assert!(text.contains("@helper_fn"));

        // Search with no results
        let result = tool_pkg_search(&format!(
            r#"{{"query":"domain:graphics","registry_path":"{}"}}"#,
            registry_dir.display()
        ));
        assert!(result.is_ok());
        assert!(result.unwrap().contains("No packages matching"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_pkg_search_missing_params() {
        let result = tool_pkg_search(r#"{"query":"test"}"#);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("registry_path"));
    }

    #[test]
    fn test_tool_pkg_publish_missing_params() {
        let result = tool_pkg_publish(r#"{"registry_path":"/tmp"}"#);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("source_dir"));
    }
}
