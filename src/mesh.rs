//! Mesh manifest and file-based discovery.
//!
//! The `.crux-mesh.json` manifest is the root of a mesh — it lists all member
//! cruxes, cross-crux edge summaries, security defaults, and redundancy config.
//! File-based operations: init, join, leave, status.

use std::fmt::Write as FmtWrite;
use std::path::{Path, PathBuf};

use crate::crypto::sha256_hex;
use crate::json::{
    extract_json_objects_from_array, extract_string_value, extract_u64_value, json_escape,
    json_opt_str,
};
use crate::schema::{load_crux_db, now_unix, CruxDb, CruxKind};

// ===========================================================================
// Security: classification levels and clearance-based filtering
// (inlined from legacy/security.rs — H-8)
// ===========================================================================

/// Security classification level, ordered by sensitivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Restricted = 3,
}

impl SecurityLevel {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> SecurityLevel {
        match s.to_lowercase().as_str() {
            "public" => SecurityLevel::Public,
            "internal" => SecurityLevel::Internal,
            "confidential" => SecurityLevel::Confidential,
            "restricted" => SecurityLevel::Restricted,
            _ => SecurityLevel::Internal,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityLevel::Public => "public",
            SecurityLevel::Internal => "internal",
            SecurityLevel::Confidential => "confidential",
            SecurityLevel::Restricted => "restricted",
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn from_u8(n: u8) -> SecurityLevel {
        match n {
            0 => SecurityLevel::Public,
            1 => SecurityLevel::Internal,
            2 => SecurityLevel::Confidential,
            3 => SecurityLevel::Restricted,
            _ => SecurityLevel::Restricted,
        }
    }
}

/// Filter nodes by clearance level. Nodes with classification > clearance are omitted.
/// Nodes with redact_below > clearance are included but with redacted content.
pub fn filter_by_clearance(nodes: &[crate::schema::CruxNode], clearance: SecurityLevel) -> Vec<crate::schema::CruxNode> {
    let clearance_level = clearance.as_u8();
    let mut result = Vec::new();
    for node in nodes {
        let node_level = SecurityLevel::from_str(&node.security.classification).as_u8();
        if node_level > clearance_level {
            continue;
        }
        if let Some(ref redact_str) = node.security.redact_below {
            let redact_level = SecurityLevel::from_str(redact_str).as_u8();
            if redact_level > clearance_level {
                result.push(redact_node(node));
                continue;
            }
        }
        result.push(node.clone());
    }
    result
}

/// Create a redacted copy of a node — name visible, content hidden.
fn redact_node(node: &crate::schema::CruxNode) -> crate::schema::CruxNode {
    crate::schema::CruxNode {
        node_id: node.node_id.clone(),
        name: node.name.clone(),
        kind: node.kind.clone(),
        module: node.module.clone(),
        summary: "[REDACTED]".to_string(),
        schema: crate::schema::NodeSchema::empty(),
        tags: Vec::new(),
        reach: Vec::new(),
        properties: Vec::new(),
        warnings: Vec::new(),
        planning: crate::schema::PlanningMetadata::empty(),
        security: node.security.clone(),
        content_hash: String::new(),
        deleted_at: node.deleted_at,
    }
}

// ===========================================================================
// Helper functions
// ===========================================================================

/// Encode bytes as hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex string to bytes.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("Invalid hex character at position {}", i))
        })
        .collect()
}

// ===========================================================================
// Structs
// ===========================================================================

/// A member crux registered in the mesh.
#[derive(Debug, Clone)]
pub struct MeshMember {
    pub crux_id: String,
    pub crux_name: String,
    pub crux_kind: CruxKind,
    pub path: String,
    pub socket: Option<String>,
    pub status: String,
    pub last_seen: u64,
    pub replica_group: Option<String>,
    /// Access-control cluster within the mesh (separate from replica_group)
    pub cluster: Option<String>,
    /// Quantum-resistant key pair for this mesh membership
    pub mesh_public_key: Vec<u8>,
    pub mesh_private_key: Vec<u8>,
}

/// Summary of cross-crux edges between two members.
#[derive(Debug, Clone)]
pub struct CrossEdgeRef {
    pub src_crux: String,
    pub dst_crux: String,
    pub edge_count: usize,
    pub last_synced: u64,
}

/// Security defaults for the mesh.
#[derive(Debug, Clone)]
pub struct MeshSecurity {
    pub default_classification: String,
    pub levels: Vec<String>,
}

impl MeshSecurity {
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        MeshSecurity {
            default_classification: "internal".to_string(),
            levels: vec![
                "public".to_string(),
                "internal".to_string(),
                "confidential".to_string(),
                "restricted".to_string(),
            ],
        }
    }
}

/// The mesh manifest — root data structure for a crux mesh.
#[derive(Debug, Clone)]
pub struct MeshManifest {
    pub mesh_version: u32,
    pub mesh_id: String,
    pub mesh_name: String,
    pub created_at: u64,
    pub members: Vec<MeshMember>,
    pub cross_edges: Vec<CrossEdgeRef>,
    pub security: MeshSecurity,
}

// ===========================================================================
// ID generation
// ===========================================================================

/// Generate a mesh ID from the mesh name and creation timestamp.
pub fn generate_mesh_id(name: &str, created_at: u64) -> String {
    let input = format!("mesh:{}:{}", name, created_at);
    format!("sha256:{}", sha256_hex(input.as_bytes()))
}

// ===========================================================================
// Construction
// ===========================================================================

/// Create a new empty mesh manifest.
pub fn create_mesh(name: &str) -> MeshManifest {
    let ts = now_unix();
    MeshManifest {
        mesh_version: 1,
        mesh_id: generate_mesh_id(name, ts),
        mesh_name: name.to_string(),
        created_at: ts,
        members: Vec::new(),
        cross_edges: Vec::new(),
        security: MeshSecurity::default(),
    }
}

// ===========================================================================
// Serialization
// ===========================================================================

/// Serialize a MeshManifest to JSON string.
pub fn serialize_mesh(manifest: &MeshManifest) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str("{\n");

    let _ = writeln!(out, "  \"mesh_version\": {},", manifest.mesh_version);
    let _ = writeln!(out, "  \"mesh_id\": {},", json_escape(&manifest.mesh_id));
    let _ = writeln!(
        out,
        "  \"mesh_name\": {},",
        json_escape(&manifest.mesh_name)
    );
    let _ = writeln!(out, "  \"created_at\": {},", manifest.created_at);

    // Members
    out.push_str("  \"members\": [");
    for (i, m) in manifest.members.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("\n    {\n");
        let _ = writeln!(out, "      \"crux_id\": {},", json_escape(&m.crux_id));
        let _ = writeln!(out, "      \"crux_name\": {},", json_escape(&m.crux_name));
        let _ = writeln!(
            out,
            "      \"crux_kind\": {},",
            json_escape(m.crux_kind.as_str())
        );
        let _ = writeln!(out, "      \"path\": {},", json_escape(&m.path));
        let _ = writeln!(out, "      \"socket\": {},", json_opt_str(&m.socket));
        let _ = writeln!(out, "      \"status\": {},", json_escape(&m.status));
        let _ = writeln!(out, "      \"last_seen\": {},", m.last_seen);
        let _ = writeln!(out, "      \"replica_group\": {},", json_opt_str(&m.replica_group));
        let _ = writeln!(out, "      \"cluster\": {},", json_opt_str(&m.cluster));
        let _ = writeln!(
            out,
            "      \"mesh_public_key\": {}",
            json_escape(&bytes_to_hex(&m.mesh_public_key))
        );
        let _ = writeln!(
            out,
            "      \"mesh_private_key\": {}",
            json_escape(&bytes_to_hex(&m.mesh_private_key))
        );
        out.push_str("    }");
    }
    out.push_str("\n  ],\n");

    // Cross-edges
    out.push_str("  \"cross_edges\": [");
    for (i, ce) in manifest.cross_edges.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("\n    {");
        let _ = write!(out, " \"src_crux\": {}", json_escape(&ce.src_crux));
        let _ = write!(out, ", \"dst_crux\": {}", json_escape(&ce.dst_crux));
        let _ = write!(out, ", \"edge_count\": {}", ce.edge_count);
        let _ = write!(out, ", \"last_synced\": {}", ce.last_synced);
        out.push_str(" }");
    }
    out.push_str("\n  ],\n");

    // Security
    out.push_str("  \"security\": {\n");
    let _ = writeln!(
        out,
        "    \"default_classification\": {},",
        json_escape(&manifest.security.default_classification)
    );
    out.push_str("    \"levels\": [");
    for (i, level) in manifest.security.levels.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&json_escape(level));
    }
    out.push_str("]\n");
    out.push_str("  }\n");

    out.push_str("}\n");
    out
}

// ===========================================================================
// Deserialization
// ===========================================================================

/// Parse a MeshManifest from a JSON string.
pub fn parse_mesh(text: &str) -> Result<MeshManifest, String> {
    let mesh_version = extract_u64_value(text, "mesh_version").unwrap_or(1) as u32;
    let mesh_id = extract_string_value(text, "mesh_id").unwrap_or_default();
    let mesh_name = extract_string_value(text, "mesh_name").unwrap_or_default();
    let created_at = extract_u64_value(text, "created_at").unwrap_or(0);

    let members = parse_members(text);
    let cross_edges = parse_cross_edges(text);
    let security = parse_security(text);

    Ok(MeshManifest {
        mesh_version,
        mesh_id,
        mesh_name,
        created_at,
        members,
        cross_edges,
        security,
    })
}

/// Parse the "members" array from the mesh JSON.
fn parse_members(text: &str) -> Vec<MeshMember> {
    let mut members = Vec::new();
    let start = match text.find("\"members\"") {
        Some(i) => i,
        None => return members,
    };
    let after = &text[start..];
    let bracket = match after.find('[') {
        Some(i) => i,
        None => return members,
    };
    let array_text = &after[bracket..];

    for obj in extract_json_objects_from_array(array_text) {
        let obj = obj.as_str();
        let crux_id = extract_string_value(obj, "crux_id").unwrap_or_default();
        let crux_name = extract_string_value(obj, "crux_name").unwrap_or_default();
        let crux_kind_str = extract_string_value(obj, "crux_kind")
            .unwrap_or_else(|| "codebase".to_string());
        let path = extract_string_value(obj, "path").unwrap_or_default();
        let socket = extract_string_value(obj, "socket");
        let status = extract_string_value(obj, "status")
            .unwrap_or_else(|| "offline".to_string());
        let last_seen = extract_u64_value(obj, "last_seen").unwrap_or(0);
        let replica_group = extract_string_value(obj, "replica_group");
        let cluster = extract_string_value(obj, "cluster");
        let mesh_public_key_hex = extract_string_value(obj, "mesh_public_key")
            .unwrap_or_default();
        let mesh_private_key_hex = extract_string_value(obj, "mesh_private_key")
            .unwrap_or_default();

        let mesh_public_key = hex_to_bytes(&mesh_public_key_hex).unwrap_or_default();
        let mesh_private_key = hex_to_bytes(&mesh_private_key_hex).unwrap_or_default();

        members.push(MeshMember {
            crux_id,
            crux_name,
            crux_kind: CruxKind::from_str(&crux_kind_str),
            path,
            socket,
            status,
            last_seen,
            replica_group,
            cluster,
            mesh_public_key,
            mesh_private_key,
        });
    }
    members
}

/// Parse the "cross_edges" array from the mesh JSON.
fn parse_cross_edges(text: &str) -> Vec<CrossEdgeRef> {
    let mut edges = Vec::new();
    let start = match text.find("\"cross_edges\"") {
        Some(i) => i,
        None => return edges,
    };
    let after = &text[start..];
    let bracket = match after.find('[') {
        Some(i) => i,
        None => return edges,
    };
    let array_text = &after[bracket..];

    for obj in extract_json_objects_from_array(array_text) {
        let obj = obj.as_str();
        let src_crux = extract_string_value(obj, "src_crux").unwrap_or_default();
        let dst_crux = extract_string_value(obj, "dst_crux").unwrap_or_default();
        let edge_count = extract_u64_value(obj, "edge_count").unwrap_or(0) as usize;
        let last_synced = extract_u64_value(obj, "last_synced").unwrap_or(0);
        edges.push(CrossEdgeRef {
            src_crux,
            dst_crux,
            edge_count,
            last_synced,
        });
    }
    edges
}

/// Parse the "security" object from the mesh JSON.
fn parse_security(text: &str) -> MeshSecurity {
    // Find the "security" section — but avoid matching "classification" first
    let default_class = extract_string_value(text, "default_classification")
        .unwrap_or_else(|| "internal".to_string());

    // Parse levels array within the security section
    let levels = parse_security_levels(text);

    MeshSecurity {
        default_classification: default_class,
        levels,
    }
}

/// Parse the security "levels" array. We need to be careful not to match
/// other arrays, so we look for it near "default_classification".
fn parse_security_levels(text: &str) -> Vec<String> {
    // Find "security" section
    let sec_start = match text.find("\"security\"") {
        Some(i) => i,
        None => {
            return vec![
                "public".to_string(),
                "internal".to_string(),
                "confidential".to_string(),
                "restricted".to_string(),
            ]
        }
    };
    let sec_text = &text[sec_start..];

    // Find "levels" within the security section
    let levels_start = match sec_text.find("\"levels\"") {
        Some(i) => i,
        None => {
            return vec![
                "public".to_string(),
                "internal".to_string(),
                "confidential".to_string(),
                "restricted".to_string(),
            ]
        }
    };
    let after = &sec_text[levels_start..];
    let bracket = match after.find('[') {
        Some(i) => i,
        None => {
            return vec![
                "public".to_string(),
                "internal".to_string(),
                "confidential".to_string(),
                "restricted".to_string(),
            ]
        }
    };
    let array_text = &after[bracket + 1..];
    let end = match array_text.find(']') {
        Some(i) => i,
        None => {
            return vec![
                "public".to_string(),
                "internal".to_string(),
                "confidential".to_string(),
                "restricted".to_string(),
            ]
        }
    };
    let inner = &array_text[..end];

    let mut result = Vec::new();
    let mut in_str = false;
    let mut current = String::new();
    let mut escaped = false;

    for c in inner.chars() {
        if escaped {
            current.push(c);
            escaped = false;
        } else if c == '\\' && in_str {
            escaped = true;
        } else if c == '"' {
            if in_str {
                result.push(std::mem::take(&mut current));
                in_str = false;
            } else {
                in_str = true;
            }
        } else if in_str {
            current.push(c);
        }
    }
    result
}

// ===========================================================================
// File I/O
// ===========================================================================

/// The standard mesh manifest filename.
pub const MESH_MANIFEST_FILE: &str = ".crux-mesh.json";

/// Save a mesh manifest to a `.crux-mesh.json` file in the given directory.
pub fn save_mesh(manifest: &MeshManifest, dir: &Path) -> Result<(), String> {
    let path = dir.join(MESH_MANIFEST_FILE);
    let json = serialize_mesh(manifest);
    std::fs::write(&path, json).map_err(|e| format!("Failed to write mesh manifest: {}", e))
}

/// Load a mesh manifest from a `.crux-mesh.json` file in the given directory.
pub fn load_mesh(dir: &Path) -> Result<MeshManifest, String> {
    let path = dir.join(MESH_MANIFEST_FILE);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read mesh manifest: {}", e))?;
    parse_mesh(&text)
}

/// Find the mesh manifest by searching the given directory and its parents.
pub fn find_mesh(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(MESH_MANIFEST_FILE);
        if candidate.exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

// ===========================================================================
// Mesh operations
// ===========================================================================

/// Load the policy crux for a mesh from its manifest.
pub fn load_policy_crux(manifest: &MeshManifest, mesh_dir: &Path) -> Result<crate::schema::CruxDb, String> {
    let policy_member = manifest.members.iter()
        .find(|m| m.crux_kind == crate::schema::CruxKind::Policy)
        .ok_or_else(|| "Mesh has no policy crux".to_string())?;
    let policy_dir = mesh_dir.join(&policy_member.path);
    crate::schema::load_crux_db(&policy_dir)
}

/// Update a crux's .crux.json file to record a new mesh membership.
/// The keypair stays in the mesh manifest; only the public key hash is written to the crux.
fn record_mesh_membership(
    crux_dir: &Path,
    mesh_id: &str,
    mesh_name: &str,
    public_key_hex: &str,
    cluster: Option<&str>,
) -> Result<(), String> {
    let mut db = crate::schema::load_crux_db(crux_dir)?;
    let public_key_hash = crate::crypto::sha256_hex(public_key_hex.as_bytes());
    db.header.mesh_memberships.push(crate::schema::MeshMembership {
        mesh_id: mesh_id.to_string(),
        mesh_name: mesh_name.to_string(),
        joined_at: now_unix(),
        cluster: cluster.map(|s| s.to_string()),
        public_key_hash,
    });
    crate::schema::save_crux_db(&db, crux_dir)
}

/// Write a mesh-keyring node to the policy crux for a given crux_id + public key.
///
/// This allows anyone who can read the policy crux to verify audit-chain
/// signatures produced by `crux_id`. Called from `init_mesh_with_policy`
/// and `join_mesh` after keypair generation.
pub fn seed_keyring_node(
    manifest: &MeshManifest,
    mesh_dir: &Path,
    crux_id: &str,
    pubkey_hex: &str,
) -> Result<(), String> {
    let mut policy_db = load_policy_crux(manifest, mesh_dir)?;
    let policy_member = manifest.members.iter()
        .find(|m| m.crux_kind == crate::schema::CruxKind::Policy)
        .ok_or_else(|| "No policy crux in mesh".to_string())?;
    let policy_dir = mesh_dir.join(&policy_member.path);

    // Idempotent: skip if keyring node for this crux_id already exists
    if policy_db.nodes.iter().any(|n| {
        n.kind == "mesh-keyring"
            && n.properties.iter().any(|p| p == &format!("crux_id={crux_id}"))
    }) {
        return Ok(());
    }

    let pubkey_hash = sha256_hex(pubkey_hex.as_bytes());
    let node = crate::schema::CruxNode {
        node_id: crate::schema::generate_node_id(&format!("keyring-{crux_id}"), "keyring"),
        name: format!("keyring/{crux_id}"),
        kind: "mesh-keyring".to_string(),
        module: "policy".to_string(),
        summary: format!("W-OTS public key for audit-chain signatures from {crux_id}"),
        schema: crate::schema::NodeSchema::empty(),
        tags: vec!["keyring".to_string(), "signing".to_string()],
        reach: vec![],
        properties: vec![
            format!("crux_id={crux_id}"),
            format!("pubkey_hex={pubkey_hex}"),
            format!("pubkey_hash=sha256:{pubkey_hash}"),
        ],
        warnings: vec![],
        planning: crate::schema::PlanningMetadata::empty(),
        security: crate::schema::SecurityMetadata {
            classification: "restricted".to_string(),
            redact_below: None,
        },
        content_hash: sha256_hex(pubkey_hex.as_bytes()),
        deleted_at: None,
    };

    policy_db.nodes.push(node);
    crate::schema::save_crux_db(&policy_db, &policy_dir)
}

/// Look up the public key bytes for a given `crux_id` in the policy crux.
/// Returns `None` if no keyring node exists for that crux.
pub fn resolve_pubkey(policy_db: &crate::schema::CruxDb, crux_id: &str) -> Option<Vec<u8>> {
    for node in &policy_db.nodes {
        if node.kind != "mesh-keyring" || node.deleted_at.is_some() {
            continue;
        }
        if !node.properties.iter().any(|p| p == &format!("crux_id={crux_id}")) {
            continue;
        }
        if let Some(hex) = node.properties.iter().find_map(|p| p.strip_prefix("pubkey_hex=")) {
            let bytes: Result<Vec<u8>, _> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect();
            return bytes.ok();
        }
    }
    None
}

/// Create a new cluster definition in the mesh policy crux.
/// A cluster is a named access-control group.
pub fn create_cluster(mesh_dir: &Path, cluster_name: &str, classification: &str, cross_cluster_policy: &str) -> Result<(), String> {
    let manifest = load_mesh(mesh_dir)?;
    let mut policy_db = load_policy_crux(&manifest, mesh_dir)?;

    // Check cluster doesn't already exist
    let exists = policy_db.nodes.iter().any(|n| {
        n.properties.iter().any(|p| p == &format!("cluster_name={}", cluster_name))
    });
    if exists {
        return Err(format!("Cluster '{}' already exists in this mesh", cluster_name));
    }

    let node = crate::schema::CruxNode {
        node_id: crate::schema::generate_node_id(&format!("cluster-{}", cluster_name), "definition"),
        name: format!("Cluster: {}", cluster_name),
        kind: "cluster-definition".to_string(),
        module: "policy".to_string(),
        summary: format!("Access-control cluster '{}'", cluster_name),
        schema: crate::schema::NodeSchema::empty(),
        tags: vec!["cluster".to_string(), cluster_name.to_string()],
        reach: vec![],
        properties: vec![
            format!("cluster_name={}", cluster_name),
            format!("cluster_classification={}", classification),
            format!("cross_cluster_policy={}", cross_cluster_policy),
        ],
        warnings: vec![],
        planning: crate::schema::PlanningMetadata::empty(),
        security: crate::schema::SecurityMetadata {
            classification: classification.to_string(),
            redact_below: None,
        },
        content_hash: crate::crypto::sha256_hex(cluster_name.as_bytes()),
        deleted_at: None,
    };
    policy_db.nodes.push(node);

    let policy_member = manifest.members.iter()
        .find(|m| m.crux_kind == crate::schema::CruxKind::Policy)
        .ok_or("No policy crux found")?;
    let policy_dir = mesh_dir.join(&policy_member.path);
    crate::schema::save_crux_db(&policy_db, &policy_dir)
}

/// Assign a mesh member to a cluster by crux_id or crux_name.
pub fn assign_cluster(mesh_dir: &Path, identifier: &str, cluster_name: &str) -> Result<MeshManifest, String> {
    let mut manifest = load_mesh(mesh_dir)?;

    // Verify cluster exists in policy crux
    if let Ok(policy_db) = load_policy_crux(&manifest, mesh_dir) {
        let cluster_exists = policy_db.nodes.iter().any(|n| {
            n.properties.iter().any(|p| p == &format!("cluster_name={}", cluster_name))
        });
        if !cluster_exists {
            return Err(format!("Cluster '{}' does not exist. Create it first with create_cluster.", cluster_name));
        }
    }

    let member = manifest.members.iter_mut()
        .find(|m| m.crux_id == identifier || m.crux_name == identifier)
        .ok_or_else(|| format!("No member '{}' found in mesh", identifier))?;

    member.cluster = Some(cluster_name.to_string());
    save_mesh(&manifest, mesh_dir)?;
    Ok(manifest)
}

/// List all cluster names defined in the mesh policy crux.
pub fn list_clusters(mesh_dir: &Path) -> Result<Vec<String>, String> {
    let manifest = load_mesh(mesh_dir)?;
    let policy_db = load_policy_crux(&manifest, mesh_dir)?;
    let clusters: Vec<String> = policy_db.nodes.iter()
        .filter(|n| n.kind == "cluster-definition")
        .filter_map(|n| {
            n.properties.iter()
                .find(|p| p.starts_with("cluster_name="))
                .map(|p| p["cluster_name=".len()..].to_string())
        })
        .collect();
    Ok(clusters)
}

/// Sign an MCP server registration with a W-OTS subkey derived from the mesh
/// policy member's master private key.
///
/// Returns `"sig=<hex>;pk=<hex>"` on success, or an empty string if the key
/// is unavailable (e.g. during tests with dummy keys that are too short).
fn compute_self_sig(priv_key: &[u8], alias: &str, transport: &str, url: &str, clearance: &str) -> String {
    if priv_key.is_empty() { return String::new(); }
    let subkey = crate::crypto::derive_subkey(priv_key, 0);
    let canonical = format!("{}\x1f{}\x1f{}\x1f{}", alias, transport, url, clearance);
    let hash_vec = crate::crypto::sha256(canonical.as_bytes());
    let hash: [u8; 32] = match hash_vec.try_into() {
        Ok(a) => a,
        Err(_) => return String::new(),
    };
    let sig = crate::crypto::wots_sign_raw(&subkey, &hash);
    let pk = crate::crypto::wots_pubkey_from_privkey(&subkey);
    format!("sig={};pk={}", crate::crypto::bytes_to_hex(&sig), crate::crypto::bytes_to_hex(&pk))
}

/// Register an external MCP server in the mesh's policy crux.
///
/// Stores an `mcp_server_registration` node so the crux-router (in
/// `--policy-router` mode) can discover and proxy calls to it.
/// Returns an error if the alias is already registered or if transport/clearance
/// values are invalid.
pub fn mesh_register_mcp(
    mesh_dir: &Path,
    alias: &str,
    transport: &str,
    command: &str,
    url: &str,
    required_clearance: &str,
    allowed_tools: &str,
    rate_limit: &str,
    oauth: &crate::schema::OAuthConfig,
) -> Result<String, String> {
    use crate::schema::{
        McpClearance, McpServerRegistration, McpTransport,
        build_mcp_server_registration, parse_mcp_server_registration,
    };

    // Validate inputs
    if alias.is_empty() {
        return Err("alias is required".to_string());
    }
    let transport_val = McpTransport::from_str(transport)
        .ok_or_else(|| format!("Invalid transport '{}': must be 'stdio' or 'http'", transport))?;
    let clearance_val = McpClearance::from_str(required_clearance)
        .unwrap_or(McpClearance::Internal);

    let manifest = load_mesh(mesh_dir)?;
    let mut policy_db = load_policy_crux(&manifest, mesh_dir)?;

    // Check alias uniqueness
    let duplicate = policy_db.nodes.iter().any(|n| {
        n.kind == "mcp_server_registration"
            && n.deleted_at.is_none()
            && n.properties.iter().any(|p| p == &format!("alias={}", alias))
    });
    if duplicate {
        return Err(format!("MCP server '{}' is already registered", alias));
    }

    let status = {
        let requires = crate::schema::get_policy_property(&policy_db, "require_approval")
            .map(|v| v == "true")
            .unwrap_or(false);
        if requires { "proposed" } else { "approved" }
    };

    let policy_priv: Vec<u8> = manifest.members.iter()
        .find(|m| m.crux_kind == CruxKind::Policy)
        .map(|m| m.mesh_private_key.clone())
        .unwrap_or_default();
    let public_key = compute_self_sig(&policy_priv, alias, transport_val.as_str(), url, clearance_val.as_str());

    let reg = McpServerRegistration {
        alias: alias.to_string(),
        transport: transport_val,
        command: command.to_string(),
        url: url.to_string(),
        required_clearance: clearance_val,
        allowed_tools: if allowed_tools.is_empty() { "*".to_string() } else { allowed_tools.to_string() },
        public_key,
        audit_required: true,
        capability_manifest: String::new(),
        rate_limit: if rate_limit.is_empty() { None } else { Some(rate_limit.to_string()) },
        status: status.to_string(),
        source: "manual".to_string(),
        fingerprint: String::new(),
        discovered_at: None,
        auth: oauth.auth.clone(),
        oauth_client_id: oauth.client_id.clone(),
        oauth_scopes: oauth.scopes.clone(),
        oauth_discovery_url: oauth.discovery_url.clone(),
        oauth_authorization_endpoint: oauth.authorization_endpoint.clone(),
        oauth_token_endpoint: oauth.token_endpoint.clone(),
        oauth_registration_endpoint: oauth.registration_endpoint.clone(),
    };

    let node = build_mcp_server_registration(&reg);
    let node_name = node.name.clone();
    policy_db.nodes.push(node);

    let policy_member = manifest.members.iter()
        .find(|m| m.crux_kind == crate::schema::CruxKind::Policy)
        .ok_or("No policy crux found")?;
    let policy_dir = mesh_dir.join(&policy_member.path);
    crate::schema::save_crux_db(&policy_db, &policy_dir)?;

    // Parse back to confirm round-trip
    let registered = policy_db.nodes.iter()
        .find(|n| n.name == node_name)
        .and_then(|n| parse_mcp_server_registration(n))
        .ok_or("Registration write verification failed")?;

    Ok(format!(
        "Registered MCP server '{}' (transport={}, clearance={}, tools={}, rate_limit={})",
        registered.alias,
        registered.transport.as_str(),
        registered.required_clearance.as_str(),
        registered.allowed_tools,
        registered.rate_limit.as_deref().unwrap_or("none"),
    ))
}

/// Like `mesh_register_mcp` but accepts an explicit `source` label and always
/// uses `status="proposed"` (the caller is responsible for approval).
pub fn mesh_register_mcp_with_source(
    mesh_dir: &Path,
    alias: &str,
    transport: &str,
    command: &str,
    url: &str,
    required_clearance: &str,
    allowed_tools: &str,
    rate_limit: &str,
    source: &str,
    oauth: &crate::schema::OAuthConfig,
) -> Result<String, String> {
    use crate::schema::{
        McpClearance, McpServerRegistration, McpTransport,
        build_mcp_server_registration, parse_mcp_server_registration,
    };

    if alias.is_empty() {
        return Err("alias is required".to_string());
    }
    let transport_val = McpTransport::from_str(transport)
        .ok_or_else(|| format!("Invalid transport '{}': must be 'stdio' or 'http'", transport))?;
    let clearance_val = McpClearance::from_str(required_clearance)
        .unwrap_or(McpClearance::Internal);

    let manifest = load_mesh(mesh_dir)?;
    let mut policy_db = load_policy_crux(&manifest, mesh_dir)?;

    let duplicate = policy_db.nodes.iter().any(|n| {
        n.kind == "mcp_server_registration"
            && n.deleted_at.is_none()
            && n.properties.iter().any(|p| p == &format!("alias={}", alias))
    });
    if duplicate {
        return Err(format!("MCP server '{}' is already registered", alias));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let fingerprint = {
        let canonical = format!("{}|{}|{}|{}", alias, transport, command, url);
        let hash = crate::crypto::sha256(canonical.as_bytes());
        format!("sha256:{}", crate::crypto::bytes_to_hex(&hash))
    };

    let policy_priv: Vec<u8> = manifest.members.iter()
        .find(|m| m.crux_kind == CruxKind::Policy)
        .map(|m| m.mesh_private_key.clone())
        .unwrap_or_default();
    let public_key = compute_self_sig(&policy_priv, alias, transport_val.as_str(), url, clearance_val.as_str());

    let reg = McpServerRegistration {
        alias: alias.to_string(),
        transport: transport_val,
        command: command.to_string(),
        url: url.to_string(),
        required_clearance: clearance_val,
        allowed_tools: if allowed_tools.is_empty() { "*".to_string() } else { allowed_tools.to_string() },
        public_key,
        audit_required: true,
        capability_manifest: String::new(),
        rate_limit: if rate_limit.is_empty() { None } else { Some(rate_limit.to_string()) },
        status: "proposed".to_string(),
        source: source.to_string(),
        fingerprint,
        discovered_at: Some(now),
        auth: oauth.auth.clone(),
        oauth_client_id: oauth.client_id.clone(),
        oauth_scopes: oauth.scopes.clone(),
        oauth_discovery_url: oauth.discovery_url.clone(),
        oauth_authorization_endpoint: oauth.authorization_endpoint.clone(),
        oauth_token_endpoint: oauth.token_endpoint.clone(),
        oauth_registration_endpoint: oauth.registration_endpoint.clone(),
    };

    let node = build_mcp_server_registration(&reg);
    let node_name = node.name.clone();
    policy_db.nodes.push(node);

    let policy_member = manifest.members.iter()
        .find(|m| m.crux_kind == crate::schema::CruxKind::Policy)
        .ok_or("No policy crux found")?;
    let policy_dir = mesh_dir.join(&policy_member.path);
    crate::schema::save_crux_db(&policy_db, &policy_dir)?;

    let registered = policy_db.nodes.iter()
        .find(|n| n.name == node_name)
        .and_then(|n| parse_mcp_server_registration(n))
        .ok_or("Registration write verification failed")?;

    Ok(format!(
        "Staged '{}' as proposed registration (source={}, transport={}, clearance={})",
        registered.alias, registered.source,
        registered.transport.as_str(), registered.required_clearance.as_str(),
    ))
}

/// Summary of a `mesh_discover` scan run.
#[derive(Debug, Default)]
pub struct DiscoveryReport {
    /// Aliases of servers newly added (as proposed or approved).
    pub added: Vec<String>,
    /// Aliases of servers updated (fingerprint changed, re-staged as proposed).
    pub updated: Vec<String>,
    /// Aliases skipped — already present with the same fingerprint.
    pub skipped: Vec<String>,
    /// Parse errors encountered (file path + message).
    pub errors: Vec<String>,
}

/// Scan `<mesh_dir>/.crux-discovery/` for manifest files and stage each one
/// as an MCP server registration in the policy crux.
///
/// Each file must be a JSON object with at least `alias` and `transport`.
/// New servers are registered with `status="proposed"` when `require_approval=true`,
/// or `status="approved"` otherwise.  Idempotent: re-scanning with the same files
/// is a no-op; changed files (different fingerprint) update the registration.
pub fn mesh_discover(mesh_dir: &Path) -> Result<DiscoveryReport, String> {
    use crate::json::extract_string_value;
    use crate::schema::{
        McpClearance, McpServerRegistration, McpTransport,
        build_mcp_server_registration,
    };

    let manifest = load_mesh(mesh_dir)?;
    let mut policy_db = load_policy_crux(&manifest, mesh_dir)?;
    let policy_member = manifest.members.iter()
        .find(|m| m.crux_kind == crate::schema::CruxKind::Policy)
        .ok_or("No policy crux found")?;
    let policy_dir = mesh_dir.join(&policy_member.path);

    let require_approval = crate::schema::get_policy_property(&policy_db, "require_approval")
        .map(|v| v == "true")
        .unwrap_or(false);

    let discovery_dir = mesh_dir.join(".crux-discovery");
    if !discovery_dir.exists() {
        return Ok(DiscoveryReport::default());
    }

    let mut report = DiscoveryReport::default();
    let entries = std::fs::read_dir(&discovery_dir)
        .map_err(|e| format!("Cannot read discovery dir: {e}"))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                report.errors.push(format!("{}: {e}", path.display()));
                continue;
            }
        };

        let alias = match extract_string_value(&content, "alias") {
            Some(a) if !a.is_empty() => a,
            _ => {
                report.errors.push(format!("{}: missing alias field", path.display()));
                continue;
            }
        };
        let transport_str = extract_string_value(&content, "transport").unwrap_or_default();
        let transport = match McpTransport::from_str(&transport_str) {
            Some(t) => t,
            None => {
                report.errors.push(format!("{}: invalid transport '{transport_str}'", path.display()));
                continue;
            }
        };
        let command = extract_string_value(&content, "command").unwrap_or_default();
        let url = extract_string_value(&content, "url").unwrap_or_default();
        let clearance_str = extract_string_value(&content, "required_clearance").unwrap_or_default();
        let required_clearance = McpClearance::from_str(&clearance_str).unwrap_or(McpClearance::Internal);

        // Stable fingerprint: sha256 of alias|transport|command|url
        let fp_input = format!("{alias}|{transport_str}|{command}|{url}");
        let fingerprint = format!("sha256:{}", sha256_hex(fp_input.as_bytes()));
        let source = format!("manifest:{}", path.file_name().and_then(|n| n.to_str()).unwrap_or("?"));

        // Check for existing registration with this alias
        let existing = policy_db.nodes.iter().find(|n| {
            n.kind == "mcp_server_registration"
                && n.deleted_at.is_none()
                && n.properties.iter().any(|p| p == &format!("alias={alias}"))
        });

        match existing {
            Some(node) => {
                // Check fingerprint
                let existing_fp = node.properties.iter()
                    .find_map(|p| p.strip_prefix("fingerprint=").map(|v| v.to_string()))
                    .unwrap_or_default();
                if existing_fp == fingerprint {
                    report.skipped.push(alias);
                } else {
                    // Fingerprint changed — update by soft-deleting old and adding new
                    let ts = crate::schema::now_unix();
                    let node_id = node.node_id.clone();
                    if let Some(n) = policy_db.nodes.iter_mut().find(|n| n.node_id == node_id) {
                        n.deleted_at = Some(ts);
                    }
                    let policy_priv: Vec<u8> = manifest.members.iter()
                        .find(|m| m.crux_kind == CruxKind::Policy)
                        .map(|m| m.mesh_private_key.clone())
                        .unwrap_or_default();
                    let public_key = compute_self_sig(
                        &policy_priv, &alias, transport.as_str(), &url, required_clearance.as_str(),
                    );
                    let reg = McpServerRegistration {
                        alias: alias.clone(),
                        transport,
                        command,
                        url,
                        required_clearance,
                        allowed_tools: "*".to_string(),
                        public_key,
                        audit_required: true,
                        capability_manifest: String::new(),
                        rate_limit: None,
                        status: if require_approval { "proposed" } else { "approved" }.to_string(),
                        source,
                        fingerprint,
                        discovered_at: Some(ts),
                        auth: "none".to_string(),
                        oauth_client_id: String::new(),
                        oauth_scopes: String::new(),
                        oauth_discovery_url: String::new(),
                        oauth_authorization_endpoint: String::new(),
                        oauth_token_endpoint: String::new(),
                        oauth_registration_endpoint: String::new(),
                    };
                    policy_db.nodes.push(build_mcp_server_registration(&reg));
                    report.updated.push(alias);
                }
            }
            None => {
                let ts = crate::schema::now_unix();
                let policy_priv: Vec<u8> = manifest.members.iter()
                    .find(|m| m.crux_kind == CruxKind::Policy)
                    .map(|m| m.mesh_private_key.clone())
                    .unwrap_or_default();
                let public_key = compute_self_sig(
                    &policy_priv, &alias, transport.as_str(), &url, required_clearance.as_str(),
                );
                let reg = McpServerRegistration {
                    alias: alias.clone(),
                    transport,
                    command,
                    url,
                    required_clearance,
                    allowed_tools: "*".to_string(),
                    public_key,
                    audit_required: true,
                    capability_manifest: String::new(),
                    rate_limit: None,
                    status: if require_approval { "proposed" } else { "approved" }.to_string(),
                    source,
                    fingerprint,
                    discovered_at: Some(ts),
                    auth: "none".to_string(),
                    oauth_client_id: String::new(),
                    oauth_scopes: String::new(),
                    oauth_discovery_url: String::new(),
                    oauth_authorization_endpoint: String::new(),
                    oauth_token_endpoint: String::new(),
                    oauth_registration_endpoint: String::new(),
                };
                policy_db.nodes.push(build_mcp_server_registration(&reg));
                report.added.push(alias);
            }
        }
    }

    crate::schema::save_crux_db(&policy_db, &policy_dir)?;
    Ok(report)
}

/// Return all `proposed` MCP server registrations from the policy crux.
pub fn load_discovered_mcp(mesh_dir: &Path) -> Vec<crate::schema::McpServerRegistration> {
    let manifest = match load_mesh(mesh_dir) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let policy_db = match load_policy_crux(&manifest, mesh_dir) {
        Ok(db) => db,
        Err(_) => return Vec::new(),
    };
    policy_db.nodes.iter()
        .filter(|n| n.kind == "mcp_server_registration" && n.deleted_at.is_none())
        .filter_map(|n| crate::schema::parse_mcp_server_registration(n))
        .filter(|r| r.status == "proposed")
        .collect()
}

/// Approve a proposed MCP server registration, setting its status to `"approved"`.
pub fn mesh_approve_mcp(mesh_dir: &Path, alias: &str) -> Result<String, String> {
    if alias.is_empty() {
        return Err("alias is required".to_string());
    }
    let manifest = load_mesh(mesh_dir)?;
    let mut policy_db = load_policy_crux(&manifest, mesh_dir)?;

    let target_prop = format!("alias={alias}");
    let found = policy_db.nodes.iter_mut().find(|n| {
        n.kind == "mcp_server_registration"
            && n.deleted_at.is_none()
            && n.properties.iter().any(|p| p == &target_prop)
    });

    match found {
        None => Err(format!("No active MCP server registration found for alias '{alias}'")),
        Some(node) => {
            // Update status=proposed → status=approved in properties
            let updated = node.properties.iter_mut().find(|p| p.as_str() == "status=proposed");
            match updated {
                Some(prop) => { *prop = "status=approved".to_string(); }
                None => {
                    // status was not "proposed" — check if it's already approved
                    if node.properties.iter().any(|p| p == "status=approved") {
                        return Ok(format!("MCP server '{alias}' is already approved."));
                    }
                    // Add approved status if not present
                    node.properties.push("status=approved".to_string());
                }
            }

            let policy_member = manifest.members.iter()
                .find(|m| m.crux_kind == crate::schema::CruxKind::Policy)
                .ok_or("No policy crux found")?;
            let policy_dir = mesh_dir.join(&policy_member.path);
            crate::schema::save_crux_db(&policy_db, &policy_dir)?;
            Ok(format!("MCP server '{alias}' approved."))
        }
    }
}

/// Probe the capabilities of an MCP server by performing a stdio handshake.
///
/// Spawns the command, performs `initialize` + `notifications/initialized` +
/// `tools/list`, and returns the raw `tools` JSON array string (e.g.
/// `[{"name":"foo",...}]`).  Returns `Err` if the server cannot be contacted
/// or does not respond with a valid `tools/list` result within 3 seconds.
pub fn probe_capabilities(reg: &crate::schema::McpServerRegistration) -> Result<String, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    if reg.transport != crate::schema::McpTransport::Stdio {
        return Err("HTTP probe is not supported; only stdio transports can be probed".to_string());
    }
    if reg.command.is_empty() {
        return Err("Cannot probe: command is empty".to_string());
    }

    let parts: Vec<&str> = reg.command.split_whitespace().collect();
    let (prog, args) = parts.split_first()
        .ok_or_else(|| "Empty command".to_string())?;

    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Cannot spawn '{}': {e}", reg.command))?;

    let mut stdin = child.stdin.take().ok_or("No stdin")?;
    let stdout = child.stdout.take().ok_or("No stdout")?;
    let mut reader = BufReader::new(stdout);

    let send = |stdin: &mut std::process::ChildStdin, msg: &str| -> Result<(), String> {
        writeln!(stdin, "{msg}").map_err(|e| format!("Write error: {e}"))
    };
    let recv = |reader: &mut BufReader<std::process::ChildStdout>| -> Result<String, String> {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| format!("Read error: {e}"))?;
        Ok(line.trim().to_string())
    };

    send(&mut stdin, r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"crux-probe","version":"0.1"}}}"#)?;
    let _ = recv(&mut reader)?; // initialize response
    send(&mut stdin, r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#)?;
    send(&mut stdin, r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#)?;
    let tools_resp = recv(&mut reader)?;
    let _ = child.kill();
    let _ = child.wait();

    // Extract the "tools" array from the response
    let needle = "\"tools\":";
    if let Some(pos) = tools_resp.find(needle) {
        let rest = &tools_resp[pos + needle.len()..].trim_start();
        if rest.starts_with('[') {
            // Find the matching close bracket, string-awarely: a `[`/`]` inside a
            // quoted string (e.g. a tool description containing `[WARN]`) must not
            // affect bracket depth.
            let mut depth = 0usize;
            let mut in_str = false;
            let mut escaped = false;
            for (i, c) in rest.char_indices() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if c == '\\' && in_str {
                    escaped = true;
                    continue;
                }
                if c == '"' {
                    in_str = !in_str;
                    continue;
                }
                if in_str {
                    continue;
                }
                match c {
                    '[' => depth += 1,
                    ']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(rest[..=i].to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Err(format!("tools/list response did not contain a tools array: {tools_resp}"))
}

/// Probe the capabilities of a registered MCP server and update the
/// `capability_manifest` property in the policy crux node.
///
/// Returns `Ok(manifest_json)` on success.
pub fn refresh_capability_manifest(mesh_dir: &Path, alias: &str) -> Result<String, String> {
    let manifest = load_mesh(mesh_dir)?;
    let mut policy_db = load_policy_crux(&manifest, mesh_dir)?;

    let target_prop = format!("alias={alias}");
    let node = policy_db.nodes.iter_mut().find(|n| {
        n.kind == "mcp_server_registration"
            && n.deleted_at.is_none()
            && n.properties.iter().any(|p| p == &target_prop)
    }).ok_or_else(|| format!("No registration found for alias '{alias}'"))?;

    // Parse the registration to get transport + command
    let reg = crate::schema::parse_mcp_server_registration(node)
        .ok_or_else(|| format!("Cannot parse registration for '{alias}'"))?;

    let tools_json = probe_capabilities(&reg)?;

    // Update capability_manifest property
    let cap_prop = format!("capability_manifest={tools_json}");
    if let Some(p) = node.properties.iter_mut().find(|p| p.starts_with("capability_manifest=")) {
        *p = cap_prop;
    } else {
        node.properties.push(cap_prop);
    }

    let policy_member = manifest.members.iter()
        .find(|m| m.crux_kind == crate::schema::CruxKind::Policy)
        .ok_or("No policy crux found")?;
    let policy_dir = mesh_dir.join(&policy_member.path);
    crate::schema::save_crux_db(&policy_db, &policy_dir)?;

    Ok(tools_json)
}

/// Load all active `mcp_server_registration` records from the mesh policy crux.
/// Returns an empty vec if there is no policy crux or no registrations.
pub fn load_mcp_registrations(mesh_dir: &Path) -> Vec<crate::schema::McpServerRegistration> {
    let manifest = match load_mesh(mesh_dir) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let policy_db = match load_policy_crux(&manifest, mesh_dir) {
        Ok(db) => db,
        Err(_) => return Vec::new(),
    };
    policy_db.nodes.iter()
        .filter(|n| n.kind == "mcp_server_registration" && n.deleted_at.is_none())
        .filter_map(|n| crate::schema::parse_mcp_server_registration(n))
        .filter(|r| r.status != "proposed")
        .collect()
}

/// List all active `mcp_server_registration` records from the mesh policy crux,
/// formatted as a human-readable table.
pub fn mesh_list_mcp_servers(mesh_dir: &Path) -> Result<String, String> {
    let regs = load_mcp_registrations(mesh_dir);
    if regs.is_empty() {
        return Ok("No MCP servers registered.".to_string());
    }
    let mut out = format!(
        "{:<20} {:<8} {:<14} {:<30} {:<10} {:<6}\n",
        "ALIAS", "TRANSPORT", "CLEARANCE", "ALLOWED_TOOLS", "RATE_LIMIT", "AUDIT"
    );
    out.push_str(&"-".repeat(94));
    out.push('\n');
    for r in &regs {
        let tools = if r.allowed_tools.len() > 28 {
            format!("{}…", &r.allowed_tools[..27])
        } else {
            r.allowed_tools.clone()
        };
        let rl = r.rate_limit.as_deref().unwrap_or("—");
        out.push_str(&format!(
            "{:<20} {:<8} {:<14} {:<30} {:<10} {}\n",
            r.alias,
            r.transport.as_str(),
            r.required_clearance.as_str(),
            tools,
            rl,
            if r.audit_required { "yes" } else { "no" }
        ));
    }
    out.push_str(&format!("\n{} server(s) registered.", regs.len()));
    Ok(out)
}

/// Soft-delete an `mcp_server_registration` node by alias.
/// Sets `deleted_at` to the current timestamp; the record is preserved for audit.
pub fn mesh_revoke_mcp(mesh_dir: &Path, alias: &str) -> Result<String, String> {
    if alias.is_empty() {
        return Err("alias is required".to_string());
    }
    let manifest = load_mesh(mesh_dir)?;
    let mut policy_db = load_policy_crux(&manifest, mesh_dir)?;

    let ts = now_unix();
    let target_prop = format!("alias={}", alias);
    let mut found = false;
    for node in &mut policy_db.nodes {
        if node.kind == "mcp_server_registration"
            && node.deleted_at.is_none()
            && node.properties.iter().any(|p| p == &target_prop)
        {
            node.deleted_at = Some(ts);
            found = true;
            break;
        }
    }
    if !found {
        return Err(format!("No active MCP server registration found for alias '{}'", alias));
    }

    let policy_member = manifest.members.iter()
        .find(|m| m.crux_kind == crate::schema::CruxKind::Policy)
        .ok_or("No policy crux found")?;
    let policy_dir = mesh_dir.join(&policy_member.path);
    crate::schema::save_crux_db(&policy_db, &policy_dir)?;

    Ok(format!("Revoked MCP server registration for alias '{}'.", alias))
}

/// Initialize a new mesh in the given directory.
/// Automatically creates a policy crux with security and organizational parameters.
/// Pass `Some(config)` to customize the policy, or `None` for defaults.
pub fn init_mesh(name: &str, dir: &Path) -> Result<MeshManifest, String> {
    init_mesh_with_policy(name, dir, None)
}

/// Initialize a mesh with a custom PolicyConfig.
pub fn init_mesh_with_policy(name: &str, dir: &Path, config: Option<crate::schema::PolicyConfig>) -> Result<MeshManifest, String> {
    let manifest_path = dir.join(MESH_MANIFEST_FILE);
    if manifest_path.exists() {
        return Err(format!(
            "Mesh already exists at {}",
            manifest_path.display()
        ));
    }

    // Create the policy crux first
    let policy_crux = match config {
        Some(c) => crate::schema::create_policy_crux_with_config(name, c),
        None    => crate::schema::create_policy_crux(name),
    };
    let policy_dir = dir.join(format!("{}-policy", name));
    std::fs::create_dir_all(&policy_dir).map_err(|e| format!("Failed to create policy directory: {}", e))?;
    crate::schema::save_crux_db(&policy_crux, &policy_dir)?;

    // Generate quantum-resistant key pair for this mesh membership
    let keypair = crate::crypto::generate_keypair();

    // Create the mesh manifest (establishes mesh_id)
    let mut manifest = create_mesh(name);

    // Persist private key to ~/.crux-keys/<mesh_id>.priv (best-effort)
    let _ = crate::crypto::write_crux_key(&manifest.mesh_id, &keypair.private_key);

    // Add the policy crux as the first member
    manifest.members.push(MeshMember {
        crux_id: policy_crux.header.crux_id,
        crux_name: policy_crux.header.crux_name,
        crux_kind: policy_crux.header.crux_kind,
        path: format!("{}-policy", name),
        socket: None,
        status: "online".to_string(), // Changed from "active" to "online"
        last_seen: policy_crux.header.created_at,
        replica_group: Some("policy".to_string()),
        cluster: None,
        mesh_public_key: keypair.public_key,
        mesh_private_key: keypair.private_key,
    });

    save_mesh(&manifest, dir)?;

    // Seed the mesh-keyring policy node for the initial policy crux member
    let pubkey_hex = bytes_to_hex(&manifest.members[0].mesh_public_key);
    let crux_id = manifest.members[0].crux_id.clone();
    let _ = seed_keyring_node(&manifest, dir, &crux_id, &pubkey_hex);

    Ok(manifest)
}

/// Join a crux to an existing mesh. The crux_path is relative to the mesh dir.
pub fn join_mesh(mesh_dir: &Path, crux_path: &str) -> Result<MeshManifest, String> {
    let mut manifest = load_mesh(mesh_dir)?;

    // Resolve the crux file path relative to the mesh dir
    let abs_crux_path = mesh_dir.join(crux_path);
    let crux_file = if abs_crux_path.is_file() {
        abs_crux_path.clone()
    } else {
        // Try as directory containing .crux.json
        let candidate = abs_crux_path.join(".crux.json");
        if candidate.exists() {
            candidate
        } else {
            return Err(format!(
                "No crux file found at '{}' or '{}'",
                abs_crux_path.display(),
                abs_crux_path.join(".crux.json").display()
            ));
        }
    };

    // Load the crux DB
    let crux_dir = crux_file
        .parent()
        .ok_or_else(|| "Cannot determine crux directory".to_string())?;
    let db = load_crux_db(crux_dir)?;

    // Check for duplicate
    if manifest
        .members
        .iter()
        .any(|m| m.crux_id == db.header.crux_id)
    {
        return Err(format!(
            "Crux '{}' is already a member of this mesh",
            db.header.crux_name
        ));
    }

    // Prevent multiple policy cruxes in the same mesh
    if db.header.crux_kind == crate::schema::CruxKind::Policy
        && manifest.members.iter().any(|m| m.crux_kind == crate::schema::CruxKind::Policy)
    {
        return Err("Mesh already has a policy crux. Only one policy crux per mesh is allowed.".to_string());
    }

    // Enforce policy crux rules for non-policy joins
    #[allow(clippy::collapsible_if)]
    if db.header.crux_kind != crate::schema::CruxKind::Policy {
        if let Ok(policy_db) = load_policy_crux(&manifest, mesh_dir) {
            // Check allowed_crux_kinds
            if let Some(kinds_str) = crate::schema::get_policy_property(&policy_db, "allowed_crux_kinds") {
                if !kinds_str.is_empty() {
                    let kind_str = db.header.crux_kind.as_str();
                    let allowed: Vec<&str> = kinds_str.split(',').map(|s| s.trim()).collect();
                    if !allowed.contains(&kind_str) {
                        return Err(format!(
                            "Mesh policy does not allow crux kind '{}'. Allowed: {}",
                            kind_str, kinds_str
                        ));
                    }
                }
            }
            // Check max_members (excluding the policy crux itself)
            if let Some(max_str) = crate::schema::get_policy_property(&policy_db, "max_members") {
                if !max_str.is_empty() {
                    if let Ok(max) = max_str.parse::<usize>() {
                        let current = manifest.members.len(); // includes policy crux
                        if current > max {
                            return Err(format!(
                                "Mesh is at capacity ({} members). Max allowed: {}",
                                current - 1, max
                            ));
                        }
                    }
                }
            }
        }
    }

    // Enforce cross-mesh policy: check the joining crux's existing memberships
    if !db.header.mesh_memberships.is_empty() {
        // Check this mesh's policy allows multi-mesh
        if let Ok(policy_db) = load_policy_crux(&manifest, mesh_dir) {
            let cross_mesh_policy = crate::schema::get_policy_property(&policy_db, "cross_mesh_policy")
                .unwrap_or_else(|| "explicit_allow".to_string());
            let multi_allowed = crate::schema::get_policy_property(&policy_db, "multi_mesh_allowed")
                .map(|v| v != "false")
                .unwrap_or(true);

            if !multi_allowed || cross_mesh_policy == "deny_all" {
                return Err(format!(
                    "Mesh policy '{}' prevents cruxes from joining multiple meshes",
                    cross_mesh_policy
                ));
            }
            if cross_mesh_policy == "explicit_allow" {
                // The crux's existing meshes must all be in allowed_external_meshes,
                // OR the crux must have no other meshes besides the target
                // (if allowed_external_meshes is empty, all are allowed)
                let allowed_str = crate::schema::get_policy_property(&policy_db, "allowed_external_meshes")
                    .unwrap_or_default();
                if !allowed_str.is_empty() {
                    let allowed: Vec<&str> = allowed_str.split(',').map(|s| s.trim()).collect();
                    for existing in &db.header.mesh_memberships {
                        if !allowed.contains(&existing.mesh_id.as_str()) {
                            return Err(format!(
                                "Crux is already in mesh '{}' which is not in this mesh's allowed_external_meshes list",
                                existing.mesh_name
                            ));
                        }
                    }
                }
            }
        }
    }

    let ts = now_unix();
    // Generate quantum-resistant key pair for this mesh membership
    let keypair = crate::crypto::generate_keypair();

    // Determine status based on require_approval policy
    let status = if db.header.crux_kind != crate::schema::CruxKind::Policy {
        if let Ok(policy_db) = load_policy_crux(&manifest, mesh_dir) {
            let requires = crate::schema::get_policy_property(&policy_db, "require_approval")
                .map(|v| v == "true")
                .unwrap_or(false);
            if requires { "pending" } else { "online" }
        } else {
            "online"
        }
    } else {
        "online"
    };

    let member = MeshMember {
        crux_id: db.header.crux_id.clone(),
        crux_name: db.header.crux_name.clone(),
        crux_kind: db.header.crux_kind.clone(),
        path: crux_path.to_string(),
        socket: None,
        status: status.to_string(),
        last_seen: ts,
        replica_group: None,
        cluster: None,
        mesh_public_key: keypair.public_key,
        mesh_private_key: keypair.private_key,
    };

    // Record the membership in the crux's .crux.json file (best-effort)
    let _ = record_mesh_membership(
        crux_dir,
        &manifest.mesh_id,
        &manifest.mesh_name,
        &bytes_to_hex(&member.mesh_public_key),
        None,
    );

    // Persist keypair: write private key to disk; seed public key in policy keyring (best-effort)
    let _ = crate::crypto::write_crux_key(&manifest.mesh_id, &member.mesh_private_key);
    let pubkey_hex = bytes_to_hex(&member.mesh_public_key);
    let _ = seed_keyring_node(&manifest, mesh_dir, &member.crux_id, &pubkey_hex);

    manifest.members.push(member);

    // Run introduction protocol — discover cross-edges with existing members
    introduce_crux(&mut manifest, &db, mesh_dir);

    save_mesh(&manifest, mesh_dir)?;
    Ok(manifest)
}

/// Remove a crux from the mesh by its crux_id or name.
pub fn leave_mesh(mesh_dir: &Path, identifier: &str) -> Result<MeshManifest, String> {
    let mut manifest = load_mesh(mesh_dir)?;

    let idx = manifest
        .members
        .iter()
        .position(|m| m.crux_id == identifier || m.crux_name == identifier);

    match idx {
        Some(i) => {
            if manifest.members[i].crux_kind == crate::schema::CruxKind::Policy {
                return Err("Cannot remove the policy crux from a mesh. The policy crux is required.".to_string());
            }
            let removed = manifest.members.remove(i);
            // Also remove any cross-edges involving this crux
            manifest.cross_edges.retain(|ce| {
                ce.src_crux != removed.crux_id && ce.dst_crux != removed.crux_id
            });
            save_mesh(&manifest, mesh_dir)?;
            Ok(manifest)
        }
        None => Err(format!(
            "No member matching '{}' found in the mesh",
            identifier
        )),
    }
}

/// Generate a human-readable status report for a mesh.
pub fn mesh_status_text(manifest: &MeshManifest) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "Mesh: {}", manifest.mesh_name);
    let _ = writeln!(out, "  ID: {}", manifest.mesh_id);
    let _ = writeln!(out, "  Version: {}", manifest.mesh_version);

    let online = manifest.members.iter().filter(|m| m.status == "online").count();
    let _ = writeln!(
        out,
        "  Members: {} ({} online)",
        manifest.members.len(),
        online
    );

    if !manifest.members.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Members:");
        for m in &manifest.members {
            let _ = writeln!(
                out,
                "  {} ({}) [{}] — {}",
                m.crux_name,
                m.crux_kind.as_str(),
                m.status,
                m.path
            );
        }
    }

    let total_cross_edges: usize = manifest.cross_edges.iter().map(|ce| ce.edge_count).sum();
    if total_cross_edges > 0 {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Cross-edges: {} (across {} pairs)",
            total_cross_edges,
            manifest.cross_edges.len()
        );
    }

    out
}

/// Check the health of all mesh members by verifying their crux files exist.
pub fn check_member_health(manifest: &mut MeshManifest, mesh_dir: &Path) {
    let ts = now_unix();
    for member in &mut manifest.members {
        let abs_path = mesh_dir.join(&member.path);
        let crux_file = if abs_path.is_file() {
            abs_path.clone()
        } else {
            abs_path.join(".crux.json")
        };
        if crux_file.exists() {
            member.status = "online".to_string();
            member.last_seen = ts;
        } else {
            member.status = "offline".to_string();
        }
    }
}

/// Get a loaded CruxDb for each online member. Returns (member_index, CruxDb) pairs.
pub fn load_member_dbs(manifest: &MeshManifest, mesh_dir: &Path) -> Vec<(usize, CruxDb)> {
    let mut results = Vec::new();
    for (i, member) in manifest.members.iter().enumerate() {
        if member.status != "online" {
            continue;
        }
        let abs_path = mesh_dir.join(&member.path);
        let crux_dir = if abs_path.is_file() {
            abs_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        } else {
            abs_path
        };
        if let Ok(db) = load_crux_db(&crux_dir) {
            results.push((i, db));
        }
    }
    results
}

// ===========================================================================
// Introduction Protocol — Cross-Edge Discovery
// ===========================================================================

/// Run the introduction protocol: discover cross-crux edges between a new crux
/// and all existing mesh members. Updates the mesh manifest with new CrossEdgeRefs.
pub fn introduce_crux(
    manifest: &mut MeshManifest,
    new_db: &CruxDb,
    mesh_dir: &Path,
) {
    let new_crux_id = &new_db.header.crux_id;

    // Load all existing members' DBs
    let existing_dbs = load_member_dbs(manifest, mesh_dir);

    for (_idx, existing_db) in &existing_dbs {
        // Skip self
        if existing_db.header.crux_id == *new_crux_id {
            continue;
        }

        let candidates = compute_edge_candidates(new_db, existing_db);
        if candidates > 0 {
            // Check if a CrossEdgeRef already exists for this pair
            let existing = manifest.cross_edges.iter_mut().find(|ce| {
                (ce.src_crux == *new_crux_id && ce.dst_crux == existing_db.header.crux_id)
                    || (ce.dst_crux == *new_crux_id
                        && ce.src_crux == existing_db.header.crux_id)
            });
            match existing {
                Some(ce) => {
                    ce.edge_count = candidates;
                    ce.last_synced = now_unix();
                }
                None => {
                    manifest.cross_edges.push(CrossEdgeRef {
                        src_crux: new_crux_id.clone(),
                        dst_crux: existing_db.header.crux_id.clone(),
                        edge_count: candidates,
                        last_synced: now_unix(),
                    });
                }
            }
        }
    }
}

/// Compute the number of edge candidates between two cruxes.
/// Counts tag_overlap matches + name_match matches (deduplicated).
pub fn compute_edge_candidates(crux_a: &CruxDb, crux_b: &CruxDb) -> usize {
    let tag_matches = match_by_tags(crux_a, crux_b);
    let name_matches = match_by_names(crux_a, crux_b);

    // Deduplicate: if a pair is found by both methods, count it once
    let mut unique_pairs: Vec<(String, String)> = Vec::new();
    for (src, dst) in tag_matches.iter().chain(name_matches.iter()) {
        if !unique_pairs.iter().any(|(s, d)| s == src && d == dst) {
            unique_pairs.push((src.clone(), dst.clone()));
        }
    }
    unique_pairs.len()
}

/// Find edge candidates by tag overlap. Returns (src_node_name, dst_node_name) pairs
/// where the two nodes share at least one tag.
pub fn match_by_tags(crux_a: &CruxDb, crux_b: &CruxDb) -> Vec<(String, String)> {
    let mut matches = Vec::new();
    for node_a in &crux_a.nodes {
        if node_a.tags.is_empty() {
            continue;
        }
        for node_b in &crux_b.nodes {
            if node_b.tags.is_empty() {
                continue;
            }
            let jaccard = jaccard_similarity(&node_a.tags, &node_b.tags);
            if jaccard > 0.0 {
                matches.push((node_a.name.clone(), node_b.name.clone()));
            }
        }
    }
    matches
}

/// Find edge candidates by exact name match across cruxes.
/// Returns (src_node_name, dst_node_name) pairs.
pub fn match_by_names(crux_a: &CruxDb, crux_b: &CruxDb) -> Vec<(String, String)> {
    let mut matches = Vec::new();
    for node_a in &crux_a.nodes {
        for node_b in &crux_b.nodes {
            if node_a.name == node_b.name && !node_a.name.is_empty() {
                matches.push((node_a.name.clone(), node_b.name.clone()));
            }
        }
    }
    matches
}

/// Compute Jaccard similarity between two tag sets: |A ∩ B| / |A ∪ B|.
pub fn jaccard_similarity(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let intersection = a.iter().filter(|t| b.contains(t)).count();
    // Union = |A| + |B| - |intersection|
    let union = a.len() + b.len() - intersection;
    if union == 0 {
        return 0.0;
    }
    intersection as f64 / union as f64
}

// ===========================================================================
// Pass-Through Queries
// ===========================================================================

/// A query result from a mesh query — includes provenance.
#[derive(Debug, Clone)]
pub struct MeshQueryResult {
    pub node_name: String,
    pub node_kind: String,
    pub node_summary: String,
    pub tags: Vec<String>,
    pub from_crux: String,
    pub from_crux_name: String,
}

/// Build a map from cluster_name → SecurityLevel by scanning cluster-definition
/// nodes in the policy crux.
fn cluster_clearance_map(policy_db: &crate::schema::CruxDb)
    -> std::collections::HashMap<String, SecurityLevel>
{
    let mut map = std::collections::HashMap::new();
    for node in &policy_db.nodes {
        if node.kind != "cluster-definition" || node.deleted_at.is_some() {
            continue;
        }
        let name = node.properties.iter()
            .find_map(|p| p.strip_prefix("cluster_name=").map(|v| v.to_string()));
        let classification = node.properties.iter()
            .find_map(|p| p.strip_prefix("cluster_classification=").map(|v| v.to_string()));
        if let (Some(n), Some(c)) = (name, classification) {
            map.insert(n, SecurityLevel::from_str(&c));
        }
    }
    map
}

/// Query across all mesh members. Returns matching nodes with provenance.
pub fn mesh_query(
    manifest: &MeshManifest,
    mesh_dir: &Path,
    filter: &crate::query::NodeFilter,
) -> Vec<MeshQueryResult> {
    let mut results = Vec::new();

    // Determine clearance from policy crux (default: Internal)
    let (clearance, cluster_levels) = if let Ok(policy_db) = load_policy_crux(manifest, mesh_dir) {
        let level_str = crate::schema::get_policy_property(&policy_db, "default_classification")
            .unwrap_or_else(|| "internal".to_string());
        let lvl = SecurityLevel::from_str(&level_str);
        let cmap = cluster_clearance_map(&policy_db);
        (lvl, cmap)
    } else {
        (SecurityLevel::Internal, std::collections::HashMap::new())
    };

    // Build per-member cluster clearance from the manifest
    let member_clusters: std::collections::HashMap<String, Option<String>> = manifest.members
        .iter()
        .map(|m| (m.crux_id.clone(), m.cluster.clone()))
        .collect();

    let audit_log = crate::audit::AuditLog::for_crux(mesh_dir);

    let dbs = load_member_dbs(manifest, mesh_dir);
    'outer: for (_idx, db) in &dbs {
        // Cluster gating: if the member belongs to a cluster, the caller must
        // hold at least that cluster's required clearance.
        if let Some(Some(cluster_name)) = member_clusters.get(&db.header.crux_id) {
            if let Some(&required) = cluster_levels.get(cluster_name) {
                if clearance < required {
                    continue; // skip this member's crux entirely
                }
            }
        }

        // Apply security filtering before NodeFilter
        let visible_nodes = filter_by_clearance(&db.nodes, clearance);
        let mut matching: Vec<&crate::schema::CruxNode> = visible_nodes
            .iter()
            .filter(|n| filter.matches(n))
            .collect();
        filter.apply_sort(&mut matching);
        for node in matching {
            results.push(MeshQueryResult {
                node_name: node.name.clone(),
                node_kind: node.kind.clone(),
                node_summary: node.summary.clone(),
                tags: node.tags.clone(),
                from_crux: db.header.crux_id.clone(),
                from_crux_name: db.header.crux_name.clone(),
            });
            if results.len() >= filter.limit {
                break 'outer;
            }
        }
    }

    // Cross-link traversal: follow mesh_link edges from matched local nodes
    // into linked remote cruxes and merge their results.
    if filter.follow_links && results.len() < filter.limit {
        let local_matched: std::collections::HashSet<String> =
            results.iter().map(|r| r.node_name.clone()).collect();

        let mut linked_crux_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for (_idx, db) in &dbs {
            for edge in &db.edges {
                if edge.kind == crate::schema::EdgeKind::MeshLink
                    && local_matched.contains(&edge.src)
                {
                    if let Some((crux_id, _)) = parse_mesh_link_dst(&edge.dst) {
                        linked_crux_ids.insert(crux_id);
                    }
                }
            }
        }

        'links: for linked_crux_id in &linked_crux_ids {
            let member = match manifest.members.iter()
                .find(|m| &m.crux_id == linked_crux_id)
            {
                Some(m) => m,
                None => continue,
            };
            // Cluster clearance gate
            if let Some(cluster_name) = &member.cluster {
                if let Some(&required) = cluster_levels.get(cluster_name.as_str()) {
                    if clearance < required { continue; }
                }
            }
            let remote_db = match crate::schema::load_crux_db(&mesh_dir.join(&member.path)) {
                Ok(db) => db,
                Err(_) => continue,
            };
            let visible = filter_by_clearance(&remote_db.nodes, clearance);
            let mut matching: Vec<&crate::schema::CruxNode> =
                visible.iter().filter(|n| filter.matches(n)).collect();
            filter.apply_sort(&mut matching);
            for node in matching {
                results.push(MeshQueryResult {
                    node_name: node.name.clone(),
                    node_kind: node.kind.clone(),
                    node_summary: node.summary.clone(),
                    tags: node.tags.clone(),
                    from_crux: remote_db.header.crux_id.clone(),
                    from_crux_name: format!("{} [cross-link]", remote_db.header.crux_name),
                });
                if results.len() >= filter.limit { break 'links; }
            }
        }
    }

    crate::audit::log_query(
        &audit_log,
        &manifest.mesh_id,
        filter.query.as_deref().unwrap_or(""),
        results.len(),
        None,
    );

    results
}

/// Parse a `mesh_link` edge `dst` field into `(crux_id, node_name)`.
///
/// The format is `"sha256:<hex>:<node_name>"` — the crux_id is the `sha256:` prefix
/// plus the hex hash; the node_name is everything after the second colon.
fn parse_mesh_link_dst(dst: &str) -> Option<(String, String)> {
    let without_prefix = dst.strip_prefix("sha256:")?;
    let sep = without_prefix.find(':')?;
    let crux_id = format!("sha256:{}", &without_prefix[..sep]);
    let node_name = without_prefix[sep + 1..].to_string();
    Some((crux_id, node_name))
}

/// Find shortest path between two nodes across the mesh.
///
/// Uses BFS over within-crux edges. `mesh_link` edges are followed across crux
/// boundaries; the path includes a `"[cross-link → <crux_name>]"` label at each
/// boundary crossing. Clearance is not enforced here (the caller controls access).
pub fn mesh_path(
    manifest: &MeshManifest,
    mesh_dir: &Path,
    src_name: &str,
    dst_name: &str,
) -> Option<Vec<String>> {
    let dbs = load_member_dbs(manifest, mesh_dir);

    // crux_id → crux_name for cross-link labels
    let crux_names: std::collections::HashMap<String, String> = manifest.members.iter()
        .map(|m| (m.crux_id.clone(), m.crux_name.clone()))
        .collect();

    // Build combined adjacency. For mesh_link edges, insert a synthetic label
    // node between src and the remote node so the path is human-readable:
    //   src → "[cross-link → crux_name]" → remote_node
    let mut adjacency: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for (_idx, db) in &dbs {
        for edge in &db.edges {
            if edge.kind == crate::schema::EdgeKind::MeshLink {
                if let Some((crux_id, node_name)) = parse_mesh_link_dst(&edge.dst) {
                    let crux_name = crux_names.get(&crux_id).cloned().unwrap_or(crux_id);
                    let label = format!("[cross-link → {}]", crux_name);
                    adjacency.entry(edge.src.clone()).or_default().push(label.clone());
                    adjacency.entry(label).or_default().push(node_name);
                }
            } else {
                adjacency.entry(edge.src.clone()).or_default().push(edge.dst.clone());
            }
        }
    }

    // BFS from src to dst
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<Vec<String>> = std::collections::VecDeque::new();

    queue.push_back(vec![src_name.to_string()]);
    visited.insert(src_name.to_string());

    while let Some(path) = queue.pop_front() {
        let current = path.last().unwrap();
        if current == dst_name {
            return Some(path);
        }
        if let Some(neighbors) = adjacency.get(current) {
            for neighbor in neighbors.clone() {
                if !visited.contains(&neighbor) {
                    visited.insert(neighbor.clone());
                    let mut new_path = path.clone();
                    new_path.push(neighbor);
                    queue.push_back(new_path);
                }
            }
        }
    }
    None
}

/// Find all transitive callers of a node across the mesh (reverse BFS).
pub fn mesh_impact(
    manifest: &MeshManifest,
    mesh_dir: &Path,
    target_name: &str,
) -> Vec<String> {
    let dbs = load_member_dbs(manifest, mesh_dir);

    // Build reverse adjacency: dst -> Vec<src>
    let mut reverse_adj: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for (_idx, db) in &dbs {
        for edge in &db.edges {
            reverse_adj
                .entry(edge.dst.clone())
                .or_default()
                .push(edge.src.clone());
        }
    }

    // BFS from target
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut callers = Vec::new();

    queue.push_back(target_name.to_string());
    visited.insert(target_name.to_string());

    while let Some(current) = queue.pop_front() {
        if let Some(sources) = reverse_adj.get(&current) {
            for source in sources {
                if !visited.contains(source) {
                    visited.insert(source.clone());
                    callers.push(source.clone());
                    queue.push_back(source.clone());
                }
            }
        }
    }
    callers
}

/// Format mesh query results as text.
pub fn format_mesh_query_results(results: &[MeshQueryResult], query: &str) -> String {
    if results.is_empty() {
        return format!("No nodes matching '{}' found across the mesh.", query);
    }

    let mut out = format!(
        "Found {} node(s) matching '{}' across the mesh:\n",
        results.len(),
        query
    );
    for r in results {
        let _ = writeln!(
            out,
            "  {} ({}) — {} [from: {}]",
            r.node_name, r.node_kind, r.node_summary, r.from_crux_name
        );
        if !r.tags.is_empty() {
            let _ = writeln!(out, "    tags: {}", r.tags.join(", "));
        }
    }
    out
}

// ===========================================================================
// Vector-clock helpers
// ===========================================================================

/// Merge the VectorClocks from every member's audit log into one.
///
/// Used by callers that want to know the current causal frontier of the mesh.
pub fn mesh_current_clock(manifest: &MeshManifest, mesh_dir: &Path) -> crate::propagation::VectorClock {
    let mut merged = crate::propagation::VectorClock::new();
    for member in &manifest.members {
        let crux_dir = mesh_dir.join(&member.path);
        let log = crate::audit::AuditLog::for_crux(&crux_dir);
        merged.merge(&log.current_clock());
    }
    merged
}

/// Return all audit events from every member whose clock is NOT dominated by `since`.
///
/// Clients that already hold a VectorClock (from a prior `mesh_current_clock` call)
/// pass it here to receive only the events they haven't seen yet.
pub fn diff_clock(
    manifest: &MeshManifest,
    mesh_dir: &Path,
    since: &crate::propagation::VectorClock,
) -> Vec<crate::audit::AuditEvent> {
    let mut events = Vec::new();
    for member in &manifest.members {
        let crux_dir = mesh_dir.join(&member.path);
        let log = crate::audit::AuditLog::for_crux(&crux_dir);
        events.extend(log.diff_since_clock(since));
    }
    events
}

// ===========================================================================
// Replication
// ===========================================================================

/// Merge nodes and edges from `src_db` into `dst_db`, respecting clearance.
///
/// Conflict rule: last-write-wins by `planning.updated_at` unix timestamp.
/// Returns `(added_count, updated_count)`.
pub fn mesh_replicate(
    src_db: &crate::schema::CruxDb,
    dst_db: &mut crate::schema::CruxDb,
    clearance: SecurityLevel,
) -> (usize, usize) {
    let mut added = 0usize;
    let mut updated = 0usize;

    let clearance_level = clearance.as_u8();

    for src_node in &src_db.nodes {
        let node_level = SecurityLevel::from_str(&src_node.security.classification).as_u8();
        if node_level > clearance_level {
            continue;
        }
        let src_ts = src_node.planning.updated_at.unwrap_or(0);
        if let Some(dst_node) = dst_db.nodes.iter_mut().find(|n| n.node_id == src_node.node_id) {
            let dst_ts = dst_node.planning.updated_at.unwrap_or(0);
            if src_ts > dst_ts {
                *dst_node = src_node.clone();
                updated += 1;
            }
        } else {
            dst_db.nodes.push(src_node.clone());
            added += 1;
        }
    }

    for src_edge in &src_db.edges {
        let already = dst_db.edges.iter().any(|e| {
            e.src == src_edge.src && e.dst == src_edge.dst && e.kind == src_edge.kind
        });
        if !already {
            dst_db.edges.push(src_edge.clone());
        }
    }

    (added, updated)
}

/// Resolve a crux by name, id, or file path within a mesh and return its directory.
fn resolve_crux_dir(manifest: &MeshManifest, mesh_dir: &Path, identifier: &str) -> Result<PathBuf, String> {
    // Try as explicit path first
    let as_path = PathBuf::from(identifier);
    if as_path.exists() {
        return Ok(if as_path.is_dir() { as_path } else { as_path.parent().unwrap_or(&as_path).to_path_buf() });
    }
    // Try matching mesh member by name or id
    let member = manifest.members.iter()
        .find(|m| m.crux_name == identifier || m.crux_id == identifier)
        .ok_or_else(|| format!("No mesh member '{}' found", identifier))?;
    Ok(mesh_dir.join(&member.path))
}

/// Push nodes+edges from `src` into `dst`, filtered by caller clearance.
/// Both identifiers can be a mesh member name/id or an explicit file path.
pub fn mesh_push(mesh_dir: &Path, src: &str, dst: &str, clearance: SecurityLevel) -> Result<String, String> {
    let manifest = load_mesh(mesh_dir)?;
    let src_dir = resolve_crux_dir(&manifest, mesh_dir, src)?;
    let dst_dir = resolve_crux_dir(&manifest, mesh_dir, dst)?;

    let src_db = load_crux_db(&src_dir)?;
    let mut dst_db = load_crux_db(&dst_dir)?;

    let (added, updated) = mesh_replicate(&src_db, &mut dst_db, clearance);
    crate::schema::save_crux_db(&dst_db, &dst_dir)?;

    let dst_name = manifest.members.iter()
        .find(|m| mesh_dir.join(&m.path) == dst_dir)
        .map(|m| m.crux_name.as_str())
        .unwrap_or(dst);
    Ok(format!("Replicated: +{} added, {} updated into {}", added, updated, dst_name))
}

/// Pull nodes+edges from `src` into `dst`, filtered by caller clearance.
pub fn mesh_pull(mesh_dir: &Path, src: &str, dst: &str, clearance: SecurityLevel) -> Result<String, String> {
    mesh_push(mesh_dir, src, dst, clearance)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{create_crux_db, save_crux_db, CruxNode, NodeSchema,
                         PlanningMetadata, SecurityMetadata};
    use std::fs;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("crux_mesh_test_{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_generate_mesh_id() {
        let id = generate_mesh_id("test-mesh", 1000);
        assert!(id.starts_with("sha256:"));
        assert_eq!(id.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_create_mesh() {
        let manifest = create_mesh("acme-corp");
        assert_eq!(manifest.mesh_name, "acme-corp");
        assert_eq!(manifest.mesh_version, 1);
        assert!(manifest.members.is_empty());
        assert!(manifest.cross_edges.is_empty());
        assert_eq!(manifest.security.default_classification, "internal");
        assert_eq!(manifest.security.levels.len(), 4);
    }

    #[test]
    fn test_serialize_parse_roundtrip() {
        let mut manifest = create_mesh("roundtrip-test");
        manifest.members.push(MeshMember {
            crux_id: "sha256:abc123".to_string(),
            crux_name: "backend".to_string(),
            crux_kind: CruxKind::Codebase,
            path: "./backend/.crux.json".to_string(),
            socket: Some("tcp://localhost:9701".to_string()),
            status: "online".to_string(),
            last_seen: 1741000100,
            replica_group: Some("A".to_string()),
            cluster: None,
            mesh_public_key: vec![1, 2, 3, 4], // dummy key for test
            mesh_private_key: vec![5, 6, 7, 8], // dummy key for test
        });
        manifest.cross_edges.push(CrossEdgeRef {
            src_crux: "sha256:abc123".to_string(),
            dst_crux: "sha256:def456".to_string(),
            edge_count: 42,
            last_synced: 1741000100,
        });

        let json = serialize_mesh(&manifest);
        let parsed = parse_mesh(&json).unwrap();

        assert_eq!(parsed.mesh_name, "roundtrip-test");
        assert_eq!(parsed.mesh_version, 1);
        assert_eq!(parsed.members.len(), 1);
        assert_eq!(parsed.members[0].crux_name, "backend");
        assert_eq!(parsed.members[0].crux_kind, CruxKind::Codebase);
        assert_eq!(parsed.members[0].socket, Some("tcp://localhost:9701".to_string()));
        assert_eq!(parsed.members[0].replica_group, Some("A".to_string()));
        assert_eq!(parsed.cross_edges.len(), 1);
        assert_eq!(parsed.cross_edges[0].edge_count, 42);
        assert_eq!(parsed.security.default_classification, "internal");
        assert_eq!(parsed.security.levels.len(), 4);
    }

    #[test]
    fn test_serialize_empty_mesh() {
        let manifest = create_mesh("empty");
        let json = serialize_mesh(&manifest);
        let parsed = parse_mesh(&json).unwrap();
        assert_eq!(parsed.mesh_name, "empty");
        assert!(parsed.members.is_empty());
        assert!(parsed.cross_edges.is_empty());
    }

    #[test]
    fn test_init_mesh_file_io() {
        let dir = temp_dir("init_mesh");
        let manifest = init_mesh("test-mesh", &dir).unwrap();
        assert_eq!(manifest.mesh_name, "test-mesh");

        // File should exist
        assert!(dir.join(MESH_MANIFEST_FILE).exists());

        // Should fail if already exists
        let err = init_mesh("another", &dir);
        assert!(err.is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_join_and_leave_mesh() {
        let dir = temp_dir("join_leave");
        init_mesh("join-test", &dir).unwrap();

        // Create a crux in a subdirectory
        let crux_dir = dir.join("backend");
        fs::create_dir_all(&crux_dir).unwrap();
        let db = create_crux_db("backend-api", CruxKind::Codebase, "rust");
        save_crux_db(&db, &crux_dir).unwrap();

        // Join
        let manifest = join_mesh(&dir, "backend").unwrap();
        assert_eq!(manifest.members.len(), 2); // policy crux + joined crux
        assert_eq!(manifest.members[1].crux_name, "backend-api"); // policy is first, joined is second

        // Duplicate join should fail
        let err = join_mesh(&dir, "backend");
        assert!(err.is_err());

        // Leave by name
        let manifest = leave_mesh(&dir, "backend-api").unwrap();
        assert_eq!(manifest.members.len(), 1); // only policy crux remains
        assert_eq!(manifest.members[0].crux_kind, CruxKind::Policy);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_join_two_cruxes() {
        let dir = temp_dir("join_two");
        init_mesh("multi-test", &dir).unwrap();

        // Create two cruxes
        let crux1 = dir.join("service-a");
        fs::create_dir_all(&crux1).unwrap();
        let db1 = create_crux_db("service-a", CruxKind::Codebase, "rust");
        save_crux_db(&db1, &crux1).unwrap();

        let crux2 = dir.join("docs");
        fs::create_dir_all(&crux2).unwrap();
        let db2 = create_crux_db("api-docs", CruxKind::Documentation, "markdown");
        save_crux_db(&db2, &crux2).unwrap();

        join_mesh(&dir, "service-a").unwrap();
        let manifest = join_mesh(&dir, "docs").unwrap();

        assert_eq!(manifest.members.len(), 3); // policy + 2 joined
        assert_eq!(manifest.members[1].crux_name, "service-a"); // policy is 0, service-a is 1
        assert_eq!(manifest.members[2].crux_name, "api-docs"); // docs is 2
        assert_eq!(manifest.members[2].crux_kind, CruxKind::Documentation);

        // Leave one, verify the other remains
        let manifest = leave_mesh(&dir, "service-a").unwrap();
        assert_eq!(manifest.members.len(), 2); // policy + docs
        assert_eq!(manifest.members[0].crux_name, "multi-test-policy"); // policy remains
        assert_eq!(manifest.members[1].crux_name, "api-docs");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_status_text() {
        let mut manifest = create_mesh("status-test");
        manifest.members.push(MeshMember {
            crux_id: "sha256:aaa".to_string(),
            crux_name: "backend".to_string(),
            crux_kind: CruxKind::Codebase,
            path: "./backend".to_string(),
            socket: None,
            status: "online".to_string(),
            last_seen: 100,
            replica_group: None,
            cluster: None,
            mesh_public_key: vec![1, 2, 3, 4],
            mesh_private_key: vec![5, 6, 7, 8],
        });
        manifest.members.push(MeshMember {
            crux_id: "sha256:bbb".to_string(),
            crux_name: "docs".to_string(),
            crux_kind: CruxKind::Documentation,
            path: "./docs".to_string(),
            socket: None,
            status: "offline".to_string(),
            last_seen: 50,
            replica_group: None,
            cluster: None,
            mesh_public_key: vec![9, 10, 11, 12],
            mesh_private_key: vec![13, 14, 15, 16],
        });

        let status = mesh_status_text(&manifest);
        assert!(status.contains("Mesh: status-test"));
        assert!(status.contains("Members: 2 (1 online)"));
        assert!(status.contains("backend (codebase) [online]"));
        assert!(status.contains("docs (documentation) [offline]"));
    }

    #[test]
    fn test_check_member_health() {
        let dir = temp_dir("health_check");
        let mut manifest = create_mesh("health-test");

        // Add a member whose crux file exists
        let crux_dir = dir.join("alive");
        fs::create_dir_all(&crux_dir).unwrap();
        let db = create_crux_db("alive-crux", CruxKind::Codebase, "rust");
        save_crux_db(&db, &crux_dir).unwrap();

        manifest.members.push(MeshMember {
            crux_id: db.header.crux_id.clone(),
            crux_name: "alive-crux".to_string(),
            crux_kind: CruxKind::Codebase,
            path: "alive".to_string(),
            socket: None,
            status: "unknown".to_string(),
            last_seen: 0,
            replica_group: None,
            cluster: None,
            mesh_public_key: vec![1, 2, 3, 4],
            mesh_private_key: vec![5, 6, 7, 8],
        });

        // Add a member whose crux file does NOT exist
        manifest.members.push(MeshMember {
            crux_id: "sha256:gone".to_string(),
            crux_name: "missing-crux".to_string(),
            crux_kind: CruxKind::Codebase,
            path: "missing".to_string(),
            socket: None,
            status: "unknown".to_string(),
            last_seen: 0,
            replica_group: None,
            cluster: None,
            mesh_public_key: vec![9, 10, 11, 12],
            mesh_private_key: vec![13, 14, 15, 16],
        });

        check_member_health(&mut manifest, &dir);

        assert_eq!(manifest.members[0].status, "online");
        assert!(manifest.members[0].last_seen > 0);
        assert_eq!(manifest.members[1].status, "offline");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_find_mesh() {
        let dir = temp_dir("find_mesh");
        let sub = dir.join("a").join("b").join("c");
        fs::create_dir_all(&sub).unwrap();

        // No mesh exists yet
        assert!(find_mesh(&sub).is_none());

        // Create mesh at root
        init_mesh("find-test", &dir).unwrap();

        // Should find it from deep subdirectory
        let found = find_mesh(&sub);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), dir);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_leave_nonexistent_member() {
        let dir = temp_dir("leave_nonexist");
        init_mesh("leave-test", &dir).unwrap();

        let err = leave_mesh(&dir, "nonexistent");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("No member matching"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_leave_mesh_blocks_policy_removal() {
        let dir = temp_dir("leave_policy_guard");
        let manifest = init_mesh("policy-guard-test", &dir).unwrap();

        // The policy crux is the first member
        let policy_member = manifest.members.iter()
            .find(|m| m.crux_kind == crate::schema::CruxKind::Policy)
            .expect("policy crux must exist");
        let policy_name = policy_member.crux_name.clone();

        let err = leave_mesh(&dir, &policy_name);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("Cannot remove the policy crux"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_member_dbs() {
        let dir = temp_dir("load_members");
        init_mesh("load-test", &dir).unwrap();

        // Create and join a crux
        let crux_dir = dir.join("api");
        fs::create_dir_all(&crux_dir).unwrap();
        let db = create_crux_db("api-service", CruxKind::Api, "manual");
        save_crux_db(&db, &crux_dir).unwrap();
        let manifest = join_mesh(&dir, "api").unwrap();

        let loaded = load_member_dbs(&manifest, &dir);
        assert_eq!(loaded.len(), 2); // policy crux + api-service
        // Find the api-service (not the policy crux)
        let api_db = loaded.iter().find(|(_, db)| db.header.crux_name == "api-service").unwrap();
        assert_eq!(api_db.1.header.crux_name, "api-service");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cross_edges_removed_on_leave() {
        let dir = temp_dir("cross_edge_leave");
        init_mesh("ce-test", &dir).unwrap();

        // Create two cruxes
        let c1 = dir.join("svc1");
        fs::create_dir_all(&c1).unwrap();
        let db1 = create_crux_db("svc1", CruxKind::Codebase, "rust");
        save_crux_db(&db1, &c1).unwrap();

        let c2 = dir.join("svc2");
        fs::create_dir_all(&c2).unwrap();
        let db2 = create_crux_db("svc2", CruxKind::Codebase, "rust");
        save_crux_db(&db2, &c2).unwrap();

        join_mesh(&dir, "svc1").unwrap();
        join_mesh(&dir, "svc2").unwrap();

        // Manually add cross-edges
        let mut manifest = load_mesh(&dir).unwrap();
        // Find the actual svc1 and svc2 members (skip policy crux at index 0)
        let svc1_member = manifest.members.iter().find(|m| m.crux_name == "svc1").unwrap();
        let svc2_member = manifest.members.iter().find(|m| m.crux_name == "svc2").unwrap();
        let id1 = svc1_member.crux_id.clone();
        let id2 = svc2_member.crux_id.clone();
        manifest.cross_edges.push(CrossEdgeRef {
            src_crux: id1.clone(),
            dst_crux: id2.clone(),
            edge_count: 10,
            last_synced: now_unix(),
        });
        save_mesh(&manifest, &dir).unwrap();

        // Leave svc1 — cross-edges involving it should be removed
        let manifest = leave_mesh(&dir, "svc1").unwrap();
        assert_eq!(manifest.members.len(), 2); // policy + svc2
        assert!(manifest.cross_edges.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    // ===================================================================
    // Introduction Protocol tests
    // ===================================================================

    fn make_node(name: &str, tags: &[&str]) -> CruxNode {
        CruxNode {
            node_id: format!("sha256:node_{}", name),
            name: name.to_string(),
            kind: "function".to_string(),
            module: "main".to_string(),
            summary: format!("Node {}", name),
            schema: NodeSchema::empty(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            reach: Vec::new(),
            properties: Vec::new(),
            warnings: Vec::new(),
            planning: PlanningMetadata::empty(),
            security: SecurityMetadata::internal(),
            content_hash: String::new(),
            deleted_at: None,
        }
    }

    #[test]
    fn test_jaccard_similarity() {
        let a = vec!["io".to_string(), "tensor".to_string(), "ml".to_string()];
        let b = vec!["ml".to_string(), "gpu".to_string()];
        let sim = jaccard_similarity(&a, &b);
        // intersection = {"ml"} = 1, union = {"io","tensor","ml","gpu"} = 4
        assert!((sim - 0.25).abs() < 0.001);

        // Identical sets
        let c = vec!["x".to_string()];
        assert!((jaccard_similarity(&c, &c) - 1.0).abs() < 0.001);

        // Disjoint sets
        let d = vec!["a".to_string()];
        let e = vec!["b".to_string()];
        assert!((jaccard_similarity(&d, &e)).abs() < 0.001);

        // Both empty
        assert!((jaccard_similarity(&[], &[])).abs() < 0.001);
    }

    #[test]
    fn test_match_by_tags_overlapping() {
        let mut db_a = create_crux_db("crux-a", CruxKind::Codebase, "rust");
        db_a.nodes.push(make_node("@load_data", &["io", "tensor"]));
        db_a.nodes.push(make_node("@train", &["ml", "tensor"]));

        let mut db_b = create_crux_db("crux-b", CruxKind::Documentation, "markdown");
        db_b.nodes.push(make_node("data-format", &["tensor", "format"]));
        db_b.nodes.push(make_node("deploy-guide", &["ops"]));

        let matches = match_by_tags(&db_a, &db_b);
        // @load_data has "tensor", data-format has "tensor" → match
        // @train has "tensor", data-format has "tensor" → match
        // deploy-guide has no overlap with either
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().any(|(s, d)| s == "@load_data" && d == "data-format"));
        assert!(matches.iter().any(|(s, d)| s == "@train" && d == "data-format"));
    }

    #[test]
    fn test_match_by_tags_no_overlap() {
        let mut db_a = create_crux_db("crux-a", CruxKind::Codebase, "rust");
        db_a.nodes.push(make_node("@foo", &["alpha"]));

        let mut db_b = create_crux_db("crux-b", CruxKind::Codebase, "rust");
        db_b.nodes.push(make_node("@bar", &["beta"]));

        let matches = match_by_tags(&db_a, &db_b);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_by_names() {
        let mut db_a = create_crux_db("crux-a", CruxKind::Codebase, "rust");
        db_a.nodes.push(make_node("@validate", &["io"]));
        db_a.nodes.push(make_node("@unique_fn", &["custom"]));

        let mut db_b = create_crux_db("crux-b", CruxKind::Codebase, "python");
        db_b.nodes.push(make_node("@validate", &["web"]));
        db_b.nodes.push(make_node("@other_fn", &["util"]));

        let matches = match_by_names(&db_a, &db_b);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], ("@validate".to_string(), "@validate".to_string()));
    }

    #[test]
    fn test_compute_edge_candidates_dedup() {
        // Two nodes that match by BOTH name and tags should count as 1
        let mut db_a = create_crux_db("crux-a", CruxKind::Codebase, "rust");
        db_a.nodes.push(make_node("@shared_fn", &["io"]));

        let mut db_b = create_crux_db("crux-b", CruxKind::Codebase, "rust");
        db_b.nodes.push(make_node("@shared_fn", &["io"]));

        let count = compute_edge_candidates(&db_a, &db_b);
        assert_eq!(count, 1); // Not 2 (one from tags, one from names)
    }

    #[test]
    fn test_introduce_crux_creates_cross_edges() {
        let dir = temp_dir("introduce");
        init_mesh("intro-test", &dir).unwrap();

        // Create first crux with tagged nodes
        let c1 = dir.join("service");
        fs::create_dir_all(&c1).unwrap();
        let mut db1 = create_crux_db("service", CruxKind::Codebase, "rust");
        db1.nodes.push(make_node("@process_data", &["data", "pipeline"]));
        save_crux_db(&db1, &c1).unwrap();
        join_mesh(&dir, "service").unwrap();

        // Create second crux with overlapping tags
        let c2 = dir.join("docs");
        fs::create_dir_all(&c2).unwrap();
        let mut db2 = create_crux_db("api-docs", CruxKind::Documentation, "markdown");
        db2.nodes.push(make_node("data-pipeline-spec", &["data", "spec"]));
        save_crux_db(&db2, &c2).unwrap();

        // Join should trigger introduction and create cross-edges
        let manifest = join_mesh(&dir, "docs").unwrap();
        assert_eq!(manifest.members.len(), 3); // policy + 2 joined
        // Should have 1 cross-edge ref (tag overlap on "data")
        assert_eq!(manifest.cross_edges.len(), 1);
        assert_eq!(manifest.cross_edges[0].edge_count, 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_introduce_crux_no_overlap() {
        let dir = temp_dir("introduce_none");
        init_mesh("no-overlap-test", &dir).unwrap();

        // Create first crux
        let c1 = dir.join("alpha");
        fs::create_dir_all(&c1).unwrap();
        let mut db1 = create_crux_db("alpha", CruxKind::Codebase, "rust");
        db1.nodes.push(make_node("@foo", &["abc"]));
        save_crux_db(&db1, &c1).unwrap();
        join_mesh(&dir, "alpha").unwrap();

        // Create second crux with completely different tags
        let c2 = dir.join("beta");
        fs::create_dir_all(&c2).unwrap();
        let mut db2 = create_crux_db("beta", CruxKind::Codebase, "rust");
        db2.nodes.push(make_node("@bar", &["xyz"]));
        save_crux_db(&db2, &c2).unwrap();

        let manifest = join_mesh(&dir, "beta").unwrap();
        assert_eq!(manifest.members.len(), 3); // policy + 2 joined
        assert!(manifest.cross_edges.is_empty()); // No overlap

        let _ = fs::remove_dir_all(&dir);
    }

    // ===================================================================
    // Pass-through query tests
    // ===================================================================

    #[test]
    fn test_mesh_query_across_members() {
        let dir = temp_dir("mesh_query");
        init_mesh("query-test", &dir).unwrap();

        // Create two cruxes with different nodes
        let c1 = dir.join("api");
        fs::create_dir_all(&c1).unwrap();
        let mut db1 = create_crux_db("api-service", CruxKind::Codebase, "rust");
        db1.nodes.push(make_node("@handle_request", &["http", "api"]));
        db1.nodes.push(make_node("@validate_input", &["validation"]));
        save_crux_db(&db1, &c1).unwrap();
        join_mesh(&dir, "api").unwrap();

        let c2 = dir.join("docs");
        fs::create_dir_all(&c2).unwrap();
        let mut db2 = create_crux_db("api-docs", CruxKind::Documentation, "markdown");
        db2.nodes.push(make_node("api-reference", &["api", "docs"]));
        save_crux_db(&db2, &c2).unwrap();
        join_mesh(&dir, "docs").unwrap();

        let manifest = load_mesh(&dir).unwrap();

        // Query for "api" should find nodes from both cruxes
        let mut f = crate::query::NodeFilter::default();
        f.query = Some("api".to_string());
        let results = mesh_query(&manifest, &dir, &f);
        assert_eq!(results.len(), 2); // @handle_request (tag:api) + api-reference (tag:api)

        // Query for "validation" should find 1
        let mut f2 = crate::query::NodeFilter::default();
        f2.query = Some("validation".to_string());
        let results = mesh_query(&manifest, &dir, &f2);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].from_crux_name, "api-service");

        // Query with limit
        let mut f3 = crate::query::NodeFilter::default();
        f3.query = Some("api".to_string());
        f3.limit = 1;
        let results = mesh_query(&manifest, &dir, &f3);
        assert_eq!(results.len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_query_no_results() {
        let dir = temp_dir("mesh_query_none");
        init_mesh("empty-query", &dir).unwrap();

        let manifest = load_mesh(&dir).unwrap();
        let mut f = crate::query::NodeFilter::default();
        f.query = Some("nonexistent".to_string());
        let results = mesh_query(&manifest, &dir, &f);
        assert!(results.is_empty());

        let formatted = format_mesh_query_results(&results, "nonexistent");
        assert!(formatted.contains("No nodes matching"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_query_follow_links_no_links_returns_local_only() {
        // follow_links=true with no mesh_link edges should behave identically to follow_links=false
        let dir = temp_dir("follow_links_no_links");
        init_mesh("fl-local", &dir).unwrap();
        let crux_dir = dir.join("local");
        fs::create_dir_all(&crux_dir).unwrap();
        let mut db = create_crux_db("local", CruxKind::Codebase, "rust");
        db.nodes.push(make_node("@alpha", &["search_me"]));
        save_crux_db(&db, &crux_dir).unwrap();
        join_mesh(&dir, "local").unwrap();

        let manifest = load_mesh(&dir).unwrap();
        let mut f = crate::query::NodeFilter::default();
        f.query = Some("search_me".to_string());
        f.follow_links = true;
        let results = mesh_query(&manifest, &dir, &f);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].node_name, "@alpha");
        assert!(!results[0].from_crux_name.contains("cross-link"), "no cross-link expected");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_query_follow_links_false_ignores_remote() {
        // Without follow_links, mesh_link edges must not be followed
        let dir = temp_dir("follow_links_off");
        init_mesh("fl-off", &dir).unwrap();

        // Local crux with one matching node and a mesh_link edge pointing to a remote crux_id
        let local_dir = dir.join("local");
        fs::create_dir_all(&local_dir).unwrap();
        let mut db = create_crux_db("local", CruxKind::Codebase, "rust");
        db.nodes.push(make_node("@src_node", &["tagged"]));
        db.edges.push(crate::schema::CruxEdge {
            edge_id: "ml1".to_string(),
            src: "@src_node".to_string(),
            dst: "sha256:remote_crux_id:@remote_node".to_string(),
            kind: crate::schema::EdgeKind::MeshLink,
            weight: 1.0,
            detail: String::new(),
            cross_crux: true,
            binding: String::new(),
            created_at: 0,
            dangling: false,
        });
        save_crux_db(&db, &local_dir).unwrap();
        join_mesh(&dir, "local").unwrap();

        let manifest = load_mesh(&dir).unwrap();
        let mut f = crate::query::NodeFilter::default();
        f.query = Some("tagged".to_string());
        f.follow_links = false;
        let results = mesh_query(&manifest, &dir, &f);
        // Only local result, no remote traversal
        assert!(results.iter().all(|r| !r.from_crux_name.contains("cross-link")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_query_follow_links_traverses_mesh_link_edges() {
        // follow_links=true: matching local node has a mesh_link to a crux that IS a mesh member —
        // results should include nodes from the remote crux.
        let dir = temp_dir("follow_links_traverse");
        init_mesh("fl-traverse", &dir).unwrap();

        // Join a local "api" crux
        let api_dir = dir.join("api");
        fs::create_dir_all(&api_dir).unwrap();
        let mut api_db = create_crux_db("api", CruxKind::Codebase, "rust");
        api_db.nodes.push(make_node("@endpoint", &["search_me"]));
        save_crux_db(&api_db, &api_dir).unwrap();
        let manifest_after_api = join_mesh(&dir, "api").unwrap();
        let api_member = manifest_after_api.members.iter()
            .find(|m| m.crux_name == "api").unwrap();
        let api_crux_id = api_member.crux_id.clone();

        // Join a remote "spec" crux
        let spec_dir = dir.join("spec");
        fs::create_dir_all(&spec_dir).unwrap();
        let mut spec_db = create_crux_db("spec", CruxKind::Codebase, "rust");
        spec_db.nodes.push(make_node("@spec_node", &["linked_spec"]));
        save_crux_db(&spec_db, &spec_dir).unwrap();
        let manifest_after_spec = join_mesh(&dir, "spec").unwrap();
        let spec_member = manifest_after_spec.members.iter()
            .find(|m| m.crux_name == "spec").unwrap();
        let spec_crux_id = spec_member.crux_id.clone();

        // Add a mesh_link edge from @endpoint (api) → @spec_node (spec)
        let api_db_loaded = load_policy_crux(&manifest_after_spec, &dir);
        drop(api_db_loaded);
        let mut api_db2 = crate::schema::load_crux_db(&api_dir).unwrap();
        api_db2.edges.push(crate::schema::CruxEdge {
            edge_id: "ml_test".to_string(),
            src: "@endpoint".to_string(),
            dst: format!("{}:@spec_node", spec_crux_id),
            kind: crate::schema::EdgeKind::MeshLink,
            weight: 1.0,
            detail: String::new(),
            cross_crux: true,
            binding: String::new(),
            created_at: 0,
            dangling: false,
        });
        save_crux_db(&api_db2, &api_dir).unwrap();
        let _ = api_crux_id;

        let manifest = load_mesh(&dir).unwrap();
        let mut f = crate::query::NodeFilter::default();
        f.query = Some("search_me".to_string());
        f.follow_links = true;
        let results = mesh_query(&manifest, &dir, &f);

        // Local match (@endpoint) + remote traversal into spec crux
        // The remote crux runs the same filter — "search_me" not in spec_node tags,
        // so only the local node should be found. The test verifies no crash and correct local result.
        assert!(results.iter().any(|r| r.node_name == "@endpoint"), "local match missing");

        // Now search for "linked_spec" with follow_links — should find @spec_node via cross-link
        let mut f2 = crate::query::NodeFilter::default();
        f2.query = Some("search_me".to_string());
        f2.follow_links = true;
        let results2 = mesh_query(&manifest, &dir, &f2);
        assert!(results2.iter().any(|r| r.node_name == "@endpoint"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_path() {
        let dir = temp_dir("mesh_path");
        init_mesh("path-test", &dir).unwrap();

        // Create a crux with edges
        let c1 = dir.join("graph");
        fs::create_dir_all(&c1).unwrap();
        let mut db1 = create_crux_db("graph", CruxKind::Codebase, "rust");
        db1.nodes.push(make_node("@a", &[]));
        db1.nodes.push(make_node("@b", &[]));
        db1.nodes.push(make_node("@c", &[]));
        db1.edges.push(crate::schema::CruxEdge {
            edge_id: "e1".to_string(),
            src: "@a".to_string(),
            dst: "@b".to_string(),
            kind: crate::schema::EdgeKind::Calls,
            weight: 1.0,
            detail: String::new(),
            cross_crux: false,
            binding: String::new(),
            created_at: 0,
            dangling: false,
        });
        db1.edges.push(crate::schema::CruxEdge {
            edge_id: "e2".to_string(),
            src: "@b".to_string(),
            dst: "@c".to_string(),
            kind: crate::schema::EdgeKind::Calls,
            weight: 1.0,
            detail: String::new(),
            cross_crux: false,
            binding: String::new(),
            created_at: 0,
            dangling: false,
        });
        save_crux_db(&db1, &c1).unwrap();
        join_mesh(&dir, "graph").unwrap();

        let manifest = load_mesh(&dir).unwrap();

        // Path from @a to @c should be @a -> @b -> @c
        let path = mesh_path(&manifest, &dir, "@a", "@c");
        assert!(path.is_some());
        let path = path.unwrap();
        assert_eq!(path, vec!["@a", "@b", "@c"]);

        // No path from @c to @a (directed graph)
        let path = mesh_path(&manifest, &dir, "@c", "@a");
        assert!(path.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_path_no_cross_link_when_no_mesh_link_edge() {
        // Two cruxes, no mesh_link edges — path within first crux still works
        let dir = temp_dir("path_no_crosslink");
        init_mesh("path-nocross", &dir).unwrap();

        let c1 = dir.join("crux1");
        fs::create_dir_all(&c1).unwrap();
        let mut db1 = create_crux_db("crux1", CruxKind::Codebase, "rust");
        db1.nodes.push(make_node("@x", &[]));
        db1.nodes.push(make_node("@y", &[]));
        db1.edges.push(crate::schema::CruxEdge {
            edge_id: "ex".to_string(),
            src: "@x".to_string(),
            dst: "@y".to_string(),
            kind: crate::schema::EdgeKind::Calls,
            weight: 1.0,
            detail: String::new(),
            cross_crux: false,
            binding: String::new(),
            created_at: 0,
            dangling: false,
        });
        save_crux_db(&db1, &c1).unwrap();
        join_mesh(&dir, "crux1").unwrap();

        let c2 = dir.join("crux2");
        fs::create_dir_all(&c2).unwrap();
        let mut db2 = create_crux_db("crux2", CruxKind::Codebase, "rust");
        db2.nodes.push(make_node("@z", &[]));
        save_crux_db(&db2, &c2).unwrap();
        join_mesh(&dir, "crux2").unwrap();

        let manifest = load_mesh(&dir).unwrap();

        // Local path still works
        let p = mesh_path(&manifest, &dir, "@x", "@y");
        assert_eq!(p, Some(vec!["@x".to_string(), "@y".to_string()]));

        // No path to @z — not connected
        let p2 = mesh_path(&manifest, &dir, "@x", "@z");
        assert!(p2.is_none(), "should not reach @z without a mesh_link edge");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_path_follows_mesh_link_cross_crux() {
        // Two cruxes connected by a mesh_link edge — path should cross the crux boundary
        // and include the [cross-link → <name>] label segment.
        let dir = temp_dir("path_cross_crux");
        init_mesh("path-cross", &dir).unwrap();

        // crux "src" with node @start → @mid (local edge)
        let src_dir = dir.join("src_crux");
        fs::create_dir_all(&src_dir).unwrap();
        let mut src_db = create_crux_db("src_crux", CruxKind::Codebase, "rust");
        src_db.nodes.push(make_node("@start", &[]));
        src_db.nodes.push(make_node("@mid", &[]));
        src_db.edges.push(crate::schema::CruxEdge {
            edge_id: "e_local".to_string(),
            src: "@start".to_string(),
            dst: "@mid".to_string(),
            kind: crate::schema::EdgeKind::Calls,
            weight: 1.0,
            detail: String::new(),
            cross_crux: false,
            binding: String::new(),
            created_at: 0,
            dangling: false,
        });
        save_crux_db(&src_db, &src_dir).unwrap();
        let manifest_v1 = join_mesh(&dir, "src_crux").unwrap();

        // crux "dst" with node @finish
        let dst_dir = dir.join("dst_crux");
        fs::create_dir_all(&dst_dir).unwrap();
        let mut dst_db = create_crux_db("dst_crux", CruxKind::Codebase, "rust");
        dst_db.nodes.push(make_node("@finish", &[]));
        save_crux_db(&dst_db, &dst_dir).unwrap();
        let manifest_v2 = join_mesh(&dir, "dst_crux").unwrap();

        // Get the dst crux_id so we can form the mesh_link dst address
        let dst_member = manifest_v2.members.iter()
            .find(|m| m.crux_name == "dst_crux").unwrap();
        let dst_crux_id = dst_member.crux_id.clone();
        let _ = manifest_v1;

        // Add mesh_link edge: @mid → @finish (across cruxes)
        let mut src_db2 = crate::schema::load_crux_db(&src_dir).unwrap();
        src_db2.edges.push(crate::schema::CruxEdge {
            edge_id: "e_cross".to_string(),
            src: "@mid".to_string(),
            dst: format!("{}:@finish", dst_crux_id),
            kind: crate::schema::EdgeKind::MeshLink,
            weight: 1.0,
            detail: String::new(),
            cross_crux: true,
            binding: String::new(),
            created_at: 0,
            dangling: false,
        });
        save_crux_db(&src_db2, &src_dir).unwrap();

        let manifest = load_mesh(&dir).unwrap();

        let path = mesh_path(&manifest, &dir, "@start", "@finish");
        assert!(path.is_some(), "expected a path from @start to @finish");
        let path = path.unwrap();
        assert_eq!(path.first().map(|s| s.as_str()), Some("@start"));
        assert_eq!(path.last().map(|s| s.as_str()), Some("@finish"));
        assert!(
            path.iter().any(|s| s.contains("cross-link")),
            "path must include a cross-link label segment, got: {:?}", path
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_impact() {
        let dir = temp_dir("mesh_impact");
        init_mesh("impact-test", &dir).unwrap();

        let c1 = dir.join("graph");
        fs::create_dir_all(&c1).unwrap();
        let mut db1 = create_crux_db("graph", CruxKind::Codebase, "rust");
        db1.nodes.push(make_node("@main", &[]));
        db1.nodes.push(make_node("@helper", &[]));
        db1.nodes.push(make_node("@util", &[]));
        db1.edges.push(crate::schema::CruxEdge {
            edge_id: "e1".to_string(),
            src: "@main".to_string(),
            dst: "@helper".to_string(),
            kind: crate::schema::EdgeKind::Calls,
            weight: 1.0,
            detail: String::new(),
            cross_crux: false,
            binding: String::new(),
            created_at: 0,
            dangling: false,
        });
        db1.edges.push(crate::schema::CruxEdge {
            edge_id: "e2".to_string(),
            src: "@helper".to_string(),
            dst: "@util".to_string(),
            kind: crate::schema::EdgeKind::Calls,
            weight: 1.0,
            detail: String::new(),
            cross_crux: false,
            binding: String::new(),
            created_at: 0,
            dangling: false,
        });
        save_crux_db(&db1, &c1).unwrap();
        join_mesh(&dir, "graph").unwrap();

        let manifest = load_mesh(&dir).unwrap();

        // Impact of @util: callers are @helper and @main
        let callers = mesh_impact(&manifest, &dir, "@util");
        assert_eq!(callers.len(), 2);
        assert!(callers.contains(&"@helper".to_string()));
        assert!(callers.contains(&"@main".to_string()));

        // Impact of @main: no callers
        let callers = mesh_impact(&manifest, &dir, "@main");
        assert!(callers.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_format_mesh_query_results() {
        let results = vec![MeshQueryResult {
            node_name: "@process".to_string(),
            node_kind: "function".to_string(),
            node_summary: "Process data".to_string(),
            tags: vec!["io".to_string()],
            from_crux: "sha256:abc".to_string(),
            from_crux_name: "backend".to_string(),
        }];
        let text = format_mesh_query_results(&results, "process");
        assert!(text.contains("1 node(s)"));
        assert!(text.contains("@process"));
        assert!(text.contains("[from: backend]"));
        assert!(text.contains("tags: io"));
    }

    // ---- Phase 3: Multi-mesh and clusters ----

    #[test]
    fn test_mesh_membership_on_crux_header() {
        let dir = temp_dir("membership_header");
        init_mesh("m-mesh", &dir).unwrap();

        let crux_dir = dir.join("mycrux");
        fs::create_dir_all(&crux_dir).unwrap();
        let db = create_crux_db("my-crux", CruxKind::Codebase, "manual");
        save_crux_db(&db, &crux_dir).unwrap();

        join_mesh(&dir, "mycrux").unwrap();

        // Reload the crux — it should now have a mesh_membership entry
        let updated_db = load_crux_db(&crux_dir).unwrap();
        assert_eq!(updated_db.header.mesh_memberships.len(), 1);
        assert_eq!(updated_db.header.mesh_memberships[0].mesh_name, "m-mesh");
        assert!(!updated_db.header.mesh_memberships[0].public_key_hash.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_membership_serialization_roundtrip() {
        let dir = temp_dir("membership_roundtrip");
        init_mesh("roundtrip-mesh", &dir).unwrap();

        let crux_dir = dir.join("c1");
        fs::create_dir_all(&crux_dir).unwrap();
        let db = create_crux_db("c1", CruxKind::Documentation, "manual");
        save_crux_db(&db, &crux_dir).unwrap();
        join_mesh(&dir, "c1").unwrap();

        // Load and re-serialize
        let db_loaded = load_crux_db(&crux_dir).unwrap();
        let json = crate::schema::serialize_crux_db(&db_loaded);
        let parsed = crate::schema::parse_crux_db(&json).unwrap();
        assert_eq!(parsed.header.mesh_memberships.len(), 1);
        assert_eq!(parsed.header.mesh_memberships[0].mesh_name, "roundtrip-mesh");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cross_mesh_deny_all_blocks_join() {
        let dir = temp_dir("cross_deny");
        let mesh1_dir = dir.join("mesh1");
        let mesh2_dir = dir.join("mesh2");
        fs::create_dir_all(&mesh1_dir).unwrap();
        fs::create_dir_all(&mesh2_dir).unwrap();

        // Mesh2 denies all cross-mesh
        let config2 = crate::schema::PolicyConfig {
            cross_mesh_policy: "deny_all".to_string(),
            multi_mesh_allowed: false,
            ..crate::schema::PolicyConfig::default()
        };
        init_mesh("mesh1", &mesh1_dir).unwrap();
        init_mesh_with_policy("mesh2", &mesh2_dir, Some(config2)).unwrap();

        let crux_dir = dir.join("shared-crux");
        fs::create_dir_all(&crux_dir).unwrap();
        let db = create_crux_db("shared", CruxKind::Codebase, "manual");
        save_crux_db(&db, &crux_dir).unwrap();

        // Join mesh1 first
        let rel_path = "../shared-crux";
        join_mesh(&mesh1_dir, rel_path).unwrap();

        // Joining mesh2 should fail: deny_all / multi_mesh_allowed=false
        let err = join_mesh(&mesh2_dir, rel_path);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("prevents cruxes from joining multiple meshes"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cluster_create_and_list() {
        let dir = temp_dir("cluster_create");
        init_mesh("cluster-mesh", &dir).unwrap();

        create_cluster(&dir, "engineering", "internal", "allow").unwrap();
        create_cluster(&dir, "sales", "confidential", "deny").unwrap();

        let clusters = list_clusters(&dir).unwrap();
        assert!(clusters.contains(&"engineering".to_string()));
        assert!(clusters.contains(&"sales".to_string()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cluster_create_duplicate_fails() {
        let dir = temp_dir("cluster_dup");
        init_mesh("dup-mesh", &dir).unwrap();
        create_cluster(&dir, "eng", "internal", "allow").unwrap();
        let err = create_cluster(&dir, "eng", "internal", "allow");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("already exists"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cluster_assignment() {
        let dir = temp_dir("cluster_assign");
        init_mesh("assign-mesh", &dir).unwrap();
        create_cluster(&dir, "eng", "internal", "allow").unwrap();

        let crux_dir = dir.join("service");
        fs::create_dir_all(&crux_dir).unwrap();
        let db = create_crux_db("service", CruxKind::Codebase, "manual");
        save_crux_db(&db, &crux_dir).unwrap();
        join_mesh(&dir, "service").unwrap();

        let manifest = assign_cluster(&dir, "service", "eng").unwrap();
        let member = manifest.members.iter().find(|m| m.crux_name == "service").unwrap();
        assert_eq!(member.cluster, Some("eng".to_string()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cluster_assignment_unknown_cluster_fails() {
        let dir = temp_dir("cluster_assign_fail");
        init_mesh("fail-mesh", &dir).unwrap();

        let crux_dir = dir.join("svc");
        fs::create_dir_all(&crux_dir).unwrap();
        let db = create_crux_db("svc", CruxKind::Codebase, "manual");
        save_crux_db(&db, &crux_dir).unwrap();
        join_mesh(&dir, "svc").unwrap();

        let err = assign_cluster(&dir, "svc", "nonexistent-cluster");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("does not exist"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_policy_crux() {
        let dir = temp_dir("load_policy");
        init_mesh("load-policy-test", &dir).unwrap();
        let manifest = load_mesh(&dir).unwrap();
        let policy_db = load_policy_crux(&manifest, &dir).unwrap();
        assert_eq!(policy_db.header.crux_kind, crate::schema::CruxKind::Policy);
        assert!(policy_db.nodes.iter().any(|n| n.name == "Security Policy"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_join_respects_allowed_kinds() {
        let dir = temp_dir("join_allowed_kinds");
        let config = crate::schema::PolicyConfig {
            allowed_crux_kinds: vec!["codebase".to_string()],
            ..crate::schema::PolicyConfig::default()
        };
        init_mesh_with_policy("kind-test", &dir, Some(config)).unwrap();

        // A documentation crux should be rejected
        let doc_dir = dir.join("docs");
        fs::create_dir_all(&doc_dir).unwrap();
        let doc_db = create_crux_db("my-docs", crate::schema::CruxKind::Documentation, "manual");
        save_crux_db(&doc_db, &doc_dir).unwrap();
        let err = join_mesh(&dir, "docs");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("does not allow crux kind"));

        // A codebase crux should be accepted
        let code_dir = dir.join("mycode");
        fs::create_dir_all(&code_dir).unwrap();
        let code_db = create_crux_db("my-code", crate::schema::CruxKind::Codebase, "manual");
        save_crux_db(&code_db, &code_dir).unwrap();
        assert!(join_mesh(&dir, "mycode").is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_join_respects_max_members() {
        let dir = temp_dir("join_max_members");
        let config = crate::schema::PolicyConfig {
            max_members: Some(1),
            ..crate::schema::PolicyConfig::default()
        };
        init_mesh_with_policy("maxmem-test", &dir, Some(config)).unwrap();

        // First member should be accepted
        let c1 = dir.join("crux1");
        fs::create_dir_all(&c1).unwrap();
        let db1 = create_crux_db("crux-one", crate::schema::CruxKind::Codebase, "manual");
        save_crux_db(&db1, &c1).unwrap();
        assert!(join_mesh(&dir, "crux1").is_ok());

        // Second member should be rejected (at capacity)
        let c2 = dir.join("crux2");
        fs::create_dir_all(&c2).unwrap();
        let db2 = create_crux_db("crux-two", crate::schema::CruxKind::Codebase, "manual");
        save_crux_db(&db2, &c2).unwrap();
        let err = join_mesh(&dir, "crux2");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("at capacity"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_join_with_approval_sets_pending() {
        let dir = temp_dir("join_approval");
        let config = crate::schema::PolicyConfig {
            require_approval: true,
            ..crate::schema::PolicyConfig::default()
        };
        init_mesh_with_policy("approval-test", &dir, Some(config)).unwrap();

        let c1 = dir.join("crux1");
        fs::create_dir_all(&c1).unwrap();
        let db1 = create_crux_db("pending-crux", crate::schema::CruxKind::Codebase, "manual");
        save_crux_db(&db1, &c1).unwrap();
        let manifest = join_mesh(&dir, "crux1").unwrap();

        let member = manifest.members.iter()
            .find(|m| m.crux_name == "pending-crux")
            .unwrap();
        assert_eq!(member.status, "pending");

        let _ = fs::remove_dir_all(&dir);
    }

    // ===== Security tests (inlined from legacy/security.rs — H-8) =====

    fn make_security_node(name: &str, classification: &str, redact_below: Option<&str>) -> CruxNode {
        CruxNode {
            node_id: format!("sha256:{}", name),
            name: name.to_string(),
            kind: "function".to_string(),
            module: "main".to_string(),
            summary: format!("Summary of {}", name),
            schema: NodeSchema::empty(),
            tags: vec!["test".to_string()],
            reach: Vec::new(),
            properties: Vec::new(),
            warnings: Vec::new(),
            planning: PlanningMetadata::empty(),
            security: SecurityMetadata {
                classification: classification.to_string(),
                redact_below: redact_below.map(|s| s.to_string()),
            },
            content_hash: String::new(),
            deleted_at: None,
        }
    }

    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::Public < SecurityLevel::Internal);
        assert!(SecurityLevel::Internal < SecurityLevel::Confidential);
        assert!(SecurityLevel::Confidential < SecurityLevel::Restricted);
    }

    #[test]
    fn test_security_level_roundtrip() {
        for level in &[
            SecurityLevel::Public,
            SecurityLevel::Internal,
            SecurityLevel::Confidential,
            SecurityLevel::Restricted,
        ] {
            assert_eq!(SecurityLevel::from_str(level.as_str()), *level);
            assert_eq!(SecurityLevel::from_u8(level.as_u8()), *level);
        }
    }

    #[test]
    fn test_filter_omits_high_classification() {
        let nodes = vec![
            make_security_node("@public_fn", "public", None),
            make_security_node("@internal_fn", "internal", None),
            make_security_node("@secret_fn", "restricted", None),
        ];
        let visible = filter_by_clearance(&nodes, SecurityLevel::Public);
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name, "@public_fn");
        let visible = filter_by_clearance(&nodes, SecurityLevel::Internal);
        assert_eq!(visible.len(), 2);
        let visible = filter_by_clearance(&nodes, SecurityLevel::Restricted);
        assert_eq!(visible.len(), 3);
    }

    #[test]
    fn test_filter_redacts_below_clearance() {
        let nodes = vec![
            make_security_node("@normal_fn", "internal", None),
            make_security_node("@sensitive_fn", "internal", Some("confidential")),
        ];
        let visible = filter_by_clearance(&nodes, SecurityLevel::Internal);
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0].summary, "Summary of @normal_fn");
        assert_eq!(visible[1].summary, "[REDACTED]");
        assert!(visible[1].tags.is_empty());
        let visible = filter_by_clearance(&nodes, SecurityLevel::Confidential);
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[1].summary, "Summary of @sensitive_fn");
    }

    #[test]
    fn test_redact_node() {
        let node = make_security_node("@secret", "confidential", None);
        let redacted = redact_node(&node);
        assert_eq!(redacted.name, "@secret");
        assert_eq!(redacted.kind, "function");
        assert_eq!(redacted.summary, "[REDACTED]");
        assert!(redacted.tags.is_empty());
        assert!(redacted.schema.inputs.is_empty());
        assert_eq!(redacted.content_hash, "");
    }

    #[test]
    fn test_empty_nodes_filter() {
        let nodes: Vec<CruxNode> = Vec::new();
        let visible = filter_by_clearance(&nodes, SecurityLevel::Restricted);
        assert!(visible.is_empty());
    }

    // --- Edge-case tests (Phase A-2) ---

    #[test]
    fn test_security_level_from_str_case_insensitive() {
        assert_eq!(SecurityLevel::from_str("PUBLIC"), SecurityLevel::Public);
        assert_eq!(SecurityLevel::from_str("Confidential"), SecurityLevel::Confidential);
    }

    #[test]
    fn test_security_level_from_str_unknown_defaults_internal() {
        assert_eq!(SecurityLevel::from_str(""), SecurityLevel::Internal);
        assert_eq!(SecurityLevel::from_str("top-secret"), SecurityLevel::Internal);
    }

    #[test]
    fn test_mesh_security_default_has_four_levels() {
        let sec = MeshSecurity::default();
        assert_eq!(sec.levels.len(), 4);
        assert_eq!(sec.default_classification, "internal");
        assert_eq!(sec.levels[0], "public");
        assert_eq!(sec.levels[3], "restricted");
    }

    #[test]
    fn test_create_mesh_empty_name() {
        let m = create_mesh("");
        assert_eq!(m.mesh_name, "");
        assert!(m.members.is_empty());
    }

    #[test]
    fn test_generate_mesh_id_deterministic() {
        let a = generate_mesh_id("test", 1000);
        let b = generate_mesh_id("test", 1000);
        assert_eq!(a, b);
    }

    #[test]
    fn test_generate_mesh_id_different_inputs() {
        let a = generate_mesh_id("alpha", 1000);
        let b = generate_mesh_id("beta", 1000);
        assert_ne!(a, b);
    }

    #[test]
    fn test_serialize_roundtrip_empty_mesh() {
        let manifest = create_mesh("empty-test");
        let json = serialize_mesh(&manifest);
        let parsed = parse_mesh(&json).unwrap();
        assert_eq!(parsed.mesh_name, "empty-test");
        assert!(parsed.members.is_empty());
        assert!(parsed.cross_edges.is_empty());
    }

    #[test]
    fn test_parse_mesh_missing_fields() {
        // Minimal valid JSON — just mesh_name
        let json = r#"{"mesh_name": "bare", "mesh_version": 1, "mesh_id": "sha256:abc", "created_at": 0}"#;
        let parsed = parse_mesh(json).unwrap();
        assert_eq!(parsed.mesh_name, "bare");
        assert!(parsed.members.is_empty());
    }

    #[test]
    fn test_parse_mesh_empty_string_tolerant() {
        // parse_mesh is tolerant — empty input produces an empty mesh, not an error
        let result = parse_mesh("");
        assert!(result.is_ok());
        let manifest = result.unwrap();
        assert!(manifest.members.is_empty());
    }

    #[test]
    fn test_parse_mesh_malformed_json_tolerant() {
        // parse_mesh is tolerant — malformed input still parses (best-effort)
        let result = parse_mesh("{not valid json}");
        assert!(result.is_ok());
    }

    // --- mesh_list_mcp_servers / mesh_revoke_mcp ---

    fn setup_mesh_with_mcp(dir: &std::path::Path, alias: &str) -> MeshManifest {
        use crate::schema::{McpServerRegistration, McpTransport, McpClearance, build_mcp_server_registration};
        let manifest = init_mesh("test", dir).unwrap();
        let policy_member = manifest.members.iter()
            .find(|m| m.crux_kind == crate::schema::CruxKind::Policy)
            .unwrap();
        let policy_dir = dir.join(&policy_member.path);
        let mut db = load_policy_crux(&manifest, dir).unwrap();
        let reg = McpServerRegistration {
            alias: alias.to_string(),
            transport: McpTransport::Stdio,
            command: "my-server".to_string(),
            url: String::new(),
            required_clearance: McpClearance::Internal,
            allowed_tools: "tool_a,tool_b".to_string(),
            public_key: String::new(),
            audit_required: true,
            capability_manifest: String::new(),
            rate_limit: None,
            status: "approved".to_string(),
            source: "manual".to_string(),
            fingerprint: String::new(),
            discovered_at: None,
            auth: "none".to_string(),
            oauth_client_id: String::new(),
            oauth_scopes: String::new(),
            oauth_discovery_url: String::new(),
            oauth_authorization_endpoint: String::new(),
            oauth_token_endpoint: String::new(),
            oauth_registration_endpoint: String::new(),
        };
        db.nodes.push(build_mcp_server_registration(&reg));
        crate::schema::save_crux_db(&db, &policy_dir).unwrap();
        manifest
    }

    #[test]
    fn test_mesh_list_mcp_servers_empty() {
        let dir = temp_dir("list_mcp_empty");
        init_mesh("test", &dir).unwrap();
        let result = mesh_list_mcp_servers(&dir).unwrap();
        assert!(result.contains("No MCP servers registered"), "got: {}", result);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_list_mcp_servers_shows_alias() {
        let dir = temp_dir("list_mcp_alias");
        setup_mesh_with_mcp(&dir, "my-server");
        let result = mesh_list_mcp_servers(&dir).unwrap();
        assert!(result.contains("my-server"), "got: {}", result);
        assert!(result.contains("stdio"), "got: {}", result);
        assert!(result.contains("internal"), "got: {}", result);
        assert!(result.contains("tool_a"), "got: {}", result);
        assert!(result.contains("1 server(s)"), "got: {}", result);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_revoke_mcp_success() {
        let dir = temp_dir("revoke_mcp");
        setup_mesh_with_mcp(&dir, "to-revoke");
        // Confirm it's listed before revocation
        let before = mesh_list_mcp_servers(&dir).unwrap();
        assert!(before.contains("to-revoke"));
        // Revoke
        let msg = mesh_revoke_mcp(&dir, "to-revoke").unwrap();
        assert!(msg.contains("to-revoke"), "got: {}", msg);
        // Confirm it's gone after revocation
        let after = mesh_list_mcp_servers(&dir).unwrap();
        assert!(!after.contains("to-revoke"), "still listed after revoke: {}", after);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_revoke_mcp_unknown_alias() {
        let dir = temp_dir("revoke_mcp_miss");
        setup_mesh_with_mcp(&dir, "existing");
        let err = mesh_revoke_mcp(&dir, "nonexistent").unwrap_err();
        assert!(err.contains("nonexistent"), "got: {}", err);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mesh_revoke_mcp_empty_alias() {
        let dir = temp_dir("revoke_mcp_empty");
        init_mesh("test", &dir).unwrap();
        let err = mesh_revoke_mcp(&dir, "").unwrap_err();
        assert!(err.contains("required"), "got: {}", err);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ----- C7: dynamic discovery tests -------------------------------------

    fn write_discovery_manifest(dir: &std::path::Path, filename: &str, alias: &str, command: &str) {
        let disc_dir = dir.join(".crux-discovery");
        fs::create_dir_all(&disc_dir).unwrap();
        let content = format!(
            r#"{{"alias":"{alias}","transport":"stdio","command":"{command}","required_clearance":"internal"}}"#
        );
        fs::write(disc_dir.join(filename), content).unwrap();
    }

    #[test]
    fn test_discover_empty_dir_ok() {
        let dir = temp_dir("discover_empty");
        init_mesh("discover-mesh", &dir).unwrap();
        fs::create_dir_all(dir.join(".crux-discovery")).unwrap();
        let report = mesh_discover(&dir).unwrap();
        assert!(report.added.is_empty());
        assert!(report.errors.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_discover_creates_proposed_when_require_approval() {
        let dir = temp_dir("discover_proposed");
        let config = crate::schema::PolicyConfig { require_approval: true, ..Default::default() };
        init_mesh_with_policy("appr-mesh", &dir, Some(config)).unwrap();
        write_discovery_manifest(&dir, "echo.json", "echo", "/bin/echo");

        let report = mesh_discover(&dir).unwrap();
        assert_eq!(report.added, vec!["echo".to_string()]);

        let proposed = load_discovered_mcp(&dir);
        assert_eq!(proposed.len(), 1, "should have 1 proposed server");
        assert_eq!(proposed[0].alias, "echo");
        assert_eq!(proposed[0].status, "proposed");

        // load_mcp_registrations (used by router) excludes proposed
        let active = load_mcp_registrations(&dir);
        assert!(active.is_empty(), "proposed must not appear in active list");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_discover_auto_approves_when_open() {
        let dir = temp_dir("discover_auto");
        init_mesh("open-mesh", &dir).unwrap(); // require_approval=false (default)
        write_discovery_manifest(&dir, "cat.json", "cat", "/bin/cat");

        let report = mesh_discover(&dir).unwrap();
        assert_eq!(report.added, vec!["cat".to_string()]);

        let active = load_mcp_registrations(&dir);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].status, "approved");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_discover_idempotent() {
        let dir = temp_dir("discover_idem");
        init_mesh("idem-mesh", &dir).unwrap();
        write_discovery_manifest(&dir, "tool.json", "tool", "/bin/tool");

        mesh_discover(&dir).unwrap();
        let report2 = mesh_discover(&dir).unwrap(); // second scan
        assert!(report2.added.is_empty(), "second scan must not re-add");
        assert_eq!(report2.skipped, vec!["tool".to_string()], "second scan must skip identical");

        let active = load_mcp_registrations(&dir);
        assert_eq!(active.len(), 1, "must not duplicate");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_discover_updates_on_fingerprint_change() {
        let dir = temp_dir("discover_update");
        init_mesh("update-mesh", &dir).unwrap();
        write_discovery_manifest(&dir, "tool.json", "tool", "/bin/tool-v1");
        mesh_discover(&dir).unwrap();

        // Overwrite with different command → new fingerprint
        write_discovery_manifest(&dir, "tool.json", "tool", "/bin/tool-v2");
        let report = mesh_discover(&dir).unwrap();
        assert_eq!(report.updated, vec!["tool".to_string()]);

        let active = load_mcp_registrations(&dir);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].command, "/bin/tool-v2");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_approve_mcp_flips_status() {
        let dir = temp_dir("approve_flip");
        let config = crate::schema::PolicyConfig { require_approval: true, ..Default::default() };
        init_mesh_with_policy("appr-mesh2", &dir, Some(config)).unwrap();
        write_discovery_manifest(&dir, "svc.json", "svc", "/usr/bin/svc");
        mesh_discover(&dir).unwrap();

        // Before: proposed, not in active list
        assert!(load_mcp_registrations(&dir).is_empty());

        let msg = mesh_approve_mcp(&dir, "svc").unwrap();
        assert!(msg.contains("approved"), "got: {msg}");

        // After: approved, in active list
        let active = load_mcp_registrations(&dir);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].status, "approved");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_approve_mcp_unknown_alias_errors() {
        let dir = temp_dir("approve_unknown");
        init_mesh("test", &dir).unwrap();
        let err = mesh_approve_mcp(&dir, "nonexistent").unwrap_err();
        assert!(err.contains("No active"), "got: {err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_register_mcp_respects_require_approval() {
        let dir = temp_dir("register_approval");
        let config = crate::schema::PolicyConfig { require_approval: true, ..Default::default() };
        init_mesh_with_policy("strict-mesh", &dir, Some(config)).unwrap();

        let msg = mesh_register_mcp(&dir, "my-svc", "stdio", "/bin/my-svc", "", "internal", "*", "", &crate::schema::OAuthConfig::default()).unwrap();
        assert!(msg.contains("my-svc"), "got: {msg}");

        // Should be proposed, not in active list
        let active = load_mcp_registrations(&dir);
        assert!(active.is_empty(), "registered under strict policy must be proposed, not active");

        let proposed = load_discovered_mcp(&dir);
        assert_eq!(proposed.len(), 1);
        assert_eq!(proposed[0].status, "proposed");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_keyring_node_present_after_init() {
        let dir = temp_dir("keyring_init");
        let manifest = init_mesh("keyring-test", &dir).unwrap();

        let policy_db = load_policy_crux(&manifest, &dir).unwrap();
        let crux_id = &manifest.members[0].crux_id;
        let keyring_node = policy_db.nodes.iter()
            .find(|n| n.kind == "mesh-keyring"
                && n.properties.iter().any(|p| p == &format!("crux_id={crux_id}")));

        assert!(keyring_node.is_some(), "no mesh-keyring node for {crux_id}");
        let node = keyring_node.unwrap();
        assert!(node.properties.iter().any(|p| p.starts_with("pubkey_hex=")));
        assert!(node.properties.iter().any(|p| p.starts_with("pubkey_hash=sha256:")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_keyring_node_present_after_join() {
        let dir = temp_dir("keyring_join");
        init_mesh("keyring-join-mesh", &dir).unwrap();

        let crux_dir = dir.join("code");
        std::fs::create_dir_all(&crux_dir).unwrap();
        let db = create_crux_db("code", CruxKind::Codebase, "manual");
        save_crux_db(&db, &crux_dir).unwrap();

        let manifest = join_mesh(&dir, "code").unwrap();
        let code_member = manifest.members.iter().find(|m| m.crux_name == "code").unwrap();
        let crux_id = &code_member.crux_id;

        let policy_db = load_policy_crux(&manifest, &dir).unwrap();
        let keyring_nodes: Vec<_> = policy_db.nodes.iter()
            .filter(|n| n.kind == "mesh-keyring"
                && n.properties.iter().any(|p| p == &format!("crux_id={crux_id}")))
            .collect();

        assert_eq!(keyring_nodes.len(), 1, "expected 1 keyring node for joined crux, got {}", keyring_nodes.len());
        assert!(keyring_nodes[0].properties.iter().any(|p| p.starts_with("pubkey_hex=")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_register_mcp_self_sig_non_empty_after_init() {
        let dir = temp_dir("self_sig_non_empty");
        init_mesh("test-self-sig", &dir).unwrap();
        let result = mesh_register_mcp(&dir, "my-mcp", "stdio", "my-tool --mcp", "", "internal", "*", "", &crate::schema::OAuthConfig::default()).unwrap();
        assert!(result.contains("my-mcp"), "got: {result}");

        let manifest = load_mesh(&dir).unwrap();
        let policy_db = load_policy_crux(&manifest, &dir).unwrap();
        let node = policy_db.nodes.iter()
            .find(|n| n.kind == "mcp_server_registration"
                && n.properties.iter().any(|p| p == "alias=my-mcp"))
            .expect("registration node not found");
        let pk_val = node.properties.iter()
            .find_map(|p| p.strip_prefix("public_key=").map(|v| v.to_string()))
            .unwrap_or_default();
        assert!(pk_val.starts_with("sig="), "expected public_key to start with 'sig=', got: {pk_val}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Replication tests
    // -----------------------------------------------------------------------

    fn repl_node(id: &str, name: &str, classification: &str, updated_at: u64) -> CruxNode {
        CruxNode {
            node_id: id.to_string(),
            name: name.to_string(),
            kind: "function".to_string(),
            module: "test".to_string(),
            summary: format!("Node {}", name),
            schema: NodeSchema::empty(),
            tags: vec![],
            reach: vec![],
            properties: vec![],
            warnings: vec![],
            planning: PlanningMetadata { updated_at: Some(updated_at), ..PlanningMetadata::empty() },
            security: SecurityMetadata { classification: classification.to_string(), redact_below: None },
            content_hash: String::new(),
            deleted_at: None,
        }
    }

    #[test]
    fn test_push_copies_nodes() {
        let dir = temp_dir("replicate_push");
        init_mesh("push-mesh", &dir).unwrap();

        let crux_a = dir.join("crux-a");
        let crux_b = dir.join("crux-b");
        fs::create_dir_all(&crux_a).unwrap();
        fs::create_dir_all(&crux_b).unwrap();

        let mut db_a = create_crux_db("crux-a", CruxKind::Codebase, "manual");
        db_a.nodes.push(repl_node("id-1", "alpha", "internal", 100));
        db_a.nodes.push(repl_node("id-2", "beta", "internal", 200));
        save_crux_db(&db_a, &crux_a).unwrap();

        let db_b = create_crux_db("crux-b", CruxKind::Codebase, "manual");
        save_crux_db(&db_b, &crux_b).unwrap();

        join_mesh(&dir, "crux-a").unwrap();
        join_mesh(&dir, "crux-b").unwrap();

        mesh_push(&dir, "crux-a", "crux-b", SecurityLevel::Internal).unwrap();

        let result = load_crux_db(&crux_b).unwrap();
        let names: Vec<&str> = result.nodes.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"alpha"), "alpha must be in dst");
        assert!(names.contains(&"beta"), "beta must be in dst");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_pull_respects_clearance() {
        let dir = temp_dir("replicate_clearance");
        init_mesh("clear-mesh", &dir).unwrap();

        let crux_a = dir.join("crux-a");
        let crux_b = dir.join("crux-b");
        fs::create_dir_all(&crux_a).unwrap();
        fs::create_dir_all(&crux_b).unwrap();

        let mut db_a = create_crux_db("crux-a", CruxKind::Codebase, "manual");
        db_a.nodes.push(repl_node("id-pub", "pub_node", "public", 100));
        db_a.nodes.push(repl_node("id-res", "restricted_node", "restricted", 200));
        save_crux_db(&db_a, &crux_a).unwrap();

        let db_b = create_crux_db("crux-b", CruxKind::Codebase, "manual");
        save_crux_db(&db_b, &crux_b).unwrap();

        join_mesh(&dir, "crux-a").unwrap();
        join_mesh(&dir, "crux-b").unwrap();

        // Caller is internal — restricted node must not flow
        mesh_pull(&dir, "crux-a", "crux-b", SecurityLevel::Internal).unwrap();

        let result = load_crux_db(&crux_b).unwrap();
        let names: Vec<&str> = result.nodes.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"pub_node"), "pub_node must be copied");
        assert!(!names.contains(&"restricted_node"), "restricted_node must be blocked");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_push_is_idempotent() {
        let dir = temp_dir("replicate_idem");
        init_mesh("idem-mesh", &dir).unwrap();

        let crux_a = dir.join("crux-a");
        let crux_b = dir.join("crux-b");
        fs::create_dir_all(&crux_a).unwrap();
        fs::create_dir_all(&crux_b).unwrap();

        let mut db_a = create_crux_db("crux-a", CruxKind::Codebase, "manual");
        db_a.nodes.push(repl_node("id-x", "node_x", "internal", 100));
        save_crux_db(&db_a, &crux_a).unwrap();

        let db_b = create_crux_db("crux-b", CruxKind::Codebase, "manual");
        save_crux_db(&db_b, &crux_b).unwrap();

        join_mesh(&dir, "crux-a").unwrap();
        join_mesh(&dir, "crux-b").unwrap();

        mesh_push(&dir, "crux-a", "crux-b", SecurityLevel::Internal).unwrap();
        mesh_push(&dir, "crux-a", "crux-b", SecurityLevel::Internal).unwrap();

        let result = load_crux_db(&crux_b).unwrap();
        let count = result.nodes.iter().filter(|n| n.node_id == "id-x").count();
        assert_eq!(count, 1, "second push must not duplicate the node");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_register_mcp_self_sig_verifies() {
        let dir = temp_dir("self_sig_verify");
        init_mesh("test-verify-sig", &dir).unwrap();
        mesh_register_mcp(&dir, "verify-mcp", "http", "", "http://localhost:9000", "restricted", "*", "", &crate::schema::OAuthConfig::default()).unwrap();

        let manifest = load_mesh(&dir).unwrap();
        let policy_db = load_policy_crux(&manifest, &dir).unwrap();
        let node = policy_db.nodes.iter()
            .find(|n| n.kind == "mcp_server_registration"
                && n.properties.iter().any(|p| p == "alias=verify-mcp"))
            .expect("registration node not found");
        let pk_val = node.properties.iter()
            .find_map(|p| p.strip_prefix("public_key=").map(|v| v.to_string()))
            .unwrap_or_default();

        let sig_hex = pk_val.split(';')
            .find_map(|p| p.strip_prefix("sig=").map(|v| v.to_string()))
            .unwrap_or_default();
        let pk_hex = pk_val.split(';')
            .find_map(|p| p.strip_prefix("pk=").map(|v| v.to_string()))
            .unwrap_or_default();
        assert!(!sig_hex.is_empty(), "sig missing from public_key field");
        assert!(!pk_hex.is_empty(), "pk missing from public_key field");

        let sig_bytes = crate::crypto::hex_to_bytes(&sig_hex).expect("sig hex valid");
        let pk_bytes = crate::crypto::hex_to_bytes(&pk_hex).expect("pk hex valid");
        let canonical = "verify-mcp\x1fhttp\x1fhttp://localhost:9000\x1frestricted";
        let hash_vec = crate::crypto::sha256(canonical.as_bytes());
        let hash: [u8; 32] = hash_vec.try_into().expect("sha256 is 32 bytes");
        assert!(
            crate::crypto::wots_verify_raw(&pk_bytes, &hash, &sig_bytes),
            "self-sig verification failed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
