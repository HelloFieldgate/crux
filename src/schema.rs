//! Universal Crux Schema v2 — the core data model for Crux Mesh.
//!
//! Defines language-agnostic knowledge graph structures that can represent
//! code, documentation, preferences, organizational values, skillsets, and
//! any other structured knowledge source.

use std::fmt;
use std::fmt::Write as FmtWrite;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::sha256_hex;
use crate::json::{
    extract_bool_value, extract_json_objects_from_array, extract_string_array, extract_string_value,
    extract_u64_value, find_json_key, is_null_value, json_escape, json_opt_str, json_opt_u64,
    json_opt_u8, json_str_array,
};

// ===========================================================================
// Enums
// ===========================================================================

/// The kind of knowledge a crux represents.
#[derive(Debug, Clone, PartialEq)]
pub enum CruxKind {
    Codebase,
    Documentation,
    Preferences,
    Organization,
    Skillset,
    Api,
    Dataset,
    Policy,  // Special crux containing mesh security and organizational parameters
    Custom(String),
}

impl CruxKind {
    pub fn as_str(&self) -> &str {
        match self {
            CruxKind::Codebase => "codebase",
            CruxKind::Documentation => "documentation",
            CruxKind::Preferences => "preferences",
            CruxKind::Organization => "organization",
            CruxKind::Skillset => "skillset",
            CruxKind::Api => "api",
            CruxKind::Dataset => "dataset",
            CruxKind::Policy => "policy",
            CruxKind::Custom(s) => s,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> CruxKind {
        match s {
            "codebase" => CruxKind::Codebase,
            "documentation" => CruxKind::Documentation,
            "preferences" => CruxKind::Preferences,
            "organization" => CruxKind::Organization,
            "skillset" => CruxKind::Skillset,
            "api" => CruxKind::Api,
            "dataset" => CruxKind::Dataset,
            "policy" => CruxKind::Policy,
            other => CruxKind::Custom(other.to_string()),
        }
    }
}

impl fmt::Display for CruxKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The kind of relationship an edge represents.
#[derive(Debug, Clone, PartialEq)]
pub enum EdgeKind {
    // Structural
    Calls,
    Imports,
    Contains,
    Extends,
    Implements,
    // Data
    DataFlow,
    Reads,
    Writes,
    Transforms,
    Produces,
    // Semantic
    RelatesTo,
    Contradicts,
    Supersedes,
    Exemplifies,
    // Domain
    BelongsToDomain,
    Tagged,
    // Mesh
    MeshLink,
}

impl EdgeKind {
    pub fn as_str(&self) -> &str {
        match self {
            EdgeKind::Calls => "calls",
            EdgeKind::Imports => "imports",
            EdgeKind::Contains => "contains",
            EdgeKind::Extends => "extends",
            EdgeKind::Implements => "implements",
            EdgeKind::DataFlow => "data_flow",
            EdgeKind::Reads => "reads",
            EdgeKind::Writes => "writes",
            EdgeKind::Transforms => "transforms",
            EdgeKind::Produces => "produces",
            EdgeKind::RelatesTo => "relates_to",
            EdgeKind::Contradicts => "contradicts",
            EdgeKind::Supersedes => "supersedes",
            EdgeKind::Exemplifies => "exemplifies",
            EdgeKind::BelongsToDomain => "belongs_to_domain",
            EdgeKind::Tagged => "tagged",
            EdgeKind::MeshLink => "mesh_link",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> EdgeKind {
        match s {
            "calls" => EdgeKind::Calls,
            "imports" => EdgeKind::Imports,
            "contains" => EdgeKind::Contains,
            "extends" => EdgeKind::Extends,
            "implements" => EdgeKind::Implements,
            "data_flow" => EdgeKind::DataFlow,
            "reads" => EdgeKind::Reads,
            "writes" => EdgeKind::Writes,
            "transforms" => EdgeKind::Transforms,
            "produces" => EdgeKind::Produces,
            "relates_to" => EdgeKind::RelatesTo,
            "contradicts" => EdgeKind::Contradicts,
            "supersedes" => EdgeKind::Supersedes,
            "exemplifies" => EdgeKind::Exemplifies,
            "belongs_to_domain" => EdgeKind::BelongsToDomain,
            "tagged" => EdgeKind::Tagged,
            "mesh_link" => EdgeKind::MeshLink,
            _ => EdgeKind::RelatesTo, // fallback
        }
    }
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ===========================================================================
// Core structs
// ===========================================================================

/// A record of one mesh this crux belongs to.
/// Stored in the crux file so the crux is aware of its mesh memberships.
/// Only the public key hash is stored here — actual keypairs live in each
/// mesh's manifest, preventing cross-mesh key leakage.
#[derive(Debug, Clone, PartialEq)]
pub struct MeshMembership {
    pub mesh_id: String,
    pub mesh_name: String,
    pub joined_at: u64,
    pub cluster: Option<String>,
    pub public_key_hash: String,  // SHA-256 hex of the per-mesh public key
}

/// Identity and metadata for a crux.
#[derive(Debug, Clone)]
pub struct CruxHeader {
    pub crux_version: u32,
    pub crux_id: String,
    pub crux_name: String,
    pub crux_kind: CruxKind,
    pub crux_origin: String,
    pub created_at: u64,
    pub last_modified_at: u64,
    /// All meshes this crux is a member of. Empty if standalone.
    pub mesh_memberships: Vec<MeshMembership>,
}

/// Input or output slot in a node's schema.
#[derive(Debug, Clone, PartialEq)]
pub struct SchemaSlot {
    pub name: String,
    pub type_str: String,
}

/// The interface/signature of a knowledge node.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeSchema {
    pub inputs: Vec<SchemaSlot>,
    pub outputs: Vec<SchemaSlot>,
}

impl NodeSchema {
    pub fn empty() -> Self {
        NodeSchema {
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }
}

/// Planning metadata for tracking implementation progress.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanningMetadata {
    pub status: Option<String>,
    pub priority: Option<u8>,
    pub depends: Vec<String>,
    pub updated_at: Option<u64>,
    pub planned_for_update: bool,
}

impl PlanningMetadata {
    pub fn empty() -> Self {
        PlanningMetadata {
            status: None,
            priority: None,
            depends: Vec::new(),
            updated_at: None,
            planned_for_update: false,
        }
    }

    pub fn done() -> Self {
        PlanningMetadata {
            status: Some("done".to_string()),
            priority: None,
            depends: Vec::new(),
            updated_at: None,
            planned_for_update: false,
        }
    }
}

/// Security classification for a node.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityMetadata {
    pub classification: String,
    pub redact_below: Option<String>,
}

impl SecurityMetadata {
    pub fn internal() -> Self {
        SecurityMetadata {
            classification: "internal".to_string(),
            redact_below: None,
        }
    }

    pub fn public() -> Self {
        SecurityMetadata {
            classification: "public".to_string(),
            redact_below: None,
        }
    }
}

/// A universal knowledge node — the fundamental unit of a crux.
#[derive(Debug, Clone)]
pub struct CruxNode {
    pub node_id: String,
    pub name: String,
    pub kind: String,
    pub module: String,
    pub summary: String,
    pub schema: NodeSchema,
    pub tags: Vec<String>,
    pub reach: Vec<String>,
    pub properties: Vec<String>,
    pub warnings: Vec<String>,
    pub planning: PlanningMetadata,
    pub security: SecurityMetadata,
    pub content_hash: String,
    /// Soft-deletion timestamp (None = not deleted).
    pub deleted_at: Option<u64>,
}

/// A directed edge between two nodes (within or across cruxes).
#[derive(Debug, Clone)]
pub struct CruxEdge {
    pub edge_id: String,
    pub src: String,
    pub dst: String,
    pub kind: EdgeKind,
    pub weight: f64,
    pub detail: String,
    pub cross_crux: bool,
    pub binding: String,
    pub created_at: u64,
    /// True if either endpoint has been deleted.
    pub dangling: bool,
}

/// A source file or compilation unit tracked by the crux.
#[derive(Debug, Clone)]
pub struct ModuleNode {
    pub path: String,
    pub content_hash: String,
    pub node_count: usize,
    pub last_analyzed: u64,
}

/// Domain grouping (virtual tag applied to nodes).
#[derive(Debug, Clone)]
pub struct DomainNode {
    pub tag: String,
    pub member_count: usize,
}

/// The top-level crux database — a self-contained knowledge graph.
#[derive(Debug, Clone)]
pub struct CruxDb {
    pub header: CruxHeader,
    pub nodes: Vec<CruxNode>,
    pub edges: Vec<CruxEdge>,
    pub modules: Vec<ModuleNode>,
    pub domains: Vec<DomainNode>,
}

// ===========================================================================
// Construction helpers
// ===========================================================================

/// Get the current Unix timestamp in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a crux ID from the crux name and creation timestamp.
pub fn generate_crux_id(name: &str, created_at: u64) -> String {
    let input = format!("crux:{}:{}", name, created_at);
    format!("sha256:{}", sha256_hex(input.as_bytes()))
}

/// Prefix marking a `content_hash` that this codebase computed and can therefore
/// re-derive and check.
///
/// Everything written before this existed stored something else under the same
/// field name — `sha256(name)` from `crux_add_node`, `sha256(whole document)`
/// from the markdown and plaintext adapters, `sha256(relative path)` from the
/// scanner, an opaque digest from LML, and in Helm's case a hex *timestamp*.
/// None of those can be recomputed from the node, so none of them can prove
/// anything about its contents. Tagging our own hashes distinctly is what lets
/// `verify` tell "this payload changed" apart from "this predates the check" —
/// without it, a tampered node and an adapter node look identical.
pub const CRUX_HASH_PREFIX: &str = "cruxv1:";

/// Hash a node's *authored* payload: name, kind, module, summary and tags.
///
/// Fields are length-prefixed so no two distinct nodes can collide by shifting a
/// delimiter across a boundary (`name="a:b", summary="c"` must not hash the same
/// as `name="a", summary="b:c"`).
///
/// Deliberately excluded, because each is written by machinery rather than by the
/// author and would invalidate the hash on every run:
///   - `properties` — `crux enrich` appends `file=...` entries
///   - `reach`, `warnings` — computed by enrichment
///   - `planning` — `updated_at` is stamped on every edit
///   - `security`, `node_id`, `created_at`, `deleted_at` — not payload
///
/// The hash is set when a node is *authored* (`add_node`, `update_node`) and is
/// never recomputed by a mechanical load-and-save. That is the whole point: a
/// read path that quietly mangles a summary — which is exactly what the JSON
/// escape decoder did for months — then writes it back out will no longer match,
/// and `verify` will say so.
pub fn node_content_hash(node: &CruxNode) -> String {
    fn field(buf: &mut String, s: &str) {
        let _ = write!(buf, "|{}:{}", s.len(), s);
    }
    let mut buf = String::from("cruxnode/v1");
    field(&mut buf, &node.name);
    field(&mut buf, &node.kind);
    field(&mut buf, &node.module);
    field(&mut buf, &node.summary);
    let _ = write!(buf, "|{}", node.tags.len());
    for t in &node.tags {
        field(&mut buf, t);
    }
    format!("{}{}", CRUX_HASH_PREFIX, sha256_hex(buf.as_bytes()))
}

/// What a stored `content_hash` is actually able to tell us about a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashStatus {
    /// Re-derived and matched — the authored payload is intact.
    Verified,
    /// Re-derived and did NOT match — the payload changed after it was authored.
    /// This is the only genuine tamper/corruption signal.
    Mismatch,
    /// Not one of ours: a legacy `sha256(name)`, an adapter-supplied digest, or a
    /// Helm timestamp. Shape can be checked; contents cannot.
    Unverifiable,
    /// Malformed — present but not a recognisable hash of any provenance.
    Malformed,
    /// No hash stored at all.
    Absent,
}

/// Classify a node's stored `content_hash`. See [`HashStatus`].
pub fn check_node_hash(node: &CruxNode) -> HashStatus {
    let h = node.content_hash.trim();
    if h.is_empty() || h == "sha256:" || h == CRUX_HASH_PREFIX {
        return HashStatus::Absent;
    }
    if let Some(hex) = h.strip_prefix(CRUX_HASH_PREFIX) {
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return HashStatus::Malformed;
        }
        return if h == node_content_hash(node) {
            HashStatus::Verified
        } else {
            HashStatus::Mismatch
        };
    }
    // Pre-existing provenances. A bare 64-hex digest, with or without the
    // `sha256:` prefix, is a hash we simply cannot re-derive; Helm's short hex
    // timestamps land here too. Anything else is not a hash at all.
    let body = h.strip_prefix("sha256:").unwrap_or(h);
    if !body.is_empty() && body.bytes().all(|b| b.is_ascii_hexdigit()) {
        HashStatus::Unverifiable
    } else {
        HashStatus::Malformed
    }
}

/// Generate a node ID from the node name and its content hash.
pub fn generate_node_id(name: &str, content_hash: &str) -> String {
    let input = format!("node:{}:{}", name, content_hash);
    format!("sha256:{}", sha256_hex(input.as_bytes()))
}

/// Generate an edge ID from src, dst, and kind.
pub fn generate_edge_id(src: &str, dst: &str, kind: &str) -> String {
    let input = format!("edge:{}:{}:{}", src, dst, kind);
    format!("sha256:{}", sha256_hex(input.as_bytes()))
}

/// Create a new empty CruxDb with the given name and kind.
pub fn create_crux_db(name: &str, kind: CruxKind, origin: &str) -> CruxDb {
    let ts = now_unix();
    CruxDb {
        header: CruxHeader {
            crux_version: 2,
            crux_id: generate_crux_id(name, ts),
            crux_name: name.to_string(),
            crux_kind: kind,
            crux_origin: origin.to_string(),
            created_at: ts,
            last_modified_at: ts,
            mesh_memberships: Vec::new(),
        },
        nodes: Vec::new(),
        edges: Vec::new(),
        modules: Vec::new(),
        domains: Vec::new(),
    }
}

/// Configuration for a mesh policy crux.
/// All fields have sensible defaults — only override what you need.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    // Security Policy node properties
    pub default_classification: String,
    pub cross_mesh_policy: String,      // "deny_all" | "explicit_allow" | "public_only"
    pub multi_mesh_allowed: bool,
    pub allowed_external_meshes: Vec<String>,  // mesh IDs, used with explicit_allow
    pub require_signatures: bool,
    // Organizational Policy node properties
    pub org_name: String,
    pub org_domain: String,
    pub allowed_crux_kinds: Vec<String>,  // empty = all kinds allowed
    pub max_members: Option<usize>,       // None = unlimited
    pub require_approval: bool,
    pub governance_model: String,         // "open" | "managed" | "strict"
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            default_classification: "internal".to_string(),
            cross_mesh_policy: "explicit_allow".to_string(),
            multi_mesh_allowed: true,
            allowed_external_meshes: vec![],
            require_signatures: false,
            org_name: String::new(),
            org_domain: String::new(),
            allowed_crux_kinds: vec![],
            max_members: None,
            require_approval: false,
            governance_model: "open".to_string(),
        }
    }
}

/// Get the value of a named property from the policy crux.
/// Properties are stored as "key=value" strings.
/// Searches all nodes for the first matching key.
pub fn get_policy_property(db: &CruxDb, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    for node in &db.nodes {
        for prop in &node.properties {
            if let Some(val) = prop.strip_prefix(&prefix) {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Create a policy crux for a mesh with default security and organizational parameters.
pub fn create_policy_crux(mesh_name: &str) -> CruxDb {
    create_policy_crux_with_config(mesh_name, PolicyConfig::default())
}

/// Create a policy crux with a custom PolicyConfig.
pub fn create_policy_crux_with_config(mesh_name: &str, config: PolicyConfig) -> CruxDb {
    let mut db = create_crux_db(
        &format!("{}-policy", mesh_name),
        CruxKind::Policy,
        "mesh-init"
    );

    let sec_props = vec![
        format!("default_classification={}", config.default_classification),
        format!("cross_mesh_policy={}", config.cross_mesh_policy),
        format!("multi_mesh_allowed={}", config.multi_mesh_allowed),
        format!("allowed_external_meshes={}", config.allowed_external_meshes.join(",")),
        format!("require_signatures={}", config.require_signatures),
    ];

    let org_props = vec![
        format!("org_name={}", config.org_name),
        format!("org_domain={}", config.org_domain),
        format!("allowed_crux_kinds={}", config.allowed_crux_kinds.join(",")),
        format!("max_members={}", config.max_members.map(|n| n.to_string()).unwrap_or_default()),
        format!("require_approval={}", config.require_approval),
        format!("governance_model={}", config.governance_model),
    ];

    let security_policy = CruxNode {
        node_id: generate_node_id("security-policy", "default"),
        name: "Security Policy".to_string(),
        kind: "policy".to_string(),
        module: "security".to_string(),
        summary: "Security classification levels, cross-mesh policy, and access controls".to_string(),
        schema: NodeSchema::empty(),
        tags: vec!["security".to_string(), "policy".to_string()],
        reach: vec![],
        properties: sec_props,
        warnings: vec![],
        planning: PlanningMetadata::empty(),
        security: SecurityMetadata {
            classification: "restricted".to_string(),
            redact_below: None,
        },
        content_hash: sha256_hex(b"Security policy node"),
        deleted_at: None,
    };

    let org_policy = CruxNode {
        node_id: generate_node_id("organizational-policy", "default"),
        name: "Organizational Policy".to_string(),
        kind: "policy".to_string(),
        module: "organization".to_string(),
        summary: "Organizational intent, governance parameters, and membership controls".to_string(),
        schema: NodeSchema::empty(),
        tags: vec!["organization".to_string(), "policy".to_string()],
        reach: vec![],
        properties: org_props,
        warnings: vec![],
        planning: PlanningMetadata::empty(),
        security: SecurityMetadata {
            classification: "restricted".to_string(),
            redact_below: None,
        },
        content_hash: sha256_hex(b"Organizational policy node"),
        deleted_at: None,
    };

    db.nodes.push(security_policy);
    db.nodes.push(org_policy);

    db
}

// ===========================================================================
// Serialization
// ===========================================================================

/// Serialize a CruxDb to JSON string.
pub fn serialize_crux_db(db: &CruxDb) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("{\n");

    // Header
    let _ = writeln!(out, "  \"crux_version\": {},", db.header.crux_version);
    let _ = writeln!(out, "  \"crux_id\": {},", json_escape(&db.header.crux_id));
    let _ = writeln!(out, "  \"crux_name\": {},", json_escape(&db.header.crux_name));
    let _ = writeln!(out, "  \"crux_kind\": {},", json_escape(db.header.crux_kind.as_str()));
    let _ = writeln!(out, "  \"crux_origin\": {},", json_escape(&db.header.crux_origin));
    let _ = writeln!(out, "  \"created_at\": {},", db.header.created_at);
    let _ = writeln!(out, "  \"last_modified_at\": {},", db.header.last_modified_at);

    // Mesh memberships
    out.push_str("  \"mesh_memberships\": [");
    for (i, m) in db.header.mesh_memberships.iter().enumerate() {
        if i > 0 { out.push_str(", "); }
        let _ = write!(
            out,
            "{{\"mesh_id\": {}, \"mesh_name\": {}, \"joined_at\": {}, \"cluster\": {}, \"public_key_hash\": {}}}",
            json_escape(&m.mesh_id),
            json_escape(&m.mesh_name),
            m.joined_at,
            json_opt_str(&m.cluster),
            json_escape(&m.public_key_hash),
        );
    }
    out.push_str("],\n");

    // Modules
    out.push_str("  \"modules\": [");
    for (i, m) in db.modules.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push_str("\n    {");
        let _ = write!(out, " \"path\": {}", json_escape(&m.path));
        let _ = write!(out, ", \"content_hash\": {}", json_escape(&m.content_hash));
        let _ = write!(out, ", \"node_count\": {}", m.node_count);
        let _ = write!(out, ", \"last_analyzed\": {}", m.last_analyzed);
        out.push_str(" }");
    }
    out.push_str("\n  ],\n");

    // Domains
    out.push_str("  \"domains\": [");
    for (i, d) in db.domains.iter().enumerate() {
        if i > 0 { out.push(','); }
        let _ = write!(out, "\n    {{ \"tag\": {}, \"member_count\": {} }}", json_escape(&d.tag), d.member_count);
    }
    out.push_str("\n  ],\n");

    // Nodes
    out.push_str("  \"nodes\": [");
    for (i, n) in db.nodes.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push_str("\n    {\n");
        let _ = writeln!(out, "      \"node_id\": {},", json_escape(&n.node_id));
        let _ = writeln!(out, "      \"name\": {},", json_escape(&n.name));
        let _ = writeln!(out, "      \"kind\": {},", json_escape(&n.kind));
        let _ = writeln!(out, "      \"module\": {},", json_escape(&n.module));
        let _ = writeln!(out, "      \"summary\": {},", json_escape(&n.summary));

        // Schema
        out.push_str("      \"schema\": {\n");
        out.push_str("        \"inputs\": [");
        for (j, slot) in n.schema.inputs.iter().enumerate() {
            if j > 0 { out.push_str(", "); }
            let _ = write!(out, "{{ \"name\": {}, \"type\": {} }}", json_escape(&slot.name), json_escape(&slot.type_str));
        }
        out.push_str("],\n");
        out.push_str("        \"outputs\": [");
        for (j, slot) in n.schema.outputs.iter().enumerate() {
            if j > 0 { out.push_str(", "); }
            let _ = write!(out, "{{ \"name\": {}, \"type\": {} }}", json_escape(&slot.name), json_escape(&slot.type_str));
        }
        out.push_str("]\n");
        out.push_str("      },\n");

        let _ = writeln!(out, "      \"tags\": {},", json_str_array(&n.tags));
        let _ = writeln!(out, "      \"reach\": {},", json_str_array(&n.reach));
        let _ = writeln!(out, "      \"properties\": {},", json_str_array(&n.properties));
        let _ = writeln!(out, "      \"warnings\": {},", json_str_array(&n.warnings));

        // Planning
        out.push_str("      \"planning\": {\n");
        let _ = writeln!(out, "        \"status\": {},", json_opt_str(&n.planning.status));
        let _ = writeln!(out, "        \"priority\": {},", json_opt_u8(&n.planning.priority));
        let _ = writeln!(out, "        \"depends\": {},", json_str_array(&n.planning.depends));
        let _ = writeln!(out, "        \"updated_at\": {},", json_opt_u64(&n.planning.updated_at));
        let _ = writeln!(out, "        \"planned_for_update\": {}", n.planning.planned_for_update);
        out.push_str("      },\n");

        // Security
        out.push_str("      \"security\": {\n");
        let _ = writeln!(out, "        \"classification\": {},", json_escape(&n.security.classification));
        let _ = writeln!(out, "        \"redact_below\": {}", json_opt_str(&n.security.redact_below));
        out.push_str("      },\n");

        let _ = writeln!(out, "      \"content_hash\": {},", json_escape(&n.content_hash));
        let _ = writeln!(out, "      \"deleted_at\": {}", json_opt_u64(&n.deleted_at));
        out.push_str("    }");
    }
    out.push_str("\n  ],\n");

    // Edges
    out.push_str("  \"edges\": [");
    for (i, e) in db.edges.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push_str("\n    {");
        let _ = write!(out, " \"edge_id\": {}", json_escape(&e.edge_id));
        let _ = write!(out, ", \"src\": {}", json_escape(&e.src));
        let _ = write!(out, ", \"dst\": {}", json_escape(&e.dst));
        let _ = write!(out, ", \"kind\": {}", json_escape(e.kind.as_str()));
        let _ = write!(out, ", \"weight\": {}", e.weight);
        let _ = write!(out, ", \"detail\": {}", json_escape(&e.detail));
        let _ = write!(out, ", \"cross_crux\": {}", e.cross_crux);
        let _ = write!(out, ", \"binding\": {}", json_escape(&e.binding));
        let _ = write!(out, ", \"created_at\": {}", e.created_at);
        let _ = write!(out, ", \"dangling\": {}", e.dangling);
        out.push_str(" }");
    }
    out.push_str("\n  ]\n");

    out.push_str("}\n");
    out
}

// ===========================================================================
// Deserialization
// ===========================================================================

/// Parse a CruxDb from a JSON string.
pub fn parse_crux_db(text: &str) -> Result<CruxDb, String> {
    // Header fields
    let crux_version = extract_u64_value(text, "crux_version").unwrap_or(2) as u32;
    let crux_id = extract_string_value(text, "crux_id").unwrap_or_default();
    let crux_name = extract_string_value(text, "crux_name").unwrap_or_default();
    let crux_kind_str = extract_string_value(text, "crux_kind").unwrap_or_else(|| "codebase".to_string());
    let crux_origin = extract_string_value(text, "crux_origin").unwrap_or_else(|| "unknown".to_string());
    let created_at = extract_u64_value(text, "created_at").unwrap_or(0);
    let last_modified_at = extract_u64_value(text, "last_modified_at").unwrap_or(0);

    // Parse mesh_memberships (backward compatible — missing field → empty vec)
    let mesh_memberships = parse_mesh_memberships(text);

    let header = CruxHeader {
        crux_version,
        crux_id,
        crux_name,
        crux_kind: CruxKind::from_str(&crux_kind_str),
        crux_origin,
        created_at,
        last_modified_at,
        mesh_memberships,
    };

    // Parse nodes
    let nodes = parse_nodes(text);

    // Parse edges
    let edges = parse_edges(text);

    // Parse modules
    let modules = parse_modules(text);

    // Parse domains
    let domains = parse_domains(text);

    Ok(CruxDb {
        header,
        nodes,
        edges,
        modules,
        domains,
    })
}

/// Parse the "nodes" array from JSON text.
fn parse_nodes(text: &str) -> Vec<CruxNode> {
    let mut nodes = Vec::new();
    let nodes_start = match find_json_key(text, "\"nodes\"") {
        Some(i) => i,
        None => return nodes,
    };
    let after = &text[nodes_start..];
    let bracket = match after.find('[') {
        Some(i) => i,
        None => return nodes,
    };
    let array_text = &after[bracket..];

    // Split on node objects with the shared string-aware scanner, so structural
    // brackets inside string values (e.g. a `summary` containing `{children && (`)
    // don't corrupt the depth counter and silently drop this node and all after it.
    for obj in extract_json_objects_from_array(array_text) {
        nodes.push(parse_single_node(&obj));
    }
    nodes
}

/// Parse a single node JSON object.
fn parse_single_node(obj: &str) -> CruxNode {
    let node_id = extract_string_value(obj, "node_id").unwrap_or_default();
    let name = extract_string_value(obj, "name").unwrap_or_default();
    let kind = extract_string_value(obj, "kind").unwrap_or_else(|| "function".to_string());
    let module = extract_string_value(obj, "module").unwrap_or_default();
    let summary = extract_string_value(obj, "summary").unwrap_or_default();
    let tags = extract_string_array(obj, "tags");
    let reach = extract_string_array(obj, "reach");
    let properties = extract_string_array(obj, "properties");
    let warnings = extract_string_array(obj, "warnings");
    let content_hash = extract_string_value(obj, "content_hash").unwrap_or_default();

    // Parse schema inputs/outputs
    let inputs = parse_schema_slots(obj, "inputs");
    let outputs = parse_schema_slots(obj, "outputs");

    // Planning
    let status = extract_string_value(obj, "status");
    let priority = extract_u64_value(obj, "priority").map(|v| v as u8);
    let depends = extract_string_array(obj, "depends");
    let updated_at = extract_u64_value(obj, "updated_at");
    let planned_for_update = extract_bool_value(obj, "planned_for_update").unwrap_or(false);

    // Security
    let classification = extract_string_value(obj, "classification")
        .unwrap_or_else(|| "internal".to_string());
    let redact_below = if is_null_value(obj, "redact_below") {
        None
    } else {
        extract_string_value(obj, "redact_below")
    };

    let deleted_at = extract_u64_value(obj, "deleted_at");

    CruxNode {
        node_id,
        name,
        kind,
        module,
        summary,
        schema: NodeSchema { inputs, outputs },
        tags,
        reach,
        properties,
        warnings,
        planning: PlanningMetadata {
            status,
            priority,
            depends,
            updated_at,
            planned_for_update,
        },
        security: SecurityMetadata {
            classification,
            redact_below,
        },
        content_hash,
        deleted_at,
    }
}

/// Parse schema slots (inputs or outputs) from a node object.
fn parse_schema_slots(obj: &str, key: &str) -> Vec<SchemaSlot> {
    let mut slots = Vec::new();
    let pattern = format!("\"{}\"", key);
    let idx = match obj.find(&pattern) {
        Some(i) => i,
        None => return slots,
    };
    let after = &obj[idx + pattern.len()..];
    let bracket = match after.find('[') {
        Some(i) => i,
        None => return slots,
    };
    let array_text = &after[bracket..];

    // Split each { "name": ..., "type": ... } string-awarely.
    for slot_obj in extract_json_objects_from_array(array_text) {
        let name = extract_string_value(&slot_obj, "name").unwrap_or_default();
        let type_str = extract_string_value(&slot_obj, "type").unwrap_or_default();
        slots.push(SchemaSlot { name, type_str });
    }
    slots
}

/// Parse the "edges" array from JSON text.
fn parse_edges(text: &str) -> Vec<CruxEdge> {
    let mut edges = Vec::new();
    let edges_start = match find_json_key(text, "\"edges\"") {
        Some(i) => i,
        None => return edges,
    };
    let after = &text[edges_start..];
    let bracket = match after.find('[') {
        Some(i) => i,
        None => return edges,
    };
    let array_text = &after[bracket..];

    for obj in extract_json_objects_from_array(array_text) {
        let obj = obj.as_str();
        let edge_id = extract_string_value(obj, "edge_id").unwrap_or_default();
        let src = extract_string_value(obj, "src").unwrap_or_default();
        let dst = extract_string_value(obj, "dst").unwrap_or_default();
        let kind_str = extract_string_value(obj, "kind").unwrap_or_else(|| "relates_to".to_string());
        let weight = extract_weight(obj);
        let detail = extract_string_value(obj, "detail").unwrap_or_default();
        let cross_crux = extract_bool_value(obj, "cross_crux").unwrap_or(false);
        let binding = extract_string_value(obj, "binding").unwrap_or_default();
        let created_at = extract_u64_value(obj, "created_at").unwrap_or(0);
        let dangling = extract_bool_value(obj, "dangling").unwrap_or(false);

        edges.push(CruxEdge {
            edge_id,
            src,
            dst,
            kind: EdgeKind::from_str(&kind_str),
            weight,
            detail,
            cross_crux,
            binding,
            created_at,
            dangling,
        });
    }
    edges
}

/// Extract a float "weight" value from a JSON object.
fn extract_weight(obj: &str) -> f64 {
    let pattern = "\"weight\"";
    let idx = match obj.find(pattern) {
        Some(i) => i,
        None => return 1.0,
    };
    let after = &obj[idx + pattern.len()..];
    let after_colon = match after.trim_start().strip_prefix(':') {
        Some(s) => s,
        None => return 1.0,
    };
    let trimmed = after_colon.trim_start();
    let num_str: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    num_str.parse().unwrap_or(1.0)
}

/// Parse the "modules" array from JSON text.
fn parse_modules(text: &str) -> Vec<ModuleNode> {
    let mut modules = Vec::new();
    let start = match find_json_key(text, "\"modules\"") {
        Some(i) => i,
        None => return modules,
    };
    let after = &text[start..];
    let bracket = match after.find('[') {
        Some(i) => i,
        None => return modules,
    };
    let array_text = &after[bracket..];

    for obj in extract_json_objects_from_array(array_text) {
        let obj = obj.as_str();
        let path = extract_string_value(obj, "path").unwrap_or_default();
        let content_hash = extract_string_value(obj, "content_hash").unwrap_or_default();
        let node_count = extract_u64_value(obj, "node_count").unwrap_or(0) as usize;
        let last_analyzed = extract_u64_value(obj, "last_analyzed").unwrap_or(0);
        modules.push(ModuleNode { path, content_hash, node_count, last_analyzed });
    }
    modules
}

/// Parse the "domains" array from JSON text.
fn parse_domains(text: &str) -> Vec<DomainNode> {
    let mut domains = Vec::new();
    let start = match find_json_key(text, "\"domains\"") {
        Some(i) => i,
        None => return domains,
    };
    let after = &text[start..];
    let bracket = match after.find('[') {
        Some(i) => i,
        None => return domains,
    };
    let array_text = &after[bracket..];

    for obj in extract_json_objects_from_array(array_text) {
        let tag = extract_string_value(&obj, "tag").unwrap_or_default();
        let member_count = extract_u64_value(&obj, "member_count").unwrap_or(0) as usize;
        domains.push(DomainNode { tag, member_count });
    }
    domains
}

/// Parse the "mesh_memberships" array from JSON text.
/// Returns empty vec if the field is missing (backward compatible).
fn parse_mesh_memberships(text: &str) -> Vec<MeshMembership> {
    let mut memberships = Vec::new();
    let start = match find_json_key(text, "\"mesh_memberships\"") {
        Some(i) => i,
        None => return memberships,
    };
    let after = &text[start..];
    let bracket = match after.find('[') {
        Some(i) => i,
        None => return memberships,
    };
    let array_text = &after[bracket..];

    for obj in extract_json_objects_from_array(array_text) {
        let obj = obj.as_str();
        let mesh_id   = extract_string_value(obj, "mesh_id").unwrap_or_default();
        let mesh_name = extract_string_value(obj, "mesh_name").unwrap_or_default();
        let joined_at = extract_u64_value(obj, "joined_at").unwrap_or(0);
        let cluster   = extract_string_value(obj, "cluster");
        let public_key_hash = extract_string_value(obj, "public_key_hash").unwrap_or_default();
        memberships.push(MeshMembership { mesh_id, mesh_name, joined_at, cluster, public_key_hash });
    }
    memberships
}

// ===========================================================================
// File I/O
// ===========================================================================

/// Compute transitive reach for every non-deleted node in the graph.
///
/// For each node, `reach` is populated with the names of all nodes reachable
/// by following `imports`, `calls`, or `data_flow` edges (directed, outbound).
/// Only nodes that exist in the graph are included.
pub fn compute_reach(db: &mut CruxDb) {
    use std::collections::{HashMap, HashSet, VecDeque};

    // Build adjacency map: src -> Vec<dst> for dependency-style edges
    let traversal_kinds = ["imports", "calls", "data_flow"];
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in &db.edges {
        if edge.dangling { continue; }
        let kind_str = edge.kind.as_str();
        if traversal_kinds.contains(&kind_str) {
            adj.entry(&edge.src).or_default().push(&edge.dst);
        }
    }

    // Collect live node names for membership check
    let live_names: HashSet<&str> = db.nodes.iter()
        .filter(|n| n.deleted_at.is_none())
        .map(|n| n.name.as_str())
        .collect();

    // BFS from each node to compute its reachable set
    let node_names: Vec<String> = db.nodes.iter()
        .filter(|n| n.deleted_at.is_none())
        .map(|n| n.name.clone())
        .collect();

    let mut reach_map: HashMap<String, Vec<String>> = HashMap::new();
    for start in &node_names {
        let mut visited: HashSet<&str> = HashSet::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        queue.push_back(start.as_str());
        while let Some(cur) = queue.pop_front() {
            if !visited.insert(cur) { continue; }
            if let Some(neighbors) = adj.get(cur) {
                for &nb in neighbors {
                    if live_names.contains(nb) && !visited.contains(nb) {
                        queue.push_back(nb);
                    }
                }
            }
        }
        visited.remove(start.as_str()); // exclude self
        let mut reachable: Vec<String> = visited.into_iter()
            .map(|s| s.to_string())
            .collect();
        reachable.sort();
        reach_map.insert(start.clone(), reachable);
    }

    // Write back
    for node in db.nodes.iter_mut() {
        if node.deleted_at.is_some() { continue; }
        if let Some(reach) = reach_map.remove(&node.name) {
            node.reach = reach;
        }
    }
}

/// Save a CruxDb to a `.crux.json` file.
pub fn save_crux_db(db: &CruxDb, path: &std::path::Path) -> Result<(), String> {
    let file_path = if path.is_dir() {
        path.join(".crux.json")
    } else {
        path.to_path_buf()
    };
    let json = serialize_crux_db(db);
    std::fs::write(&file_path, json)
        .map_err(|e| format!("Failed to write {}: {}", file_path.display(), e))
}

/// Load a CruxDb from a `.crux.json` file.
/// If `path` is a directory, loads `.crux.json` from inside it.
pub fn load_crux_db(path: &std::path::Path) -> Result<CruxDb, String> {
    let file_path = if path.is_dir() {
        path.join(".crux.json")
    } else {
        path.to_path_buf()
    };
    let text = std::fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read {}: {}", file_path.display(), e))?;
    parse_crux_db(&text)
}

/// Get the `.crux.json` path adjacent to a given file.
pub fn crux_db_path(source_path: &std::path::Path) -> std::path::PathBuf {
    let stem = source_path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy();
    source_path.with_file_name(format!("{}.crux.json", stem))
}

// ===========================================================================
// Referential integrity
// ===========================================================================

/// Why an edge fails to resolve against the nodes in its own crux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DanglingSides {
    pub src_missing: bool,
    pub dst_missing: bool,
}

impl DanglingSides {
    /// Human-readable reason naming every side that failed, e.g.
    /// `"src not found, dst not found"`.
    pub fn reason(&self) -> String {
        match (self.src_missing, self.dst_missing) {
            (true, true) => "src not found, dst not found".to_string(),
            (true, false) => "src not found".to_string(),
            (false, true) => "dst not found".to_string(),
            (false, false) => String::new(),
        }
    }
}

/// Test whether `name` resolves to a live (non-soft-deleted) node.
pub fn node_exists(db: &CruxDb, name: &str) -> bool {
    db.nodes.iter().any(|n| n.name == name && n.deleted_at.is_none())
}

/// Find every edge whose `src` or `dst` does not resolve to a live node.
///
/// Membership is recomputed from the current node set rather than read from
/// the stored `dangling` flag: the flag records what was true when the edge was
/// written, so it goes stale when a node is added or soft-deleted afterwards,
/// and it is simply absent from hand-edited or externally-generated files.
/// Integrity reporting must not trust a self-declared health bit.
pub fn dangling_edges(db: &CruxDb) -> Vec<(&CruxEdge, DanglingSides)> {
    let live: std::collections::HashSet<&str> = db
        .nodes
        .iter()
        .filter(|n| n.deleted_at.is_none())
        .map(|n| n.name.as_str())
        .collect();

    db.edges
        .iter()
        .filter_map(|e| {
            let sides = DanglingSides {
                src_missing: !live.contains(e.src.as_str()),
                dst_missing: !live.contains(e.dst.as_str()),
            };
            if sides.src_missing || sides.dst_missing {
                Some((e, sides))
            } else {
                None
            }
        })
        .collect()
}

// ===========================================================================
// Summary / Display
// ===========================================================================

/// Generate a compact text summary of a CruxDb (similar to LML's format_crux).
pub fn format_crux_summary(db: &CruxDb, max_nodes: Option<usize>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "CRUX MESH \"{}\"", db.header.crux_name);
    let _ = writeln!(out, "  Kind: {} (origin: {})", db.header.crux_kind, db.header.crux_origin);
    let dangling = dangling_edges(db).len();
    let edge_note = if dangling > 0 {
        format!(" ({} dangling)", dangling)
    } else {
        String::new()
    };
    let _ = writeln!(out, "  {} nodes, {} edges{}, {} modules",
        db.nodes.len(), db.edges.len(), edge_note, db.modules.len());

    if !db.domains.is_empty() {
        let tags: Vec<&str> = db.domains.iter().map(|d| d.tag.as_str()).collect();
        let _ = writeln!(out, "  Domains: {}", tags.join(", "));
    }

    // Status summary
    let done = db.nodes.iter().filter(|n| n.planning.status.as_deref() == Some("done")).count();
    let total = db.nodes.len();
    if total > 0 {
        let _ = writeln!(out, "  Status: {}/{} done", done, total);
    }

    let _ = writeln!(out, "  Key nodes:");
    let limit = max_nodes.unwrap_or(8).min(db.nodes.len());
    for node in db.nodes.iter().take(limit) {
        let status_tag = match &node.planning.status {
            Some(s) => format!(" {{{}}}", s),
            None => String::new(),
        };
        let tags_str = if node.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", node.tags.join(" "))
        };
        let _ = writeln!(out, "    {} ({}){}{} -- \"{}\"",
            node.name, node.kind, tags_str, status_tag, node.summary);
    }
    if db.nodes.len() > limit {
        let _ = writeln!(out, "    ... and {} more", db.nodes.len() - limit);
    }

    out
}

// ===========================================================================
// MCP Server Registration
// ===========================================================================

/// Transport mechanism for reaching an external MCP server.
#[derive(Debug, Clone, PartialEq)]
pub enum McpTransport {
    /// Local subprocess communicating over stdio (JSON-RPC 2.0).
    Stdio,
    /// Remote server reachable via HTTP (MCP over HTTP).
    Http,
}

impl McpTransport {
    pub fn as_str(&self) -> &str {
        match self {
            McpTransport::Stdio => "stdio",
            McpTransport::Http => "http",
        }
    }

    pub fn from_str(s: &str) -> Option<McpTransport> {
        match s {
            "stdio" => Some(McpTransport::Stdio),
            "http" => Some(McpTransport::Http),
            _ => None,
        }
    }
}

/// Minimum security clearance required before the router will forward a call
/// to this MCP server.  Mirrors the four `SecurityLevel` values in mesh.rs.
#[derive(Debug, Clone, PartialEq)]
pub enum McpClearance {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl McpClearance {
    pub fn as_str(&self) -> &str {
        match self {
            McpClearance::Public => "public",
            McpClearance::Internal => "internal",
            McpClearance::Confidential => "confidential",
            McpClearance::Restricted => "restricted",
        }
    }

    pub fn from_str(s: &str) -> Option<McpClearance> {
        match s {
            "public" => Some(McpClearance::Public),
            "internal" => Some(McpClearance::Internal),
            "confidential" => Some(McpClearance::Confidential),
            "restricted" => Some(McpClearance::Restricted),
            _ => None,
        }
    }
}

/// Typed representation of an `mcp_server_registration` node stored in a
/// policy crux.  All fields map 1-to-1 to `key=value` entries in
/// `CruxNode.properties`.
#[derive(Debug, Clone, PartialEq)]
pub struct McpServerRegistration {
    /// Short, unique routing key used by agents to address this server.
    pub alias: String,
    /// How to reach the server.
    pub transport: McpTransport,
    /// Argv for `transport=stdio` (e.g. `"my-tool --mcp"`).  Empty for HTTP.
    pub command: String,
    /// Base URL for `transport=http`.  Empty for stdio.
    pub url: String,
    /// Clearance gate — the calling agent must hold at least this level.
    pub required_clearance: McpClearance,
    /// Comma-separated tool names the router will forward.  `"*"` = all.
    pub allowed_tools: String,
    /// Hex-encoded W-OTS public key for manifest signature verification
    /// (Phase 1+).  Empty until signing is wired.
    pub public_key: String,
    /// Whether every forwarded call must produce an audit-log entry (Phase 1+).
    pub audit_required: bool,
    /// JSON-escaped snapshot of the server's `tools/list` response for offline
    /// policy authoring.  Empty until first `mesh_register_mcp` sync.
    pub capability_manifest: String,
    /// Optional rate limit in "N/W" format: N calls per W-second window (e.g. "60/60").
    /// `None` means no limit.
    pub rate_limit: Option<String>,
    /// Lifecycle status: `"approved"` (active), `"proposed"` (pending approval),
    /// or `"revoked"`. Defaults to `"approved"` for back-compat.
    pub status: String,
    /// How this registration was created: `"manual"`, `"manifest:<path>"`,
    /// `"detect:<client>"`, etc.
    pub source: String,
    /// Stable content fingerprint (sha256 of alias|transport|command|url).
    /// Used to detect duplicate or updated entries from discovery sources.
    pub fingerprint: String,
    /// Unix timestamp when this entry was first discovered (None for manual registrations).
    pub discovered_at: Option<u64>,
    // --- OAuth 2.1 client configuration (Phase 1) ---
    /// Authentication method: `"none"` (default) or `"oauth2"`.
    pub auth: String,
    /// OAuth 2.1 client ID (empty unless auth=oauth2).
    pub oauth_client_id: String,
    /// OAuth scopes, space-separated per RFC 6749 §3.3 (empty unless auth=oauth2).
    pub oauth_scopes: String,
    /// RFC 9728/8414 authorization server metadata URL.  Empty = use explicit endpoints.
    pub oauth_discovery_url: String,
    /// Explicit authorization endpoint (used when oauth_discovery_url is empty).
    pub oauth_authorization_endpoint: String,
    /// Token endpoint.
    pub oauth_token_endpoint: String,
    /// Dynamic Client Registration endpoint (RFC 7591).  Empty = no DCR.
    pub oauth_registration_endpoint: String,
}

/// OAuth 2.1 client configuration passed to MCP registration entry points.
///
/// All fields default to empty / `"none"`.  Callers that do not need OAuth
/// can pass `&OAuthConfig::default()`.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Authentication method: `"none"` (default) or `"oauth2"`.
    pub auth: String,
    /// OAuth 2.1 client ID.
    pub client_id: String,
    /// Space-separated scopes (RFC 6749 §3.3).
    pub scopes: String,
    /// RFC 9728/8414 authorization server metadata URL.
    pub discovery_url: String,
    /// Explicit authorization endpoint (used when discovery_url is empty).
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// Dynamic Client Registration endpoint (RFC 7591).
    pub registration_endpoint: String,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            auth: "none".to_string(),
            client_id: String::new(),
            scopes: String::new(),
            discovery_url: String::new(),
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            registration_endpoint: String::new(),
        }
    }
}

/// Build an `mcp_server_registration` node ready for insertion into a policy crux.
///
/// Classification is always `restricted` — MCP server registrations encode
/// trust relationships and must never leak to lower-clearance agents.
pub fn build_mcp_server_registration(reg: &McpServerRegistration) -> CruxNode {
    let content = format!("mcp-reg:{}:{}", reg.alias, reg.transport.as_str());
    let mut properties = vec![
        format!("alias={}", reg.alias),
        format!("transport={}", reg.transport.as_str()),
        format!("command={}", reg.command),
        format!("url={}", reg.url),
        format!("required_clearance={}", reg.required_clearance.as_str()),
        format!("allowed_tools={}", reg.allowed_tools),
        format!("public_key={}", reg.public_key),
        format!("audit_required={}", reg.audit_required),
        format!("capability_manifest={}", reg.capability_manifest),
    ];
    if let Some(ref rl) = reg.rate_limit {
        properties.push(format!("rate_limit={}", rl));
    }
    let status = if reg.status.is_empty() { "approved" } else { &reg.status };
    properties.push(format!("status={status}"));
    let source = if reg.source.is_empty() { "manual" } else { &reg.source };
    properties.push(format!("source={source}"));
    if !reg.fingerprint.is_empty() {
        properties.push(format!("fingerprint={}", reg.fingerprint));
    }
    if let Some(ts) = reg.discovered_at {
        properties.push(format!("discovered_at={ts}"));
    }
    // OAuth fields — only emitted when auth=oauth2; auth=none/absent leaves the
    // properties vec byte-identical to the pre-Phase-1 format.
    if reg.auth == "oauth2" {
        properties.push(format!("auth={}", reg.auth));
        if !reg.oauth_client_id.is_empty() {
            properties.push(format!("oauth_client_id={}", reg.oauth_client_id));
        }
        if !reg.oauth_scopes.is_empty() {
            properties.push(format!("oauth_scopes={}", reg.oauth_scopes));
        }
        if !reg.oauth_discovery_url.is_empty() {
            properties.push(format!("oauth_discovery_url={}", reg.oauth_discovery_url));
        }
        if !reg.oauth_authorization_endpoint.is_empty() {
            properties.push(format!("oauth_authorization_endpoint={}", reg.oauth_authorization_endpoint));
        }
        if !reg.oauth_token_endpoint.is_empty() {
            properties.push(format!("oauth_token_endpoint={}", reg.oauth_token_endpoint));
        }
        if !reg.oauth_registration_endpoint.is_empty() {
            properties.push(format!("oauth_registration_endpoint={}", reg.oauth_registration_endpoint));
        }
    }
    CruxNode {
        node_id: generate_node_id(&reg.alias, &sha256_hex(content.as_bytes())),
        name: reg.alias.clone(),
        kind: "mcp_server_registration".to_string(),
        module: "mcp".to_string(),
        summary: format!("{} MCP server ({})", reg.alias, reg.transport.as_str()),
        schema: NodeSchema::empty(),
        tags: vec!["mcp".to_string(), "registration".to_string()],
        reach: vec![],
        properties,
        warnings: vec![],
        planning: PlanningMetadata::empty(),
        security: SecurityMetadata {
            classification: "restricted".to_string(),
            redact_below: None,
        },
        content_hash: sha256_hex(content.as_bytes()),
        deleted_at: None,
    }
}

/// Decode an `mcp_server_registration` node back into a typed struct.
/// Returns `None` if the node is not of kind `mcp_server_registration` or
/// is missing the required `alias` / `transport` properties.
pub fn parse_mcp_server_registration(node: &CruxNode) -> Option<McpServerRegistration> {
    if node.kind != "mcp_server_registration" {
        return None;
    }
    let get = |key: &str| -> String {
        let prefix = format!("{}=", key);
        node.properties
            .iter()
            .find_map(|p| p.strip_prefix(&prefix).map(|v| v.to_string()))
            .unwrap_or_default()
    };
    let alias = get("alias");
    if alias.is_empty() {
        return None;
    }
    let transport = McpTransport::from_str(&get("transport"))?;
    let required_clearance = McpClearance::from_str(&get("required_clearance"))
        .unwrap_or(McpClearance::Internal);
    let allowed_tools = {
        let v = get("allowed_tools");
        if v.is_empty() { "*".to_string() } else { v }
    };
    let audit_required = get("audit_required") != "false";
    let rate_limit = {
        let v = get("rate_limit");
        if v.is_empty() { None } else { Some(v) }
    };
    let status = {
        let v = get("status");
        if v.is_empty() { "approved".to_string() } else { v }
    };
    let source = {
        let v = get("source");
        if v.is_empty() { "manual".to_string() } else { v }
    };
    let fingerprint = get("fingerprint");
    let discovered_at = {
        let v = get("discovered_at");
        if v.is_empty() { None } else { v.parse::<u64>().ok() }
    };
    // OAuth fields — absent in pre-Phase-1 nodes; defaults preserve old behaviour.
    let auth = {
        let v = get("auth");
        if v.is_empty() { "none".to_string() } else { v }
    };
    let oauth_client_id = get("oauth_client_id");
    let oauth_scopes = get("oauth_scopes");
    let oauth_discovery_url = get("oauth_discovery_url");
    let oauth_authorization_endpoint = get("oauth_authorization_endpoint");
    let oauth_token_endpoint = get("oauth_token_endpoint");
    let oauth_registration_endpoint = get("oauth_registration_endpoint");
    Some(McpServerRegistration {
        alias,
        transport,
        command: get("command"),
        url: get("url"),
        required_clearance,
        allowed_tools,
        public_key: get("public_key"),
        audit_required,
        capability_manifest: get("capability_manifest"),
        rate_limit,
        status,
        source,
        fingerprint,
        discovered_at,
        auth,
        oauth_client_id,
        oauth_scopes,
        oauth_discovery_url,
        oauth_authorization_endpoint,
        oauth_token_endpoint,
        oauth_registration_endpoint,
    })
}

/// Collect all active (non-deleted) MCP server registrations from a crux DB.
pub fn parse_all_mcp_server_registrations(db: &CruxDb) -> Vec<McpServerRegistration> {
    db.nodes.iter()
        .filter(|n| n.kind == "mcp_server_registration" && n.deleted_at.is_none())
        .filter_map(|n| parse_mcp_server_registration(n))
        .collect()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // content_hash / verify
    // -----------------------------------------------------------------

    fn hash_test_node(name: &str, summary: &str, tags: &[&str]) -> CruxNode {
        let mut n = CruxNode {
            node_id: String::new(),
            name: name.to_string(),
            kind: "note".to_string(),
            module: String::new(),
            summary: summary.to_string(),
            schema: NodeSchema::empty(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            reach: Vec::new(),
            properties: Vec::new(),
            warnings: Vec::new(),
            planning: PlanningMetadata::empty(),
            security: SecurityMetadata { classification: "internal".to_string(), redact_below: None },
            content_hash: String::new(),
            deleted_at: None,
        };
        n.content_hash = node_content_hash(&n);
        n
    }

    #[test]
    fn test_node_content_hash_is_stable_and_tagged() {
        let n = hash_test_node("a", "s", &["t"]);
        assert_eq!(node_content_hash(&n), node_content_hash(&n));
        assert!(n.content_hash.starts_with(CRUX_HASH_PREFIX));
        assert_eq!(n.content_hash.len(), CRUX_HASH_PREFIX.len() + 64);
    }

    #[test]
    fn test_node_content_hash_covers_every_authored_field() {
        let base = hash_test_node("a", "s", &["t"]);
        let mut v = base.clone(); v.name = "b".into();
        assert_ne!(node_content_hash(&v), base.content_hash, "name");
        let mut v = base.clone(); v.kind = "other".into();
        assert_ne!(node_content_hash(&v), base.content_hash, "kind");
        let mut v = base.clone(); v.module = "m".into();
        assert_ne!(node_content_hash(&v), base.content_hash, "module");
        let mut v = base.clone(); v.summary = "s2".into();
        assert_ne!(node_content_hash(&v), base.content_hash, "summary");
        let mut v = base.clone(); v.tags = vec!["t".into(), "u".into()];
        assert_ne!(node_content_hash(&v), base.content_hash, "tags");
        let mut v = base.clone(); v.tags = vec!["u".into(), "t".into()];
        assert_ne!(node_content_hash(&v), base.content_hash, "tag order");
    }

    #[test]
    fn test_node_content_hash_length_prefix_prevents_field_shifting() {
        // "a:b" + "c" must not hash the same as "a" + "b:c".
        let x = hash_test_node("a:b", "c", &[]);
        let y = hash_test_node("a", "b:c", &[]);
        assert_ne!(x.content_hash, y.content_hash);
        // Same across the tag boundary.
        let x = hash_test_node("n", "s", &["ab"]);
        let y = hash_test_node("n", "s", &["a", "b"]);
        assert_ne!(x.content_hash, y.content_hash);
    }

    #[test]
    fn test_check_node_hash_verified() {
        assert_eq!(check_node_hash(&hash_test_node("a", "s", &["t"])), HashStatus::Verified);
    }

    /// The reason this check exists: a read path mangles a summary and writes it
    /// back. Nothing else about the node changed.
    #[test]
    fn test_check_node_hash_detects_a_mangled_summary() {
        let mut n = hash_test_node("node", "an \u{2014} em dash", &["prose"]);
        n.summary = "an \\u2014 em dash".to_string();   // what the old decoder produced
        assert_eq!(check_node_hash(&n), HashStatus::Mismatch);
    }

    #[test]
    fn test_check_node_hash_legacy_forms_are_unverifiable_not_mismatched() {
        // Every provenance that predates this check must land in Unverifiable, or
        // upgrading would report the entire existing mesh as tampered.
        let mut n = hash_test_node("node", "s", &["t"]);
        for legacy in [
            format!("sha256:{}", sha256_hex(b"node")),        // crux_add_node
            format!("sha256:{}", sha256_hex(b"node:s")),      // crux_update_node
            sha256_hex(b"whole document"),                    // no prefix (mcp registration)
            "sha256:68d4f2a1".to_string(),                    // Helm hex timestamp
        ] {
            n.content_hash = legacy.clone();
            assert_eq!(check_node_hash(&n), HashStatus::Unverifiable, "{}", legacy);
        }
    }

    #[test]
    fn test_check_node_hash_absent_and_malformed() {
        let mut n = hash_test_node("node", "s", &["t"]);
        for empty in ["", "sha256:", CRUX_HASH_PREFIX] {
            n.content_hash = empty.to_string();
            assert_eq!(check_node_hash(&n), HashStatus::Absent, "{:?}", empty);
        }
        for bad in ["not-a-hash", "sha256:zzzz", "cruxv1:abc"] {
            n.content_hash = bad.to_string();
            assert_eq!(check_node_hash(&n), HashStatus::Malformed, "{}", bad);
        }
    }

    /// `crux enrich` appends `file=...` properties and fills `reach`. If those were
    /// hashed, every enrich run would report the whole crux as tampered.
    #[test]
    fn test_machine_written_fields_do_not_invalidate_the_hash() {
        let mut n = hash_test_node("node", "s", &["t"]);
        n.properties.push("file=src/lib.rs".to_string());
        n.reach.push("other-node".to_string());
        n.warnings.push("unused".to_string());
        n.planning.updated_at = Some(1_700_000_000);
        assert_eq!(check_node_hash(&n), HashStatus::Verified);
    }

    fn make_test_db() -> CruxDb {
        let mut db = CruxDb {
            header: CruxHeader {
                crux_version: 2,
                crux_id: "sha256:abc123".to_string(),
                crux_name: "test-project".to_string(),
                crux_kind: CruxKind::Codebase,
                crux_origin: "lml".to_string(),
                created_at: 1741000000,
                last_modified_at: 1741000100,
                mesh_memberships: Vec::new(),
            },
            nodes: Vec::new(),
            edges: Vec::new(),
            modules: vec![
                ModuleNode {
                    path: "main.lml".to_string(),
                    content_hash: "sha256:def456".to_string(),
                    node_count: 2,
                    last_analyzed: 1741000000,
                },
            ],
            domains: vec![
                DomainNode { tag: "io".to_string(), member_count: 1 },
                DomainNode { tag: "tensor".to_string(), member_count: 1 },
            ],
        };

        db.nodes.push(CruxNode {
            node_id: "sha256:node1".to_string(),
            name: "@main".to_string(),
            kind: "function".to_string(),
            module: "main.lml".to_string(),
            summary: "Entry point".to_string(),
            schema: NodeSchema {
                inputs: vec![SchemaSlot { name: "x".to_string(), type_str: "Int".to_string() }],
                outputs: vec![SchemaSlot { name: "result".to_string(), type_str: "Int".to_string() }],
            },
            tags: vec!["io".to_string()],
            reach: vec!["io".to_string(), "tensor".to_string()],
            properties: vec!["bounded".to_string()],
            warnings: vec![],
            planning: PlanningMetadata::done(),
            security: SecurityMetadata::internal(),
            content_hash: "sha256:content1".to_string(),
            deleted_at: None,
        });

        db.nodes.push(CruxNode {
            node_id: "sha256:node2".to_string(),
            name: "@load".to_string(),
            kind: "function".to_string(),
            module: "main.lml".to_string(),
            summary: "Load data from disk".to_string(),
            schema: NodeSchema {
                inputs: vec![SchemaSlot { name: "path".to_string(), type_str: "Str".to_string() }],
                outputs: vec![SchemaSlot { name: "data".to_string(), type_str: "Tensor".to_string() }],
            },
            tags: vec!["io".to_string(), "tensor".to_string()],
            reach: vec!["io".to_string(), "tensor".to_string()],
            properties: vec![],
            warnings: vec![],
            planning: PlanningMetadata {
                status: Some("wip".to_string()),
                priority: Some(2),
                depends: vec!["@main".to_string()],
                updated_at: Some(1741000050),
                planned_for_update: false,
            },
            security: SecurityMetadata {
                classification: "confidential".to_string(),
                redact_below: Some("internal".to_string()),
            },
            content_hash: "sha256:content2".to_string(),
            deleted_at: None,
        });

        db.edges.push(CruxEdge {
            edge_id: "sha256:edge1".to_string(),
            src: "@main".to_string(),
            dst: "@load".to_string(),
            kind: EdgeKind::Calls,
            weight: 1.0,
            detail: "".to_string(),
            cross_crux: false,
            binding: "".to_string(),
            created_at: 1741000000,
            dangling: false,
        });

        db
    }

    #[test]
    fn test_crux_kind_roundtrip() {
        let kinds = vec![
            CruxKind::Codebase, CruxKind::Documentation, CruxKind::Preferences,
            CruxKind::Organization, CruxKind::Skillset, CruxKind::Api,
            CruxKind::Dataset, CruxKind::Custom("mytype".to_string()),
        ];
        for kind in kinds {
            let s = kind.as_str();
            let parsed = CruxKind::from_str(s);
            assert_eq!(kind, parsed);
        }
    }

    #[test]
    fn test_edge_kind_roundtrip() {
        let kinds = vec![
            EdgeKind::Calls, EdgeKind::Imports, EdgeKind::Contains,
            EdgeKind::DataFlow, EdgeKind::RelatesTo, EdgeKind::MeshLink,
            EdgeKind::Tagged, EdgeKind::BelongsToDomain,
        ];
        for kind in kinds {
            let s = kind.as_str();
            let parsed = EdgeKind::from_str(s);
            assert_eq!(kind, parsed);
        }
    }

    #[test]
    fn test_generate_crux_id() {
        let id = generate_crux_id("test", 1741000000);
        assert!(id.starts_with("sha256:"));
        assert_eq!(id.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_generate_node_id() {
        let id = generate_node_id("@main", "sha256:abc");
        assert!(id.starts_with("sha256:"));
    }

    #[test]
    fn test_generate_edge_id() {
        let id = generate_edge_id("@main", "@load", "calls");
        assert!(id.starts_with("sha256:"));
    }

    #[test]
    fn test_create_crux_db() {
        let db = create_crux_db("my-project", CruxKind::Codebase, "test");
        assert_eq!(db.header.crux_version, 2);
        assert_eq!(db.header.crux_name, "my-project");
        assert_eq!(db.header.crux_kind, CruxKind::Codebase);
        assert!(db.header.crux_id.starts_with("sha256:"));
        assert!(db.nodes.is_empty());
        assert!(db.edges.is_empty());
    }

        /// Build a db whose first node carries key-shaped tags and summary text.
    ///
    /// Edges are serialized after nodes, so a node tagged "edges" puts the
    /// literal `"edges"` in the file *before* the real top-level key.
    fn db_with_key_shaped_values() -> CruxDb {
        let mut db = make_test_db();
        db.nodes[0].tags = vec![
            "edges".to_string(),
            "nodes".to_string(),
            "modules".to_string(),
            "domains".to_string(),
            "mesh_memberships".to_string(),
        ];
        db.nodes[0].summary = r#"a summary mentioning "edges": [] and "nodes": []"#.to_string();
        db.edges = vec![CruxEdge {
            edge_id: "sha256:e1".to_string(),
            src: db.nodes[0].name.clone(),
            dst: db.nodes[1].name.clone(),
            kind: EdgeKind::Calls,
            weight: 1.0,
            detail: String::new(),
            cross_crux: false,
            binding: String::new(),
            created_at: 1,
            dangling: false,
        }];
        db
    }

    #[test]
    fn test_section_anchors_ignore_key_shaped_text_in_values() {
        // A raw text.find() anchored on the tag, reparsed the tags array as the
        // edge list, and returned zero edges — which the next save persisted.
        // Every edge in the graph was destroyed by a load-modify-write.
        let db = db_with_key_shaped_values();
        let reparsed = parse_crux_db(&serialize_crux_db(&db)).expect("must reparse");

        assert_eq!(reparsed.nodes.len(), db.nodes.len(), "nodes must survive");
        assert_eq!(
            reparsed.edges.len(),
            1,
            "edges must survive a node tagged \"edges\""
        );
        assert_eq!(reparsed.edges[0].src, db.nodes[0].name);
        assert_eq!(reparsed.edges[0].dst, db.nodes[1].name);
        assert_eq!(reparsed.edges[0].kind, EdgeKind::Calls);

        // The other section anchors are equally at risk if serialization order
        // ever changes, so pin them here rather than relying on key position.
        assert_eq!(reparsed.modules.len(), db.modules.len(), "modules must survive");
        assert_eq!(reparsed.domains.len(), db.domains.len(), "domains must survive");
    }

    #[test]
    fn test_edges_survive_repeated_load_modify_write() {
        // The destructive path is not a single bad read — it is the write that
        // follows one. Loop it, because the loss only shows on the save.
        let mut text = serialize_crux_db(&db_with_key_shaped_values());
        for cycle in 0..3 {
            let round = parse_crux_db(&text).expect("must reparse");
            assert_eq!(
                round.edges.len(),
                1,
                "edge lost on load-modify-write cycle {}",
                cycle
            );
            text = serialize_crux_db(&round);
        }
    }

    #[test]
    fn test_serialize_parse_roundtrip() {
        let db = make_test_db();
        let json = serialize_crux_db(&db);
        let parsed = parse_crux_db(&json).unwrap();

        // Header
        assert_eq!(parsed.header.crux_version, 2);
        assert_eq!(parsed.header.crux_id, "sha256:abc123");
        assert_eq!(parsed.header.crux_name, "test-project");
        assert_eq!(parsed.header.crux_kind, CruxKind::Codebase);
        assert_eq!(parsed.header.crux_origin, "lml");
        assert_eq!(parsed.header.created_at, 1741000000);
        assert_eq!(parsed.header.last_modified_at, 1741000100);

        // Nodes
        assert_eq!(parsed.nodes.len(), 2);
        assert_eq!(parsed.nodes[0].name, "@main");
        assert_eq!(parsed.nodes[0].kind, "function");
        assert_eq!(parsed.nodes[0].summary, "Entry point");
        assert_eq!(parsed.nodes[0].tags, vec!["io"]);
        assert_eq!(parsed.nodes[0].schema.inputs.len(), 1);
        assert_eq!(parsed.nodes[0].schema.inputs[0].name, "x");
        assert_eq!(parsed.nodes[0].schema.inputs[0].type_str, "Int");
        assert_eq!(parsed.nodes[0].planning.status, Some("done".to_string()));

        assert_eq!(parsed.nodes[1].name, "@load");
        assert_eq!(parsed.nodes[1].planning.status, Some("wip".to_string()));
        assert_eq!(parsed.nodes[1].planning.priority, Some(2));
        assert_eq!(parsed.nodes[1].planning.depends, vec!["@main"]);
        assert_eq!(parsed.nodes[1].security.classification, "confidential");
        assert_eq!(parsed.nodes[1].security.redact_below, Some("internal".to_string()));

        // Edges
        assert_eq!(parsed.edges.len(), 1);
        assert_eq!(parsed.edges[0].src, "@main");
        assert_eq!(parsed.edges[0].dst, "@load");
        assert_eq!(parsed.edges[0].kind, EdgeKind::Calls);
        assert_eq!(parsed.edges[0].weight, 1.0);
        assert!(!parsed.edges[0].cross_crux);

        // Modules
        assert_eq!(parsed.modules.len(), 1);
        assert_eq!(parsed.modules[0].path, "main.lml");
        assert_eq!(parsed.modules[0].node_count, 2);

        // Domains
        assert_eq!(parsed.domains.len(), 2);
        assert_eq!(parsed.domains[0].tag, "io");
        assert_eq!(parsed.domains[1].tag, "tensor");
    }

    #[test]
    fn test_serialize_empty_db() {
        let db = create_crux_db("empty", CruxKind::Documentation, "manual");
        let json = serialize_crux_db(&db);
        let parsed = parse_crux_db(&json).unwrap();
        assert_eq!(parsed.header.crux_name, "empty");
        assert_eq!(parsed.header.crux_kind, CruxKind::Documentation);
        assert!(parsed.nodes.is_empty());
        assert!(parsed.edges.is_empty());
    }

    #[test]
    fn test_serialize_cross_crux_edge() {
        let mut db = create_crux_db("linked", CruxKind::Codebase, "test");
        db.edges.push(CruxEdge {
            edge_id: generate_edge_id("sha256:abc:@main", "sha256:def:spec", "mesh_link"),
            src: "sha256:abc:@main".to_string(),
            dst: "sha256:def:spec".to_string(),
            kind: EdgeKind::MeshLink,
            weight: 0.85,
            detail: "function references spec".to_string(),
            cross_crux: true,
            binding: "tag_overlap".to_string(),
            created_at: 1741000000,
            dangling: false,
        });
        let json = serialize_crux_db(&db);
        let parsed = parse_crux_db(&json).unwrap();
        assert_eq!(parsed.edges.len(), 1);
        assert!(parsed.edges[0].cross_crux);
        assert_eq!(parsed.edges[0].kind, EdgeKind::MeshLink);
        assert_eq!(parsed.edges[0].binding, "tag_overlap");
        assert!((parsed.edges[0].weight - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_format_crux_summary() {
        let db = make_test_db();
        let summary = format_crux_summary(&db, None);
        assert!(summary.contains("CRUX MESH \"test-project\""));
        assert!(summary.contains("Kind: codebase"));
        assert!(summary.contains("2 nodes"));
        assert!(summary.contains("Domains: io, tensor"));
        assert!(summary.contains("@main"));
        assert!(summary.contains("@load"));
        assert!(summary.contains("1/2 done"));
    }

    #[test]
    fn test_file_io_roundtrip() {
        let db = make_test_db();
        let tmp = std::env::temp_dir().join("crux_test_roundtrip.crux.json");
        save_crux_db(&db, &tmp).unwrap();
        let loaded = load_crux_db(&tmp).unwrap();
        assert_eq!(loaded.header.crux_name, "test-project");
        assert_eq!(loaded.nodes.len(), 2);
        assert_eq!(loaded.edges.len(), 1);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_crux_db_path() {
        let p = std::path::Path::new("/project/main.lml");
        let cp = crux_db_path(p);
        assert_eq!(cp.to_string_lossy(), "/project/main.crux.json");
    }

    #[test]
    fn test_node_schema_serialization() {
        let mut db = create_crux_db("schema-test", CruxKind::Api, "test");
        db.nodes.push(CruxNode {
            node_id: "sha256:n1".to_string(),
            name: "get_users".to_string(),
            kind: "endpoint".to_string(),
            module: "api.yaml".to_string(),
            summary: "Get list of users".to_string(),
            schema: NodeSchema {
                inputs: vec![
                    SchemaSlot { name: "page".to_string(), type_str: "Int".to_string() },
                    SchemaSlot { name: "limit".to_string(), type_str: "Int".to_string() },
                ],
                outputs: vec![
                    SchemaSlot { name: "users".to_string(), type_str: "Vec(User)".to_string() },
                ],
            },
            tags: vec!["api".to_string()],
            reach: vec![],
            properties: vec![],
            warnings: vec![],
            planning: PlanningMetadata::empty(),
            security: SecurityMetadata::public(),
            content_hash: "sha256:ep1".to_string(),
            deleted_at: None,
        });
        let json = serialize_crux_db(&db);
        let parsed = parse_crux_db(&json).unwrap();
        assert_eq!(parsed.nodes[0].schema.inputs.len(), 2);
        assert_eq!(parsed.nodes[0].schema.inputs[0].name, "page");
        assert_eq!(parsed.nodes[0].schema.inputs[1].type_str, "Int");
        assert_eq!(parsed.nodes[0].schema.outputs.len(), 1);
        assert_eq!(parsed.nodes[0].schema.outputs[0].type_str, "Vec(User)");
    }

    #[test]
    fn test_json_escape_in_summary() {
        let mut db = create_crux_db("escape-test", CruxKind::Documentation, "test");
        db.nodes.push(CruxNode {
            node_id: "sha256:esc".to_string(),
            name: "doc with \"quotes\"".to_string(),
            kind: "document".to_string(),
            module: "".to_string(),
            summary: "Contains\nnewlines\tand\ttabs".to_string(),
            schema: NodeSchema::empty(),
            tags: vec![],
            reach: vec![],
            properties: vec![],
            warnings: vec![],
            planning: PlanningMetadata::empty(),
            security: SecurityMetadata::internal(),
            content_hash: "".to_string(),
            deleted_at: None,
        });
        let json = serialize_crux_db(&db);
        let parsed = parse_crux_db(&json).unwrap();
        assert_eq!(parsed.nodes[0].name, "doc with \"quotes\"");
        assert_eq!(parsed.nodes[0].summary, "Contains\nnewlines\tand\ttabs");
    }

    #[test]
    fn test_policy_config_defaults() {
        let config = PolicyConfig::default();
        assert_eq!(config.default_classification, "internal");
        assert_eq!(config.cross_mesh_policy, "explicit_allow");
        assert!(config.multi_mesh_allowed);
        assert!(!config.require_approval);
        assert_eq!(config.governance_model, "open");
        assert!(config.allowed_crux_kinds.is_empty());
        assert!(config.max_members.is_none());
    }

    #[test]
    fn test_policy_crux_has_properties() {
        let db = create_policy_crux("test-mesh");
        // Security Policy node should have the expected properties
        let sec = db.nodes.iter().find(|n| n.name == "Security Policy").unwrap();
        assert!(sec.properties.iter().any(|p| p.starts_with("cross_mesh_policy=")));
        assert!(sec.properties.iter().any(|p| p.starts_with("multi_mesh_allowed=")));
        // Org Policy node should have the expected properties
        let org = db.nodes.iter().find(|n| n.name == "Organizational Policy").unwrap();
        assert!(org.properties.iter().any(|p| p.starts_with("governance_model=")));
        assert!(org.properties.iter().any(|p| p.starts_with("require_approval=")));
    }

    #[test]
    fn test_policy_crux_with_custom_config() {
        let config = PolicyConfig {
            cross_mesh_policy: "deny_all".to_string(),
            org_name: "Acme Corp".to_string(),
            max_members: Some(10),
            require_approval: true,
            governance_model: "strict".to_string(),
            ..PolicyConfig::default()
        };
        let db = create_policy_crux_with_config("acme-mesh", config);
        assert_eq!(get_policy_property(&db, "cross_mesh_policy"), Some("deny_all".to_string()));
        assert_eq!(get_policy_property(&db, "org_name"), Some("Acme Corp".to_string()));
        assert_eq!(get_policy_property(&db, "max_members"), Some("10".to_string()));
        assert_eq!(get_policy_property(&db, "require_approval"), Some("true".to_string()));
        assert_eq!(get_policy_property(&db, "governance_model"), Some("strict".to_string()));
    }

    #[test]
    fn test_get_policy_property() {
        let db = create_policy_crux("prop-test");
        // default_classification should be "internal"
        assert_eq!(get_policy_property(&db, "default_classification"), Some("internal".to_string()));
        // non-existent key returns None
        assert_eq!(get_policy_property(&db, "nonexistent_key"), None);
    }

    #[test]
    fn test_mcp_server_registration_roundtrip() {
        let reg = McpServerRegistration {
            alias: "my-tool".to_string(),
            transport: McpTransport::Stdio,
            command: "my-tool --mcp".to_string(),
            url: String::new(),
            required_clearance: McpClearance::Internal,
            allowed_tools: "*".to_string(),
            public_key: String::new(),
            audit_required: true,
            capability_manifest: String::new(),
            rate_limit: Some("60/60".to_string()),
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
        let node = build_mcp_server_registration(&reg);

        // Node metadata
        assert_eq!(node.kind, "mcp_server_registration");
        assert_eq!(node.module, "mcp");
        assert_eq!(node.security.classification, "restricted");
        assert!(node.tags.contains(&"mcp".to_string()));

        // Survives serialize → parse roundtrip via crux JSON
        let mut db = create_policy_crux("roundtrip-mesh");
        db.nodes.push(node);
        let json = serialize_crux_db(&db);
        let parsed_db = parse_crux_db(&json).unwrap();
        let parsed_node = parsed_db.nodes.iter()
            .find(|n| n.kind == "mcp_server_registration")
            .unwrap();
        let parsed_reg = parse_mcp_server_registration(parsed_node).unwrap();

        assert_eq!(parsed_reg.alias, "my-tool");
        assert_eq!(parsed_reg.transport, McpTransport::Stdio);
        assert_eq!(parsed_reg.command, "my-tool --mcp");
        assert_eq!(parsed_reg.required_clearance, McpClearance::Internal);
        assert_eq!(parsed_reg.allowed_tools, "*");
        assert!(parsed_reg.audit_required);
        assert_eq!(parsed_reg.rate_limit, Some("60/60".to_string()));
    }

    #[test]
    fn test_mcp_server_registration_missing_alias() {
        // A node with the right kind but no alias property must return None.
        let node = CruxNode {
            node_id: "sha256:test".to_string(),
            name: "unnamed".to_string(),
            kind: "mcp_server_registration".to_string(),
            module: "mcp".to_string(),
            summary: "missing alias".to_string(),
            schema: NodeSchema::empty(),
            tags: vec![],
            reach: vec![],
            properties: vec!["transport=stdio".to_string()],
            warnings: vec![],
            planning: PlanningMetadata::empty(),
            security: SecurityMetadata::internal(),
            content_hash: String::new(),
            deleted_at: None,
        };
        assert!(parse_mcp_server_registration(&node).is_none());
    }

    #[test]
    fn test_mcp_server_registration_new_fields_roundtrip() {
        let reg = McpServerRegistration {
            alias: "discovered-tool".to_string(),
            transport: McpTransport::Http,
            command: String::new(),
            url: "http://localhost:8080".to_string(),
            required_clearance: McpClearance::Public,
            allowed_tools: "*".to_string(),
            public_key: String::new(),
            audit_required: false,
            capability_manifest: String::new(),
            rate_limit: None,
            status: "proposed".to_string(),
            source: "manifest:.crux-discovery/tool.json".to_string(),
            fingerprint: "sha256:abcdef1234".to_string(),
            discovered_at: Some(1700000000),
            auth: "none".to_string(),
            oauth_client_id: String::new(),
            oauth_scopes: String::new(),
            oauth_discovery_url: String::new(),
            oauth_authorization_endpoint: String::new(),
            oauth_token_endpoint: String::new(),
            oauth_registration_endpoint: String::new(),
        };
        let node = build_mcp_server_registration(&reg);
        let parsed = parse_mcp_server_registration(&node).unwrap();

        assert_eq!(parsed.status, "proposed");
        assert_eq!(parsed.source, "manifest:.crux-discovery/tool.json");
        assert_eq!(parsed.fingerprint, "sha256:abcdef1234");
        assert_eq!(parsed.discovered_at, Some(1700000000));
    }

    #[test]
    fn test_mcp_registration_status_defaults_to_approved() {
        // A node with no status= property parses as "approved" (back-compat).
        let node = CruxNode {
            node_id: "n-backcompat".to_string(),
            name: "old-tool".to_string(),
            kind: "mcp_server_registration".to_string(),
            module: "mcp".to_string(),
            summary: "legacy node".to_string(),
            schema: NodeSchema::empty(),
            tags: vec![],
            reach: vec![],
            properties: vec![
                "alias=old-tool".to_string(),
                "transport=stdio".to_string(),
                "command=old-tool --mcp".to_string(),
            ],
            warnings: vec![],
            planning: PlanningMetadata::empty(),
            security: SecurityMetadata::internal(),
            content_hash: String::new(),
            deleted_at: None,
        };
        let parsed = parse_mcp_server_registration(&node).unwrap();
        assert_eq!(parsed.status, "approved");
        assert_eq!(parsed.source, "manual");
        assert!(parsed.fingerprint.is_empty());
        assert_eq!(parsed.discovered_at, None);
    }

    #[test]
    fn test_mcp_registration_auth_none_byte_identical() {
        // A registration with auth="none" must produce ZERO new properties vs the
        // pre-Phase-1 baseline — the oauth2 guard is the critical invariant.
        let reg_none = McpServerRegistration {
            alias: "plain-server".to_string(),
            transport: McpTransport::Stdio,
            command: "plain --mcp".to_string(),
            url: String::new(),
            required_clearance: McpClearance::Internal,
            allowed_tools: "*".to_string(),
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
        let node = build_mcp_server_registration(&reg_none);
        // No property may mention "oauth" or "auth="
        for prop in &node.properties {
            assert!(
                !prop.starts_with("auth=") && !prop.starts_with("oauth_"),
                "auth=none must not emit OAuth properties; got: {prop}"
            );
        }
        // Parser must round-trip auth back to "none" (the default for absent prop)
        let parsed = parse_mcp_server_registration(&node).unwrap();
        assert_eq!(parsed.auth, "none");
        assert!(parsed.oauth_client_id.is_empty());
    }

    #[test]
    fn test_mcp_registration_oauth2_roundtrip() {
        // A registration with auth=oauth2 must survive a full serialize→parse
        // round-trip with all OAuth fields intact.
        let reg = McpServerRegistration {
            alias: "oauth-server".to_string(),
            transport: McpTransport::Http,
            command: String::new(),
            url: "https://api.example.com/mcp".to_string(),
            required_clearance: McpClearance::Confidential,
            allowed_tools: "*".to_string(),
            public_key: String::new(),
            audit_required: true,
            capability_manifest: String::new(),
            rate_limit: None,
            status: "approved".to_string(),
            source: "manual".to_string(),
            fingerprint: String::new(),
            discovered_at: None,
            auth: "oauth2".to_string(),
            oauth_client_id: "client-abc123".to_string(),
            oauth_scopes: "mcp:read mcp:write".to_string(),
            oauth_discovery_url: "https://auth.example.com/.well-known/oauth-authorization-server".to_string(),
            oauth_authorization_endpoint: String::new(),
            oauth_token_endpoint: String::new(),
            oauth_registration_endpoint: "https://auth.example.com/register".to_string(),
        };
        let node = build_mcp_server_registration(&reg);
        // OAuth properties must be present
        assert!(node.properties.iter().any(|p| p == "auth=oauth2"), "auth=oauth2 not serialized");
        assert!(node.properties.iter().any(|p| p.starts_with("oauth_client_id=")));
        assert!(node.properties.iter().any(|p| p.starts_with("oauth_scopes=")));
        assert!(node.properties.iter().any(|p| p.starts_with("oauth_discovery_url=")));
        // Empty endpoint fields must NOT be emitted
        assert!(!node.properties.iter().any(|p| p.starts_with("oauth_authorization_endpoint=")));
        assert!(!node.properties.iter().any(|p| p.starts_with("oauth_token_endpoint=")));

        // Full crux serialize→parse round-trip
        let mut db = create_policy_crux("oauth2-roundtrip");
        db.nodes.push(node);
        let json = serialize_crux_db(&db);
        let parsed_db = parse_crux_db(&json).unwrap();
        let parsed_node = parsed_db.nodes.iter()
            .find(|n| n.kind == "mcp_server_registration").unwrap();
        let parsed = parse_mcp_server_registration(parsed_node).unwrap();

        assert_eq!(parsed.auth, "oauth2");
        assert_eq!(parsed.oauth_client_id, "client-abc123");
        assert_eq!(parsed.oauth_scopes, "mcp:read mcp:write");
        assert_eq!(parsed.oauth_discovery_url, "https://auth.example.com/.well-known/oauth-authorization-server");
        assert!(parsed.oauth_authorization_endpoint.is_empty());
        assert!(parsed.oauth_token_endpoint.is_empty());
        assert_eq!(parsed.oauth_registration_endpoint, "https://auth.example.com/register");
    }

    // --- String-aware JSON scanner regression tests ---------------------------

    /// Build a 3-node db (@a, @mid, @b) where @mid carries an arbitrary summary.
    fn db_with_middle_summary(summary: &str) -> CruxDb {
        let mut db = create_crux_db("brackets", CruxKind::Codebase, "test");
        for (name, sum) in [("@a", "first"), ("@mid", summary), ("@b", "third")] {
            db.nodes.push(CruxNode {
                node_id: generate_node_id(name, "h"),
                name: name.to_string(),
                kind: "function".to_string(),
                module: String::new(),
                summary: sum.to_string(),
                schema: NodeSchema { inputs: Vec::new(), outputs: Vec::new() },
                tags: vec!["doc".to_string()],
                reach: Vec::new(),
                properties: Vec::new(),
                warnings: Vec::new(),
                planning: PlanningMetadata::done(),
                security: SecurityMetadata::internal(),
                content_hash: "sha256:h".to_string(),
                deleted_at: None,
            });
        }
        db
    }

    #[test]
    fn test_parse_nodes_unbalanced_brackets_no_cascade() {
        // Each of these in a middle node's summary used to corrupt the bracket
        // depth counter and silently drop @mid and every node after it.
        let cases = [
            "}",
            "{",
            "]",
            "[",
            "){",
            ")}",
            "code: {children && (<>x</>)}",
            "escaped \" then }",
            "unbalanced {children && (",
            "tail ] oops",
        ];
        for case in cases {
            let json = serialize_crux_db(&db_with_middle_summary(case));
            let parsed = parse_crux_db(&json).unwrap();
            assert_eq!(parsed.nodes.len(), 3, "node cascade-dropped for case {case:?}");
            assert_eq!(parsed.nodes[0].name, "@a", "case {case:?}");
            assert_eq!(parsed.nodes[1].name, "@mid", "case {case:?}");
            assert_eq!(parsed.nodes[2].name, "@b", "case {case:?}");
            // The offending node's summary round-trips exactly...
            assert_eq!(parsed.nodes[1].summary, case, "summary mangled for case {case:?}");
            // ...and the node *after* it is fully intact (not partially parsed).
            assert_eq!(parsed.nodes[2].tags, vec!["doc".to_string()], "case {case:?}");
        }
    }

    #[test]
    fn test_parse_nodes_embedded_key_not_confused() {
        // A summary that literally contains key-shaped text must not shadow the
        // node's real `name` (which is serialized before `summary`, but the value
        // is also resolvable for fields after it now that find_json_key is
        // string-aware).
        let json = serialize_crux_db(&db_with_middle_summary(r#"{"name": "fake", "kind": "bogus"}"#));
        let parsed = parse_crux_db(&json).unwrap();
        assert_eq!(parsed.nodes.len(), 3);
        assert_eq!(parsed.nodes[1].name, "@mid");
        assert_eq!(parsed.nodes[1].kind, "function");
        assert_eq!(parsed.nodes[1].summary, r#"{"name": "fake", "kind": "bogus"}"#);
    }

    #[test]
    fn test_roundtrip_bracket_laden_summaries() {
        // Full CruxDb round-trip with bracket/quote/backslash-laden summaries.
        let mut db = make_test_db();
        db.nodes[0].summary = r#"JSX: {children && (<a href="x">y</a>)}"#.to_string();
        db.nodes[1].summary = r#"path C:\tmp\f and tail ] plus { open"#.to_string();
        let before_count = db.nodes.len();

        let parsed = parse_crux_db(&serialize_crux_db(&db)).unwrap();

        assert_eq!(parsed.nodes.len(), before_count);
        for (orig, got) in db.nodes.iter().zip(parsed.nodes.iter()) {
            assert_eq!(got.name, orig.name);
            assert_eq!(got.summary, orig.summary);
            assert_eq!(got.tags, orig.tags);
            assert_eq!(got.kind, orig.kind);
        }
        assert_eq!(parsed.edges.len(), db.edges.len());
    }
}
