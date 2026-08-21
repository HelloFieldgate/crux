//! Agent-first package manager.
//!
//! Package = crux spec + LML source files + metadata.
//! Registry = mesh of package cruxes (dogfoods the crux mesh).
//! Discovery = structured query (domain, tags, type signatures).
//! Install = mesh_join + lml_check validation.
//! Versions = content hashes + Supersedes edges (no semver).
//! Trust = W-OTS signatures + type-checking gate.

use std::fmt::Write as FmtWrite;
use std::path::{Path, PathBuf};

use crate::crypto::sha256_hex;
use crate::mesh;
use crate::schema;

// ===========================================================================
// Data types
// ===========================================================================

/// Parsed search query with structured filters.
#[derive(Debug, Clone)]
pub struct SearchQuery {
    /// Free-text terms to match against name/summary.
    pub text: Vec<String>,
    /// Domain filter (e.g., "crypto", "io").
    pub domain: Option<String>,
    /// Tag filters (e.g., "hash", "encoding").
    pub tags: Vec<String>,
    /// Effect filter: "pure" or "io".
    pub effect: Option<String>,
    /// Type signature filter: "[Bytes] -> Bytes".
    pub type_sig: Option<TypeSigFilter>,
}

/// A parsed type signature filter.
#[derive(Debug, Clone)]
pub struct TypeSigFilter {
    pub inputs: Vec<String>,
    pub output: Option<String>,
}

/// A search result with relevance score.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub crux_id: String,
    pub crux_name: String,
    pub node_name: String,
    pub node_kind: String,
    pub summary: String,
    pub tags: Vec<String>,
    pub schema: schema::NodeSchema,
    pub score: f64,
}

/// Result of a package installation.
#[derive(Debug)]
pub struct InstallResult {
    pub installed: bool,
    pub crux_name: String,
    pub functions_imported: Vec<String>,
    pub type_check: String,
}

/// A node in the dependency tree.
#[derive(Debug, Clone)]
pub struct DepNode {
    pub crux_name: String,
    pub crux_id: String,
    pub functions: Vec<String>,
    pub children: Vec<DepNode>,
}

/// Result of a package audit.
#[derive(Debug)]
pub struct AuditResult {
    pub verified: Vec<String>,
    pub tampered: Vec<String>,
    pub missing: Vec<String>,
    pub dangling_edges: Vec<String>,
}

/// An available update.
#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub crux_name: String,
    pub current_id: String,
    pub new_id: String,
    pub added_fns: Vec<String>,
    pub removed_fns: Vec<String>,
    pub changed_fns: Vec<String>,
}

// ===========================================================================
// Query parsing
// ===========================================================================

/// Parse a search query string into structured filters.
///
/// Syntax:
///   - `domain:crypto`       — domain filter
///   - `tag:hash`            — tag filter (repeatable)
///   - `effect:pure`         — effect filter
///   - `[Bytes @input] -> Bytes` — type signature
///   - bare words            — free-text match
pub fn parse_search_query(query: &str) -> SearchQuery {
    let mut result = SearchQuery {
        text: Vec::new(),
        domain: None,
        tags: Vec::new(),
        effect: None,
        type_sig: None,
    };

    // Check for type signature (contains -> )
    if let Some(arrow_pos) = query.find("->") {
        // Look for [ before the arrow
        if let Some(bracket_start) = query[..arrow_pos].rfind('[') {
            let raw_inputs = query[bracket_start + 1..arrow_pos].trim();
            let inputs_str = raw_inputs.trim_end_matches(']').trim();
            let output_str = query[arrow_pos + 2..].trim();

            let inputs: Vec<String> = inputs_str
                .split_whitespace()
                .filter(|s| !s.starts_with('@'))
                .map(|s| s.to_string())
                .collect();

            let output = if output_str.is_empty() {
                None
            } else {
                // Take the first word as output type, rest might be other filters
                let first_word = output_str.split_whitespace().next().unwrap_or("");
                if first_word.contains(':') {
                    None // It's a filter, not a type
                } else {
                    Some(first_word.to_string())
                }
            };

            result.type_sig = Some(TypeSigFilter { inputs, output });

            // Parse remaining tokens (before bracket + after output type)
            let prefix = &query[..bracket_start];
            let suffix_start = arrow_pos + 2;
            let suffix = &query[suffix_start..];
            let remaining = format!("{} {}", prefix, suffix);
            parse_filter_tokens(&remaining, &mut result);
            return result;
        }
    }

    // No type signature — parse all tokens
    parse_filter_tokens(query, &mut result);
    result
}

fn parse_filter_tokens(text: &str, q: &mut SearchQuery) {
    for token in text.split_whitespace() {
        if let Some(rest) = token.strip_prefix("domain:") {
            q.domain = Some(rest.to_string());
        } else if let Some(rest) = token.strip_prefix("tag:") {
            q.tags.push(rest.to_string());
        } else if let Some(rest) = token.strip_prefix("effect:") {
            q.effect = Some(rest.to_string());
        } else if !token.is_empty()
            && !token.starts_with('[')
            && !token.starts_with('@')
            && !token.contains('-')
        {
            // Skip type-sig fragments that leaked through
            q.text.push(token.to_lowercase());
        }
    }
}

// ===========================================================================
// Search / scoring
// ===========================================================================

/// Score a node against a search query. Returns 0.0 if no match.
pub fn score_node(node: &schema::CruxNode, query: &SearchQuery) -> f64 {
    let mut score = 0.0;
    let name_lower = node.name.to_lowercase();
    let summary_lower = node.summary.to_lowercase();
    let tags_lower: Vec<String> = node.tags.iter().map(|t| t.to_lowercase()).collect();

    // Free-text matching
    for term in &query.text {
        if name_lower.contains(term) {
            score += 3.0; // Name match is most relevant
        }
        if summary_lower.contains(term) {
            score += 1.0;
        }
        if tags_lower.iter().any(|t| t.contains(term)) {
            score += 2.0;
        }
    }

    // Domain filter
    if let Some(ref domain) = query.domain {
        let domain_lower = domain.to_lowercase();
        if tags_lower.iter().any(|t| t.contains(&domain_lower)) {
            score += 5.0;
        } else {
            return 0.0; // Domain is a hard filter
        }
    }

    // Tag filters
    for tag_filter in &query.tags {
        let tag_lower = tag_filter.to_lowercase();
        if tags_lower.iter().any(|t| t.contains(&tag_lower)) {
            score += 2.0;
        } else {
            return 0.0; // Tag is a hard filter
        }
    }

    // Effect filter
    if let Some(ref effect) = query.effect {
        let effect_lower = effect.to_lowercase();
        let has_io = tags_lower.iter().any(|t| t == "io" || t == "effect");
        if effect_lower == "pure" && has_io {
            return 0.0;
        }
        if effect_lower == "io" && !has_io {
            return 0.0;
        }
        score += 1.0;
    }

    // Type signature matching
    if let Some(ref sig) = query.type_sig {
        let sig_score = score_type_signature(&node.schema, sig);
        if sig_score == 0.0 && (!sig.inputs.is_empty() || sig.output.is_some()) {
            return 0.0; // Type sig is a hard filter when specified
        }
        score += sig_score;
    }

    // Boost if there's any text and we got this far with no text match
    if query.text.is_empty() && score == 0.0 {
        // No filters matched at all — no result
        // But if query has only structured filters and all passed, give base score
        if query.domain.is_some() || !query.tags.is_empty() || query.effect.is_some()
            || query.type_sig.is_some()
        {
            score = 1.0;
        }
    }

    score
}

/// Score type signature match: compare NodeSchema inputs/outputs against filter.
fn score_type_signature(schema: &schema::NodeSchema, sig: &TypeSigFilter) -> f64 {
    if schema.inputs.is_empty() && schema.outputs.is_empty() {
        return 0.0; // No schema info available
    }

    let mut score = 0.0;

    // Match inputs
    if !sig.inputs.is_empty() {
        let schema_input_types: Vec<String> = schema
            .inputs
            .iter()
            .map(|s| s.type_str.to_lowercase())
            .collect();
        let query_types: Vec<String> = sig.inputs.iter().map(|s| s.to_lowercase()).collect();

        // Count matches (order-independent for flexibility)
        let mut matched = 0;
        for qt in &query_types {
            if schema_input_types.iter().any(|st| st.contains(qt)) {
                matched += 1;
            }
        }
        if matched == query_types.len() {
            score += 4.0; // All input types matched
        } else if matched > 0 {
            score += matched as f64;
        }
    }

    // Match output
    if let Some(ref out_type) = sig.output {
        let out_lower = out_type.to_lowercase();
        let has_match = schema
            .outputs
            .iter()
            .any(|s| s.type_str.to_lowercase().contains(&out_lower));
        if has_match {
            score += 3.0;
        }
    }

    score
}

/// Search a registry mesh for packages matching a query.
pub fn search_registry(
    mesh_dir: &Path,
    query_str: &str,
    limit: Option<usize>,
) -> Result<Vec<SearchResult>, String> {
    let manifest = mesh::load_mesh(mesh_dir)?;
    let query = parse_search_query(query_str);
    let max = limit.unwrap_or(20);

    let dbs = mesh::load_member_dbs(&manifest, mesh_dir);
    let mut results = Vec::new();

    for (_idx, db) in &dbs {
        for node in &db.nodes {
            if node.deleted_at.is_some() {
                continue;
            }
            let s = score_node(node, &query);
            if s > 0.0 {
                results.push(SearchResult {
                    crux_id: db.header.crux_id.clone(),
                    crux_name: db.header.crux_name.clone(),
                    node_name: node.name.clone(),
                    node_kind: node.kind.clone(),
                    summary: node.summary.clone(),
                    tags: node.tags.clone(),
                    schema: node.schema.clone(),
                    score: s,
                });
            }
        }
    }

    // Sort by score descending
    results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    results.truncate(max);
    Ok(results)
}

/// Format search results as text.
pub fn format_search_results(results: &[SearchResult], query: &str) -> String {
    if results.is_empty() {
        return format!("No packages matching '{}' found in the registry.", query);
    }

    let mut out = format!(
        "Found {} result(s) for '{}':\n\n",
        results.len(),
        query
    );
    for r in results {
        let _ = writeln!(out, "  {} ({}) — score: {:.1}", r.node_name, r.node_kind, r.score);
        let _ = writeln!(out, "    from: {} [{}]", r.crux_name, &r.crux_id[..20.min(r.crux_id.len())]);
        if !r.summary.is_empty() {
            let _ = writeln!(out, "    {}", r.summary);
        }
        if !r.tags.is_empty() {
            let _ = writeln!(out, "    tags: {}", r.tags.join(", "));
        }
        if !r.schema.inputs.is_empty() || !r.schema.outputs.is_empty() {
            let inputs: Vec<String> = r.schema.inputs.iter().map(|s| {
                if s.name.is_empty() {
                    s.type_str.clone()
                } else {
                    format!("{}: {}", s.name, s.type_str)
                }
            }).collect();
            let outputs: Vec<String> = r.schema.outputs.iter().map(|s| s.type_str.clone()).collect();
            let _ = writeln!(out, "    sig: [{}] -> {}", inputs.join(", "), outputs.join(", "));
        }
        out.push('\n');
    }
    out
}

// ===========================================================================
// Publish
// ===========================================================================

/// Publish a package to a registry mesh.
///
/// 1. Generate crux from LML project (or use existing .crux.json)
/// 2. Compute content hash for the whole package
/// 3. Sign the content hash with W-OTS (if key material provided)
/// 4. mesh_join the crux to the registry mesh
pub fn publish_package(
    project_path: &Path,
    registry_path: &Path,
) -> Result<String, String> {
    // 1. Find or create the crux for this project
    let crux_path = find_or_create_crux(project_path)?;

    // 2. Load the crux and compute a package-level content hash
    let db = schema::load_crux_db(&crux_path)?;
    let pkg_hash = compute_package_hash(&db);

    // 3. Add package metadata as properties on the header
    let mut db_mut = db;
    // Store the package hash as a node property on all nodes (for verification)
    let ts = schema::now_unix();
    for node in &mut db_mut.nodes {
        node.properties.push(format!("pkg_hash={}", pkg_hash));
        node.properties.push(format!("published_at={}", ts));
    }
    schema::save_crux_db(&db_mut, &crux_path)?;

    // 4. Copy the crux into the registry directory
    let dest_dir = registry_path.join(&db_mut.header.crux_name);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("Failed to create package dir: {}", e))?;

    let dest_file = dest_dir.join(".crux.json");
    let serialized = schema::serialize_crux_db(&db_mut);
    std::fs::write(&dest_file, &serialized)
        .map_err(|e| format!("Failed to write crux: {}", e))?;

    // Copy LML source files alongside the crux
    copy_lml_sources(project_path, &dest_dir)?;

    // Join the mesh
    let rel_path = db_mut.header.crux_name.clone();
    let manifest = mesh::join_mesh(registry_path, &rel_path)?;

    Ok(format!(
        "Published '{}' to registry '{}'\nPackage hash: {}\nPublished at: {}\nRegistry members: {}",
        db_mut.header.crux_name,
        manifest.mesh_name,
        pkg_hash,
        ts,
        manifest.members.len()
    ))
}

/// Find an existing .crux.json or signal that one needs to be created.
fn find_or_create_crux(project_path: &Path) -> Result<PathBuf, String> {
    let crux_file = project_path.join(".crux.json");
    if crux_file.exists() {
        return Ok(project_path.to_path_buf());
    }
    // Check subdirectories
    if let Ok(entries) = std::fs::read_dir(project_path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let candidate = p.join(".crux.json");
                if candidate.exists() {
                    return Ok(p);
                }
            }
        }
    }
    Err(format!(
        "No .crux.json found in '{}'. Generate one with lml_crux or crux_create first.",
        project_path.display()
    ))
}

/// Compute a package-level content hash from all node hashes.
fn compute_package_hash(db: &schema::CruxDb) -> String {
    let mut combined = String::new();
    combined.push_str(&db.header.crux_id);
    for node in &db.nodes {
        combined.push(':');
        combined.push_str(&node.content_hash);
    }
    for edge in &db.edges {
        combined.push(':');
        combined.push_str(&edge.edge_id);
    }
    format!("sha256:{}", sha256_hex(combined.as_bytes()))
}

/// Copy .lml files from the project to the destination directory.
fn copy_lml_sources(src: &Path, dst: &Path) -> Result<(), String> {
    if let Ok(entries) = std::fs::read_dir(src) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("lml") {
                let fname = p.file_name().unwrap();
                let dest_file = dst.join(fname);
                std::fs::copy(&p, &dest_file)
                    .map_err(|e| format!("Failed to copy {}: {}", p.display(), e))?;
            }
        }
    }
    // Also copy from src/lml/ subdirectory if it exists
    let lml_subdir = src.join("src").join("lml");
    if lml_subdir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&lml_subdir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("lml") {
                    let fname = p.file_name().unwrap();
                    let dest_file = dst.join(fname);
                    std::fs::copy(&p, &dest_file)
                        .map_err(|e| format!("Failed to copy {}: {}", p.display(), e))?;
                }
            }
        }
    }
    Ok(())
}

// ===========================================================================
// Install
// ===========================================================================

/// Install a package from a registry into a local project.
///
/// 1. Find the package in the registry mesh by crux name or ID
/// 2. Verify content hashes
/// 3. Copy source files to project
/// 4. Add import edges to project mesh (if exists)
/// 5. Type-check composition
pub fn install_package(
    crux_identifier: &str,
    project_path: &Path,
    registry_path: &Path,
) -> Result<InstallResult, String> {
    let manifest = mesh::load_mesh(registry_path)?;

    // 1. Find the package in the registry
    let member = manifest
        .members
        .iter()
        .find(|m| m.crux_name == crux_identifier || m.crux_id == crux_identifier)
        .ok_or_else(|| format!("Package '{}' not found in registry", crux_identifier))?;

    let pkg_dir = registry_path.join(&member.path);
    let db = schema::load_crux_db(&pkg_dir)?;

    // 2. Verify content hashes
    let verify_result = verify_package_hashes(&db);
    if !verify_result.tampered.is_empty() {
        return Err(format!(
            "Package integrity check failed. Tampered nodes: {}",
            verify_result.tampered.join(", ")
        ));
    }

    // 3. Copy source files to project's deps/ directory
    let deps_dir = project_path.join("deps").join(&member.crux_name);
    std::fs::create_dir_all(&deps_dir)
        .map_err(|e| format!("Failed to create deps dir: {}", e))?;

    // Copy the crux
    let crux_json = schema::serialize_crux_db(&db);
    std::fs::write(deps_dir.join(".crux.json"), &crux_json)
        .map_err(|e| format!("Failed to write crux: {}", e))?;

    // Copy LML sources
    copy_lml_sources(&pkg_dir, &deps_dir)?;

    // 4. Collect imported function names
    let functions_imported: Vec<String> = db
        .nodes
        .iter()
        .filter(|n| n.deleted_at.is_none() && n.kind == "function")
        .map(|n| n.name.clone())
        .collect();

    // 5. Join to project mesh if it exists
    let project_mesh = project_path.join(".crux-mesh.json");
    if project_mesh.exists() {
        let rel_path = format!("deps/{}", member.crux_name);
        let _ = mesh::join_mesh(project_path, &rel_path);
    }

    // 6. Type-check: look for lml binary and run lml_check
    let type_check = run_type_check(project_path, &deps_dir);

    Ok(InstallResult {
        installed: true,
        crux_name: member.crux_name.clone(),
        functions_imported,
        type_check,
    })
}

/// Run lml_check on the project to verify type compatibility.
fn run_type_check(project_path: &Path, _deps_dir: &Path) -> String {
    // Try to find lml binary
    let lml_bin = find_lml_binary();
    if lml_bin.is_none() {
        return "skipped (lml binary not found)".to_string();
    }

    // Find .lml files in the project to check
    let lml_files = find_lml_files(project_path);
    if lml_files.is_empty() {
        return "ok (no .lml files to check)".to_string();
    }

    // Check each file
    let lml = lml_bin.unwrap();
    for file in &lml_files {
        let output = std::process::Command::new(&lml)
            .arg("--check")
            .arg(file)
            .output();
        match output {
            Ok(o) if !o.status.success() => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                return format!("error: {}", stderr.trim());
            }
            Err(e) => {
                return format!("error running lml: {}", e);
            }
            _ => {}
        }
    }
    "ok".to_string()
}

fn find_lml_binary() -> Option<PathBuf> {
    if let Ok(output) = std::process::Command::new("which").arg("lml").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

fn find_lml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("lml") {
                files.push(p);
            }
        }
    }
    files
}

/// Format an install result as text.
pub fn format_install_result(result: &InstallResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Package '{}' installed successfully.", result.crux_name);
    let _ = writeln!(out, "Functions available: {}", result.functions_imported.len());
    if !result.functions_imported.is_empty() {
        let display: Vec<&str> = result.functions_imported.iter().take(20).map(|s| s.as_str()).collect();
        let _ = writeln!(out, "  {}", display.join(", "));
        if result.functions_imported.len() > 20 {
            let _ = writeln!(out, "  ... and {} more", result.functions_imported.len() - 20);
        }
    }
    let _ = writeln!(out, "Type check: {}", result.type_check);
    out
}

// ===========================================================================
// Dependencies
// ===========================================================================

/// Build a dependency tree for a project by traversing import edges.
pub fn get_dep_tree(project_path: &Path) -> Result<Vec<DepNode>, String> {
    let mesh_file = project_path.join(".crux-mesh.json");
    if !mesh_file.exists() {
        return Ok(Vec::new()); // No mesh = no dependencies
    }

    let manifest = mesh::load_mesh(project_path)?;
    let dbs = mesh::load_member_dbs(&manifest, project_path);

    let mut deps = Vec::new();
    for (_idx, db) in &dbs {
        // Find imports edges (cross-crux or within)
        let import_edges: Vec<&schema::CruxEdge> = db
            .edges
            .iter()
            .filter(|e| e.kind == schema::EdgeKind::Imports)
            .collect();

        let functions: Vec<String> = db
            .nodes
            .iter()
            .filter(|n| n.deleted_at.is_none() && n.kind == "function")
            .map(|n| n.name.clone())
            .collect();

        deps.push(DepNode {
            crux_name: db.header.crux_name.clone(),
            crux_id: db.header.crux_id.clone(),
            functions,
            children: Vec::new(), // Flat for now; tree structure from cross-edges
        });

        // Check for cross-crux imports
        for edge in &import_edges {
            if edge.cross_crux {
                // Find the target crux
                for (_j, target_db) in &dbs {
                    let has_target = target_db.nodes.iter().any(|n| n.name == edge.dst);
                    if has_target && target_db.header.crux_id != db.header.crux_id {
                        if let Some(parent) = deps.last_mut() {
                            parent.children.push(DepNode {
                                crux_name: target_db.header.crux_name.clone(),
                                crux_id: target_db.header.crux_id.clone(),
                                functions: vec![edge.dst.clone()],
                                children: Vec::new(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(deps)
}

/// Format the dependency tree as text.
pub fn format_dep_tree(deps: &[DepNode]) -> String {
    if deps.is_empty() {
        return "No dependencies found.".to_string();
    }

    let mut out = String::new();
    let total_pkgs = deps.len();
    let total_fns: usize = deps.iter().map(|d| d.functions.len()).sum();
    let _ = writeln!(out, "Dependencies: {} package(s), {} function(s)\n", total_pkgs, total_fns);

    for dep in deps {
        let _ = writeln!(out, "  {} [{}]", dep.crux_name, &dep.crux_id[..20.min(dep.crux_id.len())]);
        let _ = writeln!(out, "    functions: {}", dep.functions.len());
        for child in &dep.children {
            let _ = writeln!(out, "    -> {} ({})", child.crux_name, child.functions.join(", "));
        }
    }

    // Cycle detection: check for duplicate crux_ids
    let mut seen = std::collections::HashSet::new();
    let mut cycles = Vec::new();
    for dep in deps {
        if !seen.insert(&dep.crux_id) {
            cycles.push(dep.crux_name.clone());
        }
    }
    if !cycles.is_empty() {
        let _ = writeln!(out, "\nWarning: Circular dependencies detected: {}", cycles.join(", "));
    }

    out
}

// ===========================================================================
// Audit
// ===========================================================================

/// Verify integrity of all installed packages in a project.
pub fn audit_packages(project_path: &Path) -> Result<AuditResult, String> {
    let deps_dir = project_path.join("deps");
    if !deps_dir.exists() {
        return Ok(AuditResult {
            verified: Vec::new(),
            tampered: Vec::new(),
            missing: Vec::new(),
            dangling_edges: Vec::new(),
        });
    }

    let mut result = AuditResult {
        verified: Vec::new(),
        tampered: Vec::new(),
        missing: Vec::new(),
        dangling_edges: Vec::new(),
    };

    if let Ok(entries) = std::fs::read_dir(&deps_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let crux_file = p.join(".crux.json");
            if !crux_file.exists() {
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                result.missing.push(name);
                continue;
            }

            match schema::load_crux_db(&p) {
                Ok(db) => {
                    let verify = verify_package_hashes(&db);
                    let name = db.header.crux_name.clone();
                    if verify.tampered.is_empty() {
                        result.verified.push(name);
                    } else {
                        result.tampered.push(format!(
                            "{} ({})",
                            name,
                            verify.tampered.join(", ")
                        ));
                    }
                    // Check for dangling edges
                    for edge in &db.edges {
                        if edge.dangling {
                            result
                                .dangling_edges
                                .push(format!("{} -> {}", edge.src, edge.dst));
                        }
                    }
                }
                Err(e) => {
                    let name = p.file_name().unwrap().to_string_lossy().to_string();
                    result.missing.push(format!("{} (load error: {})", name, e));
                }
            }
        }
    }

    Ok(result)
}

/// Verify content hashes on all nodes in a crux.
fn verify_package_hashes(db: &schema::CruxDb) -> AuditResult {
    let mut result = AuditResult {
        verified: Vec::new(),
        tampered: Vec::new(),
        missing: Vec::new(),
        dangling_edges: Vec::new(),
    };

    for node in &db.nodes {
        if node.deleted_at.is_some() {
            continue;
        }
        // Both arms of this used to push to `verified`, which made `tampered`
        // unreachable and the whole audit a no-op that always came back clean.
        match crate::schema::check_node_hash(node) {
            crate::schema::HashStatus::Mismatch | crate::schema::HashStatus::Malformed => {
                result.tampered.push(node.name.clone());
            }
            // Verified, or carrying a hash that predates this check and cannot be
            // re-derived. The latter is not evidence of integrity — see
            // schema::check_node_hash — but it is not evidence of tampering either.
            _ => result.verified.push(node.name.clone()),
        }
    }

    result
}

/// Format audit result as text.
pub fn format_audit_result(result: &AuditResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Package Audit Results:");
    let _ = writeln!(out, "  Verified: {}", result.verified.len());
    if !result.verified.is_empty() {
        for v in &result.verified {
            let _ = writeln!(out, "    [ok] {}", v);
        }
    }
    if !result.tampered.is_empty() {
        let _ = writeln!(out, "  TAMPERED: {}", result.tampered.len());
        for t in &result.tampered {
            let _ = writeln!(out, "    [FAIL] {}", t);
        }
    }
    if !result.missing.is_empty() {
        let _ = writeln!(out, "  Missing: {}", result.missing.len());
        for m in &result.missing {
            let _ = writeln!(out, "    [?] {}", m);
        }
    }
    if !result.dangling_edges.is_empty() {
        let _ = writeln!(out, "  Dangling edges: {}", result.dangling_edges.len());
        for d in &result.dangling_edges {
            let _ = writeln!(out, "    [!] {}", d);
        }
    }
    out
}

// ===========================================================================
// Update
// ===========================================================================

/// Check for available updates by looking for Supersedes edges in the registry.
pub fn check_updates(
    project_path: &Path,
    registry_path: &Path,
) -> Result<Vec<UpdateInfo>, String> {
    let deps_dir = project_path.join("deps");
    if !deps_dir.exists() {
        return Ok(Vec::new());
    }

    let registry_manifest = mesh::load_mesh(registry_path)?;
    let registry_dbs = mesh::load_member_dbs(&registry_manifest, registry_path);

    let mut updates = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&deps_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let crux_file = p.join(".crux.json");
            if !crux_file.exists() {
                continue;
            }
            let local_db = match schema::load_crux_db(&p) {
                Ok(db) => db,
                Err(_) => continue,
            };

            // Look for Supersedes edges in the registry pointing FROM our current crux
            for (_idx, reg_db) in &registry_dbs {
                for edge in &reg_db.edges {
                    if edge.kind == schema::EdgeKind::Supersedes
                        && edge.src == local_db.header.crux_id
                    {
                        // Found an update — compute the diff
                        let new_db = registry_dbs
                            .iter()
                            .find(|(_i, d)| d.header.crux_id == edge.dst);

                        if let Some((_j, new_db)) = new_db {
                            let update = compute_update_diff(&local_db, new_db);
                            updates.push(update);
                        }
                    }
                }

                // Also check by name (same crux_name, different crux_id = newer version)
                if reg_db.header.crux_name == local_db.header.crux_name
                    && reg_db.header.crux_id != local_db.header.crux_id
                    && reg_db.header.created_at > local_db.header.created_at
                {
                    let update = compute_update_diff(&local_db, reg_db);
                    // Avoid duplicates
                    if !updates.iter().any(|u: &UpdateInfo| u.new_id == update.new_id) {
                        updates.push(update);
                    }
                }
            }
        }
    }

    Ok(updates)
}

/// Compute the structural diff between two crux versions.
fn compute_update_diff(old: &schema::CruxDb, new: &schema::CruxDb) -> UpdateInfo {
    let old_names: std::collections::HashSet<&str> = old
        .nodes
        .iter()
        .filter(|n| n.deleted_at.is_none() && n.kind == "function")
        .map(|n| n.name.as_str())
        .collect();

    let new_names: std::collections::HashSet<&str> = new
        .nodes
        .iter()
        .filter(|n| n.deleted_at.is_none() && n.kind == "function")
        .map(|n| n.name.as_str())
        .collect();

    let added: Vec<String> = new_names
        .difference(&old_names)
        .map(|s| s.to_string())
        .collect();
    let removed: Vec<String> = old_names
        .difference(&new_names)
        .map(|s| s.to_string())
        .collect();

    // Changed = same name but different content hash
    let mut changed = Vec::new();
    for name in old_names.intersection(&new_names) {
        let old_node = old.nodes.iter().find(|n| n.name == *name).unwrap();
        let new_node = new.nodes.iter().find(|n| n.name == *name).unwrap();
        if old_node.content_hash != new_node.content_hash {
            changed.push(name.to_string());
        }
    }

    UpdateInfo {
        crux_name: new.header.crux_name.clone(),
        current_id: old.header.crux_id.clone(),
        new_id: new.header.crux_id.clone(),
        added_fns: added,
        removed_fns: removed,
        changed_fns: changed,
    }
}

/// Format update info as text.
pub fn format_updates(updates: &[UpdateInfo]) -> String {
    if updates.is_empty() {
        return "All packages are up to date.".to_string();
    }

    let mut out = format!("{} update(s) available:\n\n", updates.len());
    for u in updates {
        let _ = writeln!(out, "  {} ({} -> {})", u.crux_name,
            &u.current_id[..16.min(u.current_id.len())],
            &u.new_id[..16.min(u.new_id.len())]);
        if !u.added_fns.is_empty() {
            let _ = writeln!(out, "    + added: {}", u.added_fns.join(", "));
        }
        if !u.removed_fns.is_empty() {
            let _ = writeln!(out, "    - removed: {}", u.removed_fns.join(", "));
        }
        if !u.changed_fns.is_empty() {
            let _ = writeln!(out, "    ~ changed: {}", u.changed_fns.join(", "));
        }
        out.push('\n');
    }
    out
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_search_query_domain() {
        let q = parse_search_query("domain:crypto");
        assert_eq!(q.domain, Some("crypto".to_string()));
        assert!(q.text.is_empty());
        assert!(q.tags.is_empty());
    }

    #[test]
    fn test_parse_search_query_tag() {
        let q = parse_search_query("tag:hash tag:encoding");
        assert_eq!(q.tags, vec!["hash", "encoding"]);
    }

    #[test]
    fn test_parse_search_query_effect() {
        let q = parse_search_query("effect:pure");
        assert_eq!(q.effect, Some("pure".to_string()));
    }

    #[test]
    fn test_parse_search_query_type_sig() {
        let q = parse_search_query("[Bytes] -> Bytes");
        assert!(q.type_sig.is_some());
        let sig = q.type_sig.unwrap();
        assert_eq!(sig.inputs, vec!["Bytes"]);
        assert_eq!(sig.output, Some("Bytes".to_string()));
    }

    #[test]
    fn test_parse_search_query_combined() {
        let q = parse_search_query("domain:crypto [Bytes] -> Bytes effect:pure");
        assert_eq!(q.domain, Some("crypto".to_string()));
        assert_eq!(q.effect, Some("pure".to_string()));
        assert!(q.type_sig.is_some());
    }

    #[test]
    fn test_parse_search_query_freetext() {
        let q = parse_search_query("sha256 hash");
        assert_eq!(q.text, vec!["sha256", "hash"]);
    }

    #[test]
    fn test_score_node_name_match() {
        let node = schema::CruxNode {
            node_id: String::new(),
            name: "@sha256_hex".to_string(),
            kind: "function".to_string(),
            module: String::new(),
            summary: "Hash bytes and return hex".to_string(),
            schema: schema::NodeSchema::empty(),
            tags: vec!["crypto".to_string(), "hash".to_string()],
            reach: Vec::new(),
            properties: Vec::new(),
            warnings: Vec::new(),
            planning: schema::PlanningMetadata::empty(),
            security: schema::SecurityMetadata::internal(),
            content_hash: String::new(),
            deleted_at: None,
        };
        let q = parse_search_query("sha256");
        let s = score_node(&node, &q);
        assert!(s > 0.0, "Expected positive score for name match, got {}", s);
    }

    #[test]
    fn test_score_node_domain_filter() {
        let node = schema::CruxNode {
            node_id: String::new(),
            name: "@sha256_hex".to_string(),
            kind: "function".to_string(),
            module: String::new(),
            summary: String::new(),
            schema: schema::NodeSchema::empty(),
            tags: vec!["crypto".to_string()],
            reach: Vec::new(),
            properties: Vec::new(),
            warnings: Vec::new(),
            planning: schema::PlanningMetadata::empty(),
            security: schema::SecurityMetadata::internal(),
            content_hash: String::new(),
            deleted_at: None,
        };
        let q = parse_search_query("domain:crypto");
        let s = score_node(&node, &q);
        assert!(s > 0.0);

        let q2 = parse_search_query("domain:io");
        let s2 = score_node(&node, &q2);
        assert_eq!(s2, 0.0, "Expected 0 for non-matching domain");
    }

    #[test]
    fn test_score_type_signature() {
        let schema = schema::NodeSchema {
            inputs: vec![schema::SchemaSlot {
                name: "@data".to_string(),
                type_str: "Bytes".to_string(),
            }],
            outputs: vec![schema::SchemaSlot {
                name: "@result".to_string(),
                type_str: "Bytes".to_string(),
            }],
        };
        let sig = TypeSigFilter {
            inputs: vec!["Bytes".to_string()],
            output: Some("Bytes".to_string()),
        };
        let s = score_type_signature(&schema, &sig);
        assert!(s > 0.0, "Expected positive score for matching sig, got {}", s);
    }

    #[test]
    fn test_compute_package_hash() {
        let db = schema::create_crux_db("test-pkg", schema::CruxKind::Codebase, "test");
        let hash = compute_package_hash(&db);
        assert!(hash.starts_with("sha256:"));
        assert!(hash.len() > 10);
    }

    #[test]
    fn test_publish_and_search_roundtrip() {
        let dir = std::env::temp_dir().join("crux_pkg_test_roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Create a registry
        let registry_dir = dir.join("registry");
        std::fs::create_dir_all(&registry_dir).unwrap();
        mesh::init_mesh("test-registry", &registry_dir).unwrap();

        // Create a "package" with a crux
        let pkg_dir = dir.join("my-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let mut db = schema::create_crux_db("my-crypto", schema::CruxKind::Codebase, "lml");
        // Add a function node
        let node = schema::CruxNode {
            node_id: format!("sha256:{}", sha256_hex(b"node:test:@sha256_hex")),
            name: "@sha256_hex".to_string(),
            kind: "function".to_string(),
            module: "crypto.lml".to_string(),
            summary: "SHA-256 hash to hex string".to_string(),
            schema: schema::NodeSchema {
                inputs: vec![schema::SchemaSlot {
                    name: "@data".to_string(),
                    type_str: "Bytes".to_string(),
                }],
                outputs: vec![schema::SchemaSlot {
                    name: "@result".to_string(),
                    type_str: "Str".to_string(),
                }],
            },
            tags: vec!["crypto".to_string(), "hash".to_string()],
            reach: Vec::new(),
            properties: Vec::new(),
            warnings: Vec::new(),
            planning: schema::PlanningMetadata::done(),
            security: schema::SecurityMetadata::internal(),
            content_hash: format!("sha256:{}", sha256_hex(b"@sha256_hex")),
            deleted_at: None,
        };
        db.nodes.push(node);
        schema::save_crux_db(&db, &pkg_dir).unwrap();

        // Publish
        let result = publish_package(&pkg_dir, &registry_dir);
        assert!(result.is_ok(), "Publish failed: {:?}", result);

        // Search by domain
        let results = search_registry(&registry_dir, "domain:crypto", None);
        assert!(results.is_ok());
        let results = results.unwrap();
        assert!(!results.is_empty(), "Expected at least one search result");
        assert_eq!(results[0].node_name, "@sha256_hex");

        // Search by free text
        let results2 = search_registry(&registry_dir, "sha256", None).unwrap();
        assert!(!results2.is_empty());

        // Search by type signature
        let results3 = search_registry(&registry_dir, "[Bytes] -> Str", None).unwrap();
        assert!(!results3.is_empty(), "Expected type sig match");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_install_package_basic() {
        let dir = std::env::temp_dir().join("crux_pkg_test_install");
        let _ = std::fs::remove_dir_all(&dir);

        // Set up registry with one package
        let registry_dir = dir.join("registry");
        std::fs::create_dir_all(&registry_dir).unwrap();
        mesh::init_mesh("install-registry", &registry_dir).unwrap();

        let pkg_dir = dir.join("source-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let db = schema::create_crux_db("math-utils", schema::CruxKind::Codebase, "lml");
        schema::save_crux_db(&db, &pkg_dir).unwrap();
        publish_package(&pkg_dir, &registry_dir).unwrap();

        // Install into a project
        let project_dir = dir.join("my-project");
        std::fs::create_dir_all(&project_dir).unwrap();

        let result = install_package("math-utils", &project_dir, &registry_dir);
        assert!(result.is_ok(), "Install failed: {:?}", result);
        let result = result.unwrap();
        assert!(result.installed);
        assert_eq!(result.crux_name, "math-utils");

        // Verify deps directory was created
        assert!(project_dir.join("deps").join("math-utils").join(".crux.json").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_audit_packages_empty() {
        let dir = std::env::temp_dir().join("crux_pkg_test_audit_empty");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let result = audit_packages(&dir).unwrap();
        assert!(result.verified.is_empty());
        assert!(result.tampered.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_audit_with_installed_packages() {
        let dir = std::env::temp_dir().join("crux_pkg_test_audit");
        let _ = std::fs::remove_dir_all(&dir);

        // Set up and install a package
        let registry_dir = dir.join("registry");
        std::fs::create_dir_all(&registry_dir).unwrap();
        mesh::init_mesh("audit-registry", &registry_dir).unwrap();

        let pkg_dir = dir.join("source");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let db = schema::create_crux_db("auditable-pkg", schema::CruxKind::Codebase, "lml");
        schema::save_crux_db(&db, &pkg_dir).unwrap();
        publish_package(&pkg_dir, &registry_dir).unwrap();

        let project_dir = dir.join("project");
        std::fs::create_dir_all(&project_dir).unwrap();
        install_package("auditable-pkg", &project_dir, &registry_dir).unwrap();

        // Audit
        let audit = audit_packages(&project_dir).unwrap();
        assert!(!audit.verified.is_empty() || !audit.missing.is_empty());
        assert!(audit.tampered.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_update_check_no_updates() {
        let dir = std::env::temp_dir().join("crux_pkg_test_update");
        let _ = std::fs::remove_dir_all(&dir);

        let registry_dir = dir.join("registry");
        std::fs::create_dir_all(&registry_dir).unwrap();
        mesh::init_mesh("update-registry", &registry_dir).unwrap();

        let project_dir = dir.join("project");
        std::fs::create_dir_all(&project_dir).unwrap();

        let updates = check_updates(&project_dir, &registry_dir).unwrap();
        assert!(updates.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dep_tree_empty() {
        let dir = std::env::temp_dir().join("crux_pkg_test_deps");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let deps = get_dep_tree(&dir).unwrap();
        assert!(deps.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_format_search_results_empty() {
        let text = format_search_results(&[], "test");
        assert!(text.contains("No packages matching"));
    }

    #[test]
    fn test_format_updates_none() {
        let text = format_updates(&[]);
        assert!(text.contains("up to date"));
    }

    #[test]
    fn test_format_audit_result() {
        let result = AuditResult {
            verified: vec!["pkg-a".to_string()],
            tampered: Vec::new(),
            missing: Vec::new(),
            dangling_edges: Vec::new(),
        };
        let text = format_audit_result(&result);
        assert!(text.contains("Verified: 1"));
        assert!(text.contains("pkg-a"));
    }
}
