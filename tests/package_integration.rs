//! End-to-end integration test for the package manager pipeline.
//!
//! Exercises: init registry → publish → search → install → audit → check updates.

use std::path::Path;

use crux_mesh::crypto::sha256_hex;
use crux_mesh::mesh;
use crux_mesh::package;
use crux_mesh::schema;

/// Helper: create a crux with one function node and save it.
fn create_test_package(dir: &Path, name: &str, fn_name: &str, domain: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let mut db = schema::create_crux_db(name, schema::CruxKind::Codebase, "lml");
    db.nodes.push(schema::CruxNode {
        node_id: format!("sha256:{}", sha256_hex(format!("node:{}:{}", name, fn_name).as_bytes())),
        name: fn_name.to_string(),
        kind: "function".to_string(),
        module: format!("{}.lml", name),
        summary: format!("{} function in {}", fn_name, domain),
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
        tags: vec![domain.to_string()],
        reach: Vec::new(),
        properties: Vec::new(),
        warnings: Vec::new(),
        planning: schema::PlanningMetadata::done(),
        security: schema::SecurityMetadata::internal(),
        content_hash: format!("sha256:{}", sha256_hex(fn_name.as_bytes())),
        deleted_at: None,
    });
    schema::save_crux_db(&db, dir).unwrap();
}

#[test]
fn test_end_to_end_package_pipeline() {
    let base = std::env::temp_dir().join("crux_e2e_pkg_pipeline");
    let _ = std::fs::remove_dir_all(&base);

    // ── Step 1: Init registry mesh ──────────────────────────────
    let registry = base.join("registry");
    std::fs::create_dir_all(&registry).unwrap();
    mesh::init_mesh("e2e-registry", &registry).unwrap();

    // Verify mesh exists (init_mesh creates a policy crux as member[0])
    let manifest = mesh::load_mesh(&registry).unwrap();
    assert_eq!(manifest.mesh_name, "e2e-registry");
    let initial_members = manifest.members.len();
    assert_eq!(initial_members, 1); // policy crux

    // ── Step 2: Create and publish a package ────────────────────
    let pkg_src = base.join("crypto-lib");
    create_test_package(&pkg_src, "crypto-lib", "@sha256_hex", "crypto");

    let publish_result = package::publish_package(&pkg_src, &registry);
    assert!(publish_result.is_ok(), "Publish failed: {:?}", publish_result);
    let publish_msg = publish_result.unwrap();
    assert!(publish_msg.contains("crypto-lib"));
    assert!(publish_msg.contains("sha256:"));

    // Verify registry now has 1 policy + 1 package = 2 members
    let manifest = mesh::load_mesh(&registry).unwrap();
    assert_eq!(manifest.members.len(), initial_members + 1);
    // The published package should be findable by name
    assert!(manifest.members.iter().any(|m| m.crux_name == "crypto-lib"));

    // ── Step 3: Search for the package ──────────────────────────
    // Search by domain
    let results = package::search_registry(&registry, "domain:crypto", None).unwrap();
    assert!(!results.is_empty(), "Domain search should find crypto-lib");
    assert_eq!(results[0].node_name, "@sha256_hex");
    assert_eq!(results[0].crux_name, "crypto-lib");

    // Search by free text
    let results = package::search_registry(&registry, "sha256", None).unwrap();
    assert!(!results.is_empty(), "Free text search should find sha256_hex");

    // Search by type signature
    let results = package::search_registry(&registry, "[Bytes] -> Str", None).unwrap();
    assert!(!results.is_empty(), "Type sig search should match");

    // Search with no match
    let results = package::search_registry(&registry, "domain:graphics", None).unwrap();
    assert!(results.is_empty(), "Should find nothing for graphics domain");

    // Formatted output
    let formatted = package::format_search_results(
        &package::search_registry(&registry, "sha256", None).unwrap(),
        "sha256",
    );
    assert!(formatted.contains("@sha256_hex"));

    // ── Step 4: Install into a project ──────────────────────────
    let project = base.join("my-project");
    std::fs::create_dir_all(&project).unwrap();

    let install = package::install_package("crypto-lib", &project, &registry);
    assert!(install.is_ok(), "Install failed: {:?}", install);
    let install = install.unwrap();
    assert!(install.installed);
    assert_eq!(install.crux_name, "crypto-lib");
    assert!(install.functions_imported.contains(&"@sha256_hex".to_string()));

    // Verify deps directory structure
    let deps_crux = project.join("deps").join("crypto-lib").join(".crux.json");
    assert!(deps_crux.exists(), "Installed crux should exist at {:?}", deps_crux);

    // Formatted install output
    let install_text = package::format_install_result(&install);
    assert!(install_text.contains("crypto-lib"));

    // ── Step 5: Audit the project ───────────────────────────────
    let audit = package::audit_packages(&project);
    assert!(audit.is_ok(), "Audit failed: {:?}", audit);
    let audit = audit.unwrap();
    assert!(audit.tampered.is_empty(), "No packages should be tampered");

    // Formatted audit output
    let audit_text = package::format_audit_result(&audit);
    assert!(!audit_text.is_empty());

    // ── Step 6: Check for updates ───────────────────────────────
    let updates = package::check_updates(&project, &registry);
    assert!(updates.is_ok(), "Update check failed: {:?}", updates);
    let updates = updates.unwrap();
    // Same version → no updates
    assert!(updates.is_empty(), "No updates expected for freshly installed package");

    let updates_text = package::format_updates(&updates);
    assert!(updates_text.contains("up to date"));

    // ── Step 7: Get dependency tree ─────────────────────────────
    let deps = package::get_dep_tree(&project);
    assert!(deps.is_ok(), "Dep tree failed: {:?}", deps);

    let deps_text = package::format_dep_tree(&deps.unwrap());
    assert!(!deps_text.is_empty());

    // ── Cleanup ─────────────────────────────────────────────────
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn test_publish_multiple_and_search_filters() {
    let base = std::env::temp_dir().join("crux_e2e_multi_pkg");
    let _ = std::fs::remove_dir_all(&base);

    let registry = base.join("registry");
    std::fs::create_dir_all(&registry).unwrap();
    mesh::init_mesh("multi-registry", &registry).unwrap();

    // Publish two packages in different domains
    let pkg1 = base.join("crypto-pkg");
    create_test_package(&pkg1, "crypto-pkg", "@encrypt", "crypto");
    package::publish_package(&pkg1, &registry).unwrap();

    let pkg2 = base.join("io-pkg");
    create_test_package(&pkg2, "io-pkg", "@read_file", "io");
    package::publish_package(&pkg2, &registry).unwrap();

    // Registry should have 1 policy + 2 packages = 3 members
    let manifest = mesh::load_mesh(&registry).unwrap();
    assert_eq!(manifest.members.len(), 3);

    // Domain filter: only crypto
    let crypto = package::search_registry(&registry, "domain:crypto", None).unwrap();
    assert!(!crypto.is_empty(), "Should find crypto package");
    assert!(crypto.iter().any(|r| r.node_name == "@encrypt"));

    // Domain filter: only io
    let io_results = package::search_registry(&registry, "domain:io", None).unwrap();
    assert!(!io_results.is_empty(), "Should find io package");
    assert!(io_results.iter().any(|r| r.node_name == "@read_file"));

    // Limit
    let limited = package::search_registry(&registry, "function", Some(1)).unwrap();
    assert!(limited.len() <= 1);

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn test_install_nonexistent_package_fails() {
    let base = std::env::temp_dir().join("crux_e2e_install_fail");
    let _ = std::fs::remove_dir_all(&base);

    let registry = base.join("registry");
    std::fs::create_dir_all(&registry).unwrap();
    mesh::init_mesh("fail-registry", &registry).unwrap();

    let project = base.join("project");
    std::fs::create_dir_all(&project).unwrap();

    let result = package::install_package("nonexistent", &project, &registry);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));

    let _ = std::fs::remove_dir_all(&base);
}
