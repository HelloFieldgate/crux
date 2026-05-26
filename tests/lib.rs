//! Integration tests for Helm API handlers.

use crux_mesh::helm::api::handle_update_node;
use crux_mesh::helm::http::Request;
use crux_mesh::mesh::init_mesh;
use crux_mesh::schema::{create_crux_db, load_crux_db, save_crux_db, CruxKind, CruxNode,
                         NodeSchema, PlanningMetadata, SecurityMetadata};
use std::collections::HashMap;

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("crux_helm_api_test_{}", name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_request(body: &str) -> Request {
    Request {
        method: "POST".to_string(),
        path: "/api/node/update".to_string(),
        query: HashMap::new(),
        body: body.as_bytes().to_vec(),
    }
}

/// POST priority: "3" round-trips through handle_update_node → disk → load.
#[test]
fn test_update_node_priority_roundtrip() {
    let dir = temp_dir("priority_roundtrip");
    init_mesh("test-mesh", &dir).unwrap();

    let crux_dir = dir.join("mycrux");
    std::fs::create_dir_all(&crux_dir).unwrap();

    let mut db = create_crux_db("my-crux", CruxKind::Codebase, "manual");
    let node = CruxNode {
        node_id: "node-001".to_string(),
        name: "alpha".to_string(),
        kind: "concept".to_string(),
        module: String::new(),
        summary: "test node".to_string(),
        schema: NodeSchema::empty(),
        tags: vec![],
        reach: vec![],
        properties: vec![],
        warnings: vec![],
        planning: PlanningMetadata::empty(),
        security: SecurityMetadata::internal(),
        content_hash: String::new(),
        deleted_at: None,
    };
    db.nodes.push(node);
    save_crux_db(&db, &crux_dir).unwrap();

    // POST priority "3"
    let req = make_request(r#"{"crux_path":"mycrux","node_id":"node-001","priority":"3"}"#);
    let resp = handle_update_node(&dir, &req);
    assert_eq!(resp.status, 200, "unexpected status {}", resp.status);

    // Reload and verify priority == Some(3)
    let updated = load_crux_db(&crux_dir).unwrap();
    let n = updated.nodes.iter().find(|n| n.node_id == "node-001").unwrap();
    assert_eq!(n.planning.priority, Some(3));

    // Empty string → None
    let req2 = make_request(r#"{"crux_path":"mycrux","node_id":"node-001","priority":""}"#);
    let resp2 = handle_update_node(&dir, &req2);
    assert_eq!(resp2.status, 200);

    let updated2 = load_crux_db(&crux_dir).unwrap();
    let n2 = updated2.nodes.iter().find(|n| n.node_id == "node-001").unwrap();
    assert_eq!(n2.planning.priority, None);

    let _ = std::fs::remove_dir_all(&dir);
}
