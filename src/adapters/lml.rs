//! LML adapter — reads LML v1 `.crux.json` and converts to universal v2 format.
//!
//! The LML compiler produces `.crux.json` files with its own schema (v1).
//! This adapter reads that format and maps it to the universal CruxDb v2.

use crate::adapters::{AdapterConfig, CruxAdapter};
use crate::json::{extract_bool_value, extract_string_array, extract_string_value, extract_u64_value};
use crate::schema::{
    create_crux_db, parse_crux_db, CruxDb, CruxEdge, CruxKind, CruxNode, EdgeKind, NodeSchema,
    PlanningMetadata, SchemaSlot, SecurityMetadata,
};

pub struct LmlAdapter;

impl CruxAdapter for LmlAdapter {
    fn generate(&self, input: &str, config: &AdapterConfig) -> Result<CruxDb, String> {
        // Auto-detect v2 format — bypass adapter entirely
        if is_v2_format(input) {
            return parse_crux_db(input);
        }

        let mut db = create_crux_db(&config.name, CruxKind::Codebase, &config.origin);

        // Parse the v1 format — extract functions array
        let functions = parse_v1_functions(input);
        let edges = parse_v1_edges(input);

        for func in &functions {
            let node_id = format!("v1:{}", func.name);
            let mut tags: Vec<String> = Vec::new();
            // Use domain tags from v1
            for d in &func.domains {
                if !tags.contains(d) {
                    tags.push(d.clone());
                }
            }

            let status = if func.status == "done" {
                Some("done".to_string())
            } else if func.status == "wip" {
                Some("wip".to_string())
            } else if func.status == "todo" {
                Some("todo".to_string())
            } else {
                func.status_opt.clone()
            };

            // Build NodeSchema from v1 param_types/param_names/return_type
            let inputs: Vec<SchemaSlot> = func.param_types.iter()
                .zip(func.param_names.iter())
                .map(|(ty, name)| SchemaSlot {
                    name: name.clone(),
                    type_str: ty.clone(),
                })
                .collect();
            let outputs = if func.return_type.is_empty() || func.return_type == "()" {
                Vec::new()
            } else {
                vec![SchemaSlot {
                    name: "@result".to_string(),
                    type_str: func.return_type.clone(),
                }]
            };
            let schema = NodeSchema { inputs, outputs };

            db.nodes.push(CruxNode {
                node_id,
                name: func.name.clone(),
                kind: "function".to_string(),
                module: func.module.clone(),
                summary: func.summary.clone(),
                schema,
                tags,
                reach: func.reach.clone(),
                properties: func.properties.clone(),
                warnings: func.warnings.clone(),
                planning: PlanningMetadata {
                    status,
                    priority: func.priority,
                    depends: func.depends.clone(),
                    updated_at: func.updated_at,
                    planned_for_update: func.planned_for_update,
                },
                security: SecurityMetadata::internal(),
                content_hash: func.content_hash.clone(),
                deleted_at: None,
            });
        }

        for edge in &edges {
            db.edges.push(CruxEdge {
                edge_id: format!("v1:edge:{}:{}", edge.src, edge.dst),
                src: edge.src.clone(),
                dst: edge.dst.clone(),
                kind: EdgeKind::from_str(&edge.kind),
                weight: edge.weight,
                detail: edge.detail.clone(),
                cross_crux: false,
                binding: "".to_string(),
                created_at: 0,
                dangling: false,
            });
        }

        Ok(db)
    }
}

/// A v1 function node parsed from LML's `.crux.json`.
struct V1Function {
    name: String,
    module: String,
    summary: String,
    param_types: Vec<String>,
    param_names: Vec<String>,
    return_type: String,
    domains: Vec<String>,
    reach: Vec<String>,
    properties: Vec<String>,
    warnings: Vec<String>,
    status: String,
    status_opt: Option<String>,
    priority: Option<u8>,
    depends: Vec<String>,
    updated_at: Option<u64>,
    planned_for_update: bool,
    content_hash: String,
}

/// A v1 edge parsed from LML's `.crux.json`.
struct V1Edge {
    src: String,
    dst: String,
    kind: String,
    weight: f64,
    detail: String,
}

/// Parse v1 function nodes from LML `.crux.json` JSON text.
fn parse_v1_functions(text: &str) -> Vec<V1Function> {
    let mut functions = Vec::new();
    let start = match text.find("\"functions\"") {
        Some(i) => i,
        None => return functions,
    };

    let after = &text[start..];
    let bracket = match after.find('[') {
        Some(i) => i,
        None => return functions,
    };
    let array_text = &after[bracket..];

    let mut depth = 0;
    let mut obj_start = None;

    for (i, c) in array_text.char_indices() {
        match c {
            '[' if depth == 0 => depth = 1,
            ']' if depth == 1 => break,
            '{' if depth == 1 => {
                depth = 2;
                obj_start = Some(i);
            }
            '{' => depth += 1,
            '}' if depth == 2 => {
                if let Some(s) = obj_start {
                    let obj = &array_text[s..=i];
                    functions.push(parse_v1_function(obj));
                }
                depth = 1;
                obj_start = None;
            }
            '}' => depth -= 1,
            _ => {}
        }
    }
    functions
}

fn parse_v1_function(obj: &str) -> V1Function {
    let name = extract_string_value(obj, "name").unwrap_or_default();
    let module = extract_string_value(obj, "source_file")
        .or_else(|| extract_string_value(obj, "module"))
        .unwrap_or_default();
    let summary = extract_string_value(obj, "summary").unwrap_or_default();
    let param_types = extract_string_array(obj, "param_types");
    let param_names = extract_string_array(obj, "param_names");
    let return_type = extract_string_value(obj, "return_type").unwrap_or_default();
    let domains = extract_string_array(obj, "domains");
    let reach = extract_string_array(obj, "downstream_reach");
    let properties = extract_string_array(obj, "properties");
    let warnings = extract_string_array(obj, "warnings");
    let status = extract_string_value(obj, "status").unwrap_or_default();
    let status_opt = extract_string_value(obj, "status");
    let priority = extract_u64_value(obj, "priority").map(|v| v as u8);
    let depends = extract_string_array(obj, "depends");
    let updated_at = extract_u64_value(obj, "updated_at");
    let planned_for_update = extract_bool_value(obj, "planned_for_update").unwrap_or(false);
    let content_hash = extract_string_value(obj, "content_hash").unwrap_or_default();

    V1Function {
        name,
        module,
        summary,
        param_types,
        param_names,
        return_type,
        domains,
        reach,
        properties,
        warnings,
        status,
        status_opt,
        priority,
        depends,
        updated_at,
        planned_for_update,
        content_hash,
    }
}

/// Parse v1 edges from LML `.crux.json` JSON text.
fn parse_v1_edges(text: &str) -> Vec<V1Edge> {
    let mut edges = Vec::new();
    let start = match text.find("\"edges\"") {
        Some(i) => i,
        None => return edges,
    };

    let after = &text[start..];
    let bracket = match after.find('[') {
        Some(i) => i,
        None => return edges,
    };
    let array_text = &after[bracket..];

    let mut depth = 0;
    let mut obj_start = None;

    for (i, c) in array_text.char_indices() {
        match c {
            '[' if depth == 0 => depth = 1,
            ']' if depth == 1 => break,
            '{' if depth == 1 => {
                depth = 2;
                obj_start = Some(i);
            }
            '{' => depth += 1,
            '}' if depth == 2 => {
                if let Some(s) = obj_start {
                    let obj = &array_text[s..=i];
                    let src = extract_string_value(obj, "src").unwrap_or_default();
                    let dst = extract_string_value(obj, "dst").unwrap_or_default();
                    let kind = extract_string_value(obj, "kind").unwrap_or_else(|| "calls".to_string());
                    let weight = extract_weight(obj);
                    let detail = extract_string_value(obj, "detail").unwrap_or_default();
                    edges.push(V1Edge {
                        src,
                        dst,
                        kind,
                        weight,
                        detail,
                    });
                }
                depth = 1;
                obj_start = None;
            }
            '}' => depth -= 1,
            _ => {}
        }
    }
    edges
}

/// Extract a float weight from JSON (simple parser).
fn extract_weight(obj: &str) -> f64 {
    if let Some(idx) = obj.find("\"weight\"") {
        let after = &obj[idx + 8..];
        if let Some(colon) = after.find(':') {
            let val_start = after[colon + 1..].trim_start();
            let num: String = val_start
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
                .collect();
            if let Ok(v) = num.parse::<f64>() {
                return v;
            }
        }
    }
    1.0
}

/// Detect whether the input is already in v2 format (has `"crux_version": 2`).
fn is_v2_format(text: &str) -> bool {
    extract_u64_value(text, "crux_version") == Some(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lml_adapter_basic() {
        let v1_json = r#"{
            "project": "test",
            "functions": [
                {
                    "name": "@main",
                    "source_file": "main.lml",
                    "summary": "Entry point",
                    "domains": ["io"],
                    "downstream_reach": ["io", "tensor"],
                    "properties": ["pure"],
                    "warnings": [],
                    "status": "done",
                    "priority": 1,
                    "depends": [],
                    "content_hash": "abc123"
                },
                {
                    "name": "@helper",
                    "source_file": "main.lml",
                    "summary": "Helper fn",
                    "domains": ["tensor"],
                    "downstream_reach": ["tensor"],
                    "properties": [],
                    "warnings": ["unused"],
                    "status": "wip",
                    "depends": ["@main"],
                    "content_hash": "def456"
                }
            ],
            "edges": [
                {
                    "src": "@main",
                    "dst": "@helper",
                    "kind": "calls",
                    "weight": 1.0,
                    "detail": "@main -> @helper[0]"
                }
            ]
        }"#;

        let adapter = LmlAdapter;
        let config = AdapterConfig::new("test-proj", "lml");

        let db = adapter.generate(v1_json, &config).unwrap();
        assert_eq!(db.nodes.len(), 2);
        assert_eq!(db.nodes[0].name, "@main");
        assert_eq!(db.nodes[0].kind, "function");
        assert_eq!(db.nodes[0].module, "main.lml");
        assert_eq!(db.nodes[0].tags, vec!["io"]);
        assert_eq!(db.nodes[0].reach, vec!["io", "tensor"]);
        assert_eq!(db.nodes[0].planning.status, Some("done".to_string()));

        assert_eq!(db.nodes[1].name, "@helper");
        assert_eq!(db.nodes[1].planning.status, Some("wip".to_string()));

        assert_eq!(db.edges.len(), 1);
        assert_eq!(db.edges[0].src, "@main");
        assert_eq!(db.edges[0].dst, "@helper");
        assert_eq!(db.edges[0].kind, EdgeKind::Calls);
    }

    #[test]
    fn test_lml_adapter_empty() {
        let adapter = LmlAdapter;
        let config = AdapterConfig::new("empty", "lml");

        let db = adapter.generate("{}", &config).unwrap();
        assert_eq!(db.nodes.len(), 0);
        assert_eq!(db.edges.len(), 0);
    }

    #[test]
    fn test_lml_adapter_v1_schema_populated() {
        let v1_json = r#"{
            "version": 1,
            "project": "test",
            "functions": [
                {
                    "name": "@add",
                    "source_file": "add.lml",
                    "summary": "Add two ints",
                    "param_types": ["Int", "Int"],
                    "param_names": ["@a", "@b"],
                    "return_type": "Int",
                    "domains": [],
                    "downstream_reach": [],
                    "properties": ["pure"],
                    "warnings": [],
                    "status": "done",
                    "priority": 2,
                    "depends": ["@main"],
                    "updated_at": 1741000000,
                    "planned_for_update": true,
                    "content_hash": "abc123"
                }
            ],
            "edges": []
        }"#;

        let adapter = LmlAdapter;
        let config = AdapterConfig::new("test-schema", "lml");
        let db = adapter.generate(v1_json, &config).unwrap();

        assert_eq!(db.nodes.len(), 1);
        let node = &db.nodes[0];

        // NodeSchema inputs
        assert_eq!(node.schema.inputs.len(), 2);
        assert_eq!(node.schema.inputs[0].name, "@a");
        assert_eq!(node.schema.inputs[0].type_str, "Int");
        assert_eq!(node.schema.inputs[1].name, "@b");
        assert_eq!(node.schema.inputs[1].type_str, "Int");

        // NodeSchema outputs
        assert_eq!(node.schema.outputs.len(), 1);
        assert_eq!(node.schema.outputs[0].name, "@result");
        assert_eq!(node.schema.outputs[0].type_str, "Int");

        // PlanningMetadata
        assert_eq!(node.planning.status, Some("done".to_string()));
        assert_eq!(node.planning.priority, Some(2));
        assert_eq!(node.planning.depends, vec!["@main"]);
        assert_eq!(node.planning.updated_at, Some(1741000000));
        assert!(node.planning.planned_for_update);
    }

    #[test]
    fn test_lml_adapter_v1_no_params() {
        let v1_json = r#"{
            "version": 1,
            "project": "test",
            "functions": [
                {
                    "name": "@main",
                    "source_file": "main.lml",
                    "summary": "Entry",
                    "domains": [],
                    "downstream_reach": [],
                    "properties": [],
                    "warnings": [],
                    "status": "done",
                    "content_hash": "xyz"
                }
            ],
            "edges": []
        }"#;

        let adapter = LmlAdapter;
        let config = AdapterConfig::new("test-no-params", "lml");
        let db = adapter.generate(v1_json, &config).unwrap();

        let node = &db.nodes[0];
        // No param_types/param_names → empty inputs
        assert!(node.schema.inputs.is_empty());
        // No return_type → empty outputs
        assert!(node.schema.outputs.is_empty());
        // No updated_at/planned_for_update → defaults
        assert_eq!(node.planning.updated_at, None);
        assert!(!node.planning.planned_for_update);
    }

    #[test]
    fn test_lml_adapter_v2_bypass() {
        // A v2 format file should be parsed directly, bypassing the v1 adapter
        let v2_json = r#"{
            "crux_version": 2,
            "crux_id": "sha256:test123",
            "crux_name": "v2-project",
            "crux_kind": "codebase",
            "crux_origin": "lml",
            "created_at": 1741000000,
            "last_modified_at": 1741000000,
            "nodes": [
                {
                    "node_id": "sha256:node1",
                    "name": "@add",
                    "kind": "function",
                    "module": "add.lml",
                    "summary": "Add two ints",
                    "schema": {
                        "inputs": [
                            {"name": "@a", "type": "Int"},
                            {"name": "@b", "type": "Int"}
                        ],
                        "outputs": [
                            {"name": "@result", "type": "Int"}
                        ]
                    },
                    "tags": ["math"],
                    "reach": [],
                    "properties": [],
                    "warnings": [],
                    "planning": {
                        "status": "done",
                        "priority": 1,
                        "depends": [],
                        "updated_at": 1741000000,
                        "planned_for_update": false
                    },
                    "security": {
                        "classification": "internal"
                    },
                    "content_hash": "sha256:abc",
                    "deleted_at": null
                }
            ],
            "edges": [],
            "modules": [],
            "domains": []
        }"#;

        let adapter = LmlAdapter;
        let config = AdapterConfig::new("ignored-name", "lml");
        let db = adapter.generate(v2_json, &config).unwrap();

        // v2 bypass: parsed directly, config name is ignored
        assert_eq!(db.header.crux_version, 2);
        assert_eq!(db.header.crux_name, "v2-project");
        assert_eq!(db.nodes.len(), 1);
        assert_eq!(db.nodes[0].name, "@add");

        // Schema preserved from v2
        assert_eq!(db.nodes[0].schema.inputs.len(), 2);
        assert_eq!(db.nodes[0].schema.inputs[0].name, "@a");
        assert_eq!(db.nodes[0].schema.outputs.len(), 1);
        assert_eq!(db.nodes[0].schema.outputs[0].type_str, "Int");

        // Planning preserved from v2
        assert_eq!(db.nodes[0].planning.status, Some("done".to_string()));
        assert_eq!(db.nodes[0].planning.updated_at, Some(1741000000));
    }

    #[test]
    fn test_is_v2_format() {
        assert!(is_v2_format(r#"{"crux_version": 2, "crux_name": "test"}"#));
        assert!(!is_v2_format(r#"{"version": 1, "project": "test"}"#));
        assert!(!is_v2_format(r#"{"project": "test"}"#));
    }
}
