//! Plaintext adapter — any text file → single document node, content-hashed.

use crate::adapters::{AdapterConfig, CruxAdapter};
use crate::crypto::sha256_hex;
use crate::schema::{
    create_crux_db, CruxDb, CruxKind, CruxNode, NodeSchema, PlanningMetadata, SecurityMetadata,
};

pub struct PlaintextAdapter;

impl CruxAdapter for PlaintextAdapter {
    fn generate(&self, input: &str, config: &AdapterConfig) -> Result<CruxDb, String> {
        let mut db = create_crux_db(&config.name, CruxKind::Documentation, &config.origin);

        let content_hash = format!("sha256:{}", sha256_hex(input.as_bytes()));
        let node_id = format!(
            "sha256:{}",
            sha256_hex(format!("node:{}:document", config.name).as_bytes())
        );

        // Produce a short summary: first line or first 100 chars
        let summary = if let Some(first_line) = input.lines().next() {
            if first_line.len() > 100 {
                format!("{}...", &first_line[..97])
            } else {
                first_line.to_string()
            }
        } else {
            "(empty document)".to_string()
        };

        db.nodes.push(CruxNode {
            node_id,
            name: config.name.clone(),
            kind: "document".to_string(),
            module: "".to_string(),
            summary,
            schema: NodeSchema::empty(),
            tags: vec!["text".to_string()],
            reach: vec![],
            properties: vec![],
            warnings: vec![],
            planning: PlanningMetadata::empty(),
            security: SecurityMetadata::internal(),
            content_hash,
            deleted_at: None,
        });

        Ok(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plaintext_adapter() {
        let adapter = PlaintextAdapter;
        let config = AdapterConfig::new("notes", "plaintext");

        let db = adapter.generate("Hello, world!\nSecond line.", &config).unwrap();
        assert_eq!(db.nodes.len(), 1);
        assert_eq!(db.nodes[0].kind, "document");
        assert_eq!(db.nodes[0].summary, "Hello, world!");
        assert!(db.nodes[0].content_hash.starts_with("sha256:"));
    }

    #[test]
    fn test_plaintext_empty() {
        let adapter = PlaintextAdapter;
        let config = AdapterConfig::new("empty", "plaintext");

        let db = adapter.generate("", &config).unwrap();
        assert_eq!(db.nodes.len(), 1);
        assert_eq!(db.nodes[0].summary, "(empty document)");
    }

    // --- Edge-case tests (Phase A-2) ---

    #[test]
    fn test_plaintext_long_first_line_truncated() {
        let long_line = "x".repeat(200);
        let adapter = PlaintextAdapter;
        let config = AdapterConfig::new("long", "plaintext");

        let db = adapter.generate(&long_line, &config).unwrap();
        assert!(db.nodes[0].summary.ends_with("..."));
        assert!(db.nodes[0].summary.len() <= 100);
    }

    #[test]
    fn test_plaintext_single_short_line() {
        let adapter = PlaintextAdapter;
        let config = AdapterConfig::new("short", "plaintext");

        let db = adapter.generate("Just one line", &config).unwrap();
        assert_eq!(db.nodes[0].summary, "Just one line");
    }

    #[test]
    fn test_plaintext_content_hash_deterministic() {
        let adapter = PlaintextAdapter;
        let config = AdapterConfig::new("det", "plaintext");

        let db1 = adapter.generate("same content", &config).unwrap();
        let db2 = adapter.generate("same content", &config).unwrap();
        assert_eq!(db1.nodes[0].content_hash, db2.nodes[0].content_hash);
    }

    #[test]
    fn test_plaintext_content_hash_differs_for_different_input() {
        let adapter = PlaintextAdapter;
        let config = AdapterConfig::new("diff", "plaintext");

        let db1 = adapter.generate("content A", &config).unwrap();
        let db2 = adapter.generate("content B", &config).unwrap();
        assert_ne!(db1.nodes[0].content_hash, db2.nodes[0].content_hash);
    }
}
