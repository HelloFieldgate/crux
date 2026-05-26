//! Markdown adapter — parse headings into section nodes with edges.

use crate::adapters::{AdapterConfig, CruxAdapter};
use crate::crypto::sha256_hex;
use crate::schema::{
    create_crux_db, CruxDb, CruxEdge, CruxKind, CruxNode, EdgeKind, NodeSchema,
    PlanningMetadata, SecurityMetadata,
};

pub struct MarkdownAdapter;

/// A parsed section from a markdown document.
struct Section {
    level: usize,
    title: String,
    summary: String,
    tags: Vec<String>,
}

impl CruxAdapter for MarkdownAdapter {
    fn generate(&self, input: &str, config: &AdapterConfig) -> Result<CruxDb, String> {
        let mut db = create_crux_db(&config.name, CruxKind::Documentation, &config.origin);
        let sections = parse_sections(input);

        if sections.is_empty() {
            // No headings — treat the whole thing as a single document node
            let content_hash = format!("sha256:{}", sha256_hex(input.as_bytes()));
            let node_id = format!(
                "sha256:{}",
                sha256_hex(format!("node:{}:root", config.name).as_bytes())
            );
            let summary = input
                .lines()
                .next()
                .unwrap_or("(empty)")
                .chars()
                .take(100)
                .collect::<String>();

            db.nodes.push(CruxNode {
                node_id,
                name: config.name.clone(),
                kind: "document".to_string(),
                module: "".to_string(),
                summary,
                schema: NodeSchema::empty(),
                tags: vec!["markdown".to_string()],
                reach: vec![],
                properties: vec![],
                warnings: vec![],
                planning: PlanningMetadata::empty(),
                security: SecurityMetadata::internal(),
                content_hash,
                deleted_at: None,
            });
            return Ok(db);
        }

        // Create nodes for each section
        for (i, section) in sections.iter().enumerate() {
            let node_id = format!(
                "sha256:{}",
                sha256_hex(format!("node:{}:section:{}", config.name, i).as_bytes())
            );
            let content_hash = format!("sha256:{}", sha256_hex(section.title.as_bytes()));

            let mut tags = section.tags.clone();
            tags.push("markdown".to_string());

            db.nodes.push(CruxNode {
                node_id,
                name: section.title.clone(),
                kind: "section".to_string(),
                module: "".to_string(),
                summary: section.summary.clone(),
                schema: NodeSchema::empty(),
                tags,
                reach: vec![],
                properties: vec![],
                warnings: vec![],
                planning: PlanningMetadata::empty(),
                security: SecurityMetadata::internal(),
                content_hash,
                deleted_at: None,
            });
        }

        // Create "contains" edges: higher-level sections contain lower-level ones
        let mut parent_stack: Vec<(usize, usize)> = Vec::new(); // (section_index, level)

        for (i, section) in sections.iter().enumerate() {
            // Pop parents that are at the same or deeper level
            while let Some(&(_, parent_level)) = parent_stack.last() {
                if parent_level >= section.level {
                    parent_stack.pop();
                } else {
                    break;
                }
            }

            // If there's a parent, create a "contains" edge
            if let Some(&(parent_idx, _)) = parent_stack.last() {
                let edge_id = format!(
                    "sha256:{}",
                    sha256_hex(format!("edge:{}:{}:{}", config.name, parent_idx, i).as_bytes())
                );
                db.edges.push(CruxEdge {
                    edge_id,
                    src: db.nodes[parent_idx].name.clone(),
                    dst: db.nodes[i].name.clone(),
                    kind: EdgeKind::Contains,
                    weight: 1.0,
                    detail: "".to_string(),
                    cross_crux: false,
                    binding: "".to_string(),
                    created_at: 0,
                    dangling: false,
                });
            }

            parent_stack.push((i, section.level));
        }

        Ok(db)
    }
}

/// Parse markdown text into sections based on `#` headings.
fn parse_sections(input: &str) -> Vec<Section> {
    let mut sections = Vec::new();
    let mut current_body = String::new();
    let mut current_heading: Option<(usize, String)> = None;

    for line in input.lines() {
        let trimmed = line.trim();
        if let Some(stripped) = trimmed.strip_prefix('#') {
            // Count heading level
            let mut level = 1;
            let mut rest = stripped;
            while let Some(s) = rest.strip_prefix('#') {
                level += 1;
                rest = s;
            }
            let title = rest.trim().to_string();

            // Flush previous section
            if let Some((prev_level, prev_title)) = current_heading.take() {
                let summary = make_summary(&current_body);
                let tags = extract_code_tags(&current_body);
                sections.push(Section {
                    level: prev_level,
                    title: prev_title,
                    summary,
                    tags,
                });
                current_body.clear();
            }

            current_heading = Some((level, title));
        } else if !trimmed.is_empty() {
            if !current_body.is_empty() {
                current_body.push(' ');
            }
            current_body.push_str(trimmed);
        }
    }

    // Flush last section
    if let Some((level, title)) = current_heading {
        let summary = make_summary(&current_body);
        let tags = extract_code_tags(&current_body);
        sections.push(Section {
            level,
            title,
            summary,
            tags,
        });
    }

    sections
}

/// Create a short summary from body text (first sentence or first 100 chars).
fn make_summary(body: &str) -> String {
    if body.is_empty() {
        return String::new();
    }
    // Take first sentence (up to period, question mark, or exclamation)
    if let Some(idx) = body.find(['.', '?', '!']) {
        let sentence = &body[..=idx];
        if sentence.len() <= 120 {
            return sentence.to_string();
        }
    }
    if body.len() <= 100 {
        body.to_string()
    } else {
        format!("{}...", &body[..97])
    }
}

/// Extract language tags from fenced code blocks (```lang).
fn extract_code_tags(body: &str) -> Vec<String> {
    let mut tags = Vec::new();
    for line in body.split(' ') {
        if let Some(lang) = line.strip_prefix("```") {
            let lang = lang.trim();
            if !lang.is_empty() && !tags.contains(&lang.to_string()) {
                tags.push(lang.to_string());
            }
        }
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markdown_with_headings() {
        let adapter = MarkdownAdapter;
        let config = AdapterConfig::new("readme", "markdown");

        let input = "# Introduction\nThis is the intro.\n\n## Getting Started\nInstall the package.\n\n## Usage\nUse it like this.\n\n# API\nAPI docs here.\n";

        let db = adapter.generate(input, &config).unwrap();
        assert_eq!(db.nodes.len(), 4);
        assert_eq!(db.nodes[0].name, "Introduction");
        assert_eq!(db.nodes[0].kind, "section");
        assert_eq!(db.nodes[1].name, "Getting Started");
        assert_eq!(db.nodes[2].name, "Usage");
        assert_eq!(db.nodes[3].name, "API");

        // Edges: Introduction -> Getting Started, Introduction -> Usage
        assert!(db.edges.len() >= 2);
        assert_eq!(db.edges[0].src, "Introduction");
        assert_eq!(db.edges[0].dst, "Getting Started");
        assert_eq!(db.edges[0].kind, EdgeKind::Contains);
    }

    #[test]
    fn test_markdown_no_headings() {
        let adapter = MarkdownAdapter;
        let config = AdapterConfig::new("plain", "markdown");

        let db = adapter.generate("Just some text without headings.", &config).unwrap();
        assert_eq!(db.nodes.len(), 1);
        assert_eq!(db.nodes[0].kind, "document");
    }

    #[test]
    fn test_parse_sections() {
        let input = "# Top\nBody.\n## Sub\nSub body.\n";
        let sections = parse_sections(input);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].level, 1);
        assert_eq!(sections[0].title, "Top");
        assert_eq!(sections[1].level, 2);
        assert_eq!(sections[1].title, "Sub");
    }

    #[test]
    fn test_make_summary() {
        assert_eq!(make_summary("Short."), "Short.");
        assert_eq!(make_summary(""), "");
        let long = "a".repeat(200);
        let s = make_summary(&long);
        assert!(s.ends_with("..."));
        assert!(s.len() <= 103);
    }

    // --- Edge-case tests (Phase A-2) ---

    #[test]
    fn test_markdown_empty_input() {
        let adapter = MarkdownAdapter;
        let config = AdapterConfig::new("empty", "markdown");

        let db = adapter.generate("", &config).unwrap();
        assert_eq!(db.nodes.len(), 1);
        assert_eq!(db.nodes[0].kind, "document");
    }

    #[test]
    fn test_parse_sections_empty() {
        assert!(parse_sections("").is_empty());
    }

    #[test]
    fn test_parse_sections_heading_only_no_body() {
        let sections = parse_sections("# Title\n");
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].title, "Title");
        assert_eq!(sections[0].summary, "");
    }

    #[test]
    fn test_parse_sections_deep_nesting() {
        let input = "# H1\n## H2\n### H3\n#### H4\n";
        let sections = parse_sections(input);
        assert_eq!(sections.len(), 4);
        assert_eq!(sections[3].level, 4);
    }

    #[test]
    fn test_make_summary_question_mark() {
        assert_eq!(make_summary("Why not?"), "Why not?");
    }

    #[test]
    fn test_make_summary_exclamation() {
        assert_eq!(make_summary("Hello!"), "Hello!");
    }

    #[test]
    fn test_markdown_code_fence_tags() {
        let adapter = MarkdownAdapter;
        let config = AdapterConfig::new("code", "markdown");
        let input = "# Setup\n```rust\nfn main() {}\n```\n";

        let db = adapter.generate(input, &config).unwrap();
        assert_eq!(db.nodes.len(), 1);
        assert!(db.nodes[0].tags.contains(&"rust".to_string()));
    }
}
