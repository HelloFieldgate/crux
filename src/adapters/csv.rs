//! RFC 4180-compliant CSV adapter for the Crux system.
//!
//! Provides `parse_csv` for parsing CSV text into (headers, rows) and
//! `CsvAdapter` for generating a `CruxDb` from CSV data with optional
//! column→field role mappings.

use std::collections::HashMap;
use crate::schema::{CruxDb, CruxNode, CruxKind, NodeSchema, PlanningMetadata, SecurityMetadata};
use crate::crypto::sha256_hex;
use super::{AdapterConfig, CruxAdapter};

/// Maps a CSV column header name → crux field role.
/// Known roles: `"name"` | `"kind"` | `"summary"` | `"tags"` | `"skip"`
/// Any other value (or absent) → treated as `"property"` (`header=value`).
pub type ColumnMap = HashMap<String, String>;

/// RFC 4180-compliant CSV adapter.
pub struct CsvAdapter;

// ── RFC 4180 parser ───────────────────────────────────────────────────────────

/// Parse RFC 4180 CSV text into `(headers, data_rows)`.
///
/// Handles: quoted fields, embedded commas, embedded newlines, `""` escapes,
/// CRLF line endings, and trailing empty lines.  First row is the header row.
pub fn parse_csv(input: &str) -> (Vec<String>, Vec<Vec<String>>) {
    #[derive(PartialEq)]
    enum State { Start, Unquoted, Quoted, AfterQuote }

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut cur_row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut state = State::Start;
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        let b = bytes[i];
        let c = b as char;
        match state {
            State::Start | State::Unquoted => {
                if b == b'"' {
                    state = State::Quoted;
                } else if b == b',' {
                    cur_row.push(field.trim().to_string());
                    field = String::new();
                    state = State::Start;
                } else if b == b'\n' || (b == b'\r' && i + 1 < len && bytes[i + 1] == b'\n') {
                    if b == b'\r' { i += 1; } // consume \n of CRLF
                    cur_row.push(field.trim().to_string());
                    field = String::new();
                    if cur_row.iter().any(|v| !v.is_empty()) {
                        rows.push(cur_row);
                    }
                    cur_row = Vec::new();
                    state = State::Start;
                } else if b == b'\r' {
                    // lone CR: treat as newline
                    cur_row.push(field.trim().to_string());
                    field = String::new();
                    if cur_row.iter().any(|v| !v.is_empty()) {
                        rows.push(cur_row);
                    }
                    cur_row = Vec::new();
                    state = State::Start;
                } else {
                    field.push(c);
                    state = State::Unquoted;
                }
            }
            State::Quoted => {
                if b == b'"' {
                    state = State::AfterQuote;
                } else {
                    field.push(c);
                }
            }
            State::AfterQuote => {
                if b == b'"' {
                    // escaped quote
                    field.push('"');
                    state = State::Quoted;
                } else if b == b',' {
                    cur_row.push(field.clone());
                    field = String::new();
                    state = State::Start;
                } else if b == b'\n' || b == b'\r' {
                    if b == b'\r' && i + 1 < len && bytes[i + 1] == b'\n' {
                        i += 1;
                    }
                    cur_row.push(field.clone());
                    field = String::new();
                    if cur_row.iter().any(|v| !v.is_empty()) {
                        rows.push(cur_row);
                    }
                    cur_row = Vec::new();
                    state = State::Start;
                } else {
                    // character after closing quote (malformed, be lenient)
                    field.push(c);
                    state = State::Unquoted;
                }
            }
        }
        i += 1;
    }

    // flush final field + row
    let final_field = if state == State::Quoted || state == State::AfterQuote {
        field.clone()
    } else {
        field.trim().to_string()
    };
    cur_row.push(final_field);
    if cur_row.iter().any(|v| !v.is_empty()) {
        rows.push(cur_row);
    }

    if rows.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let headers = rows.remove(0);
    (headers, rows)
}

// ── Node generation helpers ───────────────────────────────────────────────────

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    }
}

// ── CsvAdapter ────────────────────────────────────────────────────────────────

impl CsvAdapter {
    /// Generate a `CruxDb` with explicit column→field role mappings.
    ///
    /// `column_map` maps CSV header names to field roles:
    ///   - `"name"` → node name
    ///   - `"kind"` → node kind
    ///   - `"summary"` → node summary
    ///   - `"tags"` → split on `|` or `,`
    ///   - `"skip"` → ignore column
    ///   - anything else / absent → property `header=value`
    ///
    /// `default_kind`: node kind when no column is mapped to `"kind"`.
    pub fn generate_with_map(
        input: &str,
        config: &AdapterConfig,
        column_map: &ColumnMap,
        default_kind: &str,
    ) -> Result<CruxDb, String> {
        let (headers, rows) = parse_csv(input);
        if headers.is_empty() {
            return Err("CSV must have at least a header row".to_string());
        }
        if rows.is_empty() {
            return Err("CSV must have at least one data row".to_string());
        }

        let classification = config.default_classification.clone()
            .unwrap_or_else(|| "internal".to_string());

        let mut nodes = Vec::new();

        for (row_idx, row) in rows.iter().enumerate() {
            let real_row = row_idx + 1; // 1-based row number (header is row 0)

            let mut node_name: Option<String> = None;
            let mut node_kind: Option<String> = None;
            let mut node_summary: Option<String> = None;
            let mut extra_tags: Vec<String> = Vec::new();
            let mut properties: Vec<String> = Vec::new();
            let mut content_parts: Vec<String> = Vec::new();

            for (col_idx, header) in headers.iter().enumerate() {
                let val = row.get(col_idx).map(|s| s.as_str()).unwrap_or("").trim().to_string();
                let role = column_map.get(header).map(|s| s.as_str()).unwrap_or("property");

                match role {
                    "name" => {
                        if node_name.is_none() && !val.is_empty() {
                            node_name = Some(val.clone());
                        } else if !val.is_empty() {
                            // Secondary "name" columns become properties
                            properties.push(format!("{}={}", header, val));
                        }
                    }
                    "kind" => {
                        if !val.is_empty() {
                            node_kind = Some(val.clone());
                        }
                    }
                    "summary" => {
                        if !val.is_empty() {
                            node_summary = Some(val.clone());
                        }
                    }
                    "tags" => {
                        for tag in val.split(|c| c == '|' || c == ',') {
                            let t = tag.trim().to_string();
                            if !t.is_empty() {
                                extra_tags.push(t);
                            }
                        }
                    }
                    "skip" => {} // ignore
                    _ => {
                        // property role
                        if !val.is_empty() {
                            properties.push(format!("{}={}", header, val));
                            content_parts.push(format!("{}: {}", header, val));
                        }
                    }
                }

                // Always include non-skip, non-empty values in content hash
                if role != "skip" && !val.is_empty() {
                    if role != "property" {
                        content_parts.push(format!("{}: {}", header, val));
                    }
                    // email domain tag
                    if header.to_lowercase() == "email" && val.contains('@') {
                        if let Some(domain) = val.split('@').nth(1) {
                            extra_tags.push(domain.to_string());
                        }
                    }
                }
            }

            // Fallback name
            let name = node_name.unwrap_or_else(|| {
                // try col 0
                row.first().filter(|v| !v.is_empty()).cloned()
                    .unwrap_or_else(|| format!("Record {}", real_row))
            });

            // Fallback summary
            let summary_raw = node_summary.unwrap_or_else(|| {
                row.iter().filter(|v| !v.is_empty()).take(3)
                    .cloned().collect::<Vec<_>>().join(" | ")
            });
            let summary = truncate_str(&summary_raw, 200);

            // Source ref properties
            properties.push(format!("source_ref.row={}", real_row));
            properties.push(format!("source_ref.record_index={}", row_idx));

            // Tags
            let mut tags = vec!["csv".to_string()];
            tags.extend(extra_tags);

            let content_hash = sha256_hex(content_parts.join("\n").as_bytes());
            let node_id = format!("csv-record-{}", real_row);

            nodes.push(CruxNode {
                node_id,
                name,
                kind: node_kind.unwrap_or_else(|| default_kind.to_string()),
                module: "csv".to_string(),
                summary,
                schema: NodeSchema::empty(),
                tags,
                reach: vec![],
                properties,
                warnings: vec![],
                planning: PlanningMetadata::empty(),
                security: SecurityMetadata {
                    classification: classification.clone(),
                    redact_below: None,
                },
                content_hash,
                deleted_at: None,
            });
        }

        Ok(CruxDb {
            header: crate::schema::create_crux_db(&config.name, CruxKind::Dataset, &config.origin).header,
            nodes,
            edges: Vec::new(),
            modules: Vec::new(),
            domains: Vec::new(),
        })
    }
}

impl CruxAdapter for CsvAdapter {
    /// Generate a `CruxDb` from CSV input using auto-detected column roles.
    ///
    /// Detects a name column by checking headers for common name-like labels,
    /// then stores all other columns as properties. Uses the RFC 4180 parser.
    fn generate(&self, input: &str, config: &AdapterConfig) -> Result<CruxDb, String> {
        let (headers, rows) = parse_csv(input);
        if headers.is_empty() {
            return Err("CSV must have at least a header row".to_string());
        }
        if rows.is_empty() {
            return Err("CSV must have at least one data row".to_string());
        }

        let classification = config.default_classification.clone()
            .unwrap_or_else(|| "internal".to_string());

        // Detect a likely "name" column
        let name_col = headers.iter().position(|h| {
            let hl = h.to_lowercase();
            hl == "name" || hl == "id" || hl == "title" || hl == "subject"
                || hl == "email" || hl == "full_name" || hl == "username"
        });

        let mut nodes = Vec::new();

        for (row_idx, row) in rows.iter().enumerate() {
            let real_row = row_idx + 1;

            let mut properties: Vec<String> = Vec::new();
            let mut content_parts: Vec<String> = Vec::new();

            for (j, header) in headers.iter().enumerate() {
                let val = row.get(j).map(|s| s.as_str()).unwrap_or("").trim().to_string();
                if !val.is_empty() {
                    properties.push(format!("{}={}", header, val));
                    content_parts.push(format!("{}: {}", header, val));
                }
            }

            let content_hash = sha256_hex(content_parts.join("\n").as_bytes());

            let node_name = name_col
                .and_then(|col| row.get(col))
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| format!("Record {}", real_row));

            let summary = truncate_str(
                &row.iter().take(3).filter(|v| !v.is_empty())
                    .cloned().collect::<Vec<_>>().join(" | "),
                200,
            );

            properties.push(format!("source_ref.row={}", real_row));
            properties.push(format!("source_ref.record_index={}", row_idx));

            let mut tags = vec!["csv".to_string(), "data".to_string()];
            if let Some(pos) = headers.iter().position(|h| h.to_lowercase() == "email") {
                if let Some(email_val) = row.get(pos).filter(|v| !v.is_empty()) {
                    if let Some(domain) = email_val.split('@').nth(1) {
                        tags.push(domain.to_string());
                    }
                }
            }

            nodes.push(CruxNode {
                node_id: format!("csv-record-{}", real_row),
                name: node_name,
                kind: "data".to_string(),
                module: "csv".to_string(),
                summary,
                schema: NodeSchema::empty(),
                tags,
                reach: vec![],
                properties,
                warnings: vec![],
                planning: PlanningMetadata::empty(),
                security: SecurityMetadata {
                    classification: classification.clone(),
                    redact_below: None,
                },
                content_hash,
                deleted_at: None,
            });
        }

        Ok(CruxDb {
            header: crate::schema::create_crux_db(&config.name, CruxKind::Dataset, &config.origin).header,
            nodes,
            edges: Vec::new(),
            modules: Vec::new(),
            domains: Vec::new(),
        })
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csv_simple() {
        let (headers, rows) = parse_csv("Name,Status\nAlice,Active\nBob,Inactive\n");
        assert_eq!(headers, vec!["Name", "Status"]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec!["Alice", "Active"]);
        assert_eq!(rows[1], vec!["Bob", "Inactive"]);
    }

    #[test]
    fn test_parse_csv_quoted_commas() {
        let (headers, rows) = parse_csv("Name,Notes\nAlice,\"She said, hello\"\nBob,Plain");
        assert_eq!(headers, vec!["Name", "Notes"]);
        assert_eq!(rows[0][1], "She said, hello");
        assert_eq!(rows[1][1], "Plain");
    }

    #[test]
    fn test_parse_csv_quoted_newlines() {
        let input = "Name,Bio\nAlice,\"Line one\nLine two\"\nBob,Simple";
        let (headers, rows) = parse_csv(input);
        assert_eq!(headers, vec!["Name", "Bio"]);
        assert_eq!(rows[0][1], "Line one\nLine two");
        assert_eq!(rows[1][0], "Bob");
    }

    #[test]
    fn test_parse_csv_escaped_quotes() {
        let input = "Name,Quote\nAlice,\"She said \"\"hi\"\"\"\nBob,Normal";
        let (headers, rows) = parse_csv(input);
        assert_eq!(headers, vec!["Name", "Quote"]);
        assert_eq!(rows[0][1], "She said \"hi\"");
        assert_eq!(rows[1][1], "Normal");
    }

    #[test]
    fn test_parse_csv_crlf() {
        let input = "A,B\r\n1,2\r\n3,4\r\n";
        let (headers, rows) = parse_csv(input);
        assert_eq!(headers, vec!["A", "B"]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec!["1", "2"]);
    }

    #[test]
    fn test_generate_with_map_name_col() {
        let input = "Name,Status\nAlice,Active\nBob,Inactive";
        let config = AdapterConfig::new("test", "csv");
        let mut col_map = ColumnMap::new();
        col_map.insert("Name".to_string(), "name".to_string());
        let db = CsvAdapter::generate_with_map(input, &config, &col_map, "record").unwrap();
        assert_eq!(db.nodes.len(), 2);
        assert_eq!(db.nodes[0].name, "Alice");
        assert_eq!(db.nodes[1].name, "Bob");
        assert_eq!(db.nodes[0].kind, "record");
    }

    #[test]
    fn test_generate_with_map_tags_split() {
        let input = "Name,Tags\nAlice,foo|bar|baz";
        let config = AdapterConfig::new("test", "csv");
        let mut col_map = ColumnMap::new();
        col_map.insert("Tags".to_string(), "tags".to_string());
        let db = CsvAdapter::generate_with_map(input, &config, &col_map, "record").unwrap();
        let tags = &db.nodes[0].tags;
        assert!(tags.contains(&"foo".to_string()));
        assert!(tags.contains(&"bar".to_string()));
        assert!(tags.contains(&"baz".to_string()));
        assert!(tags.contains(&"csv".to_string()));
    }

    #[test]
    fn test_generate_with_map_default_kind() {
        let input = "Name\nAlice";
        let config = AdapterConfig::new("test", "csv");
        let col_map = ColumnMap::new();
        let db = CsvAdapter::generate_with_map(input, &config, &col_map, "task").unwrap();
        assert_eq!(db.nodes[0].kind, "task");
    }
}
