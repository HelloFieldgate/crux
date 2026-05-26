//! Auto-adapter — automatically generate cruxes from various data sources.
//!
//! This adapter can detect the format of input data and delegate to appropriate
//! sub-adapters for processing. Supports:
//! - Email (mbox, eml)
//! - Slack exports (JSON)
//! - ERP/CRM data (CSV, JSON)
//! - Codebases (existing adapters)
//! - Documents (existing adapters)

use std::collections::HashMap;
use crate::schema::{CruxDb, CruxNode, CruxEdge, EdgeKind, NodeSchema, PlanningMetadata, SecurityMetadata};
use crate::crypto::sha256_hex;
use super::{AdapterConfig, CruxAdapter};

/// Auto-detecting adapter that can process various data source formats.
pub struct AutoAdapter;

impl CruxAdapter for AutoAdapter {
    fn generate(&self, input: &str, config: &AdapterConfig) -> Result<CruxDb, String> {
        // Detect input format and delegate
        if self.is_email_format(input) {
            self.generate_from_email(input, config)
        } else if self.is_slack_export(input) {
            self.generate_from_slack(input, config)
        } else if self.is_csv_data(input) {
            self.generate_from_csv(input, config)
        } else if self.is_json_api(input) {
            self.generate_from_json_api(input, config)
        } else {
            // Fallback to plaintext adapter
            super::plaintext::PlaintextAdapter.generate(input, config)
        }
    }
}

impl AutoAdapter {
    /// Check if input looks like email data (mbox or eml format).
    fn is_email_format(&self, input: &str) -> bool {
        input.contains("From ") && input.contains("@") && input.contains("Subject:")
    }

    /// Check if input looks like Slack export JSON.
    fn is_slack_export(&self, input: &str) -> bool {
        let trimmed = input.trim();
        (trimmed.starts_with('{') || trimmed.starts_with('[')) &&
        input.contains("\"user\"") &&
        (input.contains("\"channel\"") || input.contains("\"ts\""))
    }

    /// Check if input looks like CSV data.
    fn is_csv_data(&self, input: &str) -> bool {
        let lines: Vec<&str> = input.lines().take(3).collect();
        lines.len() >= 2 &&
        lines[0].contains(',') &&
        lines[1].contains(',') &&
        !lines[0].trim().starts_with('{')
    }

    /// Check if input looks like JSON API data.
    fn is_json_api(&self, input: &str) -> bool {
        input.trim().starts_with('{') &&
        (input.contains("\"data\"") || input.contains("\"records\"") || input.contains("\"items\""))
    }

    /// Generate crux from email data.
    fn generate_from_email(&self, input: &str, config: &AdapterConfig) -> Result<CruxDb, String> {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let classification = config.default_classification.clone()
            .unwrap_or_else(|| "internal".to_string());

        // Parse email messages
        let messages = self.parse_emails(input)?;

        for (i, email) in messages.iter().enumerate() {
            let node_name = email.subject.clone().unwrap_or_else(|| format!("Email {}", i));
            let content_hash = sha256_hex(email.content.as_bytes());

            // Store email metadata as properties for cross-crux matching
            let mut properties = Vec::new();
            properties.push(format!("from={}", email.from));
            for to_addr in &email.to {
                properties.push(format!("to={}", to_addr));
            }
            if let Some(ref subj) = email.subject {
                properties.push(format!("subject={}", subj));
            }
            if let Some(ts) = email.timestamp {
                properties.push(format!("date={}", ts));
            }
            if let Some(ref msg_id) = email.message_id {
                properties.push(format!("message_id={}", msg_id));
            }
            if let Some(ref irt) = email.in_reply_to {
                properties.push(format!("in_reply_to={}", irt));
            }

            // Extract sender email address for cross-crux linking
            let sender_email = extract_email_address(&email.from);
            if let Some(ref addr) = sender_email {
                properties.push(format!("email={}", addr));
            }

            // Source reference: byte-level pointer into the mbox file for forensic retrieval
            properties.push(format!("source_ref.byte_offset={}", email.byte_offset));
            properties.push(format!("source_ref.byte_length={}", email.byte_length));
            properties.push(format!("source_ref.record_index={}", email.record_index));
            properties.push("source_ref.record_delimiter=From ".to_string());

            // Build tags: sender domain + communication type
            let mut tags = vec!["email".to_string(), "communication".to_string()];
            if let Some(ref addr) = sender_email {
                if let Some(domain) = addr.split('@').nth(1) {
                    tags.push(domain.to_string());
                }
            }

            let node = CruxNode {
                node_id: format!("email-{}", i),
                name: node_name.clone(),
                kind: "communication".to_string(),
                module: "email".to_string(),
                summary: truncate_summary(
                    &format!("Email from {} to {}", email.from, email.to.join(", ")), 200
                ),
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
            };

            nodes.push(node);

            // Create edges for email threads/replies
            if let Some(in_reply_to) = &email.in_reply_to {
                edges.push(CruxEdge {
                    edge_id: format!("email-reply-{}-{}", in_reply_to, i),
                    src: in_reply_to.clone(),
                    dst: node_name,
                    kind: EdgeKind::RelatesTo,
                    weight: 1.0,
                    detail: "email reply".to_string(),
                    cross_crux: false,
                    binding: "thread".to_string(),
                    created_at: email.timestamp.unwrap_or(0),
                    dangling: false,
                });
            }
        }

        Ok(CruxDb {
            header: crate::schema::create_crux_db(&config.name, crate::schema::CruxKind::Dataset, &config.origin).header,
            nodes,
            edges,
            modules: Vec::new(),
            domains: Vec::new(),
        })
    }

    /// Generate crux from Slack export data.
    fn generate_from_slack(&self, input: &str, config: &AdapterConfig) -> Result<CruxDb, String> {
        // Parse Slack JSON and create communication nodes
        let mut nodes = Vec::new();
        let classification = config.default_classification.clone()
            .unwrap_or_else(|| "internal".to_string());

        // Simple JSON parsing for Slack messages
        if let Ok(messages) = self.parse_slack_messages(input) {
            for (i, msg) in messages.iter().enumerate() {
                let content = format!("{}: {}", msg.user, msg.text);
                let content_hash = sha256_hex(content.as_bytes());

                // Use timestamp + user as the unique node name
                let node_name = format!("{}:{}", msg.user, msg._timestamp);

                let properties = vec![
                    format!("user={}", msg.user),
                    format!("channel={}", msg._channel),
                    format!("ts={}", msg._timestamp),
                    format!("source_ref.record_index={}", i),
                ];

                let summary = truncate_summary(&msg.text, 200);

                let node = CruxNode {
                    node_id: format!("slack-msg-{}", i),
                    name: node_name,
                    kind: "communication".to_string(),
                    module: format!("slack:{}", msg._channel),
                    summary,
                    schema: NodeSchema::empty(),
                    tags: vec![
                        "slack".to_string(),
                        "communication".to_string(),
                        msg._channel.clone(),
                    ],
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
                };

                nodes.push(node);
            }
        }

        Ok(CruxDb {
            header: crate::schema::create_crux_db(&config.name, crate::schema::CruxKind::Dataset, &config.origin).header,
            nodes,
            edges: Vec::new(),
            modules: Vec::new(),
            domains: Vec::new(),
        })
    }

    /// Generate crux from CSV data (generic business data).
    fn generate_from_csv(&self, input: &str, config: &AdapterConfig) -> Result<CruxDb, String> {
        super::csv::CsvAdapter.generate(input, config)
    }

    /// Generate crux from JSON API data.
    fn generate_from_json_api(&self, input: &str, config: &AdapterConfig) -> Result<CruxDb, String> {
        let mut nodes = Vec::new();
        let classification = config.default_classification.clone()
            .unwrap_or_else(|| "internal".to_string());

        // Simple JSON parsing for API responses
        if let Ok(records) = self.parse_json_records(input) {
            for (i, record) in records.iter().enumerate() {
                let node_id = format!("api-record-{}", i);

                // Store all key-value pairs as properties
                let mut properties: Vec<String> = record.iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect();
                properties.sort(); // deterministic

                // Build content string for hashing
                let mut content_parts: Vec<String> = record.iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                content_parts.sort();
                let content = content_parts.join("\n");
                let content_hash = sha256_hex(content.as_bytes());

                // Use "name", "id", "title", or "email" field as node name if present
                let name_keys = ["name", "id", "title", "email", "username", "full_name"];
                let node_name = name_keys.iter()
                    .find_map(|k| record.get(*k))
                    .cloned()
                    .unwrap_or_else(|| format!("API Record {}", i));

                // Build a meaningful summary from the record's fields
                let summary_parts: Vec<String> = record.iter()
                    .take(3)
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                let summary = truncate_summary(&summary_parts.join(", "), 200);

                // Tags: kind of data + any domain-like values
                let mut tags = vec!["api".to_string(), "data".to_string()];
                if let Some(email_val) = record.get("email") {
                    if let Some(domain) = email_val.split('@').nth(1) {
                        tags.push(domain.to_string());
                    }
                    properties.push(format!("email={}", email_val));
                }

                // Source reference: index within the JSON array for retrieval
                properties.push(format!("source_ref.record_index={}", i));

                let node = CruxNode {
                    node_id,
                    name: node_name,
                    kind: "data".to_string(),
                    module: "api".to_string(),
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
                };

                nodes.push(node);
            }
        }

        Ok(CruxDb {
            header: crate::schema::create_crux_db(&config.name, crate::schema::CruxKind::Api, &config.origin).header,
            nodes,
            edges: Vec::new(),
            modules: Vec::new(),
            domains: Vec::new(),
        })
    }

    // ---- Parsers ----

    /// Parse mbox-format email text into `EmailMessage` structs.
    /// Each message starts with a line beginning with "From " (mbox separator).
    /// Tracks byte offsets of each message within the source for forensic retrieval.
    fn parse_emails(&self, input: &str) -> Result<Vec<EmailMessage>, String> {
        let mut messages = Vec::new();
        let mut current_lines: Vec<&str> = Vec::new();
        let mut msg_byte_start: u64 = 0;
        let mut record_index: usize = 0;
        let mut in_message = false;
        let mut byte_pos: u64 = 0;

        for line in input.split('\n') {
            // Each line's byte length includes the '\n' that split() consumed.
            let line_byte_len = line.len() as u64 + 1;
            let trimmed = line.trim_end_matches('\r');

            if trimmed.starts_with("From ") {
                // Flush the previous message
                if in_message {
                    let byte_len = byte_pos - msg_byte_start;
                    if let Some(mut msg) = parse_email_block(&current_lines) {
                        msg.byte_offset = msg_byte_start;
                        msg.byte_length = byte_len;
                        msg.record_index = record_index;
                        messages.push(msg);
                        record_index += 1;
                    }
                    current_lines.clear();
                }
                msg_byte_start = byte_pos;
                in_message = true;
            } else if in_message {
                current_lines.push(trimmed);
            }

            byte_pos += line_byte_len;
        }

        // Flush the last message
        if in_message {
            let byte_len = input.len() as u64 - msg_byte_start;
            if let Some(mut msg) = parse_email_block(&current_lines) {
                msg.byte_offset = msg_byte_start;
                msg.byte_length = byte_len;
                msg.record_index = record_index;
                messages.push(msg);
            }
        }

        Ok(messages)
    }

    /// Parse Slack export JSON (array of message objects) into `SlackMessage` structs.
    /// Supports both a bare array `[{...}, ...]` and the `{"messages": [...]}` envelope.
    fn parse_slack_messages(&self, input: &str) -> Result<Vec<SlackMessage>, String> {
        let mut messages = Vec::new();
        // Find the array to iterate — try unwrapping an envelope first
        let array_text = if let Some(pos) = input.find("\"messages\"") {
            let after = &input[pos..];
            if let Some(bracket) = after.find('[') {
                &after[bracket..]
            } else {
                input.trim()
            }
        } else {
            input.trim()
        };

        if !array_text.starts_with('[') {
            return Ok(messages);
        }

        // Iterate over top-level objects in the array
        let mut depth = 0usize;
        let mut obj_start: Option<usize> = None;
        for (i, c) in array_text.char_indices() {
            match c {
                '[' if depth == 0 => { depth = 1; }
                ']' if depth == 1 => {
                    if let Some(s) = obj_start.take() {
                        let obj = &array_text[s..=i.saturating_sub(1)];
                        if let Some(msg) = parse_slack_object(obj) {
                            messages.push(msg);
                        }
                    }
                    break;
                }
                '{' if depth == 1 => { depth = 2; obj_start = Some(i); }
                '{' => { depth += 1; }
                '}' if depth == 2 => {
                    if let Some(s) = obj_start.take() {
                        let obj = &array_text[s..=i];
                        if let Some(msg) = parse_slack_object(obj) {
                            messages.push(msg);
                        }
                    }
                    depth = 1;
                }
                '}' => { depth -= 1; }
                _ => {}
            }
        }
        Ok(messages)
    }

    /// Parse JSON with a top-level `data`, `records`, or `items` array.
    /// Each element is turned into a `HashMap<String, String>` of its scalar fields.
    fn parse_json_records(&self, input: &str) -> Result<Vec<HashMap<String, String>>, String> {
        use crate::json::{extract_string_value};
        let mut records = Vec::new();

        // Find the first array under one of the expected keys
        let array_text = ["\"data\"", "\"records\"", "\"items\""].iter()
            .find_map(|key| {
                input.find(key).and_then(|pos| {
                    let after = &input[pos + key.len()..];
                    after.find('[').map(|b| &after[b..])
                })
            });

        let array_text = match array_text {
            Some(t) => t,
            None => return Ok(records),
        };

        // Iterate top-level objects
        let mut depth = 0usize;
        let mut obj_start: Option<usize> = None;
        for (i, c) in array_text.char_indices() {
            match c {
                '[' if depth == 0 => { depth = 1; }
                ']' if depth == 1 => break,
                '{' if depth == 1 => { depth = 2; obj_start = Some(i); }
                '{' => { depth += 1; }
                '}' if depth == 2 => {
                    if let Some(s) = obj_start.take() {
                        let obj = &array_text[s..=i];
                        // Extract all "key": "value" pairs from this object
                        let mut record = HashMap::new();
                        // Walk through the object looking for quoted keys followed by string values
                        let mut pos = 1usize; // skip '{'
                        while pos < obj.len() {
                            if let Some(key_start) = obj[pos..].find('"').map(|p| pos + p + 1) {
                                if let Some(key_end) = obj[key_start..].find('"').map(|p| key_start + p) {
                                    let key = &obj[key_start..key_end];
                                    if let Some(val) = extract_string_value(obj, key) {
                                        record.insert(key.to_string(), val);
                                    }
                                    pos = key_end + 1;
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        if !record.is_empty() {
                            records.push(record);
                        }
                    }
                    depth = 1;
                    obj_start = None;
                }
                '}' => { depth -= 1; }
                _ => {}
            }
        }
        Ok(records)
    }
}

// Helper structs for parsing
#[derive(Debug)]
struct EmailMessage {
    from: String,
    to: Vec<String>,
    subject: Option<String>,
    content: String,
    timestamp: Option<u64>,
    in_reply_to: Option<String>,
    message_id: Option<String>,
    /// Byte offset of this message's "From " line within the source file.
    byte_offset: u64,
    /// Byte length of this message (up to the next "From " line or EOF).
    byte_length: u64,
    /// 0-based index of this message within the mbox file.
    record_index: usize,
}

#[derive(Debug)]
struct SlackMessage {
    user: String,
    text: String,
    _timestamp: u64,
    _channel: String,
}

// ---- Free helper functions ----

/// Parse a single mbox email block (lines after the "From " separator).
fn parse_email_block(lines: &[&str]) -> Option<EmailMessage> {
    let mut from = String::new();
    let mut to = Vec::new();
    let mut subject = None;
    let mut timestamp = None;
    let mut in_reply_to = None;
    let mut message_id = None;
    let mut in_body = false;
    let mut body_lines = Vec::new();

    for &line in lines {
        if in_body {
            body_lines.push(line);
            continue;
        }
        if line.is_empty() {
            in_body = true;
            continue;
        }
        if let Some(val) = line.strip_prefix("From: ") {
            from = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("To: ") {
            to = val.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(val) = line.strip_prefix("Subject: ") {
            subject = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("In-Reply-To: ") {
            in_reply_to = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("Message-ID: ").or_else(|| line.strip_prefix("Message-Id: ")) {
            message_id = Some(val.trim().trim_matches(|c| c == '<' || c == '>').to_string());
        } else if let Some(val) = line.strip_prefix("Date: ") {
            // Basic epoch parsing: try to find a 10-digit number
            let digits: String = val.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 10 {
                timestamp = digits[..10].parse().ok();
            }
        }
    }

    if from.is_empty() && body_lines.is_empty() {
        return None;
    }

    Some(EmailMessage {
        from,
        to,
        subject,
        content: body_lines.join("\n"),
        timestamp,
        in_reply_to,
        message_id,
        byte_offset: 0,
        byte_length: 0,
        record_index: 0,
    })
}

/// Extract just the email address from a "Name <addr>" or "addr" string.
fn extract_email_address(s: &str) -> Option<String> {
    if let Some(start) = s.find('<') {
        if let Some(end) = s.find('>') {
            if end > start {
                return Some(s[start + 1..end].trim().to_string());
            }
        }
    }
    // No angle brackets — check if it looks like a bare email
    if s.contains('@') {
        return Some(s.trim().to_string());
    }
    None
}

/// Truncate a string to `max_len` characters, appending "…" if truncated.
fn truncate_summary(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    }
}

/// Parse a single Slack message JSON object into a `SlackMessage`.
fn parse_slack_object(obj: &str) -> Option<SlackMessage> {
    use crate::json::{extract_string_value, extract_u64_value};
    let user = extract_string_value(obj, "user").or_else(|| extract_string_value(obj, "username"))?;
    let text = extract_string_value(obj, "text").unwrap_or_default();
    let ts_str = extract_string_value(obj, "ts").unwrap_or_default();
    let ts: u64 = ts_str.split('.').next().and_then(|s| s.parse().ok())
        .or_else(|| extract_u64_value(obj, "ts"))
        .unwrap_or(0);
    let channel = extract_string_value(obj, "channel").unwrap_or_default();
    Some(SlackMessage { user, text, _timestamp: ts, _channel: channel })
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_emails_mbox() {
        let mbox = "\
From sender@example.com Mon Jan 01 00:00:00 2024
From: Alice <alice@example.com>
To: Bob <bob@example.com>
Subject: Hello Bob
Date: 1704067200

Hi Bob, how are you?

From sender2@example.com Mon Jan 01 01:00:00 2024
From: Bob <bob@example.com>
To: Alice <alice@example.com>
Subject: Re: Hello Bob
In-Reply-To: msg-001

Fine thanks!
";
        let adapter = AutoAdapter;
        let msgs = adapter.parse_emails(mbox).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].from, "Alice <alice@example.com>");
        assert_eq!(msgs[0].subject, Some("Hello Bob".to_string()));
        assert!(msgs[0].content.contains("Hi Bob"));
        assert_eq!(msgs[1].in_reply_to, Some("msg-001".to_string()));
    }

    #[test]
    fn test_parse_emails_generates_nodes() {
        let mbox = "\
From x Mon Jan 01 00:00:00 2024
From: alice@example.com
To: bob@example.com
Subject: Project Update

Meeting tomorrow at 9am.
";
        let adapter = AutoAdapter;
        let config = AdapterConfig::new("email-crux", "auto");
        let db = adapter.generate(mbox, &config).unwrap();
        assert_eq!(db.nodes.len(), 1);
        assert_eq!(db.nodes[0].kind, "communication");
        assert_eq!(db.nodes[0].module, "email");
    }

    #[test]
    fn test_parse_slack_messages() {
        let json = r#"[
  {"user": "U123", "text": "Hello world", "ts": "1704067200.000001", "channel": "general"},
  {"user": "U456", "text": "Good morning", "ts": "1704067260.000002", "channel": "general"}
]"#;
        let adapter = AutoAdapter;
        let msgs = adapter.parse_slack_messages(json).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].user, "U123");
        assert_eq!(msgs[0].text, "Hello world");
        assert_eq!(msgs[1].user, "U456");
    }

    #[test]
    fn test_parse_slack_generates_nodes() {
        let json = r#"[{"user": "alice", "text": "ship it", "ts": "1704067200.0", "channel": "eng", "type": "message"}]"#;
        let adapter = AutoAdapter;
        let config = AdapterConfig::new("slack-crux", "auto");
        let db = adapter.generate(json, &config).unwrap();
        assert_eq!(db.nodes.len(), 1);
        assert!(db.nodes[0].module.starts_with("slack:"));
        assert!(db.nodes[0].properties.iter().any(|p| p.starts_with("channel=")));
    }

    #[test]
    fn test_parse_json_records() {
        let json = r#"{"data": [
  {"name": "Alice", "role": "engineer"},
  {"name": "Bob", "role": "designer"}
]}"#;
        let adapter = AutoAdapter;
        let records = adapter.parse_json_records(json).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].get("name"), Some(&"Alice".to_string()));
        assert_eq!(records[1].get("role"), Some(&"designer".to_string()));
    }

    #[test]
    fn test_adapter_config_has_classification() {
        let mut config = AdapterConfig::new("test", "auto");
        config.default_classification = Some("confidential".to_string());
        assert_eq!(config.default_classification, Some("confidential".to_string()));
        assert!(config.schema_hints.is_empty());
    }

    // --- Edge-case tests (Phase A-2) ---

    #[test]
    fn test_parse_emails_empty_input() {
        let adapter = AutoAdapter;
        let msgs = adapter.parse_emails("").unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn test_parse_slack_empty_array() {
        let adapter = AutoAdapter;
        let msgs = adapter.parse_slack_messages("[]").unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn test_parse_json_records_empty_data() {
        let adapter = AutoAdapter;
        let records = adapter.parse_json_records(r#"{"data": []}"#).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_parse_json_records_no_recognized_key() {
        let adapter = AutoAdapter;
        let records = adapter.parse_json_records(r#"{"unknown_key": [{"a":"b"}]}"#).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_generate_empty_input_returns_ok() {
        let adapter = AutoAdapter;
        let config = AdapterConfig::new("empty", "auto");
        // Empty input should not panic or return Err
        let result = adapter.generate("", &config);
        assert!(result.is_ok());
    }
}