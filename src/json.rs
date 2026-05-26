//! Hand-rolled JSON serialization and parsing utilities.
//!
//! Zero external dependencies. Provides just enough JSON handling for
//! the crux mesh data structures.

use std::fmt::Write;

// ===========================================================================
// Serialization
// ===========================================================================

/// Escape a string for JSON output. Returns `"escaped_string"` (with quotes).
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Serialize a `Vec<String>` as a JSON array of escaped strings.
pub fn json_str_array(items: &[String]) -> String {
    if items.is_empty() {
        return "[]".to_string();
    }
    let mut out = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&json_escape(item));
    }
    out.push(']');
    out
}

/// Serialize an optional string field as JSON. Returns `"value"` or `null`.
pub fn json_opt_str(val: &Option<String>) -> String {
    match val {
        Some(s) => json_escape(s),
        None => "null".to_string(),
    }
}

/// Serialize an optional u64 field as JSON. Returns the number or `null`.
pub fn json_opt_u64(val: &Option<u64>) -> String {
    match val {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

/// Serialize an optional u8 field as JSON. Returns the number or `null`.
pub fn json_opt_u8(val: &Option<u8>) -> String {
    match val {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

// ===========================================================================
// Parsing
// ===========================================================================

/// Extract a string value for a given key from a JSON-like line.
/// Looks for `"key": "value"` and returns the unescaped value.
pub fn extract_string_value(line: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = line.find(&pattern)?;
    let after_key = &line[idx + pattern.len()..];
    // Skip `: ` or `:`
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let trimmed = after_colon.trim_start();
    if let Some(inner) = trimmed.strip_prefix('"') {
        // String value
        let mut result = String::new();
        let mut chars = inner.chars();
        loop {
            match chars.next() {
                None => break,
                Some('"') => break,
                Some('\\') => match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('"') => result.push('"'),
                    Some('\\') => result.push('\\'),
                    Some(c) => { result.push('\\'); result.push(c); }
                    None => break,
                },
                Some(c) => result.push(c),
            }
        }
        Some(result)
    } else {
        None
    }
}

/// Extract a numeric (u64) value for a given key from a JSON-like line.
pub fn extract_u64_value(line: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\"", key);
    let idx = line.find(&pattern)?;
    let after_key = &line[idx + pattern.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let trimmed = after_colon.trim_start();
    let num_str: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    num_str.parse().ok()
}

/// Extract a boolean value for a given key from a JSON-like line.
pub fn extract_bool_value(line: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{}\"", key);
    let idx = line.find(&pattern)?;
    let after_key = &line[idx + pattern.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let trimmed = after_colon.trim_start();
    if trimmed.starts_with("true") {
        Some(true)
    } else if trimmed.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Check if a value for a given key is `null`.
pub fn is_null_value(line: &str, key: &str) -> bool {
    let pattern = format!("\"{}\"", key);
    if let Some(idx) = line.find(&pattern) {
        let after_key = &line[idx + pattern.len()..];
        if let Some(after_colon) = after_key.trim_start().strip_prefix(':') {
            return after_colon.trim_start().starts_with("null");
        }
    }
    false
}

/// Extract a JSON array of strings from a line. Returns empty vec if not found.
pub fn extract_string_array(text: &str, key: &str) -> Vec<String> {
    let pattern = format!("\"{}\"", key);
    let idx = match text.find(&pattern) {
        Some(i) => i,
        None => return Vec::new(),
    };
    let after_key = &text[idx + pattern.len()..];
    let after_colon = match after_key.trim_start().strip_prefix(':') {
        Some(s) => s,
        None => return Vec::new(),
    };
    let trimmed = after_colon.trim_start();
    if !trimmed.starts_with('[') {
        return Vec::new();
    }
    let bracket_content = &trimmed[1..];
    // Depth-aware scan: skip ] inside quoted strings so "[WARN]" doesn't end the array
    let end = {
        let mut depth = 1usize;
        let mut in_str = false;
        let mut esc = false;
        let mut found = None;
        for (i, c) in bracket_content.char_indices() {
            if esc { esc = false; continue; }
            if c == '\\' && in_str { esc = true; continue; }
            if c == '"' { in_str = !in_str; continue; }
            if in_str { continue; }
            if c == '[' { depth += 1; }
            else if c == ']' {
                depth -= 1;
                if depth == 0 { found = Some(i); break; }
            }
        }
        match found {
            Some(i) => i,
            None => return Vec::new(),
        }
    };
    let inner = &bracket_content[..end];
    let mut result = Vec::new();
    let mut in_str = false;
    let mut escaped = false;
    let mut current = String::new();

    for c in inner.chars() {
        if escaped {
            match c {
                'n' => current.push('\n'),
                'r' => current.push('\r'),
                't' => current.push('\t'),
                '"' => current.push('"'),
                '\\' => current.push('\\'),
                _ => { current.push('\\'); current.push(c); }
            }
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
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_escape_simple() {
        assert_eq!(json_escape("hello"), "\"hello\"");
    }

    #[test]
    fn test_json_escape_special_chars() {
        assert_eq!(json_escape("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
    }

    #[test]
    fn test_json_str_array_empty() {
        let empty: Vec<String> = vec![];
        assert_eq!(json_str_array(&empty), "[]");
    }

    #[test]
    fn test_json_str_array_items() {
        let items = vec!["a".to_string(), "b".to_string()];
        assert_eq!(json_str_array(&items), "[\"a\", \"b\"]");
    }

    #[test]
    fn test_extract_string_value() {
        let line = r#"  "name": "my-project","#;
        assert_eq!(extract_string_value(line, "name"), Some("my-project".to_string()));
    }

    #[test]
    fn test_extract_string_value_escaped() {
        let line = r#"  "desc": "line1\nline2","#;
        assert_eq!(extract_string_value(line, "desc"), Some("line1\nline2".to_string()));
    }

    #[test]
    fn test_extract_u64_value() {
        let line = r#"  "created_at": 1741000000,"#;
        assert_eq!(extract_u64_value(line, "created_at"), Some(1741000000));
    }

    #[test]
    fn test_extract_bool_value() {
        let line = r#"  "is_process": true,"#;
        assert_eq!(extract_bool_value(line, "is_process"), Some(true));
    }

    #[test]
    fn test_is_null_value() {
        let line = r#"  "redact_below": null,"#;
        assert!(is_null_value(line, "redact_below"));
    }

    #[test]
    fn test_extract_string_array() {
        let line = r#"  "tags": ["io", "tensor", "ml"],"#;
        let result = extract_string_array(line, "tags");
        assert_eq!(result, vec!["io", "tensor", "ml"]);
    }

    #[test]
    fn test_extract_string_array_empty() {
        let line = r#"  "tags": [],"#;
        let result = extract_string_array(line, "tags");
        assert!(result.is_empty());
    }

    // --- Edge-case tests (Phase A-2) ---

    #[test]
    fn test_json_escape_empty() {
        assert_eq!(json_escape(""), "\"\"");
    }

    #[test]
    fn test_json_escape_control_chars() {
        // Control char below 0x20 (e.g., form feed 0x0C)
        assert_eq!(json_escape("\x0c"), "\"\\u000c\"");
    }

    #[test]
    fn test_json_escape_tab_and_cr() {
        assert_eq!(json_escape("\t\r"), "\"\\t\\r\"");
    }

    #[test]
    fn test_json_opt_str_some_and_none() {
        assert_eq!(json_opt_str(&Some("hi".to_string())), "\"hi\"");
        assert_eq!(json_opt_str(&None), "null");
    }

    #[test]
    fn test_json_opt_u64_some_and_none() {
        assert_eq!(json_opt_u64(&Some(42)), "42");
        assert_eq!(json_opt_u64(&None), "null");
    }

    #[test]
    fn test_json_opt_u8_some_and_none() {
        assert_eq!(json_opt_u8(&Some(3)), "3");
        assert_eq!(json_opt_u8(&None), "null");
    }

    #[test]
    fn test_extract_string_value_missing_key() {
        let line = r#"  "other": "val","#;
        assert_eq!(extract_string_value(line, "name"), None);
    }

    #[test]
    fn test_extract_string_value_empty_string() {
        let line = r#"  "name": "","#;
        assert_eq!(extract_string_value(line, "name"), Some("".to_string()));
    }

    #[test]
    fn test_extract_string_value_no_colon() {
        let line = r#"  "name" "oops","#;
        assert_eq!(extract_string_value(line, "name"), None);
    }

    #[test]
    fn test_extract_string_value_null_not_string() {
        let line = r#"  "name": null,"#;
        assert_eq!(extract_string_value(line, "name"), None);
    }

    #[test]
    fn test_extract_u64_value_missing() {
        assert_eq!(extract_u64_value(r#""x": 10"#, "y"), None);
    }

    #[test]
    fn test_extract_u64_value_not_numeric() {
        assert_eq!(extract_u64_value(r#""x": "hello""#, "x"), None);
    }

    #[test]
    fn test_extract_bool_value_false() {
        let line = r#"  "flag": false,"#;
        assert_eq!(extract_bool_value(line, "flag"), Some(false));
    }

    #[test]
    fn test_extract_bool_value_neither() {
        let line = r#"  "flag": null,"#;
        assert_eq!(extract_bool_value(line, "flag"), None);
    }

    #[test]
    fn test_is_null_value_not_null() {
        assert!(!is_null_value(r#""x": 42"#, "x"));
    }

    #[test]
    fn test_is_null_value_missing_key() {
        assert!(!is_null_value(r#""y": null"#, "x"));
    }

    #[test]
    fn test_extract_string_array_with_escapes() {
        let line = r#"  "items": ["a\"b", "c\\d"],"#;
        let result = extract_string_array(line, "items");
        assert_eq!(result, vec!["a\"b", "c\\d"]);
    }

    #[test]
    fn test_extract_string_array_missing_key() {
        let line = r#"  "other": ["a"],"#;
        assert!(extract_string_array(line, "items").is_empty());
    }

    #[test]
    fn test_extract_string_array_not_array() {
        let line = r#"  "items": "just a string","#;
        assert!(extract_string_array(line, "items").is_empty());
    }

    #[test]
    fn test_json_str_array_single() {
        let items = vec!["only".to_string()];
        assert_eq!(json_str_array(&items), "[\"only\"]");
    }
}

/// Extract all top-level JSON objects from an array string `[{...},{...}]`.
///
/// String-aware: braces inside quoted string values do not affect depth tracking.
pub fn extract_json_objects_from_array(array_text: &str) -> Vec<String> {
    let mut objects = Vec::new();
    // depth 0 = outside array, 1 = inside array (between [ and ]),
    // 2+ = inside an object
    let mut depth: usize = 0;
    let mut obj_start: Option<usize> = None;
    let mut in_str = false;
    let mut escaped = false;

    for (i, c) in array_text.char_indices() {
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
            '[' if depth == 0 => { depth = 1; }
            ']' if depth == 1 => { break; }
            '{' if depth == 1 => {
                depth = 2;
                obj_start = Some(i);
            }
            '{' if depth >= 2 => { depth += 1; }
            '}' if depth == 2 => {
                depth = 1;
                if let Some(start) = obj_start.take() {
                    objects.push(array_text[start..=i].to_string());
                }
            }
            '}' if depth > 2 => { depth -= 1; }
            _ => {}
        }
    }
    objects
}
