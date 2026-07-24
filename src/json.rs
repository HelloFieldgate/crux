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

/// Find the byte-index of the genuine JSON key `pattern` (a quoted key name such
/// as `"\"name\""`) in `text`.
///
/// String-aware: the scan walks `text` one string token at a time, so a key name
/// that appears *inside a value string* is never mistaken for a real key. This
/// matters once object boundaries are correct but a value still contains
/// key-shaped text, e.g. a `summary` whose content is literally
/// `{"name": "fake"}` — the real top-level `name` is still resolved.
///
/// A token qualifies as a key when its decoded-quote span equals the key name
/// and the next non-whitespace character after its closing quote is `':'`. This
/// also skips occurrences where the key name appears as a *value*
/// (e.g. `{"action":"query","query":"foo"}`).
fn find_json_key(text: &str, pattern: &str) -> Option<usize> {
    // `pattern` is the key wrapped in quotes; compare against the inner name.
    let key = pattern.trim_matches('"');
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        // Start of a string token at byte i — find its unescaped closing quote.
        let mut j = i + 1;
        let mut escaped = false;
        while j < bytes.len() {
            let c = bytes[j];
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                break;
            }
            j += 1;
        }
        if j >= bytes.len() {
            // Unterminated string — nothing more can be a valid key.
            break;
        }
        // Quotes are ASCII, so [i+1..j] is a valid UTF-8 boundary slice.
        if &text[i + 1..j] == key {
            let mut k = j + 1;
            while k < bytes.len() && matches!(bytes[k], b' ' | b'\t' | b'\n' | b'\r') {
                k += 1;
            }
            if k < bytes.len() && bytes[k] == b':' {
                return Some(i);
            }
        }
        // Skip past this entire string token (value or non-matching key).
        i = j + 1;
    }
    None
}

/// Extract a string value for a given key from a JSON-like line.
/// Looks for `"key": "value"` and returns the unescaped value.
pub fn extract_string_value(line: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = find_json_key(line, &pattern)?;
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
    let idx = find_json_key(line, &pattern)?;
    let after_key = &line[idx + pattern.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let trimmed = after_colon.trim_start();
    let num_str: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    num_str.parse().ok()
}

/// Extract a boolean value for a given key from a JSON-like line.
pub fn extract_bool_value(line: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{}\"", key);
    let idx = find_json_key(line, &pattern)?;
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
    if let Some(idx) = find_json_key(line, &pattern) {
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
    let idx = match find_json_key(text, &pattern) {
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
// Validation
// ===========================================================================

/// Validate that `text` is a single well-formed JSON document, strictly.
///
/// The extractors above are deliberately lenient — they scan for keys and never
/// check structure, so a manifest with a missing separator still loads. That
/// leniency is what let a writer bug (a dropped comma between two member fields)
/// survive unnoticed: every round-trip test read the output back through our own
/// tolerant reader, which cannot see the defect. This is the strict counterpart:
/// it accepts only what a conforming external parser (`jq`, `json.tool`, an
/// editor's JSON mode) would accept, so serializer tests can assert that our
/// output is portable, not merely self-readable.
///
/// Returns `Err` with a byte offset and reason on the first violation.
pub fn validate_json(text: &str) -> Result<(), String> {
    let b = text.as_bytes();
    let mut i = skip_ws(b, 0);
    i = validate_value(b, i)?;
    i = skip_ws(b, i);
    if i != b.len() {
        return Err(format!("trailing content at byte {}", i));
    }
    Ok(())
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// Validate one JSON value starting at `i`; returns the index just past it.
fn validate_value(b: &[u8], i: usize) -> Result<usize, String> {
    if i >= b.len() {
        return Err("unexpected end of input".to_string());
    }
    match b[i] {
        b'{' => validate_object(b, i),
        b'[' => validate_array(b, i),
        b'"' => validate_string(b, i),
        b't' => expect_literal(b, i, "true"),
        b'f' => expect_literal(b, i, "false"),
        b'n' => expect_literal(b, i, "null"),
        b'-' | b'0'..=b'9' => validate_number(b, i),
        c => Err(format!(
            "unexpected character '{}' at byte {}",
            c as char, i
        )),
    }
}

fn expect_literal(b: &[u8], i: usize, lit: &str) -> Result<usize, String> {
    let end = i + lit.len();
    if end <= b.len() && &b[i..end] == lit.as_bytes() {
        Ok(end)
    } else {
        Err(format!("expected `{}` at byte {}", lit, i))
    }
}

fn validate_object(b: &[u8], i: usize) -> Result<usize, String> {
    let mut i = skip_ws(b, i + 1);
    if i < b.len() && b[i] == b'}' {
        return Ok(i + 1);
    }
    loop {
        if i >= b.len() || b[i] != b'"' {
            return Err(format!("expected object key at byte {}", i));
        }
        i = validate_string(b, i)?;
        i = skip_ws(b, i);
        if i >= b.len() || b[i] != b':' {
            return Err(format!("expected ':' after object key at byte {}", i));
        }
        i = skip_ws(b, i + 1);
        i = validate_value(b, i)?;
        i = skip_ws(b, i);
        match b.get(i) {
            Some(b',') => i = skip_ws(b, i + 1),
            Some(b'}') => return Ok(i + 1),
            // The exact shape of the mesh-manifest bug: two well-formed members
            // of an object with no separator between them.
            _ => return Err(format!("expected ',' or '}}' at byte {}", i)),
        }
    }
}

fn validate_array(b: &[u8], i: usize) -> Result<usize, String> {
    let mut i = skip_ws(b, i + 1);
    if i < b.len() && b[i] == b']' {
        return Ok(i + 1);
    }
    loop {
        i = validate_value(b, i)?;
        i = skip_ws(b, i);
        match b.get(i) {
            Some(b',') => i = skip_ws(b, i + 1),
            Some(b']') => return Ok(i + 1),
            _ => return Err(format!("expected ',' or ']' at byte {}", i)),
        }
    }
}

fn validate_string(b: &[u8], i: usize) -> Result<usize, String> {
    let mut i = i + 1;
    while i < b.len() {
        match b[i] {
            b'"' => return Ok(i + 1),
            b'\\' => {
                let esc = *b.get(i + 1).ok_or("unterminated escape")?;
                match esc {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => i += 2,
                    b'u' => {
                        if i + 6 > b.len() || !b[i + 2..i + 6].iter().all(u8::is_ascii_hexdigit) {
                            return Err(format!("bad \\u escape at byte {}", i));
                        }
                        i += 6;
                    }
                    c => {
                        return Err(format!("invalid escape '\\{}' at byte {}", c as char, i));
                    }
                }
            }
            c if c < 0x20 => {
                return Err(format!("raw control byte 0x{:02x} in string at {}", c, i));
            }
            _ => i += 1,
        }
    }
    Err("unterminated string".to_string())
}

fn validate_number(b: &[u8], i: usize) -> Result<usize, String> {
    let start = i;
    let mut i = i;
    if b[i] == b'-' {
        i += 1;
    }
    // Integer part: `0` alone, or a nonzero digit followed by any digits.
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(c) if c.is_ascii_digit() => {
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
        }
        _ => return Err(format!("malformed number at byte {}", start)),
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        let frac = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == frac {
            return Err(format!("missing fraction digits at byte {}", i));
        }
    }
    if matches!(b.get(i), Some(b'e') | Some(b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+') | Some(b'-')) {
            i += 1;
        }
        let exp = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == exp {
            return Err(format!("missing exponent digits at byte {}", i));
        }
    }
    Ok(i)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_json_accepts_well_formed() {
        for ok in [
            "{}",
            "[]",
            "null",
            "-12.5e+3",
            "0",
            r#"{"a": [1, 2, {"b": "c\"d\\eÿ"}], "n": null, "t": true}"#,
            "  {\n  \"a\" : 1 ,\n \"b\": [ ]\n }  \n",
        ] {
            assert!(validate_json(ok).is_ok(), "should accept: {}", ok);
        }
    }

    #[test]
    fn test_validate_json_rejects_missing_comma() {
        // The exact defect that shipped in every .crux-mesh.json: two adjacent
        // members of an object with no separator between them.
        let bad = r#"{"mesh_public_key": "f47d" "mesh_private_key": "9b85"}"#;
        assert!(validate_json(bad).is_err());
    }

    #[test]
    fn test_validate_json_rejects_malformed() {
        for bad in [
            "",
            "{",
            "[1, 2",
            "[1 2]",
            "{\"a\": }",
            "{\"a\" 1}",
            "{a: 1}",
            "{\"a\": 1,}",
            "[1,]",
            "01",
            "1.",
            "1e",
            "\"unterminated",
            "\"bad \\q escape\"",
            "{} extra",
            "tru",
        ] {
            assert!(validate_json(bad).is_err(), "should reject: {:?}", bad);
        }
    }

    #[test]
    fn test_validate_json_accepts_escaped_output() {
        // Anything json_escape produces must survive strict validation.
        let s = json_escape("quote\" back\\slash \n\t control\u{1}");
        assert!(validate_json(&format!("{{\"k\": {}}}", s)).is_ok());
    }

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

    #[test]
    fn test_extract_string_value_key_value_collision() {
        // Regression: when a key name appears as a *value* earlier in the JSON blob
        // (e.g. `"action":"query"` followed by `"query":"…"`), find_json_key must
        // skip the value occurrence and locate the real key.  This was the root cause
        // of `mesh action=query` silently dropping the `query`/`tag` arguments.
        let line = r#"{"action":"query","query":"oauth","tag":"security"}"#;
        assert_eq!(extract_string_value(line, "action"), Some("query".to_string()));
        assert_eq!(extract_string_value(line, "query"),  Some("oauth".to_string()));
        assert_eq!(extract_string_value(line, "tag"),    Some("security".to_string()));
    }

    #[test]
    fn test_extract_string_value_repeated_key_name_as_value() {
        // The key "status" appears as a value for "kind", then as a real key.
        let line = r#"{"kind":"status","status":"approved"}"#;
        assert_eq!(extract_string_value(line, "status"), Some("approved".to_string()));
    }

    #[test]
    fn test_find_json_key_ignores_key_inside_value_string() {
        // A value string that literally contains `"name": "fake"` must not shadow
        // the real `name` key that appears *after* it in the object.
        let obj = r#"{"summary":"snippet \"name\": \"fake\" here","name":"real"}"#;
        assert_eq!(extract_string_value(obj, "name"), Some("real".to_string()));
        assert_eq!(
            extract_string_value(obj, "summary"),
            Some(r#"snippet "name": "fake" here"#.to_string())
        );
    }

    #[test]
    fn test_find_json_key_ignores_colon_bearing_value() {
        // The value of `summary` contains `tags:` text — must not be read as the
        // `tags` array key, and the real array (after) must still extract.
        let obj = r#"{"summary":"has tags: a, b, c","tags":["x","y"]}"#;
        assert_eq!(
            extract_string_value(obj, "summary"),
            Some("has tags: a, b, c".to_string())
        );
        assert_eq!(extract_string_array(obj, "tags"), vec!["x", "y"]);
    }

    #[test]
    fn test_extract_json_objects_empty_array() {
        assert!(extract_json_objects_from_array("[]").is_empty());
        assert!(extract_json_objects_from_array("[   ]").is_empty());
    }

    #[test]
    fn test_extract_json_objects_single() {
        let objs = extract_json_objects_from_array(r#"[{"a":"b"}]"#);
        assert_eq!(objs, vec![r#"{"a":"b"}"#.to_string()]);
    }

    #[test]
    fn test_extract_json_objects_nested() {
        let objs = extract_json_objects_from_array(r#"[{"a":{"b":"c"}},{"d":"e"}]"#);
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[0], r#"{"a":{"b":"c"}}"#);
        assert_eq!(objs[1], r#"{"d":"e"}"#);
    }

    #[test]
    fn test_extract_json_objects_structural_chars_in_strings() {
        // Every structural char appears inside string values — depth must be
        // unaffected, so both objects are returned intact.
        let objs = extract_json_objects_from_array(r#"[{"s":"]}{[ )} ){"},{"t":"plain"}]"#);
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[0], r#"{"s":"]}{[ )} ){"}"#);
        assert_eq!(objs[1], r#"{"t":"plain"}"#);
    }

    #[test]
    fn test_extract_json_objects_trailing_ws_and_commas() {
        let objs = extract_json_objects_from_array(r#"[ {"a":"1"} , {"a":"2"} ]  "#);
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[0], r#"{"a":"1"}"#);
        assert_eq!(objs[1], r#"{"a":"2"}"#);
    }

    #[test]
    fn test_extract_json_objects_escaped_quote_then_brace() {
        // An escaped quote followed by a structural brace inside a value.
        let objs = extract_json_objects_from_array(r#"[{"s":"say \"hi\" }"},{"s":"ok"}]"#);
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[0], r#"{"s":"say \"hi\" }"}"#);
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
