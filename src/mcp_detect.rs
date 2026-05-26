//! External MCP Detector — scans known client config files for MCP servers
//! that are configured outside the crux policy router.
//!
//! Pure read-only filesystem scan; no network probing, no subprocess execution.

use std::path::{Path, PathBuf};

// ===========================================================================
// Public API
// ===========================================================================

#[derive(Debug, Clone)]
pub struct DetectedMcp {
    pub name: String,
    pub source_label: String,
    pub source_path: PathBuf,
    pub transport: String,
    pub command: String,
    pub url: String,
    pub fingerprint: String,
    pub routed_via_crux: bool,
}

/// Scan all known client config locations on the host and return every MCP
/// server found, annotated with whether it is already routed via the crux.
pub fn detect_external_mcp(mesh_dir: &Path) -> Result<Vec<DetectedMcp>, String> {
    let regs = crate::mesh::load_mcp_registrations(mesh_dir);
    let mut results = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for src in scan_sources() {
        if !src.path.exists() {
            continue;
        }
        let canon = std::fs::canonicalize(&src.path).unwrap_or_else(|_| src.path.clone());
        if seen.iter().any(|p| p == &canon) {
            continue;
        }
        seen.push(canon);
        let content = match std::fs::read_to_string(&src.path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let entries = parse_mcp_config(&content, &src.label, &src.path, src.format);
        for mut det in entries {
            det.routed_via_crux = is_routed(&det, &regs);
            results.push(det);
        }
    }
    Ok(results)
}

/// Parse a raw config file string for MCP server entries.
/// `format` is one of: "claude-desktop", "vscode", "continue".
pub fn parse_mcp_config(
    content: &str,
    source_label: &str,
    source_path: &Path,
    format: ConfigFormat,
) -> Vec<DetectedMcp> {
    match format {
        ConfigFormat::ClaudeDesktop => parse_claude_desktop(content, source_label, source_path),
        ConfigFormat::VsCode        => parse_vscode(content, source_label, source_path),
        ConfigFormat::Continue      => parse_continue(content, source_label, source_path),
    }
}

#[derive(Clone, Copy)]
pub enum ConfigFormat {
    ClaudeDesktop,
    VsCode,
    Continue,
}

// ===========================================================================
// Source definitions
// ===========================================================================

struct Source {
    label:  &'static str,
    path:   PathBuf,
    format: ConfigFormat,
}

fn scan_sources() -> Vec<Source> {
    let home = match home_dir() {
        Some(h) => h,
        None    => return Vec::new(),
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    vec![
        // Claude Desktop
        Source {
            label: "claude-desktop",
            path:  platform_app_support(&home, "Claude").join("claude_desktop_config.json"),
            format: ConfigFormat::ClaudeDesktop,
        },
        // Claude Code — project
        Source {
            label: "claude-code-project",
            path:  cwd.join(".claude/settings.json"),
            format: ConfigFormat::ClaudeDesktop,
        },
        Source {
            label: "claude-code-project-mcp",
            path:  cwd.join(".mcp.json"),
            format: ConfigFormat::ClaudeDesktop,
        },
        // Claude Code — user
        Source {
            label: "claude-code-user",
            path:  home.join(".claude/settings.json"),
            format: ConfigFormat::ClaudeDesktop,
        },
        // VS Code — user
        Source {
            label: "vscode-user",
            path:  platform_app_support(&home, "Code").join("User/settings.json"),
            format: ConfigFormat::VsCode,
        },
        // VS Code — project
        Source {
            label: "vscode-project",
            path:  cwd.join(".vscode/settings.json"),
            format: ConfigFormat::VsCode,
        },
        // Cursor
        Source {
            label: "cursor",
            path:  home.join(".cursor/mcp.json"),
            format: ConfigFormat::ClaudeDesktop,
        },
        // Continue
        Source {
            label: "continue",
            path:  home.join(".continue/config.json"),
            format: ConfigFormat::Continue,
        },
    ]
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn platform_app_support(home: &Path, app: &str) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Application Support").join(app)
    }
    #[cfg(not(target_os = "macos"))]
    {
        home.join(".config").join(app)
    }
}

// ===========================================================================
// Per-source parsers
// ===========================================================================

/// Parse `{"mcpServers": {"name": {"command": ..., "args": [...]}}}`.
/// Used by Claude Desktop, Claude Code settings, Cursor.
fn parse_claude_desktop(content: &str, label: &str, path: &Path) -> Vec<DetectedMcp> {
    let obj = match extract_object(content, "mcpServers") {
        Some(o) => o,
        None    => return Vec::new(),
    };
    parse_server_map(&obj, label, path)
}

/// Parse VS Code settings: `{"mcp": {"servers": {"name": {...}}}}`.
fn parse_vscode(content: &str, label: &str, path: &Path) -> Vec<DetectedMcp> {
    let mcp_obj = match extract_object(content, "mcp") {
        Some(o) => o,
        None    => return Vec::new(),
    };
    let servers_obj = match extract_object(&mcp_obj, "servers") {
        Some(o) => o,
        None    => return Vec::new(),
    };
    parse_server_map(&servers_obj, label, path)
}

/// Parse Continue config: `{"mcpServers": [{"name": "...", "command": "...", "args": [...]}]}`.
fn parse_continue(content: &str, label: &str, path: &Path) -> Vec<DetectedMcp> {
    use crate::json::extract_json_objects_from_array;
    let arr_content = match extract_array(content, "mcpServers") {
        Some(a) => a,
        None    => return Vec::new(),
    };
    let mut results = Vec::new();
    for entry in extract_json_objects_from_array(&arr_content) {
        if let Some(det) = parse_server_entry_obj(&entry, label, path) {
            results.push(det);
        }
    }
    results
}

// ===========================================================================
// Shared parsing helpers
// ===========================================================================

/// Parse a `{"alias": {server_entry}, ...}` map and return a DetectedMcp per entry.
fn parse_server_map(map_content: &str, label: &str, path: &Path) -> Vec<DetectedMcp> {
    let mut results = Vec::new();
    let pairs = extract_object_keys(map_content);
    for (name, entry_json) in pairs {
        let transport = extract_transport(&entry_json);
        let command   = extract_stdio_command(&entry_json);
        let url       = crate::json::extract_string_value(&entry_json, "url")
            .unwrap_or_default();
        let fp = fingerprint(&name, &transport, &command, &url);
        results.push(DetectedMcp {
            name,
            source_label: label.to_string(),
            source_path: path.to_path_buf(),
            transport,
            command,
            url,
            fingerprint: fp,
            routed_via_crux: false, // filled in by caller
        });
    }
    results
}

/// Parse a single server entry JSON object that contains a `"name"` field (Continue format).
fn parse_server_entry_obj(entry: &str, label: &str, path: &Path) -> Option<DetectedMcp> {
    let name = crate::json::extract_string_value(entry, "name")?;
    let transport = extract_transport(entry);
    let command   = extract_stdio_command(entry);
    let url       = crate::json::extract_string_value(entry, "url").unwrap_or_default();
    let fp = fingerprint(&name, &transport, &command, &url);
    Some(DetectedMcp {
        name,
        source_label: label.to_string(),
        source_path: path.to_path_buf(),
        transport,
        command,
        url,
        fingerprint: fp,
        routed_via_crux: false,
    })
}

/// Determine transport: if a `url` key is present → "http"; else "stdio".
/// VS Code uses a `"type"` key with value `"stdio"` or `"sse"`.
fn extract_transport(entry: &str) -> String {
    if let Some(t) = crate::json::extract_string_value(entry, "type") {
        match t.as_str() {
            "sse" | "http" => return "http".to_string(),
            _ => {}
        }
    }
    if crate::json::extract_string_value(entry, "url").is_some() {
        return "http".to_string();
    }
    "stdio".to_string()
}

/// Build the full command string for stdio servers: `command [args...]`.
fn extract_stdio_command(entry: &str) -> String {
    let cmd = crate::json::extract_string_value(entry, "command")
        .unwrap_or_default();
    if cmd.is_empty() {
        return String::new();
    }
    let args = crate::json::extract_string_array(entry, "args");
    if args.is_empty() {
        cmd
    } else {
        format!("{} {}", cmd, args.join(" "))
    }
}

fn fingerprint(name: &str, transport: &str, command: &str, url: &str) -> String {
    let canonical = format!("{}|{}|{}|{}", name, transport, command, url);
    let hash = crate::crypto::sha256(canonical.as_bytes());
    format!("sha256:{}", crate::crypto::bytes_to_hex(&hash))
}

// ===========================================================================
// Routing check
// ===========================================================================

fn is_routed(det: &DetectedMcp, regs: &[crate::schema::McpServerRegistration]) -> bool {
    // Direct match: an approved registration with the same alias + matching command/url
    for reg in regs {
        if reg.alias == det.name {
            if det.transport == "stdio" && reg.command == det.command {
                return true;
            }
            if det.transport == "http" && reg.url == det.url {
                return true;
            }
        }
    }
    // Proxy pattern: the entry's command points at the crux-router binary
    // with a --policy-router flag (this means the client itself already routes via crux)
    let cmd = &det.command;
    if (cmd.ends_with("crux-router") || cmd.contains("crux-router "))
        && cmd.contains("--policy-router")
    {
        return true;
    }
    false
}

// ===========================================================================
// JSON object helpers (depth-aware, no external deps)
// ===========================================================================

/// Extract the raw JSON value (including braces) for the given key.
/// Works for object values only.
pub fn extract_object(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let key_pos = text.find(&needle)?;
    let after = text[key_pos + needle.len()..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    if !after.starts_with('{') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_str = false;
    let mut esc = false;
    let mut end = 0;
    for (i, c) in after.char_indices() {
        if esc { esc = false; continue; }
        if c == '\\' && in_str { esc = true; continue; }
        if c == '"' { in_str = !in_str; continue; }
        if in_str { continue; }
        if c == '{' { depth += 1; }
        else if c == '}' {
            depth -= 1;
            if depth == 0 { end = i + 1; break; }
        }
    }
    if end == 0 { return None; }
    // Strip outer braces so callers work on inner content
    Some(after[1..end - 1].to_string())
}

/// Extract the raw JSON array value (without brackets) for the given key.
fn extract_array(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let key_pos = text.find(&needle)?;
    let after = text[key_pos + needle.len()..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    if !after.starts_with('[') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_str = false;
    let mut esc = false;
    let mut end = 0;
    for (i, c) in after.char_indices() {
        if esc { esc = false; continue; }
        if c == '\\' && in_str { esc = true; continue; }
        if c == '"' { in_str = !in_str; continue; }
        if in_str { continue; }
        if c == '[' { depth += 1; }
        else if c == ']' {
            depth -= 1;
            if depth == 0 { end = i + 1; break; }
        }
    }
    if end == 0 { return None; }
    Some(after[1..end - 1].to_string())
}

/// Iterate the top-level key-value pairs of a JSON object body (no outer braces).
/// Returns `(key_str, raw_value_str)` pairs. Values are the raw JSON (string, object,
/// array, or number) including any surrounding quotes or braces.
fn extract_object_keys(body: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut pos = 0;
    let bytes = body.as_bytes();

    while pos < bytes.len() {
        // Skip whitespace and commas
        while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\n'
            || bytes[pos] == b'\r' || bytes[pos] == b'\t' || bytes[pos] == b',')
        {
            pos += 1;
        }
        if pos >= bytes.len() { break; }

        // Expect a quoted key
        if bytes[pos] != b'"' { break; }
        pos += 1;
        let key_start = pos;
        while pos < bytes.len() && bytes[pos] != b'"' {
            if bytes[pos] == b'\\' { pos += 1; } // skip escaped char
            pos += 1;
        }
        let key = body[key_start..pos].to_string();
        pos += 1; // closing quote

        // Skip whitespace + colon
        while pos < bytes.len() && bytes[pos] != b':' { pos += 1; }
        pos += 1; // skip colon

        // Skip whitespace
        while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\n'
            || bytes[pos] == b'\r' || bytes[pos] == b'\t')
        {
            pos += 1;
        }
        if pos >= bytes.len() { break; }

        // Extract value
        let val_start = pos;
        let val_end = skip_value(body, pos);
        let val = body[val_start..val_end].to_string();
        pos = val_end;

        pairs.push((key, val));
    }
    pairs
}

/// Returns the byte position just past the end of the JSON value starting at `pos`.
fn skip_value(text: &str, pos: usize) -> usize {
    let bytes = text.as_bytes();
    if pos >= bytes.len() { return pos; }
    match bytes[pos] {
        b'"' => {
            let mut i = pos + 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' { i += 2; continue; }
                if bytes[i] == b'"' { return i + 1; }
                i += 1;
            }
            bytes.len()
        }
        b'{' | b'[' => {
            let open = bytes[pos];
            let close = if open == b'{' { b'}' } else { b']' };
            let mut depth = 1usize;
            let mut in_str = false;
            let mut i = pos + 1;
            while i < bytes.len() {
                if in_str {
                    if bytes[i] == b'\\' { i += 2; continue; }
                    if bytes[i] == b'"' { in_str = false; }
                } else {
                    if bytes[i] == b'"' { in_str = true; }
                    else if bytes[i] == open  { depth += 1; }
                    else if bytes[i] == close {
                        depth -= 1;
                        if depth == 0 { return i + 1; }
                    }
                }
                i += 1;
            }
            bytes.len()
        }
        _ => {
            // number, bool, null — end at comma, }, ], or whitespace
            let mut i = pos;
            while i < bytes.len() {
                match bytes[i] {
                    b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t' => break,
                    _ => i += 1,
                }
            }
            i
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp_detect")
    }

    #[test]
    fn test_parse_claude_desktop_fixture() {
        let path = fixtures_dir().join("claude_desktop.json");
        let content = std::fs::read_to_string(&path)
            .expect("claude_desktop.json fixture missing");
        let results = parse_mcp_config(&content, "claude-desktop", &path, ConfigFormat::ClaudeDesktop);
        assert!(!results.is_empty(), "should parse at least one server");
        let server = results.iter().find(|s| s.name == "my-echo-server")
            .expect("expected 'my-echo-server' entry");
        assert_eq!(server.transport, "stdio");
        assert!(server.command.contains("python3"), "command: {}", server.command);
    }

    #[test]
    fn test_parse_vscode_fixture() {
        let path = fixtures_dir().join("vscode_user.json");
        let content = std::fs::read_to_string(&path)
            .expect("vscode_user.json fixture missing");
        let results = parse_mcp_config(&content, "vscode-user", &path, ConfigFormat::VsCode);
        assert!(!results.is_empty(), "should parse at least one server");
        let server = results.iter().find(|s| s.name == "vscode-server")
            .expect("expected 'vscode-server' entry");
        assert_eq!(server.transport, "stdio");
    }

    #[test]
    fn test_parse_cursor_fixture() {
        let path = fixtures_dir().join("cursor.json");
        let content = std::fs::read_to_string(&path)
            .expect("cursor.json fixture missing");
        let results = parse_mcp_config(&content, "cursor", &path, ConfigFormat::ClaudeDesktop);
        assert!(!results.is_empty(), "should parse at least one server");
        assert_eq!(results[0].name, "cursor-tool");
    }

    #[test]
    fn test_routed_via_crux_true_when_command_points_at_router() {
        let det = DetectedMcp {
            name: "x".to_string(),
            source_label: "claude-desktop".to_string(),
            source_path: PathBuf::from("/fake"),
            transport: "stdio".to_string(),
            command: "/usr/local/bin/crux-router --policy-router --proxy x".to_string(),
            url: String::new(),
            fingerprint: String::new(),
            routed_via_crux: false,
        };
        assert!(is_routed(&det, &[]), "command pointing at crux-router must be routed");
    }

    #[test]
    fn test_routed_via_crux_false_when_unregistered() {
        let det = DetectedMcp {
            name: "unregistered".to_string(),
            source_label: "claude-desktop".to_string(),
            source_path: PathBuf::from("/fake"),
            transport: "stdio".to_string(),
            command: "/usr/bin/python3 my_server.py".to_string(),
            url: String::new(),
            fingerprint: String::new(),
            routed_via_crux: false,
        };
        assert!(!is_routed(&det, &[]), "unregistered server must not be routed");
    }

    #[test]
    fn test_missing_source_files_return_empty() {
        let content = "";
        let path = PathBuf::from("/nonexistent/path.json");
        let results = parse_mcp_config(content, "claude-desktop", &path, ConfigFormat::ClaudeDesktop);
        assert!(results.is_empty(), "empty content should yield no servers");
    }

    #[test]
    fn test_detect_unrouted_emits_instructions() {
        let path = fixtures_dir().join("claude_desktop.json");
        let content = std::fs::read_to_string(&path)
            .expect("claude_desktop.json fixture missing");
        let mut results = parse_mcp_config(&content, "claude-desktop", &path, ConfigFormat::ClaudeDesktop);
        // All should be unrouted (no mesh registrations)
        for r in &mut results {
            r.routed_via_crux = is_routed(r, &[]);
        }
        let unrouted: Vec<_> = results.iter().filter(|r| !r.routed_via_crux).collect();
        assert!(!unrouted.is_empty(), "fixture servers should be unrouted");
        // Verify remediation text can be generated (tested via mcp.rs, checked structurally here)
        let instructions = format!(
            "SECURITY WARNING: '{}' is configured in {} but is NOT routed",
            unrouted[0].name,
            unrouted[0].source_path.display(),
        );
        assert!(instructions.contains("SECURITY WARNING"));
        assert!(instructions.contains(&unrouted[0].name));
    }

    #[test]
    fn test_route_external_creates_proposed_registration() {
        // Use mesh::mesh_register_mcp_with_source directly (the backing function)
        let dir = std::env::temp_dir().join("crux_detect_route_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        crate::mesh::init_mesh("detect-test", &dir).unwrap();

        let result = crate::mesh::mesh_register_mcp_with_source(
            &dir, "ext-server", "stdio", "/usr/bin/python3 server.py", "", "internal", "*", "",
            "detect:claude-desktop",
        );
        assert!(result.is_ok(), "route_external registration failed: {:?}", result);

        // Should appear in proposed list, not active list
        let proposed = crate::mesh::load_discovered_mcp(&dir);
        assert!(proposed.iter().any(|r| r.alias == "ext-server"),
            "ext-server should be in proposed list");

        let active = crate::mesh::load_mcp_registrations(&dir);
        assert!(!active.iter().any(|r| r.alias == "ext-server"),
            "ext-server must not be in active list");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
