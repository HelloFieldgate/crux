//! Background update-availability check.
//!
//! On `serve()` startup a daemon thread runs `curl` against the GitHub Releases
//! API, parses the latest tag, and stores the result in a OnceLock.  The result
//! is surfaced via `GET /api/update-check`; the UI polls once on load and shows
//! a dismissible banner when a newer version exists.
//!
//! All failures (no network, curl missing, parse error) are silent — they leave
//! the OnceLock unset, and the API returns `null`.

use std::process::Command;
use std::sync::OnceLock;

const RELEASES_API: &str =
    "https://api.github.com/repos/HelloFieldgate/crux/releases/latest";

pub struct UpdateInfo {
    pub current: &'static str,
    pub latest: String,
    pub url: String,
}

static LATEST: OnceLock<Option<UpdateInfo>> = OnceLock::new();

/// Spawn a daemon thread that fetches the latest release tag.
/// Safe to call multiple times; only the first call spawns the thread.
pub fn spawn_update_check() {
    // Only one check per process lifetime.
    static SPAWNED: OnceLock<()> = OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    std::thread::Builder::new()
        .name("helm-update-check".into())
        .spawn(|| {
            let info = fetch_update_info();
            let _ = LATEST.set(info);
        })
        .ok();
}

/// Return the cached result, or `None` if the check hasn't finished / failed.
pub fn get_update_info() -> Option<&'static Option<UpdateInfo>> {
    LATEST.get()
}

// ─────────────────────────────────────────────────────────────────────────────

fn fetch_update_info() -> Option<UpdateInfo> {
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--max-time", "8",
            "-H", "Accept: application/vnd.github+json",
            "-H", "User-Agent: Helm-UpdateCheck",
            RELEASES_API,
        ])
        .output()
        .ok()?;

    if !out.status.success() {
        return None;
    }

    let body = std::str::from_utf8(&out.stdout).ok()?;

    // Minimal JSON extraction: find "tag_name":"v0.1.2"
    let tag = extract_json_str(body, "tag_name")?;
    let html_url = extract_json_str(body, "html_url")?;

    let current = env!("CARGO_PKG_VERSION");
    if !is_newer(&tag, current) {
        return None; // up to date — no banner needed
    }

    Some(UpdateInfo {
        current,
        latest: tag,
        url: html_url,
    })
}

/// Returns JSON string: `{"current":"x","latest":"y","url":"z"}` or `null`.
pub fn update_check_json() -> String {
    match get_update_info() {
        Some(Some(info)) => format!(
            r#"{{"current":"{}","latest":"{}","url":"{}"}}"#,
            info.current,
            json_escape_simple(&info.latest),
            json_escape_simple(&info.url),
        ),
        _ => "null".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// Extract the value of a simple string field from JSON, e.g. `"tag_name":"v0.1.0"`.
fn extract_json_str<'a>(json: &'a str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let inner = &rest[1..];
    let end = inner.find('"')?;
    Some(inner[..end].to_string())
}

/// Compare two semver strings of the form `vX.Y.Z` or `X.Y.Z`.
/// Returns true if `candidate` is strictly greater than `current`.
fn is_newer(candidate: &str, current: &str) -> bool {
    fn parse(s: &str) -> Option<(u32, u32, u32)> {
        let s = s.trim_start_matches('v');
        let mut parts = s.splitn(3, '.');
        let major: u32 = parts.next()?.parse().ok()?;
        let minor: u32 = parts.next()?.parse().ok()?;
        let patch: u32 = parts.next()
            .unwrap_or("0")
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()?;
        Some((major, minor, patch))
    }
    match (parse(candidate), parse(current)) {
        (Some(c), Some(cur)) => c > cur,
        _ => false,
    }
}

fn json_escape_simple(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{extract_json_str, is_newer};

    #[test]
    fn parses_tag_name() {
        let json = r#"{"tag_name":"v0.2.0","html_url":"https://github.com/x"}"#;
        assert_eq!(extract_json_str(json, "tag_name").as_deref(), Some("v0.2.0"));
        assert_eq!(extract_json_str(json, "html_url").as_deref(), Some("https://github.com/x"));
        assert!(extract_json_str(json, "missing").is_none());
    }

    #[test]
    fn semver_comparison() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
    }
}
