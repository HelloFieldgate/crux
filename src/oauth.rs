//! OAuth 2.1 client utilities: HTTP client, PKCE, endpoint discovery,
//! token exchange, auth-status query, and revoke.
//!
//! Used by the mesh MCP tool (src/mcp.rs) and the Helm server (src/helm/)
//! for Phase 7 management operations. The `crux_router` binary continues
//! to hold its own copy of `http_request` / `oauth_authorize` so that its
//! 99 tests remain undisturbed; the two implementations are intentionally
//! parallel and tested independently.
//!
//! Security invariant: tokens/secrets never enter the policy crux; only the
//! encrypted store at `~/.crux-tokens/<alias>.tok`.

use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::json::{extract_string_value, json_escape};
use crate::schema::now_unix;
use crate::token_store::{self, TokenSet};

// ===========================================================================
// HTTP client
// ===========================================================================

/// Parsed HTTP response returned by [`http_request`].
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

/// Parse `url` (e.g. `"https://as.example.com/path"`) into (host, port, path).
///
/// Strips http:// or https:// prefix; an explicit port is required.
fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let url = url.strip_prefix("https://").unwrap_or(url);
    let url = url.strip_prefix("http://").unwrap_or(url);
    let (authority, path) = if let Some(slash) = url.find('/') {
        (&url[..slash], url[slash..].to_string())
    } else {
        (url, "/".to_string())
    };
    let (host, port_str) = authority.rfind(':')
        .map(|c| (&authority[..c], &authority[c + 1..]))?;
    let port = port_str.parse::<u16>().ok()?;
    Some((host.to_string(), port, path))
}

/// Parse a raw HTTP/1.x response string into an [`HttpResponse`].
///
/// Handles `\r\n\r\n` and `\n\n` separators and skips leading 100-Continue
/// header blocks (uses rfind to land on the last separator).
fn parse_http_response(raw: &str) -> Result<HttpResponse, String> {
    let (header_block, body) = if let Some(pos) = raw.rfind("\r\n\r\n") {
        (&raw[..pos], raw[pos + 4..].to_string())
    } else if let Some(pos) = raw.rfind("\n\n") {
        (&raw[..pos], raw[pos + 2..].to_string())
    } else {
        return Err("Malformed HTTP response (no header separator)".to_string());
    };
    let last_block = if let Some(pos) = header_block.rfind("\r\nHTTP/") {
        &header_block[pos + 2..]
    } else if let Some(pos) = header_block.rfind("\nHTTP/") {
        &header_block[pos + 1..]
    } else {
        header_block
    };
    let status_line = last_block.lines().next().unwrap_or("");
    let status = status_line.split_whitespace().nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let line_sep = if last_block.contains("\r\n") { "\r\n" } else { "\n" };
    let headers: Vec<(String, String)> = last_block.split(line_sep).skip(1)
        .filter_map(|line| {
            let colon = line.find(':')?;
            Some((line[..colon].trim().to_lowercase(), line[colon + 1..].trim().to_string()))
        })
        .collect();
    Ok(HttpResponse { status, body, headers })
}

/// Returns `Err` if `curl` is not found on PATH. Result is cached.
///
/// Required only for `https://` requests; plain `http://` uses TcpStream.
pub fn ensure_curl() -> Result<(), String> {
    static CURL_OK: OnceLock<bool> = OnceLock::new();
    let ok = *CURL_OK.get_or_init(|| {
        Command::new("curl").arg("--version")
            .stdout(Stdio::null()).stderr(Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false)
    });
    if ok { Ok(()) } else {
        Err("curl not found on PATH — required for HTTPS requests. \
             Install: macOS — `brew install curl`; Linux — `sudo apt install curl`."
            .to_string())
    }
}

/// HTTP/1.1 request over a raw `TcpStream` (plain `http://` only, no TLS).
fn http_request_tcp(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Result<HttpResponse, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let (host, port, path) = parse_http_url(url)
        .ok_or_else(|| format!("Cannot parse HTTP URL '{}' (expected host:port[/path])", url))?;
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| format!("HTTP connect to '{}': {}", addr, e))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;

    let body_str = body.unwrap_or("");
    let has_ct = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
    let mut header_lines = String::new();
    if !body_str.is_empty() && !has_ct {
        header_lines.push_str("Content-Type: application/json\r\n");
    }
    if !body_str.is_empty() {
        header_lines.push_str(&format!("Content-Length: {}\r\n", body_str.len()));
    }
    for (k, v) in headers { header_lines.push_str(&format!("{}: {}\r\n", k, v)); }
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n{}",
        method, path, host, header_lines, body_str
    );
    stream.write_all(request.as_bytes()).map_err(|e| format!("HTTP write: {}", e))?;
    stream.flush().map_err(|e| format!("HTTP flush: {}", e))?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| format!("HTTP read: {}", e))?;
    parse_http_response(&raw)
}

/// HTTP/HTTPS request via the system `curl` binary. Supports TLS and custom headers.
fn http_request_curl(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Result<HttpResponse, String> {
    use std::io::Write;
    ensure_curl()?;
    let mut cmd = Command::new("curl");
    cmd.arg("-sS").arg("-D").arg("-").arg("-X").arg(method);
    let has_ct = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
    if body.is_some() && !has_ct { cmd.arg("-H").arg("Content-Type: application/json"); }
    for (k, v) in headers { cmd.arg("-H").arg(format!("{}: {}", k, v)); }
    if body.is_some() { cmd.arg("--data-binary").arg("@-"); cmd.stdin(Stdio::piped()); }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.arg(url);
    let mut child = cmd.spawn().map_err(|e| format!("curl spawn: {}", e))?;
    if let Some(b) = body {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(b.as_bytes()).map_err(|e| format!("curl stdin write: {}", e))?;
        }
    }
    let output = child.wait_with_output().map_err(|e| format!("curl wait: {}", e))?;
    let raw = String::from_utf8_lossy(&output.stdout).into_owned();
    if raw.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl: {}", stderr.trim()));
    }
    parse_http_response(&raw)
}

/// Make an HTTP or HTTPS request.
///
/// Routes `https://` through `curl` and `http://` through a raw `TcpStream`.
pub fn http_request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Result<HttpResponse, String> {
    if url.starts_with("https://") {
        http_request_curl(method, url, headers, body)
    } else {
        http_request_tcp(method, url, headers, body)
    }
}

// ===========================================================================
// PKCE + URL helpers
// ===========================================================================

/// Percent-encode `s` per RFC 3986 §2.1 for use in URL query parameters.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => { out.push('%'); out.push_str(&format!("{:02X}", b)); }
        }
    }
    out
}

/// Decode a percent-encoded URL component.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16,
            ) { out.push(v); i += 3; continue; }
        } else if bytes[i] == b'+' { out.push(b' '); i += 1; continue; }
        out.push(bytes[i]); i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Extract a named parameter value from a URL query string (`key=val&…`).
pub fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for part in query.split('&') {
        if let Some(rest) = part.strip_prefix(key) {
            if let Some(val) = rest.strip_prefix('=') { return Some(val); }
        }
    }
    None
}

/// Generate PKCE (RFC 7636) verifier, S256 challenge, and random CSRF state.
///
/// Returns `(code_verifier, code_challenge, state)`.
pub fn pkce_generate() -> (String, String, String) {
    use crate::crypto::{base64url_encode, sha256, secure_random_bytes};
    let verifier_bytes = secure_random_bytes(32);
    let code_verifier = base64url_encode(&verifier_bytes);
    let challenge_bytes = sha256(code_verifier.as_bytes());
    let code_challenge = base64url_encode(&challenge_bytes);
    let state_bytes = secure_random_bytes(16);
    let state = base64url_encode(&state_bytes);
    (code_verifier, code_challenge, state)
}

/// Build the full authorization URL with PKCE and redirect parameters.
pub fn build_auth_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
    scopes: &str,
) -> String {
    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}\
         &code_challenge={}&code_challenge_method=S256&state={}",
        authorization_endpoint,
        percent_encode(client_id),
        percent_encode(redirect_uri),
        code_challenge,
        state,
    );
    if !scopes.is_empty() { url.push_str("&scope="); url.push_str(&percent_encode(scopes)); }
    url
}

/// Accept one OAuth callback on the loopback `listener`.
///
/// Reads the HTTP GET request, extracts `code` and `state`, sends an HTML
/// success page, and returns `(code, state)`. Times out after `timeout_secs`.
pub fn accept_oauth_callback(
    listener: std::net::TcpListener,
    timeout_secs: u64,
) -> Result<(String, String), String> {
    let (tx, rx) = std::sync::mpsc::channel::<Result<(String, String), String>>();
    std::thread::spawn(move || {
        use std::io::{BufRead, Write};
        let result: Result<(String, String), String> = (|| {
            let (stream, _) = listener.accept()
                .map_err(|e| format!("OAuth callback accept: {e}"))?;
            let mut reader = std::io::BufReader::new(stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line)
                .map_err(|e| format!("OAuth callback read: {e}"))?;
            let path = request_line.split_whitespace().nth(1)
                .ok_or_else(|| "OAuth callback: malformed request line".to_string())?;
            let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let code = query_param(query, "code").map(percent_decode)
                .ok_or_else(|| "OAuth callback: 'code' not found in redirect URL".to_string())?;
            let state = query_param(query, "state").map(percent_decode)
                .ok_or_else(|| "OAuth callback: 'state' not found in redirect URL".to_string())?;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() { break; }
                if line.trim_end_matches(|c| c == '\r' || c == '\n').is_empty() { break; }
            }
            const HTML: &str = "<html><body>\
                <h2>Authorization successful</h2>\
                <p>You may close this tab and return to Helm.</p>\
                </body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                HTML.len(), HTML,
            );
            let _ = reader.into_inner().write_all(resp.as_bytes());
            Ok((code, state))
        })();
        let _ = tx.send(result);
    });
    rx.recv_timeout(std::time::Duration::from_secs(timeout_secs))
        .map_err(|_| format!("OAuth callback timed out after {timeout_secs}s"))?
}

// ===========================================================================
// Discovery + DCR + token exchange
// ===========================================================================

/// Resolved OAuth 2.1 authorization server endpoints from RFC 8414 discovery.
#[derive(Debug, Clone)]
pub struct AuthServerMeta {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// Empty when the server doesn't advertise Dynamic Client Registration.
    pub registration_endpoint: String,
}

/// Parse an RFC 8414 authorization server metadata JSON body.
pub fn parse_auth_server_meta(json: &str) -> Result<AuthServerMeta, String> {
    let authorization_endpoint = extract_string_value(json, "authorization_endpoint")
        .ok_or_else(|| "auth server metadata missing authorization_endpoint".to_string())?;
    let token_endpoint = extract_string_value(json, "token_endpoint")
        .ok_or_else(|| "auth server metadata missing token_endpoint".to_string())?;
    let registration_endpoint = extract_string_value(json, "registration_endpoint")
        .unwrap_or_default();
    Ok(AuthServerMeta { authorization_endpoint, token_endpoint, registration_endpoint })
}

/// Slim OAuth registration needed for discovery and auth flows.
///
/// Built from `schema::McpServerRegistration` or `ParsedRegistration` in the router.
#[derive(Debug, Clone, Default)]
pub struct OAuthReg {
    pub alias: String,
    pub client_id: String,
    pub scopes: String,
    pub discovery_url: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: String,
}

impl OAuthReg {
    /// Build from a `McpServerRegistration` (lib side).
    pub fn from_schema(reg: &crate::schema::McpServerRegistration) -> Self {
        OAuthReg {
            alias: reg.alias.clone(),
            client_id: reg.oauth_client_id.clone(),
            scopes: reg.oauth_scopes.clone(),
            discovery_url: reg.oauth_discovery_url.clone(),
            authorization_endpoint: reg.oauth_authorization_endpoint.clone(),
            token_endpoint: reg.oauth_token_endpoint.clone(),
            registration_endpoint: reg.oauth_registration_endpoint.clone(),
        }
    }
}

/// Resolve OAuth endpoints for a registration.
///
/// **Fast path**: both explicit endpoints set → return immediately (no HTTP).
/// **Slow path**: fetch RFC 9728/8414 metadata from `discovery_url`.
pub fn oauth_discover(reg: &OAuthReg) -> Result<AuthServerMeta, String> {
    if !reg.authorization_endpoint.is_empty() && !reg.token_endpoint.is_empty() {
        return Ok(AuthServerMeta {
            authorization_endpoint: reg.authorization_endpoint.clone(),
            token_endpoint:         reg.token_endpoint.clone(),
            registration_endpoint:  reg.registration_endpoint.clone(),
        });
    }
    if reg.discovery_url.is_empty() {
        return Err(format!(
            "oauth_discover: '{}' has no discovery_url and no explicit endpoints",
            reg.alias
        ));
    }
    let resp = http_request("GET", &reg.discovery_url, &[], None)?;
    if resp.status != 200 {
        return Err(format!(
            "oauth_discover: '{}' metadata fetch returned HTTP {} (url: {})",
            reg.alias, resp.status, reg.discovery_url
        ));
    }
    parse_auth_server_meta(&resp.body)
}

/// Perform Dynamic Client Registration (RFC 7591).
///
/// Returns the assigned `client_id`. Persists any `client_secret` to the
/// encrypted token store under alias `"<alias>.dcr"`.
pub fn oauth_dcr(alias: &str, registration_endpoint: &str, scopes: &str) -> Result<String, String> {
    let scope_clause = if scopes.is_empty() { String::new() }
        else { format!(",\"scope\":{}", json_escape(scopes)) };
    // RFC 8252 §8.4: native/CLI OAuth clients are public clients and MUST use
    // token_endpoint_auth_method=none.  client_secret_basic would tell the AS
    // we are a confidential client, causing it to require HTTP Basic credentials
    // that we never send — breaking the token exchange on strict servers.
    let body = format!(
        "{{\"client_name\":{},\"grant_types\":[\"authorization_code\"],\
         \"response_types\":[\"code\"],\
         \"token_endpoint_auth_method\":\"none\"{}}}",
        json_escape(alias), scope_clause,
    );
    let resp = http_request("POST", registration_endpoint, &[], Some(&body))?;
    if resp.status != 201 && resp.status != 200 {
        return Err(format!(
            "DCR for '{}' returned HTTP {}: {}",
            alias, resp.status, &resp.body[..resp.body.len().min(200)]
        ));
    }
    let client_id = extract_string_value(&resp.body, "client_id")
        .ok_or_else(|| format!("DCR response for '{}' missing client_id", alias))?;
    if let Some(secret) = extract_string_value(&resp.body, "client_secret") {
        let ts = TokenSet {
            access_token: secret,
            refresh_token: None,
            expires_at: None,
            scope: if scopes.is_empty() { None } else { Some(scopes.to_string()) },
            token_type: "client_secret".to_string(),
        };
        token_store::save(&format!("{alias}.dcr"), &ts)
            .map_err(|e| format!("DCR: failed to persist client_secret for '{}': {}", alias, e))?;
    }
    Ok(client_id)
}

/// Extract a u64 value from a numeric JSON field (e.g. `"expires_in": 3600`).
fn extract_u64_field(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\"", key);
    let idx = json.find(&needle)?;
    let after = &json[idx + needle.len()..];
    let colon = after.find(':')?;
    let val = after[colon + 1..].trim_start();
    let num: String = val.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

/// Parse an RFC 6749 §5.1 token endpoint response into a `TokenSet`.
pub fn parse_token_response(json: &str) -> Result<TokenSet, String> {
    let access_token = extract_string_value(json, "access_token")
        .ok_or_else(|| "Token response missing access_token".to_string())?;
    let refresh_token = extract_string_value(json, "refresh_token");
    let token_type = extract_string_value(json, "token_type")
        .unwrap_or_else(|| "Bearer".to_string());
    let scope = extract_string_value(json, "scope");
    let expires_at = extract_u64_field(json, "expires_in").map(|n| now_unix() + n);
    Ok(TokenSet { access_token, refresh_token, expires_at, scope, token_type })
}

/// Exchange an authorization code for tokens (RFC 6749 §4.1.3 + RFC 7636 PKCE).
pub fn oauth_token_exchange(
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    scopes: &str,
) -> Result<TokenSet, String> {
    let mut body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        percent_encode(code),
        percent_encode(redirect_uri),
        percent_encode(client_id),
        code_verifier, // base64url is already URL-safe
    );
    if !scopes.is_empty() { body.push_str("&scope="); body.push_str(&percent_encode(scopes)); }
    let headers: &[(&str, &str)] = &[("Content-Type", "application/x-www-form-urlencoded")];
    let resp = http_request("POST", token_endpoint, headers, Some(&body))?;
    if resp.status != 200 {
        return Err(format!(
            "Token exchange returned HTTP {}: {}",
            resp.status, &resp.body[..resp.body.len().min(200)]
        ));
    }
    parse_token_response(&resp.body)
}

// ===========================================================================
// Auth-status + revoke
// ===========================================================================

/// OAuth authorization status for a registered alias.
#[derive(Debug)]
pub struct OAuthStatus {
    pub alias: String,
    /// `"authorized"`, `"expired"`, or `"unauthorized"`.
    pub status: String,
    pub expires_at: Option<u64>,
    pub scopes: Option<String>,
}

/// Check the token store for `alias` and return its OAuth status.
///
/// Does not make any network calls. Returns `"unauthorized"` when no
/// token file exists, `"expired"` when `expires_at` is in the past,
/// and `"authorized"` otherwise.
pub fn auth_status(alias: &str) -> OAuthStatus {
    match token_store::load(alias) {
        Ok(ts) => {
            let now = now_unix();
            let expired = ts.expires_at.map(|exp| now >= exp).unwrap_or(false);
            OAuthStatus {
                alias:      alias.to_string(),
                status:     if expired { "expired".to_string() } else { "authorized".to_string() },
                expires_at: ts.expires_at,
                scopes:     ts.scope,
            }
        }
        Err(_) => OAuthStatus {
            alias:      alias.to_string(),
            status:     "unauthorized".to_string(),
            expires_at: None,
            scopes:     None,
        },
    }
}

/// Delete the stored token for `alias` from the encrypted token store.
///
/// No-ops gracefully when the alias has no stored token.
pub fn revoke_token(alias: &str) -> Result<(), String> {
    token_store::delete(alias)
}

// ===========================================================================
// Full PKCE authorization flow (interactive — uses stdio)
// ===========================================================================

/// Run the full OAuth 2.1 PKCE authorization-code flow for `alias`.
///
/// 1. Discover endpoints via `oauth_discover`.
/// 2. Determine `client_id` (from registration or DCR).
/// 3. Bind a random loopback port; generate PKCE verifier + challenge + state.
/// 4. Print the authorization URL to stderr (visible to MCP agent).
/// 5. Wait for the loopback callback (5-minute timeout).
/// 6. Validate `state` — reject mismatches (CSRF guard).
/// 7. Exchange code for tokens; persist to encrypted store.
///
/// **Paste fallback**: supply `preauth_code`, `preauth_state`, and
/// `preauth_verifier` to skip the listener when the callback URL is pasted.
pub fn authorize(
    alias: &str,
    reg: &OAuthReg,
    preauth_code: Option<&str>,
    preauth_state: Option<&str>,
    preauth_verifier: Option<&str>,
    preauth_redirect_uri: Option<&str>,
    mesh_dir: Option<&std::path::Path>,
) -> Result<String, String> {
    let meta = oauth_discover(reg)?;

    let client_id: String = if !reg.client_id.is_empty() {
        reg.client_id.clone()
    } else if !meta.registration_endpoint.is_empty() {
        eprintln!("[crux] '{}': no client_id; attempting Dynamic Client Registration…", alias);
        oauth_dcr(alias, &meta.registration_endpoint, &reg.scopes)?
    } else {
        return Err(format!(
            "authorize: '{}' has no client_id and no registration_endpoint for DCR — \
             set oauth_client_id in the registration or add oauth_registration_endpoint",
            alias
        ));
    };

    // Paste fallback: all three preauth params supplied
    if let (Some(code), Some(_state), Some(verifier)) = (preauth_code, preauth_state, preauth_verifier) {
        let redirect_uri = preauth_redirect_uri.unwrap_or("");
        let tokens = oauth_token_exchange(
            &meta.token_endpoint, &client_id, code, verifier, redirect_uri, &reg.scopes,
        )?;
        token_store::save(alias, &tokens)
            .map_err(|e| format!("authorize: token save failed for '{}': {e}", alias))?;
        emit_oauth_audit(mesh_dir, "oauth_consent_granted", alias, true);
        return Ok(format!(
            "Authorization successful for '{}' (paste fallback). Tokens stored.", alias
        ));
    }

    // Interactive loopback flow
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("authorize: cannot bind loopback listener: {e}"))?;
    let port = listener.local_addr()
        .map_err(|e| format!("authorize: get local addr: {e}"))?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let (code_verifier, code_challenge, state) = pkce_generate();
    let auth_url = build_auth_url(
        &meta.authorization_endpoint, &client_id, &redirect_uri,
        &code_challenge, &state, &reg.scopes,
    );

    eprintln!(
        "\n[crux] OAuth authorization required for '{alias}'\n\
         \nOpen this URL in your browser:\n\
         \n  {auth_url}\n\
         \nWaiting for callback on {redirect_uri} (5-minute timeout).\n\
         If the browser cannot reach localhost, paste the full callback URL and\n\
         re-call with: code=<code> state=<state> code_verifier={code_verifier}\n"
    );

    let (code, returned_state) = accept_oauth_callback(listener, 300)?;
    if returned_state != state {
        return Err(format!(
            "authorize: state mismatch — possible CSRF attack \
             (expected '{}', got '{}')",
            state, returned_state
        ));
    }

    let tokens = oauth_token_exchange(
        &meta.token_endpoint, &client_id, &code, &code_verifier, &redirect_uri, &reg.scopes,
    )?;
    token_store::save(alias, &tokens)
        .map_err(|e| format!("authorize: token save failed for '{}': {e}", alias))?;
    emit_oauth_audit(mesh_dir, "oauth_consent_granted", alias, true);

    Ok(format!(
        "Authorization successful for '{}'. Tokens stored and ready for use.", alias
    ))
}

// ===========================================================================
// Helm web-flow helpers (used by Helm server for browser-based auth)
// ===========================================================================

/// Pending OAuth PKCE flow state stored by the Helm server between
/// `POST /api/mcp/oauth/start` and `GET /oauth/callback`.
#[derive(Debug, Clone)]
pub struct PendingOAuth {
    pub alias: String,
    pub code_verifier: String,
    pub state: String,
    pub scopes: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
}

/// Start a PKCE auth flow for the Helm web UI.
///
/// Performs discovery, generates PKCE params, and returns the authorization
/// URL and a `PendingOAuth` that the caller must store (keyed by alias)
/// until the callback arrives at `GET /oauth/callback`.
pub fn helm_oauth_start(
    alias: &str,
    reg: &OAuthReg,
    helm_port: u16,
) -> Result<(String, PendingOAuth), String> {
    let meta = oauth_discover(reg)?;

    let client_id: String = if !reg.client_id.is_empty() {
        reg.client_id.clone()
    } else if !meta.registration_endpoint.is_empty() {
        oauth_dcr(alias, &meta.registration_endpoint, &reg.scopes)?
    } else {
        return Err(format!(
            "helm_oauth_start: '{}' has no client_id and no registration_endpoint for DCR",
            alias
        ));
    };

    let redirect_uri = format!("http://127.0.0.1:{helm_port}/oauth/callback");
    let (code_verifier, code_challenge, state) = pkce_generate();
    let auth_url = build_auth_url(
        &meta.authorization_endpoint, &client_id, &redirect_uri,
        &code_challenge, &state, &reg.scopes,
    );

    let pending = PendingOAuth {
        alias: alias.to_string(),
        code_verifier,
        state,
        scopes: reg.scopes.clone(),
        token_endpoint: meta.token_endpoint,
        client_id,
        redirect_uri,
    };
    Ok((auth_url, pending))
}

/// Complete a Helm OAuth flow from the callback `code` and `state`.
///
/// Validates state, exchanges the code for tokens, stores them, and returns
/// a success message.
pub fn helm_oauth_complete(
    pending: &PendingOAuth,
    code: &str,
    returned_state: &str,
    mesh_dir: Option<&std::path::Path>,
) -> Result<String, String> {
    if returned_state != pending.state {
        return Err(format!(
            "helm_oauth_complete: state mismatch for '{}' — possible CSRF attack",
            pending.alias
        ));
    }
    let tokens = oauth_token_exchange(
        &pending.token_endpoint, &pending.client_id, code,
        &pending.code_verifier, &pending.redirect_uri, &pending.scopes,
    )?;
    token_store::save(&pending.alias, &tokens)
        .map_err(|e| format!("helm_oauth_complete: token save failed for '{}': {e}", pending.alias))?;
    emit_oauth_audit(mesh_dir, "oauth_consent_granted", &pending.alias, true);
    Ok(format!("Authorization successful for '{}'.", pending.alias))
}

// ===========================================================================
// Audit helper
// ===========================================================================

/// Emit an OAuth audit event to `.crux-audit.json` (best-effort).
pub fn emit_oauth_audit(mesh_dir: Option<&std::path::Path>, event: &str, subject: &str, allowed: bool) {
    let Some(dir) = mesh_dir else { return };
    let log_path = dir.join(".crux-audit.json");
    let ts = now_unix();
    let line = format!(
        "{{\"ts\":{},\"event\":{},\"subject\":{},\"detail\":\"oauth\",\"allowed\":{}}}\n",
        ts, json_escape(event), json_escape(subject), allowed
    );
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .and_then(|mut f| { use std::io::Write; f.write_all(line.as_bytes()) });
}
