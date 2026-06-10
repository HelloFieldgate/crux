//! OAuth 2.1 integration tests — Phase 8.
//!
//! Each test spins up one or more std::net::TcpListener mock servers on random
//! ports and exercises crux_mesh::oauth::* library functions against them.
//! No external services or binaries needed.
//!
//! Alias prefix "oi-" keeps token-store files isolated from the router binary's
//! "p5-"/"p6-" unit tests when both suites run in parallel.
//!
//! Coverage:
//!  discovery  — slow path (fetch AS metadata), fast path (explicit endpoints), 404 error
//!  DCR        — client_id returned + client_secret stored; no secret; 400 error
//!  exchange   — successful token exchange; 400 error
//!  auth_status — authorized / expired / unauthorized
//!  revoke     — clears token → unauthorized
//!  authorize  — paste-fallback: discover + exchange + store
//!  Helm flow  — start (PKCE params) + complete (exchange + store); CSRF guard
//!  Acceptance — discover → paste-authorize → authorized → revoke

use crux_mesh::oauth::{
    auth_status, authorize, helm_oauth_complete, helm_oauth_start,
    oauth_dcr, oauth_discover, oauth_token_exchange, OAuthReg, PendingOAuth,
};
use crux_mesh::schema::now_unix;
use crux_mesh::token_store::{self, TokenSet};

// ── Mock server helpers ───────────────────────────────────────────────────────

/// Bind a loopback TcpListener on an OS-assigned port; return (port, listener).
fn bind_mock() -> (u16, std::net::TcpListener) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    (p, l)
}

/// Serve `responses` (one per accepted connection) from `listener` in a
/// background thread.  Each tuple is (HTTP status, response body JSON).
fn serve_seq(listener: std::net::TcpListener, responses: Vec<(u16, String)>) {
    std::thread::spawn(move || {
        use std::io::{BufRead, Read, Write};
        for (status, body) in responses {
            let Ok((stream, _)) = listener.accept() else { return };
            let mut reader = std::io::BufReader::new(stream);
            // Drain request headers; read body if Content-Length present.
            let mut content_len: usize = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() { break; }
                let t = line.trim_end_matches(|c: char| c == '\r' || c == '\n');
                if t.is_empty() { break; }
                if let Some(v) = t.to_lowercase().strip_prefix("content-length:") {
                    content_len = v.trim().parse().unwrap_or(0);
                }
            }
            if content_len > 0 {
                let mut buf = vec![0u8; content_len];
                let _ = reader.read_exact(&mut buf);
            }
            let phrase = match status {
                200 => "OK", 201 => "Created", 400 => "Bad Request",
                401 => "Unauthorized", 404 => "Not Found", _ => "Error",
            };
            let resp = format!(
                "HTTP/1.1 {status} {phrase}\r\nContent-Type: application/json\r\n\
                 Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                len = body.len(),
            );
            let _ = reader.into_inner().write_all(resp.as_bytes());
        }
    });
}

/// One-shot mock: accepts one connection and returns `(status, body)`.
fn mock_one(status: u16, body: impl Into<String>) -> u16 {
    let body: String = body.into();
    let (port, listener) = bind_mock();
    serve_seq(listener, vec![(status, body)]);
    port
}

// ── Discovery ─────────────────────────────────────────────────────────────────

/// Slow path: oauth_discover fetches RFC 8414 AS metadata from discovery_url.
#[test]
fn test_discover_slow_path_fetches_as_metadata() {
    let meta = r#"{"authorization_endpoint":"http://as.test/authorize","token_endpoint":"http://as.test/token","registration_endpoint":"http://as.test/register"}"#;
    let port = mock_one(200, meta);
    let reg = OAuthReg {
        alias: "oi-disc-slow".to_string(),
        discovery_url: format!(
            "http://127.0.0.1:{port}/.well-known/oauth-authorization-server"
        ),
        ..Default::default()
    };
    let m = oauth_discover(&reg).expect("slow-path discover");
    assert_eq!(m.authorization_endpoint, "http://as.test/authorize");
    assert_eq!(m.token_endpoint,         "http://as.test/token");
    assert_eq!(m.registration_endpoint,  "http://as.test/register");
}

/// Fast path: explicit endpoints → oauth_discover returns them without HTTP.
#[test]
fn test_discover_fast_path_needs_no_http() {
    // No mock server — any network call would fail or panic.
    let reg = OAuthReg {
        alias: "oi-disc-fast".to_string(),
        authorization_endpoint: "http://as.test/authorize".to_string(),
        token_endpoint:         "http://as.test/token".to_string(),
        ..Default::default()
    };
    let m = oauth_discover(&reg).expect("fast-path discover");
    assert_eq!(m.authorization_endpoint, "http://as.test/authorize");
    assert_eq!(m.token_endpoint,         "http://as.test/token");
    // registration_endpoint is empty when not in the fast-path reg
    assert!(m.registration_endpoint.is_empty());
}

/// Non-200 from the AS metadata endpoint must return an error.
#[test]
fn test_discover_non_200_is_error() {
    let port = mock_one(404, r#"{"error":"not_found"}"#);
    let reg = OAuthReg {
        alias: "oi-disc-404".to_string(),
        discovery_url: format!(
            "http://127.0.0.1:{port}/.well-known/oauth-authorization-server"
        ),
        ..Default::default()
    };
    let err = oauth_discover(&reg).expect_err("non-200 must fail");
    assert!(err.contains("404"), "err: {err}");
}

// ── Dynamic Client Registration ───────────────────────────────────────────────

/// DCR: client_id returned; client_secret stored encrypted under "<alias>.dcr".
#[test]
fn test_dcr_returns_client_id_and_stores_secret() {
    let dcr_alias = "oi-dcr-secret";
    let dcr_key   = format!("{dcr_alias}.dcr");
    let _ = token_store::delete(&dcr_key);

    let port = mock_one(201, r#"{"client_id":"dcr-cid","client_secret":"dcr-sec"}"#);
    let cid = oauth_dcr(
        dcr_alias,
        &format!("http://127.0.0.1:{port}/register"),
        "read write",
    ).expect("DCR should succeed");

    assert_eq!(cid, "dcr-cid");

    let stored = token_store::load(&dcr_key).expect("secret stored under alias.dcr");
    assert_eq!(stored.access_token, "dcr-sec");
    assert_eq!(stored.token_type,   "client_secret");

    let _ = token_store::delete(&dcr_key);
}

/// DCR response without client_secret: client_id returned, no secret stored.
#[test]
fn test_dcr_without_secret_only_returns_client_id() {
    let dcr_alias = "oi-dcr-nosec";
    let _ = token_store::delete(&format!("{dcr_alias}.dcr"));

    let port = mock_one(201, r#"{"client_id":"dcr-public"}"#);
    let cid = oauth_dcr(
        dcr_alias,
        &format!("http://127.0.0.1:{port}/register"),
        "",
    ).expect("DCR without secret should succeed");

    assert_eq!(cid, "dcr-public");
    let _ = token_store::delete(&format!("{dcr_alias}.dcr"));
}

/// DCR 400 → must return an error.
#[test]
fn test_dcr_bad_status_is_error() {
    let port = mock_one(400, r#"{"error":"invalid_client_metadata"}"#);
    let err = oauth_dcr(
        "oi-dcr-fail",
        &format!("http://127.0.0.1:{port}/register"),
        "",
    ).expect_err("DCR 400 must fail");
    assert!(err.to_lowercase().contains("400"), "err: {err}");
}

// ── Token exchange ────────────────────────────────────────────────────────────

/// Successful token exchange returns a TokenSet with access + refresh tokens.
#[test]
fn test_token_exchange_success() {
    let tok_resp = r#"{"access_token":"xch-acc","token_type":"Bearer","refresh_token":"xch-ref","expires_in":3600}"#;
    let port = mock_one(200, tok_resp);

    let ts = oauth_token_exchange(
        &format!("http://127.0.0.1:{port}/token"),
        "xch-client", "auth-code-1", "code-verifier-1",
        "http://127.0.0.1:8111/oauth/callback", "read",
    ).expect("token exchange must succeed");

    assert_eq!(ts.access_token, "xch-acc");
    assert_eq!(ts.refresh_token, Some("xch-ref".to_string()));
    assert!(ts.expires_at.unwrap_or(0) > now_unix(), "expires_at must be in the future");
}

/// 400 from token endpoint → error propagated.
#[test]
fn test_token_exchange_400_is_error() {
    let port = mock_one(400, r#"{"error":"invalid_grant"}"#);
    let err = oauth_token_exchange(
        &format!("http://127.0.0.1:{port}/token"),
        "c", "code", "verifier", "http://redir", "",
    ).expect_err("400 must fail");
    assert!(err.to_lowercase().contains("400"), "err: {err}");
}

// ── auth_status ───────────────────────────────────────────────────────────────

/// Token present and not expired → "authorized".
#[test]
fn test_auth_status_authorized_after_save() {
    let alias = "oi-status-auth";
    let _ = token_store::delete(alias);
    token_store::save(alias, &TokenSet {
        access_token: "tok".to_string(),
        refresh_token: None,
        expires_at: Some(now_unix() + 3600),
        scope: Some("read".to_string()),
        token_type: "Bearer".to_string(),
    }).unwrap();
    let s = auth_status(alias);
    assert_eq!(s.status, "authorized");
    assert_eq!(s.scopes, Some("read".to_string()));
    let _ = token_store::delete(alias);
}

/// Token present but expires_at in the past → "expired".
#[test]
fn test_auth_status_expired_when_expires_at_in_past() {
    let alias = "oi-status-exp";
    let _ = token_store::delete(alias);
    token_store::save(alias, &TokenSet {
        access_token: "old".to_string(),
        refresh_token: None,
        expires_at: Some(1), // epoch+1 → always in the past
        scope: None,
        token_type: "Bearer".to_string(),
    }).unwrap();
    assert_eq!(auth_status(alias).status, "expired");
    let _ = token_store::delete(alias);
}

/// No token file → "unauthorized".
#[test]
fn test_auth_status_unauthorized_when_no_token() {
    let alias = "oi-status-unauth-zzz";
    let _ = token_store::delete(alias);
    assert_eq!(auth_status(alias).status, "unauthorized");
}

// ── revoke_token ──────────────────────────────────────────────────────────────

/// revoke_token deletes the stored token → auth_status transitions to "unauthorized".
#[test]
fn test_revoke_token_transitions_to_unauthorized() {
    let alias = "oi-revoke-ok";
    let _ = token_store::delete(alias);
    token_store::save(alias, &TokenSet {
        access_token: "tok".to_string(),
        refresh_token: Some("ref".to_string()),
        expires_at: Some(now_unix() + 3600),
        scope: None,
        token_type: "Bearer".to_string(),
    }).unwrap();
    assert_eq!(auth_status(alias).status, "authorized");
    crux_mesh::oauth::revoke_token(alias).unwrap();
    assert_eq!(auth_status(alias).status, "unauthorized");
}

// ── authorize — paste-fallback ────────────────────────────────────────────────

/// authorize() paste-fallback: discovers endpoints, exchanges code, stores token.
#[test]
fn test_authorize_paste_fallback_stores_tokens() {
    let alias = "oi-auth-paste";
    let _ = token_store::delete(alias);

    let tok_resp = r#"{"access_token":"paste-acc","token_type":"Bearer","refresh_token":"paste-ref","expires_in":3600}"#;
    let port = mock_one(200, tok_resp);

    let reg = OAuthReg {
        alias: alias.to_string(),
        client_id: "paste-client".to_string(),
        // Fast-path discovery (no HTTP needed).
        authorization_endpoint: format!("http://127.0.0.1:{port}/authorize"),
        token_endpoint: format!("http://127.0.0.1:{port}/token"),
        ..Default::default()
    };

    let msg = authorize(
        alias, &reg,
        Some("code-1"), Some("state-1"), Some("verifier-1"),
        Some("http://127.0.0.1:8111/oauth/callback"),
        None,
    ).expect("paste fallback must succeed");

    assert!(msg.contains("Authorization successful"), "msg: {msg}");
    assert_eq!(auth_status(alias).status, "authorized");

    let stored = token_store::load(alias).unwrap();
    assert_eq!(stored.access_token, "paste-acc");
    assert_eq!(stored.refresh_token, Some("paste-ref".to_string()));

    let _ = token_store::delete(alias);
}

// ── Helm OAuth flow (Phase 7 verify equivalent) ───────────────────────────────

/// helm_oauth_complete must reject a state mismatch (CSRF guard).
#[test]
fn test_helm_complete_rejects_state_mismatch() {
    let pending = PendingOAuth {
        alias:         "oi-helm-csrf".to_string(),
        code_verifier: "verifier".to_string(),
        state:         "correct-state".to_string(),
        scopes:        String::new(),
        token_endpoint: "http://127.0.0.1:1/token".to_string(),
        client_id:     "c".to_string(),
        redirect_uri:  "http://127.0.0.1:8111/oauth/callback".to_string(),
    };
    let err = helm_oauth_complete(&pending, "code", "wrong-state", None)
        .expect_err("state mismatch must be rejected");
    assert!(err.contains("state mismatch"), "err: {err}");
}

/// Phase 7 verify: authorize in Helm → status flips to "authorized";
/// revoke → "unauthorized".  Mirrors the manual Helm UI flow end-to-end at
/// the library level.
#[test]
fn test_helm_flow_status_flips_then_revoke() {
    let alias = "oi-helm-p7";
    let _ = token_store::delete(alias);

    // Mock token endpoint — serves the token exchange response.
    let tok_resp = r#"{"access_token":"helm-acc","token_type":"Bearer","refresh_token":"helm-ref","expires_in":3600}"#;
    let port = mock_one(200, tok_resp);

    let reg = OAuthReg {
        alias: alias.to_string(),
        client_id: "helm-client".to_string(),
        // Fast-path so no discovery HTTP call.
        authorization_endpoint: format!("http://127.0.0.1:{port}/authorize"),
        token_endpoint: format!("http://127.0.0.1:{port}/token"),
        scopes: "read".to_string(),
        ..Default::default()
    };

    // Start: helm_oauth_start generates PKCE params and returns auth URL.
    let (auth_url, pending) = helm_oauth_start(alias, &reg, 8111)
        .expect("helm_oauth_start must succeed");

    assert!(auth_url.contains("client_id=helm-client"), "auth_url: {auth_url}");
    assert!(auth_url.contains("code_challenge_method=S256"), "auth_url: {auth_url}");
    assert!(auth_url.contains("redirect_uri="), "auth_url: {auth_url}");
    assert_eq!(auth_status(alias).status, "unauthorized", "no token yet");

    // Simulate the AS callback by completing with the correct state.
    let state = pending.state.clone();
    helm_oauth_complete(&pending, "callback-code", &state, None)
        .expect("helm_oauth_complete must succeed");

    // Badge should flip to "authorized".
    assert_eq!(auth_status(alias).status, "authorized", "status after callback");
    let stored = token_store::load(alias).unwrap();
    assert_eq!(stored.access_token, "helm-acc");

    // Revoke: delete stored token.
    crux_mesh::oauth::revoke_token(alias).unwrap();
    assert_eq!(auth_status(alias).status, "unauthorized", "status after revoke");
}

// ── Acceptance scenario ───────────────────────────────────────────────────────

/// Full acceptance scenario for Phase 8:
///   register (OAuthReg) → discover (slow path) → authorize (paste fallback)
///   → auth_status "authorized" → revoke → auth_status "unauthorized".
///
/// The mock AS serves both requests from a single listener:
///   1. GET /.well-known/oauth-authorization-server → RFC 8414 metadata
///   2. POST /token                                 → token response
#[test]
fn test_acceptance_discover_authorize_revoke() {
    let alias = "oi-accept";
    let _ = token_store::delete(alias);

    // Bind mock AS; bake its port into the discovery metadata.
    let (port, listener) = bind_mock();
    let discovery = format!(
        r#"{{"authorization_endpoint":"http://127.0.0.1:{port}/authorize","token_endpoint":"http://127.0.0.1:{port}/token"}}"#,
    );
    let token_resp = r#"{"access_token":"acc-final","token_type":"Bearer","refresh_token":"ref-final","expires_in":3600}"#.to_string();
    serve_seq(listener, vec![(200, discovery), (200, token_resp)]);

    let reg = OAuthReg {
        alias: alias.to_string(),
        client_id: "accept-client".to_string(),
        // Slow-path: discovery_url set, no explicit endpoints.
        discovery_url: format!(
            "http://127.0.0.1:{port}/.well-known/oauth-authorization-server"
        ),
        ..Default::default()
    };

    // authorize() will:
    //   1. Call oauth_discover → GET mock AS (request 1)
    //   2. Call oauth_token_exchange → POST /token (request 2)
    //   3. Persist tokens to the encrypted store.
    let msg = authorize(
        alias, &reg,
        Some("accept-code"), Some("accept-state"), Some("accept-verifier"),
        None,
        None,
    ).expect("acceptance authorize must succeed");

    assert!(msg.contains("Authorization successful"), "msg: {msg}");
    assert_eq!(auth_status(alias).status, "authorized");

    let stored = token_store::load(alias).unwrap();
    assert_eq!(stored.access_token, "acc-final");
    assert_eq!(stored.refresh_token, Some("ref-final".to_string()));

    // Revoke.
    crux_mesh::oauth::revoke_token(alias).unwrap();
    assert_eq!(auth_status(alias).status, "unauthorized");
}
