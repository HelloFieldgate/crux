# OAuth 2.1 Client Support — Implementation Tracking

Cross-reference: [OAUTH_ROUTER_SUPPORT.md](OAUTH_ROUTER_SUPPORT.md) (spec),
[plan file](~/.claude/plans/snazzy-coalescing-wave.md) (architecture decisions).

Each phase fits one build-session context window. Tick boxes as work lands in a commit.

---

## Phase 0 — Tracking doc + zero-dep HTTPS via curl ✅ Complete

**Goal:** TLS-capable, header-aware HTTP client; curl-presence guard; no OAuth logic yet.

- [x] Create `OAUTH_ROUTER_PLAN.md` (this file)
- [x] Add `HttpResponse` struct + `parse_http_response` to `crux_router.rs`
- [x] Add `ensure_curl()` lazy presence check to `crux_router.rs`
- [x] Add `http_request()` unified dispatcher (https→curl, http→TcpStream)
- [x] Add `http_request_tcp()` — TcpStream path with header support
- [x] Add `http_request_curl()` — curl-backed path for HTTPS
- [x] Refactor `forward_http` to delegate to `http_request` (backward-compatible)
- [x] Add install-time curl check + prompt to macOS installer
- [x] Add install-time curl check + prompt to Linux installer
- [x] Add install-time curl check + prompt to Windows installer
- [x] `cargo build` green; plain-HTTP forwarding behavior unchanged

## Phase 1 — Registration schema: OAuth fields ✅ Complete

**Goal:** registrations can declare OAuth config; `auth=none` (default) preserves today's behavior.

- [x] Add OAuth fields to `McpServerRegistration` in `schema.rs`
- [x] Extend `build_mcp_server_registration` + `parse_mcp_server_registration`
- [x] Add `ParsedRegistration` struct (named, not tuple) + refactor `parse_registrations_from_crux` + `build_dynamic_registry` in `crux_router.rs`
- [x] Extend `mesh register_mcp` + `helm/api.rs` with optional OAuth args (`OAuthConfig` helper struct)
- [x] Round-trip test: auth=oauth2 fields survive serialize/deserialize; auth=none registration is byte-identical
- [x] Fix `extract_string_value` key-collision bug in `json.rs` (mesh query process hole)

## Phase 2 — Crypto: base64url + hand-rolled encrypted token store ✅ Complete

**Goal:** symmetric AEAD and encrypted on-disk token store keyed to the machine.

- [x] Add `base64url_encode` / `base64url_decode` (no padding) to `crypto.rs`
- [x] Add ChaCha20 + HMAC-SHA256 encrypt-then-MAC to `crypto.rs`
- [x] Machine-derived key: `sha256(machine_id ‖ per-install_salt)` with platform probe
- [x] New `token_store` module: `save(alias, TokenSet)` / `load(alias)` / `delete(alias)`
- [x] Unit tests: encrypt/decrypt round-trip; tamper → MAC failure; base64url RFC 4648 vectors; TokenSet save/load/delete

## Phase 3 — OAuth discovery (RFC 9728 / 8414) + optional DCR (RFC 7591) ✅ Complete

**Goal:** resolve authorization + token endpoints; optionally self-register a client.

- [x] `oauth_discover(reg) -> Result<AuthServerMeta, String>` via Phase-0 `http_request`
- [x] Honor explicit endpoints in registration (skip discovery)
- [x] Dynamic Client Registration: POST RFC 7591, persist client_id; store client_secret encrypted
- [x] Verify against mock server or captured fixture

## Phase 4 — Authorization-code + PKCE flow with loopback listener ✅ Complete

**Goal:** first-run interactive consent that yields stored tokens.

- [x] PKCE: `code_verifier = base64url(random(32))`, `code_challenge = base64url(sha256(verifier))`
- [x] Loopback redirect listener: `TcpListener` on `127.0.0.1:0`, capture `?code=&state=`
- [x] Print auth URL for user; validate `state` on callback; fallback: accept pasted URL
- [x] Token exchange: POST `grant_type=authorization_code` + verifier → store `TokenSet`
- [x] Expose trigger via `mesh` tool action / router subcommand
- [x] Verify end-to-end against mock server; state mismatch rejected

## Phase 5 — Token attachment + refresh + 401 retry on forward ✅ Complete

**Goal:** silent token use in the live forward path.

- [x] Attach `Authorization: Bearer <token>` in HTTP-forward branch of `tools/call`
- [x] Pre-flight refresh when `expires_at` is near
- [x] On 401: refresh once → retry; on refresh failure → `re-authorization required` JSON-RPC error with auth URL
- [x] In-memory access-token cache; refresh token only from encrypted store
- [x] Verify: 401→refresh→retry; refresh-failure → re-auth error with URL

## Phase 6 — Audit + clearance integration ✅ Complete

**Goal:** auth events logged; clearance enforced as with all other calls.

- [x] Emit `emit_router_audit` events: `oauth_consent_granted`, `oauth_token_refresh`, `oauth_reauth_required` (in `forward_http_oauth` + `oauth_authorize`)
- [x] Add test: below-clearance caller denied before any token use (`test_below_clearance_caller_denied_before_token_load`)
- [x] Verify `.crux-audit.json` lines for forward + refresh + reauth (events emitted to file when mesh_dir is set)

## Phase 7 — Management surface (Helm UI + mesh tool) + revoke ✅ Complete

**Goal:** see and manage auth status without editing files.

- [x] `mesh` tool: auth-status / trigger-auth / revoke per alias
- [x] Helm "MCP Servers" tab: auth status badge, (Re)authorize button, Revoke
- [x] Verify: authorize in Helm → status flips; revoke → re-auth error on next call

## Phase 8 — Integration tests with a mock OAuth authorization server ✅ Complete

**Goal:** the acceptance criterion, automated.

- [x] Mock OAuth + MCP server under `tests/` (std `TcpListener`, hand-rolled)
- [x] Cover: discovery, PKCE exchange, token attach, pre-flight refresh, 401→refresh→retry, refresh-failure
- [x] `cargo test` green; acceptance scenario: register → authorize once → invoke by alias

---

## Notes

- **Security invariant:** tokens/secrets never enter the policy crux; only the encrypted store.
- **Two registration parsers must stay in sync:** `schema.rs` (library) and `crux_router.rs` (runtime). Every new OAuth field must be added to both.
- **Out of scope:** SSE transport forwarding; router as OAuth authorization server for inbound clients.
