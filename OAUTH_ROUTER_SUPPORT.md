# OAuth Support for the Crux MCP Router

## Background

The crux-router (`src/bin/crux_router.rs`) is a secure MCP router: it registers
downstream MCP servers (`mcp_server_registration` nodes), authorizes/rate-limits/
scans calls, and forwards them — stdio children via pipe, remote servers via
`forward_http` (plain HTTP/1.1 POST, no auth headers).

This is the gap: modern remote MCP servers (e.g. Google/Gmail/Calendar/Drive
connectors) require **OAuth 2.1** (per the MCP authorization spec). `forward_http`
sends no `Authorization` header, so these servers can't currently be routed —
only unauthenticated stdio/HTTP servers work. The next GitHub release should let
the router act as an OAuth client on behalf of the agent, so *all* downstream
servers can sit behind the single trusted router endpoint.

## Goal

When a downstream registration is marked as OAuth-protected, the router should
transparently acquire, store, refresh, and attach bearer tokens when forwarding —
so the calling agent never handles credentials and every server is reachable
through one trusted endpoint.

## High-Level Steps

1. **Extend the registration schema.** Add optional auth fields to
   `mcp_server_registration` (e.g. `auth: "oauth2"`, plus `client_id`,
   `scopes`, and either discovery URL or explicit auth/token endpoints).
   `auth: "none"` (default) preserves today's behavior.

2. **Discovery.** On first use of an OAuth registration, follow the MCP auth flow:
   read the server's protected-resource metadata / authorization-server metadata
   (RFC 9728 / RFC 8414) to learn the authorization + token endpoints and supported
   grant types. Support **Dynamic Client Registration** (RFC 7591) where offered.

3. **Authorization grant (auth code + PKCE).** Implement the OAuth 2.1
   authorization-code-with-PKCE flow. Because the router has no browser, design a
   first-run consent step: print the authorization URL for the user to open, run a
   loopback redirect listener (or accept a pasted callback URL) to capture the code,
   then exchange it for tokens. This mirrors how Claude Code itself completes MCP
   OAuth.

4. **Secure token storage.** Persist tokens per registration — refresh tokens at
   rest must be encrypted (OS keychain or an encrypted store), **not** plaintext in
   the policy crux. Access tokens may be cached in memory for the router's lifetime.

5. **Token attachment in `forward_http`.** When forwarding to an OAuth registration,
   attach `Authorization: Bearer <access_token>`. Keep the existing clearance check,
   rate limit, injection scan, and response sanitization in front of this.

6. **Refresh + re-auth.** Refresh expiring access tokens using the refresh token
   before forwarding. On a `401`/invalid-token response, attempt one refresh, and if
   that fails surface a clear "re-authorization required" error to the caller (with
   the auth URL) rather than a silent failure.

7. **Audit + clearance integration.** Log auth events (consent granted, refresh,
   re-auth required, revocation) in the audit log, consistent with existing router
   entries. Respect per-registration `required_clearance` for who may invoke an
   OAuth-backed server.

8. **Management surface.** Extend the `mesh` tool / Helm "MCP Servers" tab to show
   auth status (authorized / needs consent / token expiring) and to trigger
   (re-)authorization and revoke stored tokens.

9. **Testing.** Add integration tests with a mock OAuth authorization server
   covering: discovery, code+PKCE exchange, token attachment on forward, refresh,
   401→refresh→retry, and refresh-failure surfacing.

## Out of Scope (for now)

- SSE transport forwarding (separate from auth — track independently if needed).
- Acting as an OAuth *authorization server* for inbound clients; this is the
  router-as-*client* direction only.

## Acceptance

A remote OAuth MCP server can be registered, authorized once interactively, and
thereafter invoked through the router by alias with the router silently managing
tokens — verified end-to-end against a real connector (e.g. a Google connector)
or the mock auth server in tests.
