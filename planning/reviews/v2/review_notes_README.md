# Review Notes — v2

Architectural tradeoffs and design decisions documented during review. Future sessions should reference this to avoid re-litigating settled decisions.

## Phase 1 — Scopes & Permissions

### Scope definitions are config-only, not database-stored
Scope definitions live in `riley_auth.toml`, not the database. This means:
- Adding/removing scopes requires config change + restart
- Multi-instance deployments need consistent configs
This is intentional for Phase 1. Database-stored scopes may come in a future phase.

### No scope downscoping on refresh token rotation
RFC 6749 Section 6 allows narrowing scope on refresh. We don't support this — refreshed tokens inherit the same scopes. Acceptable for Phase 1.

### Admin self-deletion is allowed
An admin can delete themselves via `DELETE /admin/users/{id}` (as long as another admin exists). This is by design — the admin knowingly invoked the endpoint. The `DELETE /auth/me` endpoint also exists for self-deletion. No guard needed.

### Silent authorization for auto_approve clients via GET
The authorize endpoint (`GET /oauth/authorize`) silently issues auth codes for `auto_approve=true` clients without a consent step. This is intentional — `auto_approve` is for first-party clients trusted by the deployer. The consent UI (future phase) handles non-auto-approve clients. The auto-approve behavior is comparable to how first-party apps work with Auth0/Okta.

### OAuth state comparison hardened to constant-time
Even though the 32-byte random state makes timing attacks impractical, we now use `subtle::ConstantTimeEq` for consistency with the client secret comparison pattern. Belt and suspenders.

### Session metadata columns (user_agent, ip_address) intentionally empty in Phase 1
Migration 002 adds these columns for Phase 3 (Session Visibility). They store `None` until Phase 3 wires up the request headers. Not a bug.

### Regex recompilation in validate_username
The username regex is compiled from config on every call. Performance impact is negligible for typical auth traffic patterns. Could be optimized with `LazyLock` if it becomes a bottleneck, but not worth the complexity now.

## Phase 6 — Exhaustive Review (Final v2)

### Webhook dispatch is fire-and-forget (known tradeoff)
All three review models flagged this. Webhooks are dispatched via `tokio::spawn` with no persistent outbox. Events are lost on restart. This is a deliberate v2 tradeoff — a persistent queue (Redis Streams, DB outbox) is the logical v3 upgrade. Documented.

### /oauth/authorize CSRF is standard OAuth behavior (NOT a bug)
Codex flagged the authorize endpoint as CSRF-vulnerable with auto_approve. This is standard OAuth — the authorize endpoint is always an unauthenticated GET. Protection comes from the `state` parameter (client-side CSRF token) and `redirect_uri` validation. Auto_approve is for first-party clients only.

### client_id on webhooks is for scoped filtering, not just metadata
After review round 13, `find_webhooks_for_event` now filters by `client_id` when the event includes one. Global events (user.created, etc.) still go to all webhooks. Client-scoped events will only reach matching webhooks.

### OIDC nonce support deferred
The nonce parameter is not implemented in v2. OIDC clients that require nonce will fail at the authorize step. This is a known gap — nonce support is a v3 item.

### ID token always issued (regardless of openid scope)
ID tokens are currently issued on both authorization_code and refresh_token grants regardless of whether the client requested the "openid" scope. This is technically non-compliant but harmless — the token is just extra data. Proper conditional issuance is a v3 refinement.

### CORS preflight may hit rate limiter
OPTIONS requests go through the rate limiter before the CORS layer. This means a rate-limited preflight returns 429 without CORS headers, which browsers see as a CORS failure. Acceptable for v2 (admin-only clients, low traffic), but should be fixed if rate limits are ever tightened.

### IP extraction is duplicated (accepted for now)
`rate_limit.rs::extract_ip` and `auth.rs::extract_client_ip` have slightly different APIs (IpAddr vs String). Consolidation is desirable but not urgent — the duplication is small and the behaviors are intentionally slightly different.

### Deleted user access token window is a stateless JWT tradeoff
Soft-deleted users retain valid access tokens for up to `access_token_ttl_secs` (default 15 min). Adding a DB check on every request would defeat the purpose of stateless JWTs. The mitigation is short access token TTL. This is inherent to JWT-based auth — documented, not a bug.

### Consume-first pattern for tokens and auth codes is intentional
Refresh tokens and authorization codes are atomically consumed (deleted/marked used) before validating binding (client_id, redirect_uri). This prevents TOCTOU races. The "burn" risk requires the attacker to possess the token value, which is already a compromise. Accepted tradeoff.

### Scope revocation not enforced on auth-code exchange (narrow window)
Auth-code exchange uses scopes stored at authorization time. If a scope is revoked between code issuance and exchange (max 10 min), the first access token carries the old scope. Refresh correctly intersects with current allowed_scopes. The window is negligibly narrow.

### Webhook SSRF protection is scheme-level only (admin-only endpoint)
URL scheme validation prevents file://, ftp://, etc. but does not filter private/internal IPs (127.0.0.1, 169.254.x.x, 10.x.x.x). Since only admins can register webhooks and admins have full system access, this is acceptable for v2. DNS resolution + IP filtering is a v3 improvement.

### No periodic cleanup task for expired tokens/codes
`cleanup_expired_tokens` and `cleanup_expired_auth_codes` exist but are never called. Expired tokens/codes accumulate but cannot be used (checked via `expires_at > now()`). A background cleanup task is a v3 item.
