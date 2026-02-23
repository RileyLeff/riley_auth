# Review Notes — v3

Architectural tradeoffs and design decisions documented during review. Future sessions should reference this to avoid re-litigating settled decisions.

## Carried Forward from v2

### Admin self-deletion is allowed
An admin can delete themselves via `DELETE /admin/users/{id}` (as long as another admin exists). By design.

### Silent authorization for auto_approve clients via GET
Standard OAuth behavior. Protection comes from `state` parameter and `redirect_uri` validation.

### OAuth state comparison hardened to constant-time
Belt and suspenders with `subtle::ConstantTimeEq`.

### /oauth/authorize CSRF is standard OAuth behavior (NOT a bug)
The authorize endpoint is always an unauthenticated GET. Protection comes from `state` parameter and `redirect_uri` validation. Auto_approve is for first-party clients only.

### Deleted user access token window is a stateless JWT tradeoff
Soft-deleted users retain valid access tokens for up to `access_token_ttl_secs` (default 15 min). Inherent to JWT-based auth.

### Consume-first pattern for tokens and auth codes is intentional
Atomic consume before validating binding prevents TOCTOU races. The "burn" risk requires the attacker to already possess the token value.

### Scope revocation not enforced on auth-code exchange (narrow window)
Auth-code exchange uses scopes stored at authorization time. Max 10-min window. Refresh correctly intersects with current allowed_scopes.

### Scope definitions are config-only, not database-stored
Intentional. Database-stored scopes are out of scope for v3.

### No scope downscoping on refresh token rotation
RFC 6749 Section 6 allows narrowing. Not supported. Out of scope for v3.

## Phase 1 — Token Family Tracking

### Concurrent same-token race is not a security hole
Two concurrent requests using the same valid (not-yet-consumed) refresh token: only one wins the atomic DELETE, the other gets None. No family revocation triggered because this isn't "reuse" in the RFC 6819 sense — it's two uses of the same not-yet-consumed token. The attacker doesn't get a valid token. This was flagged by Codex and Gemini as major, but Claude's deeper analysis confirmed it's the correct behavior. Accepted.

### In-flight rotation may survive family revocation (vanishingly narrow window)
A request consuming token C could insert a new token D into a family that was just revoked by a concurrent reuse detection of token A. The window requires exact interleaving of: consume C → detect reuse of A → revoke family → insert D. The escaped token D would be caught on the next reuse detection. Fixing this would require wrapping the entire refresh flow in a single database transaction, which is disproportionate to the risk. Accepted.

### Redis limiter is fail-open on backend failure
Security/availability tradeoff. By design.

### unsafe impl Sync for TestServer is acceptable for test-only code
The struct's fields (PgPool, Arc<Keys>, Arc<Config>, SocketAddr, TempDir) are all Send + Sync. The unsafe impl exists because TempDir's Sync bound may be version-dependent. Test-only code; not a production concern.

### Cross-context reuse detection is intentionally global
`check_token_reuse` queries `consumed_refresh_tokens` without a `client_id` filter. This is correct — a replayed consumed token signals credential theft regardless of which endpoint receives the replay. Active token isolation (scoped consume functions) is a different concern from reuse detection. Codex flagged this as a major in Round 3; Claude confirmed it's correct behavior.

### Logout/revoke don't record consumed tokens for reuse detection
When a user logs out or revokes a session, the token is deleted but not recorded in `consumed_refresh_tokens`. A pre-stolen token replayed after logout fails silently (token not found) rather than triggering family revocation. Not a security hole — the attacker is still rejected. Accepted as minor gap.

### delete_all_refresh_tokens is intentionally nuclear
`/auth/logout-all` revokes both session and OAuth client tokens for the user. This is the intended "nuclear option" behavior, not a scoping bug.

## Phase 2 — Webhook Reliability

### Webhook HMAC secrets stored in plaintext (accepted tradeoff)
Unlike OAuth client secrets which are hashed, webhook HMAC signing secrets are stored as plaintext. This is necessary because the secret is used for HMAC computation on every delivery — hashing it would make signing impossible. Envelope encryption (AES-GCM with server-side key) adds significant complexity for marginal benefit given: (1) secrets are admin-created, (2) admin already has DB access. Flagged by Claude as major; accepted as design tradeoff.

### SSRF on webhook URLs is Phase 6 planned work
Webhook URL validation checks scheme only (http/https). Private IP blocking and delivery-time IP validation is explicitly scoped for Phase 6 (Webhook SSRF Hardening). Not a Phase 2 bug.

### Outbox cleanup scheduling is Phase 5 planned work
`cleanup_webhook_outbox` exists but is never called. Periodic cleanup is scoped for Phase 5 (Background Cleanup Task).

### Webhook signing lacks replay protection (accepted for now)
HMAC signature covers payload only, no timestamp in signed content. Industry standard (Stripe, GitHub) includes timestamp + tolerance window. Could be added as a QoL improvement in Phase 7 or future work. Not a security-critical gap since attackers would also need the signing secret to forge.

### dispatch_event_for_client is not currently used with client_id
The `event_client_id` parameter on `dispatch_event_for_client` enables client-scoped webhook delivery but no call site currently passes a non-None client_id. The capability exists for future use (e.g., OAuth token grant events scoped to the requesting client).

## Phase 3 — Tiered Rate Limiting

### X-Forwarded-For leftmost IP is correct with proxy overwrite
The rate limiter takes the first (leftmost) IP from `X-Forwarded-For`. This requires the proxy to *overwrite* (not append to) the header. Documented in `riley_auth.example.toml` with nginx/Cloudflare guidance. The "count from right with trusted proxy count" is another valid approach but unnecessary complexity for this use case.

### Rate limiting fails open when IP extraction fails
Both in-memory and Redis middlewares allow requests through when `extract_ip` returns None. This is unreachable in production (ConnectInfo is always present from `into_make_service_with_connect_info`), but a `tracing::warn!` was added for monitoring in case of misconfigured deployments.

### Fixed-window boundary burst is accepted
Fixed-window counters allow up to 2x burst at window boundaries. Known tradeoff. Sliding window or token bucket would fix this but add complexity disproportionate to the threat model.

### Memory eviction runs every window_secs (2x linger possible)
Expired entries can linger up to 2x window duration before pruning. This is acceptable — under DDoS with many unique IPs, the Redis backend is the recommended path.

### Percent-encoded paths may bypass tier classification
`/auth%2Fgoogle` would not match `/auth/` prefix in `classify_path`. Non-exploitable because Axum would 404 such requests (its router normalizes differently). No code change needed.

### OPTIONS bypass permits unthrottled OPTIONS floods
The OPTIONS bypass is necessary for CORS preflights. Edge/proxy-level generic request limits should backstop this.

## Phase 4 — OIDC Compliance

### UserInfo endpoint is future work
`/auth/me` is session-only (cookies, `aud == issuer`). It cannot serve as an OIDC UserInfo endpoint because it rejects Bearer tokens from OAuth clients. The `userinfo_endpoint` was removed from the discovery document. A proper UserInfo endpoint accepting Bearer tokens with client audiences is future work.

### Setup token binding is self-referential (accepted)
The `binding` field in SetupClaims is computed from profile data inside the same signed JWT. The JWT signature already prevents tampering, so the binding adds no additional security. Keeping it as defense-in-depth, but it's a no-op.

### Nonce not carried forward on refresh (SHOULD, not MUST)
OIDC Core 1.0 Section 12.1 says refreshed ID tokens SHOULD contain the nonce. Currently passes `None` on refresh. This would require a nonce column on `refresh_tokens`. Accepted as minor spec deviation — the nonce is most important on the initial auth code exchange for replay protection.

### Authorize endpoint errors not redirected to redirect_uri
RFC 6749 Section 4.1.2.1 says errors (after validating client_id and redirect_uri) should redirect back with `?error=...`. Currently returns HTTP error responses. All current clients are auto_approve first-party, so this is not blocking. Full error redirect support is future work for third-party consent flows.

### No pagination on list_clients and list_webhooks
Admin-only endpoints with naturally small result sets. Pagination deferred.
