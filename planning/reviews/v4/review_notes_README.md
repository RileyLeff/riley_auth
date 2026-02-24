# Review Notes — v4

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

### generate_keypair shells out to openssl via PATH
CLI-only setup-time operation (the `generate-keys` subcommand). Not reachable via HTTP API. In a compromised environment, a malicious binary could intercept key generation, but this is inherent to any CLI tool. Using a Rust-native RSA library would add a heavyweight dependency for a one-time setup command. Accepted.

### Cookie Secure flag always true
All cookies are set with `Secure = true` unconditionally. This prevents local HTTP development without workarounds, but is the correct default for production. Integration tests work because reqwest ignores the Secure flag. Accepted as safe default.

## Phase 5 — Background Cleanup Task

### Maintenance worker does not run cleanup immediately on startup
Sleep-first pattern is common and acceptable. Expired data waiting another hour after restart is fine.

### Batched delete subquery without FOR UPDATE SKIP LOCKED
Single-worker architecture makes locking unnecessary. Redundant deletes are idempotent.

## Phase 6 — Webhook SSRF Hardening

### TOCTOU in DNS resolver is inherent
The DNS-check-then-connect pattern has a theoretical race window. Exploiting it requires attacker control of authoritative DNS. Standard mitigation for reqwest.

### Webhook URL validation at registration is scheme-only
Only admins can register webhooks. SSRF protection kicks in at delivery time. Adding IP checks at registration would require DNS resolution (fragile).

### Webhook delivery does not follow redirects
Disabled to prevent open-redirect SSRF bypass. Webhook endpoints should return 2xx directly.

### check_url_ip_literal silently succeeds on URL parse failure
If URL can't be parsed, reqwest will also fail. Low risk. Accepted.

## Phase 7 — Exhaustive Review

### Webhook URLs allow plain HTTP
Intentional for internal services when `allow_private_ips` is true. A warning log could be added but is not required.

### X-Forwarded-For trusted proxy list
A `trusted_proxies` config with rightmost-non-trusted extraction would be more robust, but the current leftmost-with-overwrite approach is documented and sufficient for v3.

### Maintenance worker stalling on large backlogs
Cleanup batches are fast (DELETE with LIMIT). The unlikely scenario of millions of records after long downtime doesn't warrant adding shutdown checks inside cleanup loops.

### OpenID Discovery missing userinfo_endpoint
No /userinfo endpoint exists. Profile claims are available via the ID token only. Documented in Phase 4 notes.

### DNS rebinding on SSRF resolver
Mitigated by reqwest's connection pooling — resolved IP is used immediately. Theoretical only.

### Consumed token cleanup overflow
`refresh_token_ttl_secs * 2` as i64 only overflows with absurdly large TTL values (> 146 billion years). Theoretical only.

### Redis rate limiter key prefix (test-only)
`RedisRateLimiter::new()` uses hardcoded "rate_limit" prefix. Only used in unit tests, not in production (which uses `TieredRedisRateLimiter` with per-tier prefixes).

## v4 Phase 5 Milestone — Exhaustive Review R1

### Setup tokens are not single-use (R1, MAJOR-02)
Setup tokens are signed JWTs stored in HttpOnly+Secure cookies with a 15-minute TTL. They are not invalidated server-side after use. The `link_confirm` endpoint requires both a valid session cookie AND a setup token, so exploiting replay requires stealing the entire cookie jar. Adding a `consumed_setup_tokens` table would add DB complexity for minimal security improvement given: HttpOnly+Secure, short TTL, CSRF protection, and dual-auth requirement on link_confirm.

### Client secrets use SHA-256 hashing (R1, MAJOR-04)
Client secrets are 256 bits of random entropy. Brute-force is infeasible regardless of hash function. SHA-256 is appropriate for machine-generated high-entropy secrets.

### Setup token binding removed (R1, MAJOR-01 fix)
The `binding` field in SetupClaims was tautological — computed from profile data inside the JWT, verified against the same data. The JWT signature already prevents tampering. Removed to avoid false sense of security. This supersedes the v3 note "Setup token binding is self-referential (accepted)."

### Nonce preserved on session refresh (R1, MAJOR-03 fix)
Changed `auth_refresh` to pass `token_row.nonce.as_deref()` instead of `None` for consistency with the OAuth provider refresh path. This supersedes the v3 note "Nonce not carried forward on refresh (SHOULD, not MUST)." Both refresh paths now preserve nonces.

### Temp cookie max_age aligned with JWT TTL (R1, MINOR-09 fix)
Setup cookie max_age was 10 minutes while the JWT TTL was 15 minutes. Aligned both to 15 minutes.
