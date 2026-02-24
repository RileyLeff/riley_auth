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

### Session refresh scopes are empty by design (R2, Gemini MAJOR-05 reclassified)
Session tokens (`auth_refresh`) pass `&[]` for scopes to `store_refresh_token`. This is intentional — sessions use role-based access control (admin/user role in JWT), not OAuth scopes. The OAuth provider refresh path preserves and downscopes per RFC 6749 §6, but session auth is a separate mechanism.

### Webhook SSRF check at registration time not required (R2, Claude MINOR-03)
Webhook URLs are validated for scheme at registration but not checked for private IPs. The real SSRF protection runs at delivery time via `SsrfSafeResolver` and `check_url_ip_literal`. Registration-time check is defense-in-depth but not needed — admins who can register webhooks already have elevated access.

### logout-all consumed token recording not needed (R2, Claude MINOR-01)
Per v3 review notes: `delete_all_refresh_tokens` deletes tokens without recording in `consumed_refresh_tokens`. The attacker's token is gone — presenting it fails with "token not found." Family revocation doesn't fire but the attacker gains nothing.

### OAuth authorize returns 401 for unauthenticated (R2, Gemini MINOR-13)
Phase 8 (Consent UI Support) will add proper login redirect support. Current behavior (401 JSON error) is acceptable for first-party auto-approve clients.

### client_secret_basic now supported (SUPERSEDED)
~~Only `client_secret_post` is supported.~~ v5 Phase 2 added `client_secret_basic` support for token, revoke, and introspect endpoints (631bbb0, d5a121a).

## v4 Phase 6 — UserInfo Endpoint

### OIDC protocol-level scopes: openid, profile, email (supersedes initial Phase 6 note)
Initially, `profile` and `email` required config definitions. Phase 6+7 review identified this prevents standard OIDC flows. Now `openid`, `profile`, and `email` are all protocol-level scopes — always accepted without config definitions or `allowed_scopes` checks. Custom/resource scopes still require config. This aligns with the architecture plan §1 which says `scopes_supported: ["openid", "profile", "email"]`.

### WWW-Authenticate header not included on 401 responses
RFC 6750 §3.1 says resource endpoints SHOULD (not MUST) include `WWW-Authenticate: Bearer` on 401 responses. Most OIDC client libraries work without it. Low priority; could be added later as a quality-of-life improvement.

### UserInfo endpoint supersedes Phase 4 note about no /userinfo
The Phase 4 note "UserInfo endpoint is future work" is now resolved. The `/oauth/userinfo` endpoint accepts Bearer tokens from OAuth clients (aud != issuer) and returns claims filtered by scope.

## v4 Phase 7 — Authorize Error Redirects

### 302 Found used for all OAuth redirects (not 307)
RFC 6749 §4.1.2 specifies 302 Found. `Redirect::temporary()` in Axum produces 307. Using explicit `(StatusCode::FOUND, [("location", ...)])` for interoperability.

### User-controlled input in error_description redirect parameter
Scope names from user input appear in `error_description`. URL-encoded by `query_pairs_mut`, preventing direct injection. Client apps are responsible for escaping when rendering. Standard OAuth behavior per RFC 6749 §4.1.2.1.

### Authorize error redirects supersede Phase 4 note
The Phase 4 note "Authorize endpoint errors not redirected to redirect_uri" is now resolved. Pre-redirect errors (invalid client_id/redirect_uri) return HTTP errors; post-redirect errors use `?error=...` redirects per RFC 6749 §4.1.2.1.

## v4 Phase 8 — Consent UI Support

### gen_random_uuid() for consent_id is intentional
Consent IDs are exposed in URLs and must not be guessable from timestamps. UUIDv4 (`gen_random_uuid()`) provides 122 bits of randomness vs UUIDv7's ~62 bits. SQL comment documents the choice.

### logout-all revoking OAuth client tokens is by design
`delete_all_refresh_tokens` deletes all tokens for the user, including OAuth client tokens. This is the intended "nuclear option." Users wanting granular control would use per-session revocation. Flagged as MAJOR by Claude R2; downgraded to NOTE.

### ID token exp coupled to access_token_ttl_secs is acceptable
OIDC only requires `exp` to be present. Using the same TTL as access tokens is a common pattern. A separate `id_token_ttl_secs` could be added later if needed. Flagged as MAJOR by Claude R2; downgraded to NOTE.

### Rate limit tier for /oauth/token (pre-existing)
The token endpoint falls under the `standard` tier (60/min) instead of the `auth` tier (15/min). Could be tightened in a future phase. Not a Phase 8 concern.

### Stuck outbox next_attempt_at check (pre-existing)
`reset_stuck_outbox_entries` checks `next_attempt_at` instead of processing start time. Could cause premature reset for entries that were pending a long time before being claimed. Low probability under normal operation.

### auth_time now tracked and preserved (SUPERSEDED)
~~OIDC Core 1.0 Section 12.2 says refreshed ID tokens SHOULD include `auth_time`. Not currently tracked.~~ v5 Phase 3 added `auth_time` column to `refresh_tokens`, propagated through token rotation, included in ID tokens (eb865d4, 426d3cc, cd01b86).

### PII scrubbing assumes {data} JSON structure (pre-existing)
Webhook payload scrubbing in `soft_delete_user` uses `jsonb_set(payload, '{data}', ...)`. If future event types use a different structure, user data could survive deletion. Event-registry pattern for PII paths would be more robust but adds complexity for the current single-payload-format use case.

### Protocol scopes can't be added to client allowed_scopes via admin API (pre-existing)
`register_client` validates scopes against `config.scopes.definitions`, but protocol scopes (openid, profile, email) are not config-defined. The authorize handler allows them regardless of `allowed_scopes`, so the DB record appears to lack capabilities it actually has. UX improvement for a future phase.

## v5 Phase 1 — JWKS Key Rotation & Algorithm Agility

### validate_aud = false in verify_token is intentional
Different token types have different audience semantics: access tokens for sessions use aud == issuer (enforced by extract_user), OAuth client access tokens use aud == client_id (enforced in oauth_provider.rs), and setup tokens have no aud claim. Audience is enforced at the call site, not in the generic verify_token method.

### Zero leeway on token expiry is intentional
`validation.leeway = 0` in verify_token. More secure than allowing clock skew. Servers should have synchronized clocks.

### JWKS content-type is application/json (not application/jwk-set+json)
Standard `application/json` is accepted by all OIDC clients. The more specific `application/jwk-set+json` is technically more correct per RFC 7517 but not required.

### Linear fallback in verify_token is acceptable for expected key counts
When a token has no kid or unknown kid, all keys are tried sequentially. O(N) for N keys. With 2-3 keys during rotation, this is negligible.

### OpenSSL dependency for key generation is accepted
`generate_keypair_with_algorithm` shells out to openssl. CLI-only setup-time operation. Not reachable via HTTP API. Per v4 review notes.

## v4 Phase 9 — Token Introspection

### Cross-client introspection is intentionally allowed
Any authenticated OAuth client can introspect tokens issued to any other client. This is the resource-server model: backend APIs need to validate tokens regardless of which client obtained them. If per-client isolation were needed, an `aud` check would be added. Flagged as MAJOR by Claude; accepted as intentional design.

### Basic auth credentials now URL-decoded per RFC 6749 §2.3.1 (SUPERSEDED)
~~Client IDs and secrets are server-generated alphanumeric strings that never contain special characters.~~ v5 Phase 2 added `percent_encoding::percent_decode_str()` for full RFC compliance (d5a121a).

### Base64 decode order corrected (SUPERSEDED)
~~URL_SAFE_NO_PAD tried first.~~ v5 Phase 2 corrected to STANDARD first per RFC 7617, URL_SAFE_NO_PAD as fallback (d5a121a).

## v4 Phase 10 — OIDC Back-Channel Logout

### Backchannel logout is fire-and-forget (not outbox-based)
Intentional architecture tradeoff. BCL is time-sensitive (RP should be notified ASAP), so fire-and-forget with in-process retries (1s, 3s, 9s backoff) is used instead of the durable outbox pattern. Not durable across server restarts.

### sid not implemented (backchannel_logout_session_supported: false)
The server does not track session IDs that flow through to logout tokens. Discovery correctly reports `backchannel_logout_session_supported: false`. Registration rejects `backchannel_logout_session_required: true`. All dispatch calls pass `None` for sid.

### /oauth/revoke does not dispatch backchannel logout (intentional)
The client revoking its own token already knows it's invalidated. BCL is for notifying *other* relying parties. No spec requirement for BCL on RFC 7009 revocation.

### Token reuse detection does not dispatch backchannel logout (accepted)
Family revocation is an active-attack response where speed is prioritized. The affected client discovers revocation on its next API call.

### CLI backchannel logout degrades gracefully without JWT keys
`dispatch_backchannel_logout_cli` warns and continues if PEM key files are unavailable. This handles the scenario of CLI running on a management box without signing keys.

### auth_logout ordering relies on session tokens having NULL client_id
`auth_logout` deletes the session token first, then dispatches BCL. This works because session tokens (client_id IS NULL) don't match the BCL query's `rt.client_id = c.id` JOIN. A comment explains the ordering.

## v4 Phase 11 — Multi-Provider Account Merging

### Auto-merge requires BOTH sides to have verified email (R1 fix)
The auto-merge path filters `matching_links` to only verified links (`l.email_verified = true`) before collecting user IDs. This prevents merging into accounts created via unverified email claims from less-trusted providers.

### UserInfo uses per-link email_verified (R2 fix)
The `/oauth/userinfo` endpoint uses the actual `link.email_verified` value from the database instead of hardcoding `true`. Aligns with Phase 11's per-link tracking.

### find_oauth_links_by_email already excludes soft-deleted users
The query JOINs on `users` with `u.deleted_at IS NULL`. No additional fix needed.

## v5 Phase 2 — Token Endpoint Auth: client_secret_basic

### Non-Basic Authorization headers fall through to POST body (intentional)
If the Authorization header uses a non-Basic scheme (e.g., Bearer), `extract_client_credentials` falls through to the POST body fallback. This is pragmatic — rejecting unrecognized schemes would break interop with clients that send both Bearer and POST body credentials on different endpoints.

### URL_SAFE_NO_PAD base64 fallback is intentional
After trying STANDARD base64 per RFC 7617, URL_SAFE_NO_PAD is tried as fallback for non-conformant clients. Harmless — invalid credentials will fail on client lookup regardless.

### No test for percent-encoded Basic auth credentials (accepted)
No integration test exercises the percent-decoding path with actual encoded characters. Client_ids are server-generated plain ASCII slugs, and secrets are random tokens. If user-chosen credentials are ever supported, add a test at that time.

## v5 Phase 3 — OIDC Compliance: auth_time

### auth_time semantics differ between session and OAuth paths (accepted)
`issue_tokens` (session-cookie path) uses `Utc::now()` as auth_time since it runs immediately after OAuth callback. The OAuth token handler uses `auth_code.created_at.timestamp()` (DB server time when the auth code was stored). Both are valid proxies for authentication time. Documented with comments.

### auth_time stored as bigint not timestamptz (intentional)
OIDC requires auth_time as a JSON number (Unix epoch seconds) in ID tokens. Storing as bigint avoids a conversion step. The column is not indexed or queried by timestamp functions, so timestamptz offers no advantage.

### max_age parameter not implemented (Phase 5 scope)
OIDC Core 1.0 Section 3.1.2.1 defines `max_age` which would enforce re-authentication. Phase 5 covers the `prompt` parameter family. The auth_time infrastructure now in place is a prerequisite for max_age support.

### auth_time on session-cookie refresh path is for DB consistency only
`auth_refresh` propagates auth_time to the new refresh token but does not issue ID tokens. The auth_time value is preserved so that if the token is ever used in an OAuth context (it can't be, but architecturally it's correct to preserve), the data is consistent.
