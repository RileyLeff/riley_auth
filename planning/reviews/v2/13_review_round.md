# Review Round 13 — 2026-02-22 (Phase 6 Exhaustive, Round 1)

**Models**: Codex, Gemini, Claude Opus 4.6
**Context**: ~75k tokens (full codebase)

## Major

### 1. [consensus: Codex + Claude] Webhook secrets exposed in list endpoint
**Files**: `admin.rs:321-338`, `admin.rs:406`, `db.rs:921-960`

`WebhookResponse` includes the `secret` field and `list_webhooks` returns it for every webhook. The secret should only be returned at creation time, not in list responses. Any admin can see all HMAC secrets, weakening signature trust.

**Fix**: Omit or mask the secret in list responses; only return at creation.

### 2. [consensus: Codex + Claude] Webhook URL scheme not validated (SSRF risk)
**Files**: `admin.rs:377`, `webhooks.rs:8210-8277`

`register_webhook` only checks URL is non-empty. An admin could register `http://169.254.169.254/latest/meta-data/` or other internal endpoints. `deliver_webhook` POSTs to whatever URL is stored.

**Fix**: Validate URL scheme is `https://` (or `http://` with a config flag for dev). Consider blocking private IP ranges.

### 3. [consensus: Codex + Claude] client_id-scoped webhooks not filtered during dispatch
**Files**: `db.rs:918-988`, `webhooks.rs:61`

`client_id` is accepted and stored at webhook registration but `find_webhooks_for_event` does not filter by it. Client-scoped webhooks receive unrelated events.

**Fix**: When dispatching, pass event context (client_id if applicable) and filter webhooks accordingly.

### 4. [claude-only] Scope downgrade on refresh not prevented
**Files**: `oauth_provider.rs` (refresh_token grant branch)

When processing a refresh_token grant, scopes from the original token are carried forward without checking if the client's current `allowed_scopes` still contain them. If an admin removes a scope after token issuance, refresh silently re-issues with revoked scopes.

**Fix**: Intersect token scopes with client's current allowed_scopes during refresh.

### 5. [claude-only] CLI register-client bypasses scope validation
**Files**: `cli/src/main.rs` (RegisterClient handler)

The admin HTTP endpoint validates scope names via `validate_scope_name()` and checks existence in config. The CLI's RegisterClient passes `--scopes` directly to `db::create_client()` with no validation.

**Fix**: Apply the same validation in the CLI.

## Minor

1. [codex-only] Token/code consumption order allows DoS — auth code consumed before redirect/client validation
2. [consensus: Codex + Claude] Delivery pagination offset parameter ignored in `list_deliveries`
3. [codex-only] Redis `Retry-After` returns fixed window size, not remaining TTL
4. [codex-only] Proxy header docs mention `Forwarded` but only `X-Forwarded-For` and `X-Real-IP` parsed
5. [codex-only] Redis rate-limit 429 response is plain text, inconsistent with JSON error contract
6. [codex-only] `auth_setup` maps any unique-constraint to `UsernameTaken`, masking provider-link conflicts
7. [codex-only] OIDC discovery issuer is non-URL by default (`riley-auth`), may break strict clients
8. [gemini-only] OIDC only lists `client_secret_post`; many libraries default to `client_secret_basic`
9. [consensus: Gemini + Claude] IP extraction logic duplicated between `rate_limit.rs` and `auth.rs`
10. [claude-only] ID token TTL coupled to access_token_ttl_secs — should be independently configurable
11. [claude-only] Discovery missing `userinfo_endpoint` and `claims_supported`
12. [claude-only] ID token always issued regardless of whether `openid` scope was requested
13. [claude-only] Webhook retry backoff too short (500ms, 1s, 2s)
14. [claude-only] Webhook delivery records only final attempt, not individual retries
15. [claude-only] Webhook signature header missing `sha256=` algorithm prefix
16. [claude-only] No admin endpoint to disable/re-enable webhooks (only create/delete)
17. [claude-only] Cookie prefix not validated for RFC 6265 safe characters
18. [claude-only] Redis Lua script edge case: key without TTL from crash would increment forever
19. [claude-only] Redis key prefix hardcoded to "rate_limit" — should be configurable
20. [claude-only] Regex compiled on every `validate_username` call
21. [claude-only] CORS preflight (OPTIONS) may hit rate limiter, returning 429 without CORS headers
22. [claude-only] `test-integration.sh` does not run Redis rate limit tests
23. [claude-only] Redis rate limiter hardcodes burst_size=30, window_secs=60 — should use config

## Notes

1. [codex-only] CORS defaults to permissive when origins empty (warned in logs)
2. [consensus: all 3] Webhook dispatch fire-and-forget loses events on restart — known v2 architectural tradeoff, documented
3. [codex-only] Test uses `unsafe impl Sync for TestServer` — likely avoidable
4. [claude-only] No per-scope enforcement middleware (expected for v2 — scopes are issued, enforcement is downstream)
5. [gemini-only] CLI depends on `openssl` system binary for key generation
6. [claude-only] Authorization codes marked used but not deleted (cleaned by TTL, fine)
7. [claude-only] No Redis health check in /health endpoint

## Notes on Codex CSRF Finding

Codex flagged `/oauth/authorize` as CSRF-vulnerable with `auto_approve=true`. This is standard OAuth behavior — the authorize endpoint is always a GET accessible cross-site. Protection comes from the `state` parameter (CSRF token) and `redirect_uri` validation, not from server-side CSRF headers. The `auto_approve` flag is for first-party clients only. **Not a bug — OAuth working as designed.**

## Test Coverage Gaps

1. No test for client_id webhook scoping semantics
2. No test for webhook secret redaction in list
3. No Redis middleware-level HTTP integration tests
4. No cookie prefix end-to-end HTTP test
5. No regression test for token/code burn ordering
6. No test for scope downgrade on refresh after client scope change
7. No OIDC nonce round-trip test (nonce not implemented)
