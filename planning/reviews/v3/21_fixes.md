# Fixes for Review Round 20 (Phase 7 Exhaustive R1)

**Commit**: `eb3e09e`

## Major Fixes

**1. [consensus] Webhook delivery PII scrubbing path mismatch**
- Changed SQL from `payload->'data'->>'user_id'` to `payload->>'user_id'` (flat structure)
- Changed SET clause from `jsonb_set(payload, '{data}', ...)` to replacing entire payload with `'{"scrubbed": true}'`
- Fixed integration test to use flat payload matching production `dispatch_event` calls
- Files: `db.rs`, `integration.rs`

## Minor Fixes

**2. Username length: byte count → char count**
- Changed `username.len()` to `username.chars().count()` in `validate_username()`
- Now consistent with `display_name.chars().count()` validation
- File: `auth.rs`

**3. Test cleanup: added webhook_outbox**
- Added `DELETE FROM webhook_outbox` to `clean_database()` before `DELETE FROM webhooks`
- File: `integration.rs`

**4. OAuth consumer HTTP client reuse**
- Added `static OAUTH_CLIENT: LazyLock<reqwest::Client>` with `user_agent("riley-auth")`
- Replaced 3 `reqwest::Client::new()` calls in `exchange_code`, `fetch_profile`, `fetch_github_primary_email`
- Separate from webhook client (no SSRF protection, redirects allowed)
- File: `oauth.rs`

**5. Rate limit headers on 429 responses**
- Added `x-ratelimit-remaining: 0` and `x-ratelimit-limit` to 429 responses
- Consistent with successful response headers
- File: `rate_limit.rs`

## Documented as Notes (no fix needed)

- CSRF on /oauth/authorize: Correct per OAuth 2.0 spec (GET endpoint). PKCE + redirect_uri make exploitation impossible.
- Admin self-deletion: Last-admin protection exists. Design choice.
- IP spoofing via X-Forwarded-For: Documented config requirement.
- Maintenance worker stalling: Acceptable for v3.
- OpenID Discovery: No /userinfo endpoint. Profile claims in ID token.
- Webhook HTTP URLs: Intentional for internal services.
- DNS rebinding: Mitigated by reqwest connection pooling.
- Redis key prefix: Test-only code.
- Consumed token overflow: Theoretical only.
