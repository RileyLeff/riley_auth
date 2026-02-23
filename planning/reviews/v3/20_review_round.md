# Review Round 20 — Phase 7 Exhaustive R1 (2026-02-23)

**Models**: Gemini, Claude (Opus 4.6)
**Context**: ~100k tokens (full codebase)
**Scope**: Exhaustive review of entire v3 codebase (all 7 phases)

## Findings

### Major

**1. [consensus: Claude + Gemini] Webhook delivery PII scrubbing uses wrong JSON path**
- **File**: `crates/riley-auth-core/src/db.rs` — `soft_delete_user()`
- **Description**: The scrub query uses `payload->'data'->>'user_id'` but actual webhook payloads dispatched by all `dispatch_event` call sites are flat: `{"user_id": "...", "username": "..."}` — no `"data"` nesting. The WHERE clause never matches, so PII is never actually scrubbed from webhook delivery records after account deletion.
- **Test masking**: The integration test `soft_delete_scrubs_webhook_delivery_payloads` passes because it manually inserts a payload WITH a `"data"` wrapper, which doesn't match the production payload structure.
- **Fix**: Change query to `WHERE payload->>'user_id' = $1::text` and `SET payload = '{"scrubbed": true}'::jsonb`. Fix the test to use flat payload matching production.

### Minor

**2. [claude-only] Username length validation uses byte count**
- **File**: `crates/riley-auth-api/src/routes/auth.rs` — `validate_username()`
- Uses `.len()` (bytes) instead of `.chars().count()`. Only matters if operator customizes regex to allow Unicode usernames. Display name validation correctly uses `.chars().count()`.
- **Fix**: Change to `.chars().count()` for consistency.

**3. [claude-only] Missing webhook_outbox in test cleanup**
- **File**: `crates/riley-auth-api/tests/integration.rs` — `clean_database()`
- The `webhook_outbox` table isn't cleaned. CASCADE from `webhooks` handles most cases but orphaned entries could accumulate.
- **Fix**: Add `DELETE FROM webhook_outbox` before `DELETE FROM webhooks`.

**4. [claude-only] OAuth consumer creates new HTTP client per request**
- **File**: `crates/riley-auth-core/src/oauth.rs`
- `exchange_code`, `fetch_profile`, `fetch_github_primary_email` each create a new `reqwest::Client`, losing connection pooling benefits.
- **Fix**: Pass `http_client` from AppState through to OAuth consumer functions.

**5. [claude-only] Missing rate limit headers on 429 responses**
- **File**: `crates/riley-auth-api/src/rate_limit.rs`
- 429 responses include `retry-after` but not `x-ratelimit-limit` or `x-ratelimit-remaining`. Successful responses include both.
- **Fix**: Add `x-ratelimit-limit` and `x-ratelimit-remaining: 0` to 429 responses.

**6. [gemini-only] IP Spoofing Risk via X-Forwarded-For**
- **File**: `crates/riley-auth-api/src/routes/mod.rs` — `extract_client_ip()`
- Trusts first entry of X-Forwarded-For when `behind_proxy` is true. If proxy appends (vs overwrites), client can spoof.
- **Assessment**: Documented requirement in config. A `trusted_proxies` list would be more robust but is out of scope for v3.

**7. [gemini-only] Maintenance worker stalling on large backlogs**
- **File**: `crates/riley-auth-api/src/server.rs` — `maintenance_worker()`
- Cleanup loops continue until `affected < 1000` without checking shutdown receiver.
- **Assessment**: Acceptable for v3 — cleanup batches are fast and the scenario (millions of records after long downtime) is unusual.

**8. [claude-only] OpenID Discovery missing userinfo_endpoint and standard claims**
- **File**: `crates/riley-auth-api/src/routes/mod.rs`
- Discovery document doesn't include `userinfo_endpoint` or standard OIDC claims in `claims_supported`.
- **Assessment**: No /userinfo endpoint exists. Document as intentional — profile claims are in the ID token.

**9. [claude-only] Webhook URLs allow plain HTTP without restriction**
- **File**: `crates/riley-auth-api/src/routes/admin.rs`
- Unlike redirect_uri validation, webhook URLs allow HTTP to any host. Payloads could transmit in cleartext.
- **Assessment**: Intentional for internal services when `allow_private_ips` is true. A warning log would be nice but not required.

### Notes

**10. [claude-only] CSRF on /oauth/authorize (GET)**
- OAuth spec requires GET for authorization endpoint. CSRF middleware only checks non-safe methods. PKCE + redirect_uri validation make exploitation impossible. This is correct behavior per OAuth 2.0.

**11. [claude-only] Admin self-deletion/demotion**
- Last-admin protection exists. Self-service delete has the same guard. This is an operational UX choice, not a bug.

**12. [gemini-only] Atomic token rotation gap**
- Race between `check_token_reuse` and `consume_session_refresh_token` could produce `InvalidToken` instead of family revocation. Safe failure mode — doesn't bypass security.

**13. [gemini-only] SSRF DNS rebinding**
- SsrfSafeResolver doesn't account for DNS rebinding (TTL 0 → public→private switch). Mitigated by reqwest's connection pooling using resolved IP immediately.

**14. [claude-only] Redis key prefix collision (test-only)**
- `RedisRateLimiter::new()` uses hardcoded "rate_limit" prefix. Only used in tests, not production.

**15. [claude-only] Consumed token cleanup overflow (theoretical)**
- `refresh_token_ttl_secs * 2` cast as i64 could overflow with absurdly large TTL values. Default is safe.

### Test Coverage Gaps

- No concurrent token rotation test (race condition)
- No username change cooldown enforcement test
- No webhook client_id scoping test
- No CORS header behavior test
