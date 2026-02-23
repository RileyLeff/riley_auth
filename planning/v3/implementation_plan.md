# v3 Implementation Plan

## Phase 1: Refresh Token Family Tracking

### Step 1.1: Database Migration — Family Tracking
- Add `family_id uuid NOT NULL DEFAULT gen_random_uuid()` to `refresh_tokens`
- Create `consumed_refresh_tokens` table: `token_hash text PK`, `family_id uuid`, `consumed_at timestamptz`
- Index on `consumed_at` for cleanup
- Migration file: `005_token_families.sql`

### Step 1.2: Core — Token Rotation with Reuse Detection
- Modify `consume_refresh_token()`: move consumed token to `consumed_refresh_tokens` (hash + family_id), delete from `refresh_tokens`, return row including `family_id`
- Modify `store_refresh_token()`: accept `family_id`, propagate from consumed token
- New `check_token_reuse()`: given a token hash, check `consumed_refresh_tokens` — if found, revoke all tokens with that `family_id` and return an error
- New `revoke_token_family()`: `DELETE FROM refresh_tokens WHERE family_id = $1`

### Step 1.3: API — Wire Up Reuse Detection
- `auth_refresh` in `auth.rs`: before consuming, check if the token hash exists in `consumed_refresh_tokens` — if so, revoke family and return 401
- On successful rotation, pass `family_id` to `store_refresh_token()`
- `issue_tokens()` for initial login: generate a new `family_id` (new session = new family)

### Step 1.4: Tests — Token Families
- Unit test: consume moves token to consumed table with family_id
- Integration test: normal rotation works, family_id propagates
- Integration test: presenting a consumed token triggers family revocation
- Integration test: after family revocation, all tokens in the family are invalid

---

## Phase 2: Webhook Reliability

### Step 2.1: Database Migration — Outbox
- Create `webhook_outbox` table: id, webhook_id (FK), event_type, payload (jsonb), attempts, max_attempts, next_attempt_at, last_error, status, created_at
- Partial index on `next_attempt_at WHERE status = 'pending'`
- Migration file: `006_webhook_outbox.sql`

### Step 2.2: Config — Webhook Tuning
- Add `[webhooks]` config section: `max_concurrent_deliveries` (default 10), `max_retry_attempts` (default 5)
- Parse and thread through AppState

### Step 2.3: Core — Outbox Writer
- Replace `dispatch_event()` fire-and-forget with outbox insert
- `enqueue_webhook_event()`: find matching webhooks, insert one outbox row per webhook
- Keep the function signature compatible (db pool, event_type, payload)

### Step 2.4: Core — Delivery Worker
- Background task started in `serve()`: polls outbox for pending deliveries where `next_attempt_at <= now()`
- Uses `tokio::sync::Semaphore` for bounded concurrency
- On success: update outbox status to `delivered`, record in `webhook_deliveries`
- On failure: increment attempts, set `next_attempt_at` with exponential backoff (10s, 30s, 90s, 270s, 810s), record in `webhook_deliveries`
- After max attempts: mark as `failed`

### Step 2.5: Tests — Webhook Reliability
- Integration test: event enqueued in outbox after dispatch
- Integration test: worker delivers successfully and marks delivered
- Integration test: failed delivery retries with backoff
- Integration test: max attempts exceeded marks as failed
- Unit test: semaphore limits concurrent deliveries

---

## Phase 3: Tiered Rate Limiting

### Step 3.1: Config — Rate Limit Tiers
- Add `[rate_limiting.tiers]` config: `auth`, `standard`, `public` each with `requests` and `window_secs`
- Defaults: auth=15/60, standard=60/60, public=300/60

### Step 3.2: Middleware — Tiered Rate Limiter
- Replace single `GovernorLayer` with custom middleware that classifies request path → tier
- Tier classification: `/oauth/token`, `/oauth/authorize`, `/auth/setup`, `/auth/callback/*` → auth; `/health`, `/.well-known/*` → public; everything else → standard
- Each tier has its own rate limiter instance (Redis or in-memory)
- Redis keys: `rate:{tier}:{ip}`

### Step 3.3: CORS Preflight Exemption
- OPTIONS requests bypass rate limiting entirely
- Implement as an early return in the rate limit middleware before checking limits

### Step 3.4: Tests — Tiered Rate Limiting
- Unit test: path classification returns correct tier
- Integration test: auth endpoint rate-limited at lower threshold
- Integration test: public endpoint allows higher traffic
- Integration test: OPTIONS requests are never rate-limited

---

## Phase 4: OIDC Compliance

### Step 4.1: Database Migration — Nonce Column
- Add `nonce text` to `authorization_codes`
- Migration file: `007_oidc_nonce.sql`

### Step 4.2: Nonce Support
- `GET /oauth/authorize`: accept optional `nonce` query parameter, store in authorization code
- `store_authorization_code()`: accept optional nonce
- `consume_authorization_code()`: return nonce
- `POST /oauth/token` (authorization_code): include nonce in ID token if present

### Step 4.3: Conditional ID Token Issuance
- Only include `id_token` in token response when granted scopes include `openid`
- Check scopes on both authorization_code and refresh_token grants
- Add `openid` to example config scope definitions with description

### Step 4.4: Discovery Document Updates
- Add `userinfo_endpoint` → `{public_url}/auth/me`
- Add `claims_supported` → `["sub", "name", "preferred_username", "picture"]`

### Step 4.5: Tests — OIDC
- Integration test: nonce round-trip (authorize → token → id_token contains nonce)
- Integration test: no id_token when openid scope not requested
- Integration test: discovery document includes userinfo_endpoint and claims_supported
- Integration test: authorize rejects nonce without openid scope (or accepts — decide on behavior)

---

## Phase 5: Background Cleanup Task

### Step 5.1: Config — Maintenance
- Add `[maintenance]` config section: `cleanup_interval_secs` (default 3600), `webhook_delivery_retention_days` (default 7)

### Step 5.2: Cleanup Functions
- `cleanup_consumed_refresh_tokens()`: delete where `consumed_at < now() - 2 * refresh_token_ttl`
- `cleanup_webhook_deliveries()`: delete where `attempted_at < now() - retention_days`
- `cleanup_webhook_outbox()`: delete where `status = 'failed' AND created_at < now() - retention_days`
- All use batched deletes (LIMIT 1000 per iteration) to avoid long locks

### Step 5.3: Background Worker
- Spawned in `serve()` alongside the webhook delivery worker
- Runs on configurable interval
- Calls existing `cleanup_expired_tokens()`, `cleanup_expired_auth_codes()`, plus new functions
- Logs cleanup counts at info level

### Step 5.4: Tests — Cleanup
- Unit test: cleanup functions delete correct records and leave unexpired ones
- Integration test: worker runs and cleans up expired data

---

## Phase 6: Webhook SSRF Hardening

### Step 6.1: Config — Private IP Policy
- Add `allow_private_ips` to `[webhooks]` config (default false)

### Step 6.2: Custom DNS Resolver
- Implement a `reqwest` `resolve` callback that checks resolved IPs against private ranges before connecting
- Block: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1, fc00::/7
- Use `std::net::IpAddr::is_loopback()`, `is_private()`, `is_link_local()` where available, manual checks for remaining ranges
- Skip filtering when `allow_private_ips = true`

### Step 6.3: Integration into Delivery Worker
- Apply the custom resolver to the `reqwest::Client` used by the webhook delivery worker
- On blocked IP: record delivery failure with descriptive error ("webhook URL resolved to private IP")

### Step 6.4: Tests — SSRF
- Unit test: resolver blocks private IPs, allows public IPs
- Integration test: webhook delivery to localhost-resolving URL fails with SSRF error
- Integration test: `allow_private_ips = true` permits localhost delivery

---

## Phase 7: Quality-of-Life Fixes

### Step 7.1: Cache Compiled Username Regex
- Compile the username regex once during `AppState` initialization
- Store `regex::Regex` in `AppState`
- `validate_username()` accepts the compiled regex instead of recompiling from config

### Step 7.2: display_name Length — Chars Not Bytes
- Change `display_name.len() > 200` to `display_name.chars().count() > 200`
- Same for any similar byte-counting length checks

### Step 7.3: CLI Scope Validation
- `register-client` CLI command validates scope names against config definitions
- Matches the admin API endpoint's validation logic

### Step 7.4: Consolidate IP Extraction
- Extract shared `extract_client_ip()` in `riley-auth-core`
- Both `rate_limit.rs` and `auth.rs` call the shared function
- Return type accommodates both use cases (IpAddr with .to_string() at call site)

### Step 7.5: PII Scrubbing on Soft-Delete
- On `soft_delete_user()`, scrub webhook delivery payloads containing the deleted user's ID
- `UPDATE webhook_deliveries SET payload = '{"scrubbed": true}' WHERE payload->>'user_id' = $1`

### Step 7.6: Validate redirect_uris at Registration
- Add `url::Url::parse` validation to `POST /admin/clients` for each redirect_uri
- Add matching validation to CLI `register-client`
- Reject non-http(s) schemes

### Step 7.7: Tests — QoL
- Unit test: compiled regex in AppState works
- Unit test: display_name length with multi-byte characters
- Integration test: CLI rejects invalid scopes
- Integration test: redirect_uri validation at registration

---

## Review Checkpoints

- Exhaustive review after Phase 1 (token families — security-critical schema change)
- Exhaustive review after Phase 4 (OIDC — completes spec compliance)
- Exhaustive review after Phase 7 (final — full v3)

---

## On Completion

When v3 is complete (Phase 7 review converged), **send a Slack notification and stop working.** Do not begin work on any other project, plan, or directory — even if an unfinished plan exists elsewhere in the workspace (e.g., the website repo). Just notify the user that v3 is done and wait for further instructions.
