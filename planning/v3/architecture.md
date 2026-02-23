# v3 Architecture: Hardening & Operational Maturity

v2 built the ecosystem features — scopes, webhooks, sessions, OIDC, cookie branding, rate limiting. v3 hardens what's there and fills the operational gaps that matter at scale. No new user-facing features. This is about making riley_auth the kind of thing you deploy and forget about.

## Theme

Everything in v3 serves one goal: **close the gaps that surface when riley_auth runs in production under real load with real adversaries.** Token reuse detection catches credential theft. Webhook reliability ensures events actually arrive. Tiered rate limiting protects auth endpoints without penalizing reads. Cleanup tasks prevent unbounded storage growth. OIDC compliance removes the asterisks.

No new authentication mechanisms. No new API surface beyond what's needed to operate the existing features more reliably.

---

## 1. Refresh Token Family Tracking

### Problem

When a refresh token is rotated, the old token is atomically deleted. If an attacker steals a refresh token and races the legitimate client, one party gets a new token and the other gets a 401. But there's no signal that the old token was used twice — which is the canonical indicator of token theft (RFC 6819 Section 5.2.2.3).

### Design

**Token families.** Every refresh token belongs to a family — a UUID assigned at initial grant (authorization_code exchange or session login). When a token is rotated, the new token inherits the family ID. If a consumed (already-rotated) token is presented again, it means both the attacker and the legitimate client hold tokens from the same family. Response: **revoke the entire family**.

**Database changes:**

```sql
ALTER TABLE refresh_tokens
  ADD COLUMN family_id uuid NOT NULL DEFAULT gen_random_uuid();

-- Track consumed tokens briefly to detect reuse
CREATE TABLE consumed_refresh_tokens (
  token_hash text PRIMARY KEY,
  family_id uuid NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now()
);

-- Auto-expire consumed token records (only need them for the reuse detection window)
CREATE INDEX idx_consumed_refresh_tokens_consumed_at
  ON consumed_refresh_tokens(consumed_at);
```

**Rotation flow changes:**

1. `consume_refresh_token()` — instead of `DELETE ... RETURNING`, move the token to `consumed_refresh_tokens` (insert hash + family_id + timestamp) and delete from `refresh_tokens`. Single transaction.
2. `store_refresh_token()` — new token inherits `family_id` from the consumed token.
3. If a token hash is found in `consumed_refresh_tokens` (reuse detected), revoke all tokens with that `family_id` and return an error.
4. Cleanup: consumed token records older than 2x the refresh token TTL can be safely pruned (if the attacker hasn't used the stolen token within that window, the family has naturally expired).

**Impact:** This is the single highest-value security improvement in v3. It transforms token theft from "attacker gets permanent access until refresh token expires" to "attacker's first use triggers a full revocation."

---

## 2. Webhook Reliability

### Problem

Webhook dispatch is fire-and-forget via `tokio::spawn`. Events are lost on restart. Under burst load (bulk user imports, mass deletions), unbounded concurrent HTTP requests can saturate outbound connections. There's no way to replay failed deliveries.

### Design

**Persistent outbox.** Events are written to a database table before dispatch. A background worker reads the outbox and delivers. Delivery attempts update the outbox row with status, response code, and next retry time.

```sql
CREATE TABLE webhook_outbox (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  attempts int NOT NULL DEFAULT 0,
  max_attempts int NOT NULL DEFAULT 5,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error text,
  status text NOT NULL DEFAULT 'pending',  -- pending, delivered, failed
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhook_outbox_pending
  ON webhook_outbox(next_attempt_at) WHERE status = 'pending';
```

**Bounded concurrency.** The dispatch worker uses a `tokio::sync::Semaphore` to cap concurrent outbound requests (configurable, default 10). Requests beyond the limit queue behind the semaphore rather than spawning unbounded tasks.

**Exponential backoff.** Retry delays: 10s, 30s, 90s, 270s, 810s (5 attempts over ~20 minutes). After max attempts, mark as `failed`. The existing `webhook_deliveries` table continues to log each attempt for observability.

**Config:**

```toml
[webhooks]
max_concurrent_deliveries = 10
max_retry_attempts = 5
```

**Migration from v2:** The existing `dispatch_event()` call sites change from spawning tasks directly to inserting into the outbox. The background worker is started alongside the server in `serve()`.

---

## 3. Tiered Rate Limiting

### Problem

All endpoints share the same 30req/60s limit. Authentication endpoints (login, token exchange, refresh) are much more sensitive to brute force than read-only endpoints like `/health`, `/.well-known/jwks.json`, or `/oauth/consent`.

### Design

**Three tiers:**

| Tier | Endpoints | Default Limit |
|------|-----------|---------------|
| Auth | `/oauth/token`, `/oauth/authorize`, `/auth/setup`, `/auth/callback/*` | 15 req / 60s |
| Standard | `/auth/*`, `/admin/*`, `/oauth/*` (remaining) | 60 req / 60s |
| Public | `/health`, `/.well-known/*` | 300 req / 60s |

**Config:**

```toml
[rate_limiting]
backend = "redis"

[rate_limiting.tiers]
auth = { requests = 15, window_secs = 60 }
standard = { requests = 60, window_secs = 60 }
public = { requests = 300, window_secs = 60 }
```

**Implementation.** Replace the single `GovernorLayer` with a custom middleware that inspects the request path and applies the appropriate tier's limits. The Redis (or in-memory) store key becomes `rate:{tier}:{ip}`.

**CORS preflight exemption.** OPTIONS requests bypass the rate limiter entirely. They carry no auth credentials and are browser-mandated — rate-limiting them causes CORS failures (the 429 response lacks CORS headers). This fixes the v2 known issue.

---

## 4. OIDC Compliance

### Problem

v2's OIDC support has two spec gaps: no nonce support, and ID tokens are always issued regardless of whether the `openid` scope was requested.

### Design

**Nonce support:**

- `GET /oauth/authorize` accepts an optional `nonce` query parameter
- The nonce is stored alongside the authorization code in the database
- `POST /oauth/token` (authorization_code grant) includes the nonce in the ID token's `nonce` claim
- Add `nonce text` column to `authorization_codes` table

**Conditional ID token issuance:**

- ID tokens are only included in the `/oauth/token` response when the granted scopes include `openid`
- The `openid` scope must be defined in the deployer's config (not hardcoded) and included in the client's `allowed_scopes`
- Refresh token grants include a new ID token only if the original grant included `openid`
- Add `openid` to the example config's scope definitions

**Discovery document updates:**

- Add `userinfo_endpoint` (pointing to `/auth/me`)
- Add `claims_supported`: `["sub", "name", "preferred_username", "picture"]`

---

## 5. Background Cleanup Task

### Problem

Expired authorization codes, consumed refresh tokens, old webhook delivery records, and (with v3) consumed token family records accumulate in the database. They can't be used (checked via `expires_at > now()`), but they consume storage indefinitely.

### Design

**Background worker.** A `tokio::spawn` task that runs on a configurable interval (default: 1 hour). Cleans up:

- Authorization codes where `expires_at < now()`
- Refresh tokens where `expires_at < now()`
- Consumed refresh tokens where `consumed_at < now() - 2 * refresh_token_ttl`
- Webhook delivery records older than a configurable retention period (default: 7 days)
- Failed webhook outbox entries older than retention period

**Config:**

```toml
[maintenance]
cleanup_interval_secs = 3600
webhook_delivery_retention_days = 7
```

**Implementation.** The cleanup functions (`cleanup_expired_tokens`, `cleanup_expired_auth_codes`) already exist in `db.rs` — they just need to be called. Add new cleanup functions for consumed tokens, webhook deliveries, and outbox entries. The worker batches deletes (1000 rows per iteration) to avoid long-running transactions.

---

## 6. Webhook SSRF Hardening

### Problem

Webhook URL validation only checks the scheme (http/https). An admin can register webhooks targeting private IPs (127.0.0.1, 169.254.169.254, 10.x.x.x), and delivery status codes are visible via the deliveries endpoint, creating an SSRF oracle.

### Design

**DNS resolution + IP filtering at delivery time.** Before connecting to a webhook URL, resolve the hostname and reject private/reserved IP ranges:

- 127.0.0.0/8 (loopback)
- 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
- 169.254.0.0/16 (link-local, includes AWS metadata endpoint)
- ::1, fc00::/7 (IPv6 private)

**Implementation.** Use a custom `reqwest` DNS resolver (via `resolve` on the `ClientBuilder`) that checks resolved IPs before connecting. This catches both direct-IP URLs and DNS rebinding (where a hostname resolves to a private IP).

**Config:**

```toml
[webhooks]
allow_private_ips = false  # default; set to true for development
```

---

## 7. Quality-of-Life Fixes

These are small, low-risk improvements that don't warrant their own phase but should be addressed in v3. Bundle them into the implementation as natural fits alongside the larger features.

### 7.1 Cache compiled username regex

The username regex is compiled from config on every call to `validate_username`. Store the compiled `Regex` in `AppState` at startup. Since the pattern is configurable, `LazyLock` doesn't work — but `AppState` initialization runs once and is the right place.

### 7.2 display_name length: chars vs bytes

`display_name.len() > 200` counts bytes. The error message says "characters." Change to `.chars().count()` or change the error message to say "bytes." Since display names can contain emoji and CJK characters, `.chars().count()` is the right fix.

### 7.3 CLI scope validation parity

`register-client` via CLI doesn't validate scope names against config definitions. The admin API endpoint does. Add the same validation to the CLI path.

### 7.4 Consolidate IP extraction

`rate_limit::extract_ip` and `auth::extract_client_ip` have overlapping logic with slightly different APIs (returns `IpAddr` vs `String`). Extract a shared function in `core` that both call.

### 7.5 PII cleanup on soft-delete

Webhook delivery payloads may contain PII (username, user_id) for deleted users. On soft-delete, either scrub delivery payloads for that user or document the retention as a GDPR consideration for deployers.

### 7.6 Validate redirect_uris as URLs

Neither the admin API nor the CLI validates `redirect_uris` as well-formed URLs at client registration time. Bad URIs are only caught at authorize time. Add `url::Url::parse` validation at registration.

---

## Implementation Order

1. **Token Families** — highest security impact, schema change that other features should build on
2. **Webhook Reliability** — outbox pattern replaces fire-and-forget, enables cleanup task
3. **Tiered Rate Limiting** — depends on nothing, but touching the middleware is cleaner before OIDC changes
4. **OIDC Compliance** — nonce + conditional ID token, small surface area
5. **Background Cleanup** — depends on token families (consumed token cleanup) and webhook outbox (outbox cleanup)
6. **SSRF Hardening** — independent, but makes more sense after webhook reliability is in place
7. **QoL Fixes** — bundle throughout as natural fits, or batch at the end

---

## Out of Scope

Still not in v3:

- **Email/password auth** — violates the soul doc
- **MFA/TOTP** — delegated to OAuth providers
- **Built-in frontend/UI** — riley_auth provides APIs, deployer builds UI
- **Entitlements/billing** — identity, not entitlements
- **Database-stored scope definitions** — config-only is working fine; revisit if multi-tenancy becomes a requirement
- **Scope downscoping on refresh** — RFC 6749 allows it, but no real demand
- **Account recovery** — if you lose access to your OAuth providers, that's their problem
