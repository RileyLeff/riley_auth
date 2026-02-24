# v5 Architecture: Key Infrastructure, OIDC Polish & Production Readiness

v4 completed the OAuth provider story — consent flows, token introspection, back-channel logout, multi-provider account merging. riley_auth now works as a full identity provider for third-party clients. v5 hardens the cryptographic foundation, closes the remaining OIDC spec gaps, adds the `prompt` parameter for SPA-style silent auth, and validates everything against the official OIDC conformance suite.

## Theme

**Make riley_auth's cryptographic and operational foundations production-grade for third-party deployments, and prove it with conformance testing.** v4 got the protocols right; v5 gets the keys, the error contracts, and the operator experience right — then runs the official test suite to verify.

---

## 1. JWKS Key Rotation & Algorithm Agility

### Problem

riley_auth hardcodes RS256 everywhere — a single 2048-bit RSA key pair loaded at startup. There is no way to rotate keys without downtime, no way to add a second key for graceful rollover, and no way for deployers to choose a different algorithm. The JWKS endpoint serves exactly one key.

This is the biggest gap for production deployments:
- **No rotation** means a compromised key requires immediate server restart with no overlap period. Downstream apps caching the old JWKS will reject all tokens until they refresh.
- **RS256-only** means deployers who want ES256 (faster, smaller tokens, standard in mobile/IoT) have no option.
- **2048-bit default** is adequate today but deployers should be able to choose 4096-bit RSA or P-256 ECDSA.

### Design

**Multi-key JWKS with configurable algorithms and graceful rotation.**

**Config:**
```toml
[jwt]
issuer = "https://auth.example.com"
access_token_ttl_secs = 900
refresh_token_ttl_secs = 2592000
authorization_code_ttl_secs = 300

# Signing keys — ordered list, first entry is the active signing key.
# Previous keys remain in the JWKS for verification during rotation.
[[jwt.keys]]
algorithm = "ES256"              # or "RS256"
private_key_path = "keys/current.pem"
public_key_path = "keys/current.pub.pem"
kid = "2025-02"                  # optional, auto-computed from key if omitted

[[jwt.keys]]
algorithm = "ES256"
private_key_path = "keys/previous.pem"
public_key_path = "keys/previous.pub.pem"
kid = "2025-01"
```

**Key rules:**
1. The **first** key in the list is the active signing key. All new tokens are signed with it.
2. All keys in the list are served in the JWKS endpoint and available for verification.
3. To rotate: generate a new key, prepend it to the list, restart. Old tokens verify against the old key until they expire. After one full `refresh_token_ttl_secs` window, remove the old key entry.
4. Mixed algorithms are supported — you can rotate from RS256 to ES256 by prepending an ES256 key.

**Code changes:**

`jwt.rs` — `Keys` struct becomes `KeySet`:
- Stores a `Vec<KeyEntry>` where each entry has algorithm, encoding key, decoding key, kid, and JWKS parameters.
- `sign_*` methods use `keys[0]` (active key).
- `verify_*` methods try all keys, matching on `kid` from the JWT header first (O(1) lookup via HashMap), falling back to trying all keys if `kid` is missing.
- `jwks()` returns all keys.

`config.rs` — `JwtConfig` changes:
- Replace `private_key_path` / `public_key_path` with `keys: Vec<KeyConfig>`.
- `KeyConfig` has `algorithm`, `private_key_path`, `public_key_path`, optional `kid`.
- Validation: at least one key required, first key must have a private key.
- Backward compat: if the old flat `private_key_path`/`public_key_path` fields are present (no `[[jwt.keys]]` array), treat them as a single RS256 key entry. This avoids breaking existing deployments.

**Algorithm support:**
- RS256 (RSA PKCS#1 v1.5 with SHA-256) — existing
- ES256 (ECDSA with P-256 and SHA-256) — new

Both are supported by the `jsonwebtoken` crate. ES256 keys use standard PEM format (`EC PRIVATE KEY` / `PUBLIC KEY`).

**Key generation CLI:**
```
riley-auth generate-keys --algorithm es256 --output-dir ./keys
riley-auth generate-keys --algorithm rs256 --key-size 4096 --output-dir ./keys
```

Default algorithm: ES256 (modern, fast, small tokens).

**JWKS endpoint changes:**
- Returns all keys from the key set
- ES256 keys use `kty: "EC"`, `crv: "P-256"`, `x`, `y` parameters
- RS256 keys use existing `kty: "RSA"`, `n`, `e` parameters

**Discovery document:**
- `id_token_signing_alg_values_supported` becomes dynamic, populated from the configured key algorithms

**ASN.1 parsing:**
- The existing manual DER parser for RSA components stays for RSA keys
- Add a similar EC point extractor for P-256 keys (extract x, y coordinates from the SubjectPublicKeyInfo)
- Alternatively, consider adding the `p256` crate for EC key parsing — it's lightweight and more robust than manual ASN.1

---

## 2. Token Endpoint Auth: client_secret_basic

### Problem

The token endpoint only supports `client_secret_post` (credentials in the POST body). RFC 6749 Section 2.3.1 defines `client_secret_basic` (HTTP Basic auth) as the default method, and many OAuth client libraries use it by default. The introspection endpoint already supports both methods, but the token endpoint does not.

Third-party developers integrating against riley_auth will hit auth failures if their library defaults to Basic auth.

### Design

**Add `client_secret_basic` support to the token endpoint.**

The introspection endpoint already has `extract_client_credentials()` that handles both methods. Refactor the token endpoint to use the same extraction logic.

**Token endpoint change:**
- Currently reads `client_id` and `client_secret` from the form body only
- Change to: try `Authorization: Basic` header first, fall back to form body
- If both are present, use the header (per RFC 6749 §2.3.1: "The authorization server MUST support the HTTP Basic authentication scheme")

**Discovery document update:**
```json
"token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
```

**Revocation endpoint too:**
- `/oauth/revoke` also requires client credentials — apply the same extraction

---

## 3. OIDC Compliance: auth_time Claim

### Problem

OIDC Core 1.0 Section 2 specifies the `auth_time` claim — the time when the end-user authentication occurred. Section 12.2 says refreshed ID tokens SHOULD include `auth_time`. riley_auth does not track or include this claim.

This matters for third-party clients that need to enforce authentication recency (e.g., "user must have authenticated within the last 5 minutes for this action").

### Design

**Track auth_time and include it in ID tokens.**

**Database change:**
```sql
ALTER TABLE refresh_tokens ADD COLUMN auth_time bigint;
```

Stores the Unix timestamp of the original authentication event (when the user completed OAuth callback and the session/auth code was created).

**Flow changes:**
1. `auth_callback`: when creating a session, record `auth_time = now()` on the refresh token
2. `oauth_token` (auth_code exchange): when creating the OAuth refresh token, copy `auth_time` from the auth code's creation time
3. `oauth_token` (refresh): propagate `auth_time` from the consumed token to the new token
4. `sign_id_token`: accept `auth_time` parameter, include in claims when present

**ID token claims change:**
```rust
pub struct IdTokenClaims {
    // ... existing fields ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
}
```

**Discovery document update:**
```json
"claims_supported": ["sub", "name", "preferred_username", "picture", "email", "email_verified", "updated_at", "auth_time"]
```

---

## 4. WWW-Authenticate Headers on Bearer Token Errors

### Problem

RFC 6750 Section 3 requires that when a protected resource request fails, the response includes a `WWW-Authenticate` header with the `Bearer` scheme. This tells client libraries how to authenticate and what went wrong. riley_auth's protected endpoints (UserInfo, introspection, resource endpoints) return plain 401/403 without this header.

Most client libraries will work without it, but it's a spec requirement and aids debugging for third-party integrators.

### Design

**Add `WWW-Authenticate: Bearer` headers to all Bearer-token-protected endpoint error responses.**

**Responses per RFC 6750 §3.1:**

| Scenario | Status | Header |
|----------|--------|--------|
| No token provided | 401 | `WWW-Authenticate: Bearer realm="{issuer}"` |
| Token expired | 401 | `WWW-Authenticate: Bearer realm="{issuer}", error="invalid_token", error_description="token expired"` |
| Token invalid/malformed | 401 | `WWW-Authenticate: Bearer realm="{issuer}", error="invalid_token"` |
| Insufficient scope | 403 | `WWW-Authenticate: Bearer realm="{issuer}", error="insufficient_scope", scope="profile email"` |

**Implementation:**
- Add a `BearerError` enum in `error.rs` with variants: `InvalidToken`, `ExpiredToken`, `InsufficientScope(String)`
- Add a helper `www_authenticate_header(issuer: &str, error: Option<BearerError>) -> String`
- Apply to: `/oauth/userinfo`, `/oauth/introspect` (on token validation failure, not client auth failure), and any future resource endpoints

**Affected endpoints:**
- `userinfo`: currently returns `InvalidToken` error → add `WWW-Authenticate`
- `introspect`: client auth failures stay as 401 without Bearer (they use Basic/Post auth, not Bearer)

---

## 5. Codebase Organization

### Problem

Several files have grown large enough to hurt navigability:
- `integration.rs`: ~5,920 lines (all integration tests in one file)
- `db.rs`: ~1,601 lines (all database queries)
- `auth.rs`: ~1,188 lines (all auth consumer routes)
- `oauth_provider.rs`: ~1,070 lines (all OAuth provider routes)

This is a maintainability concern, not a functional one. But for a library that external deployers will need to understand and potentially contribute to, discoverability matters.

### Design

**Split along natural domain boundaries. No behavior changes.**

**`integration.rs` → `tests/` directory:**
```
tests/
  common/mod.rs           # TestServer, helpers, setup/teardown
  auth_tests.rs           # OAuth consumer callback, login, logout, sessions
  admin_tests.rs          # User management, role changes, soft-delete
  oauth_provider_tests.rs # Authorize, token, refresh, revoke, introspect
  consent_tests.rs        # Consent flow tests
  userinfo_tests.rs       # UserInfo endpoint tests
  webhook_tests.rs        # Webhook dispatch, outbox, SSRF
  merge_tests.rs          # Account merging tests
  backchannel_tests.rs    # Back-channel logout tests
  rate_limit_tests.rs     # Rate limiting tests
```

**`db.rs` → `db/` module:**
```
db/
  mod.rs                  # Re-exports, shared types
  users.rs                # User CRUD, soft-delete, PII scrubbing
  oauth_links.rs          # OAuth link management
  sessions.rs             # Refresh tokens, auth codes, session queries
  clients.rs              # OAuth client registration, lookup
  webhooks.rs             # Webhook endpoints, outbox, deliveries
  consent.rs              # Consent record management
```

**`auth.rs` and `oauth_provider.rs`** — leave as-is for now. At ~1,100 lines each, they're at the threshold but still navigable. If v5 implementation grows them significantly, split then.

---

## 6. Observability

### Problem

riley_auth has `tracing` throughout but no metrics endpoint. Production deployments need to monitor: request rates, token issuance/verification counts, error rates, webhook delivery success/failure, rate limit hits, and key rotation status. Without metrics, operators are flying blind.

### Design

**Prometheus-compatible metrics endpoint.**

**New endpoint:** `GET /metrics`

Returns Prometheus text format. Not behind CSRF middleware (monitoring systems need direct access). Optionally behind a bearer token for security.

**Config:**
```toml
[metrics]
enabled = true
# Optional bearer token to protect the metrics endpoint.
# If unset, the endpoint is unauthenticated (suitable for internal-only access).
# bearer_token = "env:METRICS_TOKEN"
```

**Metrics to expose:**

| Metric | Type | Labels |
|--------|------|--------|
| `riley_auth_http_requests_total` | Counter | `method`, `path`, `status` |
| `riley_auth_http_request_duration_seconds` | Histogram | `method`, `path` |
| `riley_auth_tokens_issued_total` | Counter | `type` (access, refresh, id) |
| `riley_auth_token_verifications_total` | Counter | `result` (ok, expired, invalid) |
| `riley_auth_webhook_deliveries_total` | Counter | `status` (success, failed) |
| `riley_auth_rate_limit_hits_total` | Counter | `tier` |
| `riley_auth_active_sessions` | Gauge | |
| `riley_auth_signing_key_age_seconds` | Gauge | `kid` |

**Implementation:**
- Use the `metrics` crate (facade) with `metrics-exporter-prometheus` for the endpoint
- Add an Axum middleware layer that records request count and duration
- Sprinkle counter increments at token issuance/verification/webhook delivery points
- Key age is computed from the kid (if using date-based kids) or from file mtime

---

## 7. Production Defaults & Deployment Polish

### Problem

Several small gaps that don't warrant their own phases but matter for production:

1. **Key generation defaults to 2048-bit RSA** — modern recommendation is ES256 or 4096-bit RSA
2. **No CORS configuration** — third-party browser-based clients need CORS headers on the token and userinfo endpoints
3. **No `Cache-Control` on JWKS** — clients don't know how long to cache, leading to excessive fetching or stale keys during rotation

### Design

**7a. Key generation defaults (covered by Phase 1)**
- Default algorithm: ES256
- Default RSA key size: 4096 (when RSA is explicitly chosen)

**7b. CORS configuration:**

```toml
[server]
# CORS origins for browser-based OAuth clients.
# Applies to /oauth/token, /oauth/userinfo, /oauth/revoke, /oauth/introspect.
# Use ["*"] to allow all origins (not recommended for production).
# cors_origins = ["https://app1.example.com", "https://app2.example.com"]
```

When configured, add CORS headers (via `tower-http`'s `CorsLayer`) to the OAuth protocol endpoints. Discovery and JWKS endpoints already need to be publicly accessible and don't require CORS (they're GET-only, no custom headers).

**7c. JWKS Cache-Control:**

Add `Cache-Control: public, max-age=3600` to the JWKS endpoint response. During key rotation, deployers can lower this via config:

```toml
[jwt]
jwks_cache_max_age_secs = 3600  # default
```

---

## 8. Authorize `prompt` Parameter

### Problem

OIDC Core 1.0 Section 3.1.2.1 defines the `prompt` parameter on the authorization endpoint. It controls whether the OP forces re-authentication, forces consent, or silently checks for an existing session. riley_auth's `/oauth/authorize` ignores this parameter entirely.

This matters for third-party clients in two key scenarios:
- **`prompt=none`** (silent auth check): SPAs use this for silent token renewal — open a hidden iframe to `/oauth/authorize?prompt=none&...`, and if the user has a valid session, get tokens back without any user interaction. If no session exists, the OP must return `error=login_required` via redirect instead of showing a login page. Without this, SPAs must do full visible redirect flows for every renewal.
- **`prompt=login`** (forced re-auth): Security-sensitive actions (changing password delegations, linking a new provider) may require the user to prove they're present right now, not just riding a cached session.
- **`prompt=consent`** (forced consent): Re-prompt consent even if the user previously approved this client+scope combination. Useful when scope changes.

### Design

**Support `prompt=none`, `prompt=login`, and `prompt=consent` on `/oauth/authorize`.**

**`prompt=none` (silent auth):**
1. If the user has a valid session cookie → proceed with authorization silently (no UI redirects)
2. If auto_approve client and session exists → issue code, redirect to `redirect_uri`
3. If no session → redirect to `redirect_uri` with `?error=login_required`
4. If consent required (non-auto-approve, no prior consent) → redirect with `?error=consent_required`
5. Never redirect to login page or consent URL

This is the critical path for SPA silent renewal. The key property is: `prompt=none` must never show UI or redirect to anything other than the `redirect_uri`.

**`prompt=login` (forced re-auth):**
1. Even if the user has a valid session, treat them as unauthenticated
2. Redirect to the login flow (configured `login_url` or return `?error=login_required` for API-only deployments)
3. After re-authentication, continue the authorization flow
4. The new session's `auth_time` reflects the fresh authentication (ties into Phase 3)

Implementation: when `prompt=login`, skip the session check and redirect to `login_url` with the full authorization request preserved (via a return-to parameter or by stashing the request in the consent-style flow).

**`prompt=consent` (forced consent):**
1. Even if the user previously consented to this client+scope, require fresh consent
2. Redirect to `consent_url` regardless of auto_approve status
3. For auto_approve clients, `prompt=consent` is ignored (auto_approve means the deployer explicitly opted out of consent)

**`prompt` parameter validation:**
- Unknown values → redirect with `?error=invalid_request`
- Multiple space-separated values per OIDC spec (e.g., `prompt=login consent`) → if `none` is combined with anything else, error per spec

**Discovery document update:**
```json
"prompt_values_supported": ["none", "login", "consent"]
```

---

## 9. OIDC Conformance Testing

### Problem

riley_auth's OIDC compliance has been validated through manual review and integration tests. But the official OpenID Foundation conformance test suite (https://www.certification.openid.net/) is the industry-standard way to verify an OP implementation. Running it either confirms compliance or surfaces edge cases that review missed.

### Design

**Run the OIDC conformance suite against riley_auth and fix anything it catches.**

**Approach:**

The conformance suite runs as a web-based test harness that acts as an RP (Relying Party) against your OP. It requires:
1. A running riley_auth instance with a publicly accessible URL (or localhost with the conformance suite's local runner)
2. A registered OAuth client with the test suite's redirect URIs
3. The discovery document at `/.well-known/openid-configuration`

**Test profiles to target:**
- **Basic OP** — Core authorization code flow, token endpoint, UserInfo, JWKS
- **Config OP** — Discovery document correctness
- **Dynamic OP** — Skip (requires dynamic client registration, which is out of scope)

**Setup:**
1. Start riley_auth locally with test config
2. Register a client with the conformance suite's redirect URIs
3. Run the Basic OP and Config OP test profiles
4. Fix any failures
5. Re-run until clean

**What this validates:**
- Discovery document completeness and correctness
- Authorization code flow end-to-end
- Token endpoint behavior (grant types, auth methods)
- ID token claims and signing
- UserInfo endpoint response format
- JWKS endpoint format and key usage
- Error responses (invalid_request, invalid_scope, etc.)
- `prompt` parameter handling
- `nonce` and `state` parameter preservation
- Token expiration and validation

**Integration into CI (optional):**
If the conformance suite supports a CLI/Docker mode, add it as a CI job. Otherwise, document the manual testing procedure and record results.

**Deliverable:** A passing conformance report for Basic OP and Config OP profiles, with any fixes committed and reviewed. Results saved as `planning/v5/oidc_conformance_results.md`.

---

## Implementation Order

1. **JWKS Key Rotation & Algorithm Agility** — foundational infrastructure change, everything else builds on it
2. **Token Endpoint Auth: client_secret_basic** — small, unblocks third-party clients
3. **OIDC Compliance: auth_time** — small schema + flow change
4. **WWW-Authenticate Headers** — small error handling improvement
5. **Authorize `prompt` Parameter** — completes the OIDC authorize surface before conformance testing
6. **Codebase Organization** — refactor before adding metrics (cleaner diff)
7. **Observability** — depends on cleaner codebase organization
8. **Production Defaults & Deployment Polish** — CORS, cache headers, final touches
9. **OIDC Conformance Testing** — final validation of all prior work

**Grouping:**
- Phases 1-5: Cryptographic foundation + OIDC spec compliance
- Phase 6: Codebase refactor (no behavior changes)
- Phases 7-8: Operational readiness
- Phase 9: Conformance validation (fix-what-it-finds)

**Review strategy:**
- Standard review after each phase
- Exhaustive review at Phase 5 (crypto + OIDC spec complete) and Phase 8 (pre-conformance)
- Phase 9 is its own validation — the conformance suite is the reviewer

---

## Out of Scope

Still not in v5:
- **Email/password auth** — violates the soul doc
- **MFA/TOTP** — delegated to OAuth providers
- **Built-in frontend/UI** — riley_auth provides APIs, deployer builds UI
- **Dynamic client registration (RFC 7591)** — against the soul doc's API-only approach; conformance testing skips the Dynamic OP profile
- **Database-stored scope definitions** — config-only is working
- **Account recovery** — OAuth provider's problem
- **Trusted proxy list** — current leftmost-with-overwrite approach is documented and sufficient
- **CLI webhook dispatch** — CLI remains an out-of-band maintenance tool
- **Per-client introspection isolation** — current cross-client model is intentional (resource server pattern)
- **Session ID (sid) in logout tokens** — accepted tradeoff in v4, no new use case driving it
- **Horizontal scaling / distributed session store** — single-instance is sufficient for the target deployment profile
- **Documentation & packaging** — next after v5 (the code must be right before the docs are written)
