# v5 Implementation Plan

## Phase 1 — JWKS Key Rotation & Algorithm Agility

### 1.1 Config: KeyConfig struct and JwtConfig migration
- Add `KeyConfig` struct with `algorithm`, `private_key_path`, `public_key_path`, optional `kid`
- Change `JwtConfig` to accept either the old flat fields or `keys: Vec<KeyConfig>`
- Backward compat: if flat `private_key_path`/`public_key_path` present with no `[[jwt.keys]]`, treat as single RS256 entry
- Add config validation: at least one key, first key must have private key
- Unit tests for both old-style and new-style config parsing

### 1.2 jwt.rs: KeyEntry and KeySet
- Create `KeyEntry` struct: algorithm, encoding_key, decoding_key, kid, jwks_params (enum for RSA vs EC)
- Replace `Keys` with `KeySet` containing `Vec<KeyEntry>` and `HashMap<String, usize>` for kid lookup
- EC key PEM loading via `jsonwebtoken`'s `EncodingKey::from_ec_pem` / `DecodingKey::from_ec_pem`
- EC point extraction for JWKS (x, y coordinates from P-256 public key DER)
- Signing methods use `entries[0]` (active key)
- Verification tries kid-matched key first, falls back to trying all keys
- `jwks()` returns all keys with correct `kty`/`alg`/params per algorithm
- Update `compute_kid` to work for both RSA and EC keys

### 1.3 CLI: generate-keys algorithm flag
- Add `--algorithm` flag (es256, rs256) to `GenerateKeys` command, default es256
- Add `--key-size` flag for RSA (default 4096), ignored for EC
- ES256 key generation via `openssl ecparam -genkey -name prime256v1`
- Update generate_keypair to accept algorithm parameter

### 1.4 Wire up: server.rs, main.rs, AppState
- Change `AppState.keys` from `Arc<Keys>` to `Arc<KeySet>`
- Update `serve()` to load keys from new config format
- Update CLI `Serve` and `Validate` commands
- Update `dispatch_backchannel_logout_cli` to use `KeySet`

### 1.5 Discovery document: dynamic alg_values_supported
- `id_token_signing_alg_values_supported` populated from configured key algorithms (deduplicated)

### 1.6 Update existing tests
- All existing unit tests in jwt.rs adapted for KeySet API
- Integration test helper updated for KeySet
- Add new tests: multi-key JWKS, ES256 signing/verification, kid-based lookup, rotation scenario

### 1.7 Update example config
- Add `[[jwt.keys]]` examples to `riley_auth.example.toml`
- Document rotation procedure in comments

---

## Phase 2 — Token Endpoint Auth: client_secret_basic

### 2.1 Extract shared credential extraction
- Move `extract_client_credentials()` from introspect to a shared location (or make it pub)
- Ensure it handles: Authorization Basic header → form body fallback

### 2.2 Apply to token endpoint
- Refactor `oauth_token` handler to use shared extraction
- Remove direct form body client_id/client_secret reads

### 2.3 Apply to revocation endpoint
- Refactor `oauth_revoke` handler to use shared extraction

### 2.4 Update discovery document
- `token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]`
- `revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]`

### 2.5 Tests
- Integration tests for Basic auth on token endpoint (auth_code + refresh grants)
- Integration tests for Basic auth on revoke endpoint
- Test both methods work, test header takes precedence over body

---

## Phase 3 — OIDC Compliance: auth_time

### 3.1 Migration: add auth_time column
- `ALTER TABLE refresh_tokens ADD COLUMN auth_time bigint;`

### 3.2 DB layer: store and propagate auth_time
- `store_refresh_token` accepts optional `auth_time`
- `consume_refresh_token_*` functions return `auth_time` in the token row
- Auth code table: store `auth_time` at creation

### 3.3 JWT: auth_time in IdTokenClaims
- Add `auth_time: Option<i64>` to `IdTokenClaims`
- Update `sign_id_token` to accept `auth_time` parameter

### 3.4 Flow changes
- `auth_callback`: set `auth_time = now()` on session creation
- `oauth_token` (auth_code): copy auth_time from code creation time
- `oauth_token` (refresh): propagate from consumed token
- `auth_refresh`: propagate from consumed token

### 3.5 Discovery document
- Add `auth_time` to `claims_supported`

### 3.6 Tests
- Unit test: ID token includes auth_time claim
- Integration test: auth_time present in ID token from auth_code exchange
- Integration test: auth_time preserved through refresh

---

## Phase 4 — WWW-Authenticate Headers

### 4.1 BearerError helper
- Add `BearerError` enum and `www_authenticate_header()` builder to error.rs or a new module

### 4.2 Apply to userinfo endpoint
- Add `WWW-Authenticate` header on 401 responses (missing token, invalid token, expired token)
- Add on 403 responses (insufficient scope)

### 4.3 Apply to other Bearer-protected endpoints
- Introspect (token validation failure path, not client auth path)

### 4.4 Tests
- Integration tests verifying WWW-Authenticate header presence and format on userinfo 401/403
- Unit test for header builder

---

## Phase 5 — Authorize `prompt` Parameter

### 5.1 Parse prompt parameter
- Parse `prompt` query parameter in `/oauth/authorize`
- Validate: known values only, `none` cannot combine with others
- Unknown → `?error=invalid_request` redirect

### 5.2 prompt=none
- If session exists and auto_approve → issue code silently
- If session exists and consent required → `?error=consent_required` redirect
- If no session → `?error=login_required` redirect
- Never redirect to login_url or consent_url

### 5.3 prompt=login
- Skip session check, redirect to login_url with return-to
- For API-only deployments (no login_url configured), return `?error=login_required`

### 5.4 prompt=consent
- Force consent flow even if previously consented
- For auto_approve clients, ignore (auto_approve overrides)

### 5.5 Discovery document
- Add `prompt_values_supported: ["none", "login", "consent"]`

### 5.6 Tests
- Integration tests for prompt=none (session exists, no session, consent required)
- Integration tests for prompt=login
- Integration tests for prompt=consent
- Test prompt validation (unknown value, none+login combo)

---

## Phase 6 — Codebase Organization

### 6.1 Split integration.rs
- Create `tests/common/mod.rs` with TestServer and helpers
- Split tests into domain-specific files
- Verify all tests still pass with same names

### 6.2 Split db.rs into db/ module
- Create module with re-exports in mod.rs
- Split by domain: users, oauth_links, sessions, clients, webhooks, consent
- All external callers unchanged (they import `db::function_name`)

### 6.3 Verify
- Full test suite passes
- No import changes needed outside the split files

---

## Phase 7 — Observability

### 7.1 Add metrics dependencies
- Add `metrics` and `metrics-exporter-prometheus` to Cargo.toml

### 7.2 Config: MetricsConfig
- Add `[metrics]` section to config
- `enabled: bool`, optional `bearer_token`

### 7.3 Metrics middleware
- HTTP request counter and duration histogram via Axum middleware layer

### 7.4 Application metrics
- Token issuance/verification counters
- Webhook delivery counters
- Rate limit hit counter

### 7.5 /metrics endpoint
- Prometheus text format, outside CSRF middleware
- Optional bearer token protection

### 7.6 Tests
- Integration test: /metrics endpoint returns Prometheus format
- Unit test: metrics config parsing

---

## Phase 8 — Production Defaults & Deployment Polish

### 8.1 JWKS Cache-Control
- Add `Cache-Control: public, max-age={N}` header to JWKS endpoint
- Config: `jwt.jwks_cache_max_age_secs` (default 3600)

### 8.2 CORS refinement
- Verify CORS config applies to OAuth protocol endpoints
- Document CORS setup in example config

### 8.3 Tests
- Integration test: JWKS response has Cache-Control header
- Config parsing test for jwks_cache_max_age_secs

---

## Phase 9 — OIDC Conformance Testing

### 9.1 Set up conformance test environment
- Configure riley_auth instance for conformance testing
- Register test client with conformance suite redirect URIs

### 9.2 Run Basic OP profile
- Execute tests, record results
- Fix any failures

### 9.3 Run Config OP profile
- Execute tests, record results
- Fix any failures

### 9.4 Document results
- Save passing report as `planning/v5/oidc_conformance_results.md`

---

## Review Strategy

- Standard review after each phase
- Exhaustive review at Phase 5 (crypto + OIDC spec complete) and Phase 8 (pre-conformance)
- Phase 9 is self-validating via the conformance suite
