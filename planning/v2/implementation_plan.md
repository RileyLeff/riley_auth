# v2 Implementation Plan

## Phase 1: Scopes & Permissions

### Step 1.1: Database Migration — Scopes Columns
- Add `allowed_scopes text[] NOT NULL DEFAULT '{}'` to `oauth_clients`
- Add `scopes text` to `authorization_codes` (space-delimited string)
- Add `scopes text` to `refresh_tokens` (space-delimited string)
- New migration file: `002_scopes.sql`

### Step 1.2: Config — Scope Definitions
- Add `[scopes]` section to config with `definitions` list
- Each definition: `{ name, description }`
- Default to empty (no scopes defined = backwards-compatible)
- Update example config

### Step 1.3: Admin API — Client Scope Management
- Extend `POST /admin/clients` to accept `allowed_scopes`
- Extend `GET /admin/clients` response to include `allowed_scopes`
- Extend CLI `register-client` with `--scopes` flag
- Update db functions: `create_client()`, `find_client_*()`, `list_clients()`

### Step 1.4: OAuth Provider Flow — Scope Validation & Propagation
- `GET /oauth/authorize`: accept `scope` query param, validate each scope against client's `allowed_scopes` and config definitions
- `store_authorization_code()`: persist granted scopes
- `consume_authorization_code()`: return scopes
- `POST /oauth/token` (authorization_code): include `scope` in response, store scopes on refresh token
- `POST /oauth/token` (refresh_token): carry scopes forward, include in response

### Step 1.5: JWT — Scope Claim
- Add `scope: Option<String>` to `Claims` struct
- `sign_access_token()`: accept optional scopes, include in JWT
- Session tokens (aud=issuer) get no scopes; OAuth client tokens get granted scopes

### Step 1.6: Consent Data Endpoint
- `GET /oauth/consent?client_id=...&scope=...` — returns client name, requested scopes with descriptions
- Used by deployer's frontend to render a consent screen
- Only accessible with valid session cookie

### Step 1.7: Tests — Scopes
- Unit tests for scope validation logic
- Integration tests: authorize with scopes, token exchange returns scopes, refresh preserves scopes
- Integration test: requesting unauthorized scope returns error
- Integration test: consent endpoint returns scope descriptions

---

## Phase 2: OIDC Discovery & ID Tokens

### Step 2.1: OIDC Discovery Endpoint
- `GET /.well-known/openid-configuration` — returns discovery document
- All values derived from existing config (public_url, jwt.issuer, scope definitions)
- No new config needed

### Step 2.2: ID Token Issuance
- Define `IdTokenClaims` struct with standard OIDC claims: `sub`, `iss`, `aud`, `exp`, `iat`, `name`, `preferred_username`, `picture`
- Sign with same RS256 key
- Include `id_token` in `/oauth/token` response alongside `access_token`
- Only for OAuth client flows, not session cookies

### Step 2.3: Tests — OIDC
- Test discovery document structure and values
- Test id_token is present in token response
- Test id_token claims are correct

---

## Phase 3: Session Visibility

### Step 3.1: Database Migration — Session Metadata
- Add `user_agent text`, `ip_address text` to `refresh_tokens`
- Migration file: `003_session_metadata.sql`

### Step 3.2: Capture Session Metadata
- `store_refresh_token()`: accept optional user_agent and ip_address
- `issue_tokens()` in auth.rs: extract User-Agent header and client IP, pass to store
- `touch_refresh_token()`: update `last_used_at` on refresh

### Step 3.3: Session Endpoints
- `GET /auth/sessions` — list active sessions for current user (device, IP, last used, created, is_current)
- `DELETE /auth/sessions/{id}` — revoke specific session (not current)
- Update db: `list_sessions_for_user()`, `delete_session_by_id()`

### Step 3.4: Tests — Sessions
- Integration test: list sessions shows current session
- Integration test: revoke specific session
- Integration test: cannot revoke current session

---

## Phase 4: Webhooks / Event System

### Step 4.1: Database — Webhook Tables
- `webhooks` table: id, client_id (nullable), url, events (text[]), secret, active, created_at
- `webhook_deliveries` table: id, webhook_id, event_type, payload, status_code, error, attempted_at
- Migration file: `004_webhooks.sql`

### Step 4.2: Config & Event Types
- Define event type enum/constants
- No config needed — webhooks are registered via API

### Step 4.3: Webhook Registration API
- `POST /admin/webhooks` — register webhook (url, events, optional client_id)
- `GET /admin/webhooks` — list webhooks
- `DELETE /admin/webhooks/{id}` — remove webhook
- `GET /admin/webhooks/{id}/deliveries` — recent delivery attempts
- DB functions for CRUD

### Step 4.4: Event Dispatch System
- `dispatch_event()` function in core: accepts event type + payload
- Queries matching webhooks, spawns async delivery tasks
- HMAC-SHA256 signature in `X-Webhook-Signature` header
- Retry with exponential backoff (3 attempts)
- Records delivery attempts in `webhook_deliveries`

### Step 4.5: Emit Events from Existing Code
- `user.created` — after `create_user_with_link()` in auth_setup
- `user.deleted` — after `soft_delete_user()`
- `user.updated` — after display name/avatar updates
- `user.username_changed` — after `change_username()`
- `user.role_changed` — after `update_user_role()`
- `session.created` — after `issue_tokens()`
- `link.created` / `link.deleted` — after link operations

### Step 4.6: CLI — Webhook Management
- `list-webhooks`, `register-webhook`, `remove-webhook` CLI commands

### Step 4.7: Tests — Webhooks
- Unit tests for HMAC signature generation
- Integration tests: register webhook, trigger event, verify delivery
- Integration test: retry on failure
- Integration test: event filtering by type

---

## Phase 5: Cookie Prefix & OIDC Cleanup

### Step 5.1: Configurable Cookie Prefix
- Add `cookie_prefix` to `[server]` config (default: `"riley_auth"`)
- Replace hardcoded cookie name constants with runtime values from config
- Thread config through all cookie-building functions

### Step 5.2: Tests — Cookie Prefix
- Unit test: custom prefix produces correct cookie names
- Integration test: auth flow works with custom prefix

---

## Phase 6: Rate Limit Persistence (Redis)

### Step 6.1: Optional Redis Dependency
- Add `redis` crate behind `redis` cargo feature flag
- Add `[rate_limiting]` config section: backend ("memory"|"redis"), redis_url

### Step 6.2: Redis Rate Limit Store
- Implement tower_governor-compatible key store backed by Redis
- Keys: `rate:{ip}:{endpoint}` with TTL matching rate window
- Fallback to in-memory if Redis unavailable

### Step 6.3: Server Integration
- Conditionally create Redis or in-memory rate limiter based on config
- Connection pooling for Redis

### Step 6.4: Tests — Redis Rate Limiting
- Unit test: Redis store increments and expires correctly
- Integration test with docker-compose Redis service

---

## Review Checkpoints
- Exhaustive review after Phase 1 (scopes — foundational, most complex)
- Exhaustive review after Phase 3 (sessions — completes user-facing features)
- Exhaustive review after Phase 6 (final — full v2)
