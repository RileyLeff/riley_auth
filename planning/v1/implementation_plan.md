# v1 Implementation Plan

## Phase 1: Foundation

Core infrastructure that everything else builds on.

- **1.1** Config loading — TOML parsing, resolution order (CLI > env > cwd > walk up > ~/.config > /etc), `env:VAR_NAME` expansion, strongly-typed config struct
- **1.2** Error types — unified error enum, Axum `IntoResponse` impl, consistent JSON error format
- **1.3** Database — connection pool setup, sqlx migrations for all 6 tables (users, oauth_links, refresh_tokens, username_history, oauth_clients, authorization_codes)
- **1.4** Server skeleton — Axum router, CORS middleware, tracing, graceful shutdown, health endpoint

## Phase 2: JWT & Crypto

Token infrastructure used by both same-domain and cross-domain modes.

- **2.1** RS256 key loading — read PEM files, parse into signing/verification keys
- **2.2** JWT signing & verification — create and validate access tokens with claims (sub, username, role, aud, iss, iat, exp)
- **2.3** JWKS endpoint — `/.well-known/jwks.json` serving the public key in JWK format
- **2.4** Refresh token helpers — generation, SHA-256 hashing, DB storage, rotation
- **2.5** Generate-keys CLI command — `riley-auth generate-keys` to create RS256 keypair

## Phase 3: OAuth Consumer

Sign in with Google/GitHub, user creation, provider linking.

- **3.1** OAuth flow core — state generation, PKCE, auth URL construction, code exchange, profile fetching (generic over provider)
- **3.2** Google provider — profile URL, field mapping (email, name, avatar, provider_id)
- **3.3** GitHub provider — profile URL, field mapping
- **3.4** Callback handler — upsert logic: match oauth_links → existing user, email match → suggest link, no match → onboarding redirect with setup token
- **3.5** Setup endpoint — `POST /auth/setup` accepts username + setup token, creates user + oauth_link, issues tokens
- **3.6** Provider linking endpoints — `GET /auth/link/{provider}`, callback, `DELETE /auth/link/{provider}`, `GET /auth/me/links`

## Phase 4: Session Management

Cookie-based auth for same-domain mode.

- **4.1** Cookie handling — set/clear HttpOnly, Secure, SameSite=Lax cookies on configured domain, access + refresh tokens as separate cookies
- **4.2** Auth middleware — extract JWT from cookie, verify, inject user into request extensions
- **4.3** Refresh endpoint — `POST /auth/refresh` exchanges refresh cookie for new access token, rotates refresh token
- **4.4** Logout — `POST /auth/logout` clears cookies + revokes refresh token, `POST /auth/logout-all` revokes all

## Phase 5: User Profile

Identity management — the "portable identity" from the soul document.

- **5.1** Profile endpoints — `GET /auth/me`, `PATCH /auth/me` (display_name)
- **5.2** Username changes — `PATCH /auth/me/username` with cooldown, hold period, reserved words, pattern validation, re-issue JWT
- **5.3** Avatar upload — `POST /auth/me/avatar` multipart upload to S3, size/type validation; `DELETE /auth/me/avatar`
- **5.4** Account deletion — `DELETE /auth/me` soft delete + anonymization, S3 cleanup

## Phase 6: OAuth Provider

Cross-domain mode — riley_auth acts as an OAuth provider.

- **6.1** Authorization endpoint — `GET /oauth/authorize` validates client_id, redirect_uri, shows consent (or auto-approves), generates authorization code with PKCE
- **6.2** Token endpoint — `POST /oauth/token` exchanges code for tokens (authorization_code grant) or refreshes tokens (refresh_token grant), validates PKCE, client credentials
- **6.3** Revocation endpoint — `POST /oauth/revoke` per RFC 7009

## Phase 7: Admin & CLI

Operational tooling.

- **7.1** Admin middleware — role check (must be admin)
- **7.2** Admin user endpoints — list users (paginated), get user, change role, delete user
- **7.3** Admin client endpoints — list clients, register client (returns secret), remove client
- **7.4** CLI commands — serve, migrate, validate, list-users, promote, demote, revoke, delete, register-client, list-clients, remove-client

## Phase 8: Integration Testing & Deploy

End-to-end verification and deployment artifacts.

- **8.1** Docker compose test environment — Postgres 18 + MinIO (S3) + riley-auth, automated test suite running full flows
- **8.2** Integration tests — full sign-in flow (mocked OAuth provider), token refresh, username change, avatar upload, OAuth provider flow, account deletion
- **8.3** Dockerfile — multi-stage build
- **8.4** Example config — `riley_auth.example.toml` with all options documented
- **8.5** Rate limiting — tower middleware on auth endpoints
