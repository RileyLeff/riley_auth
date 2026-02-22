# Review Round 1 — 2026-02-22

**Models**: Codex (gpt-5.3-codex xhigh), Gemini, Claude (opus-4.6 subagent)
**Context**: ~31k tokens
**Mode**: Parallel, all three successful

---

## Major (must fix)

### M1. `aud` claim never enforced — token context confusion [consensus: codex + gemini]
- **Location**: `jwt.rs` verify_access_token, `auth.rs` extract_user, `admin.rs` require_admin
- **Impact**: Tokens minted via `/oauth/token` (aud=client_id) can be replayed as session cookies against `/auth/*` and `/admin/*`
- **Fix**: Enforce expected `aud` per route context; session cookies must have `aud == config.jwt.issuer`

### M2. Authorization code TOCTOU — non-atomic consumption [consensus: codex + claude + gemini]
- **Location**: `oauth_provider.rs` token(), `db.rs` find_authorization_code + mark_authorization_code_used
- **Impact**: Concurrent requests can double-use an auth code to get multiple token sets
- **Fix**: Single atomic `UPDATE ... WHERE used=false RETURNING *` query

### M3. Refresh token rotation race condition [consensus: codex + claude + gemini]
- **Location**: `auth.rs` auth_refresh, `oauth_provider.rs` token (refresh_token branch), `db.rs`
- **Impact**: Concurrent requests can reuse a refresh token before deletion; no family tracking for replay detection
- **Fix**: Wrap delete+insert in transaction, use `DELETE ... RETURNING *` for atomicity; consider token family tracking

### M4. No database transactions for multi-step mutations [consensus: codex + claude + gemini]
- **Location**: `auth.rs` (auth_setup, update_username, delete_account), `oauth_provider.rs`, `admin.rs`
- **Impact**: Partial state on failure (orphaned users, inconsistent username history, etc.)
- **Fix**: Use `pool.begin()` / `tx.commit()` for all multi-step operations

### M5. PKCE optional in OAuth provider flow [consensus: codex + claude; gemini noted]
- **Location**: `oauth_provider.rs` authorize/token, migration (code_challenge nullable)
- **Impact**: Clients can omit code_challenge, defeating PKCE protection for authorization codes
- **Fix**: Reject authorize requests without code_challenge; enforce S256 method

### M6. Soft-deleted users keep OAuth links → identity lockout [consensus: codex + gemini]
- **Location**: `db.rs` soft_delete_user, `auth.rs` auth_callback
- **Impact**: Deleted users can't re-register with same provider (UNIQUE constraint on oauth_links still active); stale links cause UserNotFound on callback
- **Fix**: Delete or tombstone OAuth links on soft-delete; filter link queries to active users

### M7. Session refresh accepts client-bound refresh tokens [codex-only]
- **Location**: `auth.rs` auth_refresh
- **Impact**: Refresh token issued to an OAuth client can be used at `/auth/refresh` to mint first-party session cookies
- **Fix**: Reject in auth_refresh unless `token_row.client_id.is_none()`

### M8. Consent not enforced for non-auto-approve OAuth clients [codex-only]
- **Location**: `oauth_provider.rs` authorize
- **Impact**: Any logged-in user is silently authorized to any registered client (auto_approve is stored but not checked)
- **Fix**: Return an error or redirect to consent page for non-auto_approve clients

### M9. No CSRF protection on state-changing endpoints [claude-only]
- **Location**: All POST/PATCH/DELETE endpoints in auth.rs, admin.rs
- **Impact**: SameSite=Lax provides incomplete protection; subdomain attacks possible with parent-domain cookies
- **Fix**: Require a custom header (X-Requested-With) or implement double-submit CSRF tokens

### M10. Admin role check relies on JWT claims only [claude-only]
- **Location**: `admin.rs` require_admin
- **Impact**: Demoted admin retains privileges for up to 15min until access token expires
- **Fix**: Add DB check for current role in admin middleware (or maintain revocation cache)

---

## Minor (should fix)

### m1. Redirect URI validation missing at client registration [consensus: codex + claude]
- Validate https scheme, reject fragments, allow localhost exception

### m2. Username config flags not fully honored [codex-only]
- `allow_changes` ignored; case_sensitive doesn't match DB behavior

### m3. Uniqueness constraint violations return 500 instead of domain errors [consensus: codex + claude]
- Map Postgres 23505 (unique violation) to UsernameTaken / ProviderAlreadyLinked etc.

### m4. Potential panic in ASN.1 parser on malformed key [codex-only]
- `&bit_string_content[1..]` with no bounds check in `parse_rsa_public_key_der`

### m5. Unix-specific signal handling unconditional [consensus: codex + claude]
- `expect()` on SIGTERM handler will panic on non-Unix platforms

### m6. CORS permissive by default when origins unset [consensus: codex + claude]
- `CorsLayer::permissive()` is dangerous in production

### m7. Redirect URL in auth_callback uses string concatenation [codex-only]
- Should use `url::Url` + `query_pairs_mut()` for link-accounts redirect

### m8. Setup token not single-use [claude-only]
- Token remains valid until expiry even after account creation

### m9. OAuth state cookie not bound to flow type [claude-only]
- Login and link flows share same cookie names; state not bound to callback URL

### m10. Regex recompiled on every username validation [claude-only]
- Should compile once at startup or use lazy init

### m11. Soft-deleted username collision with truncated UUID [claude-only]
- `deleted_{uuid_prefix[..8]}` can collide; use full UUID

### m12. Error types need better HTTP status mapping [claude-only]
- InvalidClient should be 401; conflict conditions should be 409

### m13. Missing periodic cleanup for expired tokens [consensus: gemini + claude]
- cleanup functions exist but are never called

### m14. Unverified email linking [gemini-only]
- email_verified claim from Google not checked before suggesting account link

### m15. Missing client secret rotation endpoint [gemini-only]
- No way to rotate OAuth client secrets via API or CLI

---

## Notes (observations/tradeoffs)

1. No rate limiting implemented (all three noted)
2. `last_used_at` on refresh_tokens never updated (codex)
3. OAuth token endpoint error format doesn't match RFC 6749 §5.2 — uses "detail" instead of "error_description" (claude)
4. No OpenID Connect discovery endpoint (claude)
5. No pagination metadata in list responses (claude)
6. Key generation shells out to openssl CLI (claude)
7. Migrations run automatically on serve (claude note, intentional for v1)
8. GitHub PKCE requires GitHub App not OAuth App (claude)
9. Provider names are strings not enums at DB layer (claude)
10. No /oauth/introspect or /oauth/userinfo endpoint (claude)
