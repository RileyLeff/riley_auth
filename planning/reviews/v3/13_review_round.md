# Review Round 13 — Phase 4 Exhaustive Review (Round 1)

**Date:** 2026-02-23
**Models:** Gemini, Claude subagent (Codex hit usage limit — degraded round)
**Context:** ~95k tokens (full codebase via dirgrab)
**Scope:** Exhaustive review — entire codebase after Phase 4 (OIDC Compliance)

## Findings

### Major

**M1: UserInfo endpoint (`/auth/me`) is non-functional for OIDC clients** [consensus: Gemini + Claude]
- Discovery document declares `userinfo_endpoint` pointing to `/auth/me`
- `/auth/me` only accepts cookies and rejects tokens with `aud != issuer`
- OAuth clients with `aud = client_id` cannot call the UserInfo endpoint
- Gemini also notes the response uses non-standard claim names (`id` vs `sub`, `username` vs `preferred_username`)
- **Files:** `crates/riley-auth-api/src/routes/mod.rs:47`, `crates/riley-auth-api/src/routes/auth.rs` (`extract_user`, `MeResponse`)

**M2: OAuth error responses use `detail` instead of `error_description`** [claude-only]
- RFC 6749 Section 5.2 specifies `error_description` field
- Current Error serialization uses `detail` field
- Standard OAuth client libraries look for `error_description`
- **File:** `crates/riley-auth-core/src/error.rs` (IntoResponse impl)

### Minor

**m1: OAuth authorize endpoint returns errors to user-agent instead of redirect URI** [claude-only]
- RFC 6749 Section 4.1.2.1: after validating client_id and redirect_uri, errors should redirect back with `?error=...&state=...`
- Currently returns HTTP error responses
- All current clients are auto_approve first-party, so impact is limited
- **File:** `crates/riley-auth-api/src/routes/oauth_provider.rs` (`authorize`)

**m2: OIDC nonce not carried forward on refresh** [gemini-only]
- OIDC Core 1.0 Section 12.1: refreshed ID tokens SHOULD contain the same nonce
- Currently passes `None` for nonce on refresh
- Would require adding nonce to refresh_tokens table
- **File:** `crates/riley-auth-api/src/routes/oauth_provider.rs` (refresh_token grant)

**m3: Missing test for authorization code replay** [claude-only]
- No integration test verifying a used auth code cannot be exchanged again
- **File:** `crates/riley-auth-api/tests/integration.rs`

**m4: Missing test for PKCE verification failure** [claude-only]
- No integration test verifying wrong code_verifier is rejected
- **File:** `crates/riley-auth-api/tests/integration.rs`

**m5: Missing test for expired authorization code rejection** [claude-only]
- No integration test verifying expired auth codes are rejected
- **File:** `crates/riley-auth-api/tests/integration.rs`

**m6: Empty string display names allowed** [claude-only]
- `update_display_name` only checks max length, not min
- **File:** `crates/riley-auth-api/src/routes/auth.rs`

**m7: No pagination on list_clients and list_webhooks** [claude-only]
- Other list endpoints support pagination, these don't
- **File:** `crates/riley-auth-api/src/routes/admin.rs`

### Notes

- **Setup token binding is self-referential**: Both Gemini and Claude noted the `binding` field in SetupClaims provides no additional security beyond the JWT signature. [consensus]
- **display_name/username byte vs char length**: Already planned for Phase 7 Step 7.2. [claude]
- **Regex recompilation**: Already planned for Phase 7 Step 7.1. [claude]
- **Cleanup functions never called**: Already planned for Phase 5. [claude]
- **OAuth provider creates new reqwest::Client per call**: Performance issue, not security. [claude]
- **Hex-string HMAC key**: Using hex-encoded string bytes rather than raw bytes for webhook HMAC. Functional, non-standard. [gemini]
- **CSRF bypass with permissive CORS**: Documented behavior — empty cors_origins defaults to permissive. [gemini]
- **No length limits on admin-created strings**: Admin-only endpoints, low risk. [claude]
