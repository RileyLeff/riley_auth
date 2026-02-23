# Review Round 02 — Phase 1 Exhaustive Review

**Date:** 2026-02-23
**Models:** Codex, Gemini, Claude Opus 4.6
**Context:** ~80k tokens (full codebase)
**Purpose:** Verify Round 01 fixes and catch new issues

## Findings

### Major

1. **[consensus] OAuth token endpoint consumes unrelated tokens before ownership check** (Codex + Claude)
   - **File:** `crates/riley-auth-api/src/routes/oauth_provider.rs`, `crates/riley-auth-core/src/db.rs`
   - **Issue:** The `refresh_token` grant in `/oauth/token` used the generic `consume_refresh_token()` which deletes any matching token regardless of `client_id`. A malicious client could permanently destroy another client's (or a session's) refresh token by submitting it to the token endpoint.
   - **Fix:** Added `consume_client_refresh_token()` with `AND client_id = $2`, updated OAuth token endpoint to use it. **Commit: f115314**
   - Mirror of the session endpoint bug fixed in Round 01 (d4da005).

### Minor

1. **[gemini-only] `subtle::ConstantTimeEq` on state parameter slices** — `auth.rs:142,452`
   - `ct_eq` on byte slices may panic if lengths differ. Low risk (state param, not secrets) but could be a minor DoS vector.
   - **Deferred:** Belt-and-suspenders, accepted tradeoff per review_notes_README.md.

### Notes

1. **[gemini-only] OIDC `id_token` issued regardless of `openid` scope** — `oauth_provider.rs:345,426`
   - Safe "OIDC-by-default" approach. Strict compliance would check for `openid` in scopes.
   - **Deferred to Phase 4** (OIDC Compliance).

2. **[gemini-only] `openssl` binary dependency for key generation** — `jwt.rs:159`
   - Docker image installs `ca-certificates` but not `openssl`.
   - **Note for Phase 7** (QoL).

3. **All 3 Round 01 fixes verified** by Gemini:
   - `consume_session_refresh_token` with `AND client_id IS NULL` ✓
   - `idx_consumed_refresh_tokens_family_id` ✓
   - Migration default `uuidv7()` ✓

4. **[codex-only] Auth code consume-first pattern** — Settled design decision from v2. Documented in review_notes_README.md.
