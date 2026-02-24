# Phase 3 R1 Fixes (2026-02-23)

**Commit:** cd01b86

All 4 minor items fixed:

1. **auth_time semantics comment** — Documented in auth.rs issue_tokens that Utc::now() is correct here (runs immediately after OAuth callback). Also refactored to use single `now` for expires_at and auth_time.

2. **IdTokenClaims.auth_time doc comment** — Added doc comment referencing OIDC Core 1.0 Section 2 and explaining Option is for pre-migration tokens only.

3. **Backfill migration** — Added 013_backfill_auth_time.sql: `UPDATE refresh_tokens SET auth_time = EXTRACT(EPOCH FROM created_at)::bigint WHERE auth_time IS NULL`.

4. **auth_refresh comment** — Added comment explaining auth_time is propagated for DB consistency, not surfaced in tokens on the session-cookie path.
