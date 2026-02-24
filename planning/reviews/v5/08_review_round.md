# Review Round — Phase 3 R1 (2026-02-23)

**Models**: Claude (Codex rate-limited, Gemini unavailable)
**Context**: ~155k tokens

## Findings

### Major

None (1 initially flagged, downgraded to minor on analysis).

### Minor

1. **[claude-only] auth_time semantics inconsistency** — `issue_tokens` (auth.rs) uses `Utc::now()` while OAuth token handler uses `auth_code.created_at.timestamp()`. Both are defensible since `issue_tokens` runs immediately after OAuth callback. **Fix:** Added comments documenting the design choice; refactored to use single `now` value. → cd01b86

2. **[claude-only] IdTokenClaims.auth_time lacks documentation** — `Option<i64>` with `skip_serializing_if` gives false impression it might be absent in production. **Fix:** Added doc comment explaining None is only for pre-migration tokens. → cd01b86

3. **[claude-only] No backfill for existing refresh tokens** — Pre-migration tokens have NULL auth_time that propagates through refresh. **Fix:** Added migration 013_backfill_auth_time.sql using created_at as proxy. → cd01b86

4. **[claude-only] auth_refresh propagation purpose unclear** — Session-cookie path propagates auth_time but never surfaces it in tokens. **Fix:** Added comment explaining DB consistency purpose. → cd01b86

### Notes

5. **[claude-only] max_age not implemented** — OIDC Core 1.0 Section 3.1.2.1 defines max_age parameter. Phase 5 of the architecture plan covers prompt parameter support. Not a regression from Phase 3.

6. **[claude-only] auth_time stored as bigint not timestamptz** — Deliberate choice since OIDC requires Unix epoch seconds in ID tokens. Avoids conversion.

7. **[claude-only] Introspection does not include auth_time** — Correct per RFC 7662, which does not define auth_time.
