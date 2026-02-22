# Review Round 5 — Merged Parallel Review

**Models:** Claude subagent, Gemini 2.5 Pro (Codex degraded — no output)
**Scope:** Full codebase review after R4 fixes
**Goal:** Clean pass #1 (need 2 consecutive)

## Major Findings

### M1 [Gemini-only]: Deadlock in `soft_delete_user` locking order
`soft_delete_user` locked the target user row first, then all admin rows in a second query. Two concurrent admin deletions could create circular waits → deadlock.

Same pattern existed in `update_user_role`: locked all admins first (without ORDER BY), then updated the target user in a separate statement.

**Fix (5f8d69f):** Combined both locking steps into a single `SELECT ... WHERE (id = $1 OR role = 'admin') ... ORDER BY id FOR UPDATE` query in both functions. Consistent lock ordering eliminates the deadlock.

## Minor Findings

### m1 [Claude-only]: No rate limiting on sensitive endpoints
Rate limiting variant exists but isn't applied. Deferred to Phase 8.

### m2 [Claude-only]: No scheduled cleanup for expired tokens/codes
Cleanup functions exist but nothing calls them on a schedule. Deferred to Phase 8.

### m3 [Gemini-only]: Redundant UNIQUE constraint on username column
Column-level UNIQUE exists alongside the filtered functional index `idx_users_username_lower`. The column-level constraint is redundant but harmless — the filtered index provides the real enforcement for active users. Low priority.

### m4 [Gemini-only]: `case_sensitive` config option vs DB enforcement
The `UsernameConfig::case_sensitive` option could confuse operators since the DB always enforces case-insensitive uniqueness. Noted as a documentation issue.

## Notes

- Claude confirmed all R4 fixes are correct and complete
- Gemini confirmed R4 fixes are functionally correct but flagged the locking order issue
- Both models confirmed: OAuth atomic consumes, CSRF protection, JWT integrity all sound
- 12 additional notes from Claude (all observations, no action needed)

## Verification of R4 Fixes

All verified correct by both models:
- Last-admin delete guard ✓
- PII cleanup on soft delete ✓
- Index alignment (lower(provider_email)) ✓
