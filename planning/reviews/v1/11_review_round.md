# Review Round 6 — Merged Parallel Review

**Models:** Claude subagent, Gemini 2.5 Pro, Codex
**Scope:** Full codebase review after R5 deadlock fix
**Goal:** Clean pass #1 (need 2 consecutive)

## Consensus

All three models confirmed the R5 deadlock fix is correct and complete.

## Major Findings

### M1 [Codex-only]: Deleted user can create OAuth links with valid JWT
`link_callback` didn't verify the user is still active. A deleted user with a still-valid access token (short TTL window) could create new OAuth links, squatting on `UNIQUE(provider, provider_id)` and blocking other users from linking that provider identity.

**Fix (c5591bf):** Added `find_user_by_id` check in `link_callback` before creating the link.

**Severity assessment:** Codex rated major, but the window is very narrow (access token TTL, typically 15 min) and requires deliberate action. Fixing it is the right call, but the risk is limited.

### M2 [Codex-only]: Multi-provider unlink bypass
If a user has multiple links for the same provider (e.g., two GitHub accounts), the unlink guard checked total link count (`links.len() > 1`) but the DELETE removed ALL links for that provider, potentially dropping to 0 links and permanently locking the user out.

**Fix (c5591bf):** Changed the guard to subtract same-provider count: `links.len() - same_provider_count >= 1`.

### Dismissed: Token issuance TOCTOU [Codex-only]
Codex flagged a race between fetching a user and storing a refresh token. This is not a real issue: if a user is deleted between these steps, the orphaned refresh token can never be used — the next refresh attempt calls `find_user_by_id` which filters by `deleted_at IS NULL` and returns UserNotFound. Standard JWT tradeoff.

## Minor Findings

None from any model.

## Notes

All three models produced observational notes (no action needed):
- No redirect URI format validation on client registration (UX concern)
- Cleanup functions for expired tokens/codes exist but aren't scheduled (Phase 8)
- `find_refresh_token` is dead code (will be used in Phase 8 or removed)
- Atomic token scoping correctly prevents cross-flow token reuse
- Username reclaimability works correctly with soft-delete

## R5 Deadlock Fix Verification

All three models confirmed the fix is correct:
- Single-query locking with `ORDER BY id` eliminates circular wait
- Promotion path correctly skips locking (can't violate last-admin invariant)
- Concurrent demotion + deletion serialized correctly
