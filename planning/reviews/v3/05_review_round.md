# Review Round 03 — Phase 1 Exhaustive Review

**Date:** 2026-02-23
**Models:** Codex, Claude Opus 4.6 (Gemini failed — rate limited)
**Context:** ~81k tokens (full codebase)
**Purpose:** Verify Round 02 fixes and check for convergence

## Findings

### Major

**0 genuine majors found.**

Codex flagged two items as major, both assessed as incorrect/settled:

1. **[codex-only] Cross-context reuse detection is global** — Codex claims `check_token_reuse` being unscoped by client_id is a bug. Claude explicitly confirmed this is correct: "a replayed hash should trigger family revocation regardless of which endpoint receives the replay." Active token isolation (the Round 1/2 fixes) is distinct from reuse detection. Reuse detection *should* be global — any replay of a consumed token signals credential theft.

2. **[codex-only] /oauth/authorize CSRF** — Settled v2 design decision. Already in review_notes_README.md. Standard OAuth behavior with state + redirect_uri protection.

### Minor (fixed)

1. **[claude-only] Dead code: `consume_refresh_token`** — The original unscoped function was no longer called after Round 1/2 fixes. Removed to prevent future misuse. **Commit: 83a989a**

2. **[consensus] Missing cross-endpoint isolation tests** — Both Codex and Claude noted no regression tests for the exact scenarios Rounds 1/2 fixed. Added `cross_endpoint_client_token_at_session_endpoint` and `cross_endpoint_session_token_at_oauth_endpoint`. **Commit: 83a989a**

### Minor (deferred)

3. **[claude-only] logout/revoke_session don't record consumed token** — Replay of stolen-then-revoked token fails silently (token not found) instead of triggering family revocation. Not a security hole — attacker is still rejected. Each session typically has one active token. Accepted as minor gap.

4. **[claude-only] No periodic cleanup task** — `cleanup_consumed_refresh_tokens`, `cleanup_expired_tokens`, `cleanup_expired_auth_codes` exist but are never called. **Deferred to Phase 5** (Background Cleanup Task).

### Notes

1. **[claude-only] `delete_all_refresh_tokens` is nuclear** — Revokes both session and OAuth client tokens. Could surprise users of `/auth/logout-all`. Documenting as intentional "nuclear option" behavior.

2. **[codex-only] Permissive CORS default** — Explicitly warned in code. Deployment concern, not a code bug.

3. **[codex-only] redirect_uri validation** — Already deferred to Phase 7.6.

4. **[codex-only] SSRF in webhook delivery** — Already planned for Phase 6.

## Convergence Status

Round 3: **0 majors.** This is round 1 of 2 consecutive clean rounds needed.
