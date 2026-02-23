# Review Round 01 — Phase 1 Exhaustive Review

**Date:** 2026-02-23
**Models:** Codex (gpt-5.3-codex), Gemini 3, Claude Opus 4.6
**Context:** ~80k tokens (full codebase)
**Scope:** Full codebase review with focus on v3 Phase 1 (Token Family Tracking)

## Findings

### Major

1. **[claude-only] Client-bound refresh token permanently consumed at session endpoint**
   - `auth.rs:auth_refresh()` consumes the refresh token (moving it to `consumed_refresh_tokens`) BEFORE checking `token_row.client_id.is_some()`. If a client-bound token is accidentally sent to `/auth/refresh`, it's permanently destroyed and the legitimate OAuth client loses its token.
   - **Fix:** Add `AND client_id IS NULL` to the `consume_refresh_token` query used by the session path, or create a separate `consume_session_refresh_token` function.

2. **[consensus: codex + gemini] Race condition: concurrent use of same valid token doesn't trigger family revocation**
   - `check_token_reuse` and `consume_refresh_token` are separate operations. Two concurrent requests with the same valid token: both pass the reuse check, one wins the DELETE, the other gets None. No family revocation triggered.
   - **Analysis:** Claude correctly noted this is actually the desired behavior for the RFC 6819 threat model. This scenario (two uses of the same *not-yet-consumed* token) is a race between legitimate use and theft of the same token. Only one succeeds. The attacker doesn't get a valid token. Family revocation is for when a *previously consumed* token is replayed — which our implementation handles correctly.
   - **Decision:** Accept as note. The race doesn't create a security hole — only one request wins the atomic DELETE.

3. **[codex-only] In-flight rotation survives family revocation**
   - Request A consumes token C. Request B detects reuse of token A and revokes the family. Request A then inserts new token D into the (now-revoked) family.
   - **Analysis:** Theoretically valid but the window is vanishingly small (requires exact interleaving of: consume C → detect reuse of A → revoke family → insert D, across concurrent requests). The fix would require wrapping the entire refresh flow in a database transaction, which means significant refactoring of the API layer.
   - **Decision:** Accept as note. Document in review_notes. The window is too narrow to exploit in practice, and the affected token D would still be revoked on the next reuse detection.

4. **[gemini-only] X-Forwarded-For takes first IP (spoofable)**
   - If `behind_proxy` is true, the code takes the first IP from X-Forwarded-For, which an attacker can control.
   - **Decision:** Planned for v3 Phase 7 (IP extraction consolidation). Accept as note for now.

### Minor

5. **[consensus: codex + claude] Missing index on consumed_refresh_tokens(family_id)** — `revoke_token_family()` does sequential scan. Fix in migration 004.

6. **[claude-only] Migration default uses gen_random_uuid() instead of uuidv7()** — Inconsistent with project convention. Only affects migration backfill.

7. **[codex-only] redirect_uris not validated as URLs at registration** — Planned for v3 Phase 7.6.

8. **[codex-only] Display-name length check is bytes, not chars** — Planned for v3 Phase 7.2.

9. **[codex-only] OAuth HTTP calls have no explicit timeout** — Low priority but valid.

10. **[codex-only] OIDC discovery issuer is non-URL by default** — Related to OIDC compliance (v3 Phase 4).

11. **[codex-only] CLI webhook registration doesn't validate client_id** — Inconsistency with API.

12. **[claude-only] Orphaned consumed_refresh_tokens on logout/revoke** — Not a security issue; cleanup task (Phase 5) will handle.

13. **[claude-only] No test for client-bound token at session endpoint** — Tests the fix for finding #1.

### Notes

14. **[consensus: codex + claude] unsafe impl Sync for TestServer** — Should be verified but not urgent (test-only code).
15. **[codex-only] extract_ip comment mentions Forwarded header but doesn't check it** — Documentation inconsistency.
16. **[codex-only] Redis limiter is fail-open** — By design.
17. **[gemini-only] No logging/alerting on family revocation** — Good point; should log at WARN level.
18. **[claude-only] Authorization codes not cleaned up when used** — Minor waste, cleanup task will handle.

### Test Coverage Gaps

19. **[consensus: codex + claude] No concurrent refresh token test** — Sequential tests only.
20. **[claude-only] No test for expired token reuse detection**
21. **[codex-only] Integration suite is ignored by default** — CI must use `--include-ignored`.
