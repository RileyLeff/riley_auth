# Review Round 14 — Phase 5 Exhaustive Review R1

**Date:** 2026-02-24
**Type:** Exhaustive review (Phase 5 milestone — crypto + OIDC spec complete)
**Models:** Claude Opus 4.6 only (Codex: empty output, Gemini: CLI error)
**Context:** ~161k tokens (full codebase)

## Findings

### Major

1. **[claude-only] Authorization code single-use via UPDATE-mark, not DELETE** — `db.rs::consume_authorization_code` uses `UPDATE SET used = true` instead of DELETE. RFC-compliant (WHERE used = false prevents replay). **PRE-EXISTING**: Documented in review_notes_README.md "Consume-first pattern for tokens and auth codes is intentional." Reclassified as NOTE.

2. **[claude-only] Webhook secrets stored in plaintext** — `webhooks` table stores HMAC signing secret as plaintext. Required for delivery-time HMAC computation. **PRE-EXISTING**: Documented in review_notes_README.md "Phase 2 — Webhook HMAC secrets stored in plaintext (accepted tradeoff)." Reclassified as NOTE.

**Effective major count after reclassification: 0**

### Minor

1. **[claude-only] OAuth state not bound to session/IP** — Defense-in-depth observation. HttpOnly+Secure+SameSite=Lax mitigates. PRE-EXISTING (documented).
2. **[claude-only] Setup token no single-use guarantee** — DB UNIQUE constraints prevent duplicates. PRE-EXISTING (documented in v4 Phase 5 notes).
3. **[claude-only] PKCE verifier cookie without integrity protection** — Requires combined cookie injection + state replacement. Low risk. PRE-EXISTING.
4. **[claude-only] Rate limiter counter increment behavior** — Reviewer self-notes: "No fix needed." Correct for fixed-window.
5. **[claude-only] Redis Retry-After precision** — Approximate. Acceptable. PRE-EXISTING.
6. **[claude-only] Token introspection JWT-only** — Returns inactive for refresh tokens. Technically compliant. Document behavior.
7. **[claude-only] OIDC Discovery missing some recommended fields** — Reviewer didn't verify actual content. Discovery already includes claims_supported, scopes_supported, etc. (added in v5 Phase 3+5).
8. **[claude-only] Token response scope inclusion** — Reviewer says "No action required."
9. **[claude-only] Username TOCTOU** — Reviewer says "already handled correctly via DB constraint. No change needed."
10. **[claude-only] Schema double-quoting** — Reviewer says "No action required."
11. **[claude-only] Keys/KeySet type alias** — Cleanup item → Phase 6 (codebase organization).
12. **[claude-only] Test coverage gaps (8 identified)** — (a) auth code reuse: FIXED (9604e72). (b) concurrent consent: low priority. (c) account merge verified_email: future work. (d) BCL delivery: future work. (e) webhook delivery worker: future work. (f) prompt=consent: FALSE POSITIVE — test exists (`prompt_consent_with_auto_approve_issues_code`). (g) dual auth methods: low priority. (h) scope downscoping on refresh: documented as out-of-scope.

### Notes

1. Authorization code reuse detection not implemented (RFC SHOULD, not MUST)
2. Account merge with multiple matching users handled correctly
3. Soft-delete does not cascade to consumed_refresh_tokens (no PII)
4. Maintenance worker does not clean consumed_refresh_tokens
5. Token rotation preserves nonce indefinitely (design choice)
6. Authorization code issuance duplicated in authorize/consent_decision → Phase 6 candidate
7. Error type mapping is correct per RFC 6749/6750
8. Router composition is clean and well-organized
9. Migration ordering is well-managed
10. Config validation is thorough
11. Dockerfile is production-ready

## Summary

Exhaustive review found 0 new major issues (both MAJORs are pre-existing accepted tradeoffs). 1 genuine test gap addressed (auth code reuse test added). Multiple pre-existing observations re-confirmed as acceptable. Codebase is in excellent shape for the Phase 5 milestone.
