# Review Round 23 — Phase 7 Exhaustive R3 (2026-02-23)

**Models**: Gemini, Claude (Opus 4.6)
**Context**: ~100k tokens (full codebase)
**Scope**: Exhaustive review R3 — convergence round 1

## Findings

### Major

None.

### Minor

**1. [gemini-only] Race condition in webhook delivery logging during user deletion**
- **File**: `crates/riley-auth-core/src/db.rs` — `soft_delete_user()`
- **Description**: A background worker that claimed an outbox entry before the scrub runs could insert a new delivery log with PII after `soft_delete_user` commits. The PII would persist until the 7-day maintenance cleanup.
- **Assessment**: Standard distributed systems tradeoff. Fully closing this race requires cross-process locking. The 7-day cleanup handles the edge case. Documented in review_notes_README.md.

**2. [gemini-only] Scope loss on session refresh**
- **File**: `crates/riley-auth-api/src/routes/auth.rs` — `auth_refresh`
- **Description**: Session refresh issues new token with empty scope list `&[]`. If scopes were ever added to session tokens, they'd be lost on first refresh.
- **Assessment**: Session tokens currently don't use scopes (they rely on `role` and `aud == issuer`). This is a latent issue only relevant if session scopes are added in the future. No fix needed now.

**3. [claude-only] logout-all deletes client-bound refresh tokens too**
- **File**: `crates/riley-auth-api/src/routes/auth.rs` — `auth_logout_all`
- **Description**: `delete_all_refresh_tokens` has no `client_id IS NULL` filter, so it revokes OAuth client-bound tokens alongside session tokens.
- **Assessment**: Already documented as intentional "nuclear logout" behavior in review_notes_README.md (Phase 7 R1).

**4. [claude-only] Setup token binding check is tautological**
- **File**: `crates/riley-auth-api/src/routes/auth.rs` — `decode_setup_token`
- **Description**: The binding is computed from fields embedded in the same JWT it validates. Since the JWT is RS256-signed, the check adds zero security beyond the signature.
- **Assessment**: Already documented in review_notes_README.md (Phase 7 R1, item #14). Dead code, not a vulnerability.

### Notes

**5. [gemini-only] Link suggestion flow incompleteness**
- No API endpoint accepts a setup token to confirm account linking for already-authenticated users. The frontend must initiate a standard `/auth/link/{provider}` flow.

**6. [gemini-only] Misleading error on link collision in auth_setup**
- Unique constraint violation on `oauth_links` maps to `Error::UsernameTaken` instead of a provider identity conflict error.

**7. [claude-only] In-memory rate limiter count increments even when rate-limited**
- Counter grows unboundedly for sustained attacks. Negligible impact (u64, window resets). "Remaining: 0" in headers is correct behavior.

**8. [claude-only] Constant-time comparison on hashes confirmed correct**
- SHA-256 hashing is not timing-vulnerable, ct_eq prevents residual leakage. No issue.

**9. [claude-only] OAuth state comparison uses ct_eq correctly**
- Both values are 43-byte base64url strings. Length mismatch handling is correct.

**10. [claude-only] Webhook outbox cleanup doesn't handle stuck "processing" entries**
- Same as R2 finding #5. Design limitation, not a bug. Graceful shutdown drains semaphore.

**11. [claude-only] delete_account dispatches webhook AFTER soft-delete — confirmed correct**
- The user.deleted event contains only UUID (not PII) and is inserted after the scrub transaction.

**12. [gemini-only] Engineering highlights**
- Immediate revocation via DB role check on every request
- Refresh token isolation between session and client contexts
- SSRF robustness (SsrfSafeResolver + IP literal check + redirect disable)
- Safe anonymization via `_{random}` prefix

## Verdict

**0 majors found. Convergence round 1 complete.**

All minors are either:
- Previously documented design decisions (logout-all nuclear, setup token binding)
- Standard distributed systems tradeoffs (delivery race condition)
- Latent issues only relevant for future features (scope loss on session refresh)

Both models independently concluded the codebase is ready for release.

Running R4 to confirm convergence (2 consecutive rounds with 0 majors required).
