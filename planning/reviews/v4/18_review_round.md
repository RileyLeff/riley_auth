# Review Round 18 — Phase 10 Standard Review R1

**Date:** 2026-02-23
**Models:** Claude subagent only (~138k tokens)
**Scope:** Full codebase, focused on Phase 10 OIDC Back-Channel Logout

## Findings

### Major

**M1. Race condition: tokens deleted before backchannel logout query** [claude-only]
- **Verdict:** FALSE POSITIVE. The code explicitly dispatches backchannel logout BEFORE deleting tokens. Comments in auth.rs read "dispatch backchannel logout BEFORE deleting tokens". The reviewer misread the ordering.

**M2. Logout token `aud` claim incorrect** [claude-only]
- **Verdict:** Self-downgraded by reviewer. The `client_id` string IS the correct OIDC `aud` value.

**M3. `revoke_session` doesn't dispatch backchannel logout** [claude-only]
- **Verdict:** Downgraded to note. `revoke_session` handles session tokens (client_id IS NULL), which are separate from OAuth client grants. Backchannel logout is correctly dispatched from auth_logout_all, auth_logout, and soft_delete_user where client-bound tokens exist.

### Minor (actionable)

**m1. `backchannel_logout_session_required` stored but `sid` never populated** [claude-only]
- Discovery advertised `backchannel_logout_session_supported: true` but sid is never sent
- **Action:** Fixed in 2c76c1a — set to false, reject session_required=true registrations

### Minor (notes, no action needed)

**m3. JWT reuse on retries** — Only affects >4 retry attempts (total backoff exceeds 120s token lifetime). Default is 3 retries (13s total). Acceptable.

**m5. No backpressure on spawned tasks** — Fire-and-forget is intentional per architecture (time-sensitive). Client count with backchannel URIs is small in practice.

### Notes

- m2 (SSRF gap): Self-downgraded. SsrfSafeResolver + check_url_ip_literal cover both paths.
- m4 (HTTPS validation on update): No update endpoint exposed. db function exists but isn't callable via API.
- m6 (UUIDv4 for jti): Appropriate — jti needs uniqueness, not ordering.
- N1-N7: Discovery accuracy, test coverage observations, design tradeoff notes. See full review.

## Summary

| Severity | Count | Actionable |
|----------|-------|------------|
| Major | 0 (3 raised, all false positives/self-downgraded) | 0 |
| Minor | 1 actionable (m1 sid/session) | Fixed (2c76c1a) |
| Note | 6 | 0 |
