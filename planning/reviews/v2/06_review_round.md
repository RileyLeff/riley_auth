# Review Round 2 — Phase 3 Convergence Check (2026-02-22)

**Models**: Gemini, Claude
**Context**: ~63k tokens

## Round 1 Fix Verification

Both models confirmed all four round 1 fixes are correctly implemented with no regressions:
1. IP validation via std::net::IpAddr — correct
2. User-Agent truncation to 512 chars — correct (but see M1 below)
3. 404 for non-existent session revocation — correct
4. last_used_at via touch_refresh_token — correct
5. "openid" in OIDC scopes_supported — correct

## Findings

### Major

**1. [claude-only] User-Agent truncation can panic on multi-byte UTF-8**
File: `crates/riley-auth-api/src/routes/auth.rs`, `issue_tokens`
`&ua[..512]` panics if byte 512 falls inside a multi-byte UTF-8 sequence.
**Action**: Use `ua.floor_char_boundary(512)` (stable since Rust 1.82, MSRV is 1.88).

### Minor

Same as round 1 deferred items (CLI scope validation, cleanup task scheduling, display_name byte vs char). No new minor issues.

### Notes

- Gemini: 0 major, 0 minor (clean round)
- Claude: 1 major (UTF-8 truncation), reiterated deferred minor items
- Proxy IP trust assumptions documented in config comments
