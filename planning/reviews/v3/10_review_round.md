# Review Round 10 — Phase 3 (Tiered Rate Limiting)

**Date:** 2026-02-23
**Models:** Codex, Gemini, Claude subagent (all 3 participated)
**Context:** ~93k tokens (full codebase via dirgrab)
**Scope:** Phase 3 standard review — Steps 3.1-3.4 (config, middleware, CORS exemption, tests)

## Findings

### Major

**M1: Path classification doesn't match actual routes** [consensus: all 3]
- `classify_path` checks `/auth/callback/` but actual routes are `/auth/{provider}/callback`
- OAuth callbacks (e.g. `/auth/google/callback`) get Standard tier (60/min) instead of Auth (15/min)
- Tests reinforce the wrong pattern
- **File:** `crates/riley-auth-api/src/rate_limit.rs:40`

**M2: Unbounded memory growth in InMemoryTierLimiter** [consensus: all 3]
- `HashMap<IpAddr, WindowEntry>` entries are never evicted, only counter-reset
- Long-running server will exhaust memory; attacker can accelerate via IPv6 rotation
- **File:** `crates/riley-auth-api/src/rate_limit.rs:95`

### Minor

**m1: Login redirect `/auth/{provider}` not in Auth tier** [claude-only]
- OAuth redirect initiation should be Auth-tier (subsumes into M1 fix)

**m2: `/oauth/revoke` should be Auth tier** [claude-only]
- Token revocation is a sensitive auth operation

**m3: `/auth/refresh` should be Auth tier** [claude-only]
- Token refresh is a sensitive auth operation

**m4: Missing auth classification for linking callbacks** [gemini, claude]
- `/auth/link/{provider}` and `/auth/link/{provider}/callback` should be Auth tier

**m5: Trailing slash classification bypass** [gemini-only]
- `/oauth/token/` bypasses Auth tier and falls to Standard

**m6: Inaccurate Retry-After header** [consensus: Codex + Gemini]
- Returns full `window_secs` instead of remaining time in window
- Overstates required client backoff

**m7: 429 response is plain text, not JSON** [codex-only]
- Middleware returns `"rate limit exceeded"` while rest of API uses `Error::RateLimited` → JSON `{"error":"rate_limited","detail":"rate limited"}`

**m8: Stale tower_governor comment in server.rs** [consensus: Codex + Gemini]
- Line 117: `"so tower_governor / redis middleware can extract peer IP"`

**m9: Missing `[rate_limiting]` section in example.toml** [codex-only]
- New tier config is not documented in the example config

### Notes

- **OPTIONS flood:** OPTIONS bypass permits unthrottled OPTIONS requests. Acceptable — edge/proxy-level limits backstop this. [codex]
- **Redis fail-open:** Correct design — prevents Redis failure from locking out all users. [gemini, codex] (already in review_notes_README.md)
- **Lock contention:** `std::sync::Mutex` on global HashMap is fine for intended scale. [gemini]
- **Fixed-window boundary burst:** Known tradeoff. Acceptable. [claude]
- **IP spoofing (X-Forwarded-For leftmost):** Documented in example.toml with proxy config requirements. Valid approach. [gemini]
- **Silent rate limit bypass on missing IP:** Failing open is standard for rate limiters. [claude]
- **No middleware-level integration tests:** Unit tests cover path classification and limiter logic directly. [codex]
