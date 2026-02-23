# Review Round 12 — Phase 3 Follow-up

**Date:** 2026-02-23
**Models:** Claude subagent only (Codex: no output, Gemini: path error — degraded round)
**Context:** ~93k tokens (full codebase via dirgrab)
**Scope:** Verify Phase 3 fixes from round 10

## Findings

### Major

**M1: Silent rate limit bypass when IP extraction fails** [claude-only]
- Both middlewares silently pass requests through when `extract_ip` returns None
- Unreachable in production (ConnectInfo always present), but monitoring gap
- **Fix:** Added `tracing::warn!` in both memory and Redis middleware (f13fe3b)

### Minor

**m1: Module doc comment slightly inaccurate about CORS** [claude-only]
- Comment said "429 responses lack CORS headers" — actually they get CORS headers via layer ordering
- OPTIONS bypass is correct but for a different reason (browsers treat 429 on preflight as network error)
- **Fix:** Updated comment (f13fe3b)

**m2: Redundant `x-ratelimit-after` header** [claude-only]
- Non-standard header duplicates standard `retry-after`
- **Fix:** Removed, keeping only standard `retry-after` (f13fe3b)

**m3: Percent-encoded paths could bypass tier classification** [claude-only]
- `/auth%2Fgoogle` would not match `/auth/` prefix
- Non-exploitable: Axum would 404 such requests
- **Decision:** Noted, no code change needed

**m4: Eviction frequency equals window size (2x linger)** [claude-only]
- Expired entries can linger up to 2x window before pruning
- Acceptable tradeoff for simplicity
- **Decision:** Noted, current approach is sound

### Notes

- Path classification verified correct for all actual routes
- Memory eviction logic verified sound
- Retry-After accuracy verified correct in both backends
- Redis Lua script verified correct and atomic
- JSON 429 responses use consistent Error::RateLimited format
- Overall assessment: "fixes are correct and complete"
