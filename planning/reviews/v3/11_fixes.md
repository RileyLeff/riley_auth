# Fixes for Review Round 10 — Phase 3

**Commit:** a05adf4

## Major Fixes

**M1: Path classification doesn't match actual routes** — Fixed
- Rewrote `classify_path` with segment-based matching: `/auth/{provider}`, `/auth/{provider}/callback`, `/auth/link/{provider}`, `/auth/link/{provider}/callback` now correctly classified as Auth tier
- Known non-provider segments (`me`, `logout`, `logout-all`, `sessions`, `link`, `setup`, `refresh`) excluded from wildcard matching
- Added trailing slash normalization before classification
- Tests expanded: separate test cases for exact matches, provider routes, link routes, trailing slashes

**M2: Unbounded memory growth** — Fixed
- Added `TierState` struct wrapping `HashMap` + `last_prune: Instant`
- Eviction runs every `window_secs` via `HashMap::retain()`, removing entries whose window has expired

## Minor Fixes

**m1-m4: Missing Auth tier classifications** — Fixed (subsumed by M1 rewrite)
- `/auth/{provider}` (login redirect), `/oauth/revoke`, `/auth/refresh`, `/auth/link/*` all now Auth tier

**m5: Trailing slash bypass** — Fixed
- Path normalized by stripping trailing slash (except root "/") before any matching

**m6: Inaccurate Retry-After** — Fixed
- In-memory: calculates `window_secs - elapsed` (clamped to >= 1)
- Redis: Lua script now returns `{count, TTL}` tuple; TTL used for Retry-After header

**m7: Plain text 429 response** — Fixed
- Both middlewares now use `Error::RateLimited.into_response()` → JSON `{"error":"rate_limited","detail":"rate limited"}`

**m8: Stale tower_governor comment** — Fixed
- `server.rs:117` updated to "rate limit middleware"

**m9: Missing example.toml section** — Fixed
- Added commented `[rate_limiting]` block with all tier defaults

## Tests

All 100 tests pass (36 unit + 56 integration + 8 Redis).
