# Fixes for Review Round 5 (2026-02-24)

**Commit:** `491e86b`

## Fixed

1. **M2: Rate limiter cap** — Added `MAX_ENTRIES_PER_TIER = 100_000` constant. When the map is at capacity and a new IP arrives, the request is denied (rate-limited). This prevents unbounded memory growth under distributed IP attacks.

2. **P4-4: OIDC discovery timeout** — Added `.timeout(Duration::from_secs(10))` to the `oauth_http` client in `server.rs`. Prevents indefinite blocking during server startup if an OIDC issuer is unresponsive.

3. **P4-5: Client reuse** — Changed `exchange_code()` and `fetch_profile()` to accept `&reqwest::Client` instead of creating a new one per call. Added `oauth_client` field to `AppState`. Updated both call sites in auth routes and test infrastructure.

## Not Fixed (Intentional)

- **M1**: Not a real bug — charset validation prevents double-quote injection. Added to review notes.
- **m3, m7**: False positives — `updated_at` and `SameSite` are already implemented.
- **m4**: Intentional — HMAC secrets must be available in raw form for signing.
- **m5, m6**: Nice-to-have improvements, not Phase 4 scope.
- **E3, E7, P4-1**: Legitimate but deferred to later phases or separate tickets.

## Test Results

All 226 tests passing after fixes:
- 41 core unit tests
- 26 API unit tests
- 158 integration tests
- 1 doc-test
