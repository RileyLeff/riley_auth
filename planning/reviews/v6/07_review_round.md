# Review Round 7 — Phase 4 Exhaustive R2 (2026-02-24)

**Models**: Claude subagent only (Codex usage limit, Gemini exit 13)
**Context**: ~190k tokens (full codebase)
**Focus**: Verify R1 fixes, fresh full-codebase review

## Fix Verification

All 3 Round 1 fixes verified correct and complete:
- **M2 (rate limiter cap)**: `MAX_ENTRIES_PER_TIER = 100_000`, existing IPs continue at capacity, periodic eviction works
- **P4-4 (OIDC timeout)**: 10s timeout on `oauth_http` client, applies to all discovery + runtime requests
- **P4-5 (client reuse)**: Single `oauth_http` built at startup, stored as `oauth_client` in `AppState`, passed to `exchange_code`/`fetch_profile`

## Findings

### Major
None.

### Minor
1. No pagination on `list_clients` admin endpoint (cosmetic, unlikely >1000 clients)
2. No pagination on `list_webhooks` admin endpoint (same)

### Notes
- OAuth `oauth_client` has no SSRF protection — correct for deployer-configured URLs (not user-controlled)
- Two `reqwest::Client` fields in AppState — naming could be clearer but usage is correct
- Backchannel logout dispatches per-user (not per-session) — correct given no `sid` claim
- `CorsLayer::permissive()` for `["*"]` — warning present, acceptable for dev-only config
- Webhook HMAC secret in plaintext — standard pattern, necessary for signing
- Token exchange sends client_secret in POST body — spec-compliant
