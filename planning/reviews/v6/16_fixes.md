# Phase 6 Review Round 2 — Fixes

**Commit**: `bad5a74`

## Fixed

### Minor
- m1: Added explicit `[oauth]` section header in example TOML before account_merge_policy/login_url/consent_url

### Notes (also fixed)
- N3: Added `[oauth]` row to README configuration table
- N4: Updated CLAUDE.md to reference ES256/RS256 and v6 architecture

### Notes (not fixed — by design)
- N2: `GET /auth/link/{provider}/callback` intentionally omitted from README — internal callback, consistent with existing convention

## Test Results

All 226 tests pass (41 core unit + 27 API unit + 158 integration).
