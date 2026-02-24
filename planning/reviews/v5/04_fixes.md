# Fixes for Review Round 2 — 2026-02-24

**Commit**: 11713a4

## Minor Fixes

- **m1**: Integration test setup tokens now include `kid` in JWT header, matching production behavior
- **m2**: `verify_token` adds explicit `header.alg != entry.algorithm` early rejection as defense-in-depth
- **N1**: Added comments explaining `validate_aud = false` rationale in both kid-matched and fallback paths

## Test Results

34 unit + 111 integration = 145 tests passing.
