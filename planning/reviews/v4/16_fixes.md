# Fixes for Phase 9 Review — 2026-02-23

## 1. Session token rejection (MAJOR-01)
- Added `claims.aud == issuer` check to `introspect` handler, returning `{"active": false}`
- Added `introspect_rejects_session_token` integration test
- Commit: bf7dcae

## 2. Rate limit tier (MINOR-01)
- Added `/oauth/introspect` to Auth tier in `classify_path`
- Commit: bf7dcae

## 3. Cache-Control headers (MINOR-02)
- Changed `introspect` return type to `impl IntoResponse`
- All responses (active and inactive) now include `Cache-Control: no-store` and `Pragma: no-cache`
- Added `introspect_returns_cache_control_headers` integration test
- Commit: bf7dcae

## Accepted / Not Fixed

- MAJOR-02 (cross-client introspection): Intentional resource-server model. Documented.
- MINOR-03 (URL-decode Basic auth): Client credentials are server-generated, no special chars.
- MINOR-04 (base64 fallback order): Functionally correct, harmless.
