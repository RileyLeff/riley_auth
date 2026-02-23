# Phase 8 R1 Fixes

Fixes for findings from 19_review_round.md (Phase 8 exhaustive R1).

## Major Fix

### 1. SQL Injection via Schema Name
- **File**: `crates/riley-auth-core/src/db.rs`
- **Fix**: Added validation that schema name matches `[a-zA-Z_][a-zA-Z0-9_]*` before interpolating into `SET search_path TO`. Returns `Error::Config` with descriptive message if invalid.

## Minor Fixes

### 2. Wire `behind_proxy` to Rate Limiter
- **Files**: `crates/riley-auth-api/src/routes/mod.rs`, `crates/riley-auth-api/src/server.rs`, `crates/riley-auth-api/tests/integration.rs`
- **Fix**: `router()` now accepts `behind_proxy: bool`. When true, uses `SmartIpKeyExtractor` (checks `X-Forwarded-For`, `X-Real-IP`, `Forwarded` headers, falls back to peer IP). When false, uses default `PeerIpKeyExtractor`.

### 3. Dockerfile Non-Root User
- **File**: `Dockerfile`
- **Fix**: Added `useradd -m appuser` and `USER appuser` directive before `CMD`.

### 4. Token Revocation Error Logging
- **File**: `crates/riley-auth-api/src/routes/oauth_provider.rs`
- **Fix**: Changed `let _ =` to `if let Err(e) = ... { tracing::warn!(...) }` so DB errors during token revocation are logged for observability while still returning 200 per RFC 7009.

## Verification

- `cargo test --workspace`: 15 unit tests pass, 21 integration tests ignored (expected)
- `scripts/test-integration.sh`: All 21 integration tests pass
