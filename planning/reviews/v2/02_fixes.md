# Review Round 1 Fixes (2026-02-22)

**Commit**: cf0740e

## Major Fixes

### 1. Scope name format validation [M1, M3]
- Added `validate_scope_name()` function in `config.rs` — enforces `^[a-z][a-z0-9:._-]*$`
- Config parse validates all scope definition names
- Admin API `register_client` validates each `allowed_scopes` entry for format AND existence in config
- Prevents whitespace injection, special characters, and empty scope names
- Added unit test `scope_name_validation` and integration test `admin_rejects_invalid_scope_name`

### 2. Scope deduplication [M2, consensus]
- Changed `authorize` endpoint to collect requested scopes into `BTreeSet<&str>` instead of `Vec<&str>`
- Also applied to `consent` endpoint for consistency
- Duplicate scopes in the request are now silently deduplicated
- Added integration test `oauth_deduplicates_scopes` verifying JWT and token response

### 3. Client allowed_scopes validated against config [M5, consensus]
- Admin `register_client` now checks each scope in `allowed_scopes` against `config.scopes.definitions`
- Returns 400 for undefined scopes
- Added integration tests `admin_rejects_undefined_scope` and `admin_register_client_with_scopes`

### 4. Constant-time OAuth state comparison [M4, claude-only]
- Both `auth_callback` and `link_callback` now use `subtle::ConstantTimeEq` for state comparison
- Matches existing pattern used for client secret verification

### 5. Consent endpoint validation [m6]
- Consent endpoint now returns errors for unknown/disallowed scopes instead of silently dropping them
- Matches the authorize endpoint's behavior for consistency
- Added integration test `consent_endpoint_rejects_disallowed_scope`

## Deferred Items (documented in review_notes_README.md)

- [M3] Admin self-deletion — noted as operational risk, not blocking
- [m1] Regex recompilation — performance note, not blocking
- [m3-m6] Client name validation, redirect URI format validation, OAuthClient Serialize, scope count limit — minor hardening, can address in future
- [m7] unsafe Sync in tests — code quality, non-blocking
- [m8] Session metadata columns — designed for Phase 3, not a bug

## Test Results

- 17 unit tests pass (1 new: `scope_name_validation`)
- 32 integration tests pass (5 new: dedup, admin scopes, undefined scope, invalid name, consent disallowed)
