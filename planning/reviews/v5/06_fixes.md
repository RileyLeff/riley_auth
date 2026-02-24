# Fixes for Phase 2 Review Round 1 — 2026-02-24

**Commit**: d5a121a

## Major Fixes

- **M1**: Added `percent_encoding::percent_decode_str()` + UTF-8 validation on both client_id and client_secret after base64 decode in `extract_client_credentials()`. Added `percent-encoding = "2"` dependency.

## Minor Fixes

- **m2**: Swapped base64 decode order — STANDARD first (RFC 7617), URL_SAFE_NO_PAD as fallback
- **m3**: Added `.trim()` on base64 payload for RFC 7235 OWS robustness
- **m6**: Added `token_and_revoke_reject_missing_credentials` integration test

## Test Results

34 unit + 116 integration = 150 tests passing.
