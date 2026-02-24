# Review Round 1 (Phase 2) — 2026-02-24

**Models**: Claude (Codex rate-limited, Gemini exit 13)
**Context**: ~152k tokens
**Phase**: 2 — Token Endpoint Auth: client_secret_basic

## Findings

### Major

1. **M1** [claude-only] `extract_client_credentials` missing percent-decoding of client_id/client_secret per RFC 6749 §2.3.1. After base64-decode and split on ':', values must be percent-decoded.
   - File: `crates/riley-auth-api/src/routes/oauth_provider.rs`, `extract_client_credentials()`
   - **Fixed**: d5a121a — added `percent_encoding::percent_decode_str()` + UTF-8 validation

### Minor

1. **m2** [claude-only] Base64 decode order tries URL_SAFE_NO_PAD first, STANDARD second. RFC 7617 specifies STANDARD base64.
   - **Fixed**: d5a121a — swapped order (STANDARD first, URL_SAFE_NO_PAD fallback)

2. **m3** [claude-only] No whitespace trimming on base64 portion. RFC 7235 §2.1 allows OWS between scheme and credentials.
   - **Fixed**: d5a121a — added `.trim()` on base64 payload

3. **m6** [claude-only] No negative test for missing credentials on token/revoke endpoints (fields now Optional).
   - **Fixed**: d5a121a — added `token_and_revoke_reject_missing_credentials` test

### Notes

1. **N1** [claude-only] Non-Basic Authorization headers silently fall through to POST body. Intentional tradeoff — pragmatic for interop.
2. **N2** [claude-only] Discovery document test coverage is complete across all three endpoints.
3. **N3** [claude-only] API consistency across token/revoke/introspect is clean — same pattern everywhere.
4. **N4** [claude-only] String slicing on auth header is safe due to prior ASCII validation.
5. **N5** [claude-only] Implementation matches architecture.md spec precisely.
