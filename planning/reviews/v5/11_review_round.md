# Phase 4 Review Round 1 — 2026-02-23

**Models**: Claude subagent only (Codex rate-limited, Gemini CLI error)
**Context**: ~156k tokens
**Scope**: Phase 4 WWW-Authenticate implementation (error.rs, jwt.rs, oauth_provider.rs, integration tests)

## Findings

### Major
None.

### Minor

1. **Issuer not escaped in WWW-Authenticate realm quoted-string** [claude-only]
   - `www_authenticate_value()` in `error.rs` used `format!("Bearer realm=\"{}\"", issuer)` without escaping `\` or `"` in the issuer value
   - If issuer contained those characters, the header would be malformed per RFC 7230 §3.2.6
   - **Fixed in commit a495903**

2. **`last_expired` fallback uses last-key-wins semantics** [claude-only]
   - `verify_token()` fallback path in `jwt.rs` set `last_expired = matches!(...)` each iteration, overwriting the previous value
   - During key rotation, if the correct key reports ExpiredSignature but a later key reports a different error, `last_expired` would be false — misclassifying an expired token as invalid
   - Should use `any_expired |=` (OR semantics) so any expired signature on any key is correctly reported
   - **Fixed in commit a495903**

3. **No integration test for expired token WWW-Authenticate header** [claude-only]
   - Existing tests covered missing token, invalid token, session token, and insufficient scope — but not expired tokens
   - Expired tokens should include `error_description="token expired"` in the WWW-Authenticate header, which was untested
   - **Fixed in commit a495903** — added `userinfo_expired_token_www_authenticate` test

### Notes

1. `bearer_error_response` `.unwrap()` on header value parse — safe for URL issuers, theoretically panics on control chars in issuer
2. `ExpiredToken` error_code → "invalid_token" — correct per RFC 6750 §3.1
3. `Forbidden` → "insufficient_scope" — correct per RFC 6750 §3.1
4. `Unauthenticated` → realm-only header — correct per RFC 6750 §3.1 (no error code for missing auth)
5. WWW-Authenticate correctly scoped to userinfo only (the only Bearer-protected endpoint)
6. userinfo inner/outer refactoring pattern is clean, ensures all error paths get the header
7. `verify_token` leeway=0 is a pre-existing decision; fine for single-server, worth documenting if multi-server planned
