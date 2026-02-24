# Fixes for Review Round 09 — Phase 6+7 — 2026-02-23

All 6 actionable findings fixed in a single commit.

## Fixes Applied

| Finding | Severity | Fix | Commit |
|---------|----------|-----|--------|
| #1 307→302 redirect | MAJOR | Use `(StatusCode::FOUND, [("location", ...)])` instead of `Redirect::temporary()` | fcd6b5a |
| #2 Consent before auth | MAJOR | Moved consent check after authentication + audience enforcement | fcd6b5a |
| #3 scopes_supported | MAJOR | Added "profile", "email" to hardcoded protocol-level scopes in discovery | fcd6b5a |
| #4 Unrequestable scopes | MAJOR | Made profile/email PROTOCOL_SCOPES with openid (bypass config + allowed_scopes) | fcd6b5a |
| #5 State in scope tests | MINOR | Added state param + assertion to both scope rejection tests | fcd6b5a |
| #6 Unsupported PKCE method | MINOR | New test `authorize_error_redirect_unsupported_pkce_method` | fcd6b5a |

## Notes Documented

- #7 (user input in error_description): Client's responsibility to escape
- #8 (WWW-Authenticate): Already documented, low priority

## Test Results

88 integration + 22 unit = 110 tests pass. 2 new tests added this round.
