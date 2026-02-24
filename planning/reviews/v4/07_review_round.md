# Review Round — Phase 6 (UserInfo Endpoint) — 2026-02-23

**Models**: Claude subagent (Gemini failed: exit 127, command not found)
**Context**: ~130k tokens
**Scope**: Post-Phase 6 implementation review

## Findings

### Major

1. **[claude-only] UserInfo does not require `openid` scope** — OIDC Core 1.0 §5.3 mandates that UserInfo is only accessible when the `openid` scope was granted. Missing check allows any client-scoped token to hit UserInfo.
   - **Fixed in**: 1ab2431

### Minor

2. **[claude-only] Case-sensitive Bearer prefix** — RFC 6750 §2.1 says the "Bearer" scheme is case-insensitive. `strip_prefix("Bearer ")` rejects "bearer " or "BEARER ".
   - **Fixed in**: 1ab2431

3. **[claude-only] Missing `email_verified` claim** — OIDC §5.1 recommends `email_verified` when `email` is returned. Since all emails come from verified OAuth providers, returning `true` is correct.
   - **Fixed in**: 1ab2431

4. **[claude-only] Non-deterministic email ordering** — `find_oauth_links_by_user` had no ORDER BY, making the email returned from UserInfo non-deterministic for users with multiple providers.
   - **Fixed in**: 1ab2431

5. **[claude-only] Returns 404 for deleted users** — UserInfo should return 401 (invalid token) when the token's subject has been deleted, not 404 (which leaks information about user existence/deletion).
   - **Fixed in**: 1ab2431

6. **[claude-only] `claims_supported` missing `email_verified`** — Discovery document didn't list the `email_verified` claim.
   - **Fixed in**: 1ab2431

### Notes

7. **[claude-only] `profile`/`email` not in `scopes_supported`** — Standard OIDC scopes `profile` and `email` don't appear in the discovery document unless configured. This is by design: riley_auth uses a whitelist approach where all scopes (including standard OIDC ones) must be explicitly defined in config. See review_notes_README.md.

8. **[claude-only] Missing `WWW-Authenticate` header** — RFC 6750 §3.1 says resource endpoints SHOULD include `WWW-Authenticate: Bearer` on 401 responses. Low priority; most clients don't depend on this.

9. **[claude-only] Audience isolation** — The `aud != issuer` check is excellent security design, preventing session tokens from being reused at the UserInfo endpoint.
