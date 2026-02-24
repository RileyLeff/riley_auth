# Review Round — Phase 6+7 Combined — 2026-02-23

**Models**: Claude subagent (Gemini failed: no output, only MCP startup logs)
**Context**: ~120k tokens
**Scope**: Phase 6 fix verification + Phase 7 implementation review

## Findings

### Major

1. **[claude-only] MAJOR-1: 307 instead of 302 redirect** — `Redirect::temporary()` produces 307 Temporary Redirect, but RFC 6749 §4.1.2 specifies 302 Found. Both error and success redirects affected.
   - **Fixed in**: fcd6b5a

2. **[claude-only] MAJOR-2: Consent check before authentication** — The consent check (`!client.auto_approve`) ran before the authentication check. Unauthenticated users hitting non-auto-approve clients got `consent_required` instead of `login_required`.
   - **Fixed in**: fcd6b5a

3. **[claude-only] MAJOR-3: `scopes_supported` missing `profile` and `email`** — Discovery document only listed `openid` + config-defined scopes. Standard OIDC scopes `profile` and `email` were missing.
   - **Fixed in**: fcd6b5a

4. **[claude-only] MAJOR-4: `profile` and `email` scopes unrequestable** — Only `openid` was treated as protocol-level. `profile` and `email` required config definitions and client `allowed_scopes`, making them unrequestable through the normal OAuth flow.
   - **Fixed in**: fcd6b5a

### Minor

5. **[claude-only] MINOR-2: Scope rejection tests missing state verification** — `oauth_rejects_unauthorized_scope` and `oauth_rejects_unknown_scope` didn't pass or verify `state`.
   - **Fixed in**: fcd6b5a

6. **[claude-only] MINOR-3: No test for unsupported code_challenge_method** — Only missing `code_challenge` was tested, not `code_challenge_method=plain`.
   - **Fixed in**: fcd6b5a (new test `authorize_error_redirect_unsupported_pkce_method`)

### Notes (not actioned)

7. **[claude-only] MINOR-1: User-controlled input in error_description** — Scope names from user input appear in redirect error_description. URL-encoded by `query_pairs_mut`, so no direct XSS. Client's responsibility to escape when rendering.

8. **[claude-only] MINOR-4: Missing WWW-Authenticate header** — Already documented in review_notes_README.md from Phase 6 review. Low priority.

## Phase 6 Fix Verification

All Phase 6 fixes confirmed correct:
- Audience isolation, openid scope requirement, case-insensitive Bearer prefix
- Client existence check, discovery document updates, updated_at format
