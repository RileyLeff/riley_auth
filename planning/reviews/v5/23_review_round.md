# Review Round 23 — Phase 8 Exhaustive Review R1 (Pre-Conformance)
**Date:** 2026-02-24
**Models:** Claude subagent only (Codex rate-limited, Gemini crashed)
**Scope:** Full codebase exhaustive review for OIDC Basic OP conformance readiness

## Findings

### Major (4)

1. **[M-OIDC-1][claude-only] ID Token missing email/email_verified claims when "email" scope granted** — Only returned from UserInfo. OIDC Core 1.0 §5.4 says ID Token SHOULD include email claims when email scope is granted. *Fixed: 9b6ce46*

2. **[M-OIDC-3][claude-only] Discovery document missing response_modes_supported** — Conformance suite checks for this field. Also missing claims_parameter_supported, request_parameter_supported, request_uri_parameter_supported. *Fixed: 9b6ce46*

3. **[M-COR-1][claude-only] Token endpoint error codes non-compliant** — InvalidAuthorizationCode returned "invalid_authorization_code" instead of "invalid_grant" per RFC 6749 §5.2. Unsupported grant_type returned "bad_request" instead of "unsupported_grant_type". *Fixed: 9b6ce46*

4. **[M-OIDC-6/M-OIDC-7][claude-only] Token endpoint error codes (same root cause as M-COR-1)** — Fixed via UnsupportedGrantType error variant and InvalidAuthorizationCode -> "invalid_grant" mapping. *Fixed: 9b6ce46*

### Minor (8)

1. [m-OIDC-4] auth_time with prompt=consent on auto_approve clients — Intentional behavior, documented in tests. *Accepted.*
2. [m-OIDC-5] ID Token "aud" is string, not array — Spec-compliant for single audience. Array is safer but not required. *Accepted — revisit if conformance suite rejects.*
3. [m-SEC-2] Rate limiting bypass via IPv6 rotation — Real limitation, not critical for conformance. *Accepted — document as known limitation.*
4. [m-SEC-3] PKCE code_verifier length not validated — Won't cause incorrect behavior. *Accepted — add if conformance suite checks.*
5. [m-SEC-4] Redirect URIs not checked for fragment components — *Accepted — add validation later.*
6. [m-SEC-5] Webhook secrets stored in plaintext — Necessary for HMAC signing. *Accepted — defense-in-depth concern.*
7. [m-PROD-1] Health endpoint doesn't check DB — Liveness probe is intentionally lightweight. *Accepted.*
8. [m-PROD-2] No configurable shutdown timeout — *Accepted — not blocking.*

### Notes (10)

1. [n-OIDC-8] acr_values_supported not implemented — Not required for Basic OP.
2. [n-OIDC-9] at_hash claim not included — Optional for authorization code flow.
3. [n-OIDC-10] Logout token aud correctly uses client_id string.
4. [n-SEC-0] Constant-time comparison correctly used at all 4 secret-comparison sites.
5. [n-SEC-6] Cookie security flags appropriate (HttpOnly, SameSite=Lax, configurable domain).
6. [n-SEC-7] All DB queries use parameterized sqlx queries.
7. [n-SEC-8] SSRF protection comprehensive (5-layer defense).
8. [n-COR-6] Scope validation three-layer (OIDC + client + config).
9. [n-COR-7] Authorization code one-time use correctly enforced via atomic UPDATE.
10. [n-PROD-5] Configuration validation thorough.

## Summary

4 major findings, all fixed in commit 9b6ce46. Proceeding to R2 for verification.
