# Fixes for Review Round 25

**Commit:** 85c7605

## Fixes Applied (Minor)

1. **M-R2-1: Discovery document test assertions**
   - Added assertions for response_modes_supported, claims_parameter_supported, request_parameter_supported, request_uri_parameter_supported to oidc_discovery_document test

2. **M-R2-2: Email claims in ID token integration test**
   - New test `id_token_includes_email_claims_when_email_scope_granted` in oidc.rs
   - Full authorize→token flow with "openid email" scope
   - Verifies email and email_verified claims in decoded ID token JWT
   - Also verifies claims persist through refresh token rotation

3. **M-R2-3: Unsupported grant type test**
   - New test `token_endpoint_unsupported_grant_type` in oauth.rs
   - Sends grant_type="client_credentials" to POST /oauth/token
   - Asserts 400 status and error="unsupported_grant_type"

4. **M-R2-4: Email lookup ordering** — No fix needed, verified ORDER BY exists

All 191 tests pass (35 unit + 23 core API + 133 integration).
