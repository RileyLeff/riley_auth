# Fixes for Review Round 23

**Commit:** 9b6ce46

## Fixes Applied

1. **M-COR-1 / M-OIDC-6 / M-OIDC-7: Token endpoint error codes**
   - Added `Error::UnsupportedGrantType` variant (error code: "unsupported_grant_type")
   - Changed `InvalidAuthorizationCode` error code from "invalid_authorization_code" to "invalid_grant" per RFC 6749 §5.2
   - Token endpoint now returns `UnsupportedGrantType` instead of `BadRequest` for unknown grant types
   - Updated existing test assertion from "invalid_authorization_code" to "invalid_grant"

2. **M-OIDC-3: Discovery document missing fields**
   - Added `response_modes_supported: ["query"]` to openid-configuration
   - Added `claims_parameter_supported: false`
   - Added `request_parameter_supported: false`
   - Added `request_uri_parameter_supported: false`

3. **M-OIDC-1: ID Token email claims**
   - Added `email` and `email_verified` optional fields to `IdTokenClaims`
   - Updated `sign_id_token()` to accept email parameters
   - Both authorization_code and refresh_token flows now look up user's email from oauth_links when "email" scope is granted
   - Same lookup logic as UserInfo endpoint (first oauth_link with a provider_email)
   - Updated unit tests to cover both with-email and without-email cases

All 187 tests pass (35 core + 23 API unit + 129 integration).
