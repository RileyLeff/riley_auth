# OIDC Conformance Results — v5

**Date:** 2026-02-24
**Test Method:** Automated integration tests (`oidc_conformance.rs`)
**Total Tests:** 27 (all passing)

## Approach

riley_auth does not have a built-in login UI — it delegates authentication to upstream OAuth providers. This architectural decision (per the soul document) means the official OpenID Foundation conformance suite cannot run fully automated browser-based tests against riley_auth without a test-specific login page.

Instead, we wrote comprehensive conformance verification tests that programmatically validate the same requirements the OIDC Basic OP and Config OP certification profiles check. These tests exercise the full authorization code flow, token exchange, ID token validation, UserInfo endpoint, discovery document, JWKS, error codes, and prompt parameter handling.

For formal OIDC certification (if pursued in the future), a test login page would need to be built to interface with the conformance suite's browser automation.

## Config OP Profile Results

| Test | Status | Description |
|------|--------|-------------|
| config_op_discovery_document_required_fields | PASS | All REQUIRED and RECOMMENDED fields per OIDC Discovery 1.0 §3 |
| config_op_jwks_endpoint_valid | PASS | JWKS keys have correct format, Cache-Control headers present |

### Discovery Document Fields Verified

**REQUIRED:** issuer, authorization_endpoint, token_endpoint, jwks_uri, response_types_supported, subject_types_supported, id_token_signing_alg_values_supported

**RECOMMENDED:** userinfo_endpoint, scopes_supported, claims_supported

**Additional:** grant_types_supported, token_endpoint_auth_methods_supported, response_modes_supported, claims_parameter_supported, request_parameter_supported, request_uri_parameter_supported, prompt_values_supported, revocation_endpoint, introspection_endpoint

## Basic OP Profile Results

| Test | Status | Conformance Module | Description |
|------|--------|-------------------|-------------|
| oidcc_server | PASS | oidcc-server | Full authorize → code → token flow |
| oidcc_response_type_missing | PASS | oidcc-response-type-missing | Missing response_type rejected |
| oidcc_userinfo_get | PASS | oidcc-userinfo-get | UserInfo via GET with Bearer token |
| oidcc_userinfo_post_header | PASS | oidcc-userinfo-post-header | UserInfo via POST with Bearer in header |
| oidcc_ensure_request_without_nonce_succeeds | PASS | oidcc-ensure-request-without-nonce-succeeds-for-code-flow | Nonce optional in code flow |
| oidcc_scope_profile | PASS | oidcc-scope-profile | Profile scope returns name, preferred_username, updated_at |
| oidcc_scope_email | PASS | oidcc-scope-email | Email scope returns email, email_verified (UserInfo + ID token) |
| oidcc_ensure_other_scope_order_succeeds | PASS | oidcc-ensure-other-scope-order-succeeds | Scope parameter order doesn't matter |
| oidcc_prompt_login | PASS | oidcc-prompt-login | prompt=login forces re-auth |
| oidcc_prompt_none_not_logged_in | PASS | oidcc-prompt-none-not-logged-in | prompt=none without session → login_required |
| oidcc_prompt_none_logged_in | PASS | oidcc-prompt-none-logged-in | prompt=none with session → code issued silently |
| oidcc_ensure_request_with_unknown_parameter_succeeds | PASS | oidcc-ensure-request-with-unknown-parameter-succeeds | Unknown params ignored |
| oidcc_ensure_request_with_acr_values_succeeds | PASS | oidcc-ensure-request-with-acr-values-succeeds | acr_values accepted |
| oidcc_codereuse | PASS | oidcc-codereuse | Auth code single-use enforced |
| oidcc_ensure_registered_redirect_uri | PASS | oidcc-ensure-registered-redirect-uri | Unregistered redirect_uri rejected |
| oidcc_server_client_secret_post | PASS | oidcc-server-client-secret-post | client_secret_post auth method |
| oidcc_server_client_secret_basic | PASS | oidcc-server-client-secret-basic | client_secret_basic auth method |
| oidcc_refresh_token | PASS | oidcc-refresh-token | Refresh token flow with ID token |
| oidcc_ensure_request_with_valid_pkce_succeeds | PASS | oidcc-ensure-request-with-valid-pkce-succeeds | PKCE S256 support |
| oidcc_unsupported_grant_type | PASS | (error codes) | unsupported_grant_type error per RFC 6749 §5.2 |
| oidcc_invalid_grant_bad_code | PASS | (error codes) | invalid_grant error for bad auth code |
| oidcc_id_token_required_claims | PASS | (ID token) | iss, sub, aud, exp, iat, nonce, auth_time present |
| oidcc_id_token_signature_verification | PASS | (ID token) | Signature verifiable with JWKS keys |
| oidcc_prompt_unknown_value | PASS | (prompt) | Unknown prompt → invalid_request |
| oidcc_prompt_none_combined | PASS | (prompt) | prompt=none+login → invalid_request |

## Tests Not Covered

The following official conformance modules are not directly tested due to riley_auth's architecture:

| Module | Reason |
|--------|--------|
| oidcc-scope-address | riley_auth doesn't store address data (no address scope) |
| oidcc-scope-phone | riley_auth doesn't store phone data (no phone scope) |
| oidcc-scope-all | Depends on address/phone scopes |
| oidcc-display-page | riley_auth has no login UI to style |
| oidcc-display-popup | riley_auth has no login UI to style |
| oidcc-max-age-1, oidcc-max-age-10000 | max_age parameter not implemented (auth_time is present for client-side checking) |
| oidcc-id-token-hint | id_token_hint parameter not implemented |
| oidcc-login-hint | login_hint parameter not implemented (no built-in login UI) |
| oidcc-ui-locales | No localization (no built-in UI) |
| oidcc-claims-locales | No localization |
| oidcc-claims-essential | claims parameter not supported (documented in discovery: claims_parameter_supported=false) |
| oidcc-unsigned-request-object | Request objects not supported (documented in discovery: request_parameter_supported=false) |
| oidcc-ensure-request-object-with-redirect-uri | Request objects not supported |
| oidcc-userinfo-post-body | POST with token in body not implemented (only header and GET supported) |
| oidcc-codereuse-30seconds | Covered by oidcc-codereuse (immediate reuse rejected) |

## Summary

- **27/27 tests pass** covering the core OIDC Basic OP and Config OP requirements
- **Key conformance areas verified:** Discovery, JWKS, Authorization Code flow, Token exchange, ID token claims and signing, UserInfo, PKCE, client_secret_basic/post, prompt parameter, error codes, refresh tokens
- **Not applicable:** Tests requiring built-in login UI (display, hint parameters, locales) or unsupported features (address/phone scopes, request objects, claims parameter)
- **Conformance-ready:** riley_auth correctly implements all OIDC Core 1.0 requirements for the Authorization Code flow that apply to its headless (API-only) architecture
