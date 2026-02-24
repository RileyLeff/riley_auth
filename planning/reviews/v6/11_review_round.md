# Verification Review: Phase 5 (OpenAPI/utoipa) Fixes — Round 10

## Summary

This is a verification review of the fixes applied in commit c11352d, which addressed 3 major and 4 minor issues from the Round 09 review. The fixes are mostly correct. One major issue persists (M1 partial), one new minor issue was found, and all other fixes verify clean. The broader codebase remains in solid shape.

---

## 1. Verification of Major Fixes

### M1: StatusCode::NO_CONTENT alignment — PARTIALLY VERIFIED

The Round 09 review flagged 5 handlers that returned `StatusCode::OK` but were annotated with `status = 204`. The fix changed these to `StatusCode::NO_CONTENT`.

**Verified correct** in `crates/riley-auth-api/src/routes/auth.rs`:
- `auth_logout` (line ~2331): returns `StatusCode::NO_CONTENT` — matches `status = 204` annotation. PASS.
- `auth_logout_all` (line ~2362): returns `StatusCode::NO_CONTENT` — matches `status = 204` annotation. PASS.
- `revoke_session` (line ~2470): returns `StatusCode::NO_CONTENT` — matches `status = 204` annotation. PASS.
- `delete_account` (line ~2678): returns `StatusCode::NO_CONTENT` — matches `status = 204` annotation. PASS.
- `unlink_provider` (line ~2878): returns `StatusCode::NO_CONTENT` — matches `status = 204` annotation. PASS.

**Integration tests updated correctly:**
- `logout` test (line ~5836): asserts `StatusCode::NO_CONTENT`. PASS.
- `logout_all` test (line ~5867): asserts `StatusCode::NO_CONTENT`. PASS.
- `session_revoke_other_session` test (line ~6173): asserts `StatusCode::NO_CONTENT`. PASS.
- `delete_account` test (line ~5948): asserts `StatusCode::NO_CONTENT`. PASS.

**However, a related mismatch persists (new finding):**

**[major] `update_role` returns OK but annotation says 200 — acceptable, but `delete_user` admin endpoint also returns OK for a 200-annotated success, which is fine. No mismatch here.**

Actually, upon closer inspection, the admin handlers `remove_client` (`crates/riley-auth-api/src/routes/admin.rs`, line ~1533) and `remove_webhook` (line ~1723) both return `StatusCode::OK` and their annotations say `status = 200`. These are DELETE operations returning 200 rather than 204. This is not a regression (they were like this before), but it is inconsistent with the auth route DELETE handlers that now correctly return 204.

**[minor] `remove_client` and `remove_webhook` — inconsistent DELETE semantics**
- File: `crates/riley-auth-api/src/routes/admin.rs`
- `remove_client` (line ~1533): returns `StatusCode::OK` with `status = 200` annotation.
- `remove_webhook` (line ~1723): returns `StatusCode::OK` with `status = 200` annotation.
- These DELETE endpoints return no body, so 204 No Content would be more conventional and consistent with the auth route DELETE handlers that were just fixed. The annotation and code are at least consistent with each other, so this is not a spec/behavior mismatch, but it is a design inconsistency.

**Verdict: M1 PASS (all 5 flagged items fixed). New inconsistency noted as minor.**

### M2: SecurityAddon for bearer scheme — VERIFIED

File: `crates/riley-auth-api/src/routes/mod.rs`, lines ~3338-3352.

The `SecurityAddon` struct implements `utoipa::Modify` and adds an `Http(Bearer)` security scheme named `"bearer"`. The `ApiDoc` derive references it via `modifiers(&SecurityAddon)` (line ~3334) and `security(("bearer" = []))` (line ~3332). This means the generated OpenAPI spec will include a proper `securitySchemes` component and a global security requirement.

The `#[utoipa::path]` annotation on `userinfo` explicitly references `security(("bearer" = []))` (line ~4680), which is correct since that is the only endpoint that uses Bearer token auth from the Authorization header.

**Verdict: M2 PASS.**

### M3: /oauth/userinfo POST support description — VERIFIED

File: `crates/riley-auth-api/src/routes/oauth_provider.rs`, line ~4675.

The `#[utoipa::path]` annotation on `userinfo` includes:
```
description = "OIDC UserInfo endpoint. Both GET and POST are supported per OIDC Core 1.0 §5.3.",
```

The route registration (line ~3581) correctly registers both GET and POST:
```rust
.route("/oauth/userinfo", get(userinfo).post(userinfo))
```

**Verdict: M3 PASS.**

---

## 2. Verification of Minor Fixes

### m1: SessionResponse in components(schemas) — VERIFIED

File: `crates/riley-auth-api/src/routes/mod.rs`, line ~3305.

`auth::SessionResponse` is now listed in the `components(schemas(...))` block of the `ApiDoc` derive. PASS.

### m3: 400 response for delete_account — VERIFIED

File: `crates/riley-auth-api/src/routes/auth.rs`, lines ~2639-2642.

The `#[utoipa::path]` annotation on `delete_account` now includes:
```
(status = 400, description = "Cannot delete last admin", body = ErrorBody),
```

This correctly documents the `LastAdmin` branch (line ~2659-2660). PASS.

### m6: Comment explaining /metrics exclusion — VERIFIED

File: `crates/riley-auth-api/src/routes/mod.rs`, lines ~3241-3243.

Comment reads:
```
// --- OpenAPI ---
// Note: /metrics is an operational endpoint (Prometheus text format) and is
// intentionally excluded from the API spec.
```

PASS.

### m7: openapi_spec in ApiDoc paths — VERIFIED

File: `crates/riley-auth-api/src/routes/mod.rs`, line ~3256.

`openapi_spec` is included in the `paths(...)` list of the `ApiDoc` derive. The handler at line ~3362 has a corresponding `#[utoipa::path]` annotation. PASS.

---

## 3. Deferred Items — Acknowledged

- m2 (callback query params): Reasonable deferral — these are OAuth redirect endpoints, not consumer-facing APIs.
- m4 (typed responses for list_users/get_user): These still use `Json<Vec<serde_json::Value>>` and `Json<serde_json::Value>` respectively. Future work is appropriate.
- m5 (typed responses for jwks/openid_configuration): Still return `Json<serde_json::Value>`. Future work is appropriate.

---

## 4. Regression Check

No regressions detected. The 204 status code changes are correctly propagated to both handler return values and test assertions. The CSRF middleware, rate limiting, and cookie handling are unaffected by these changes.

---

## 5. Remaining OpenAPI Annotation Issues

### [minor] Missing `email_verified` field in `SetupRequest` profile flow

Not an OpenAPI issue per se, but `SetupRequest` (line ~1796) only has a `username` field. The `OAuthProfile` embedded in the setup token contains the provider info, which is correct. No annotation issue here — just noting it is documented correctly as a single-field body.

### [minor] `ConsentDecision` annotation inconsistency

File: `crates/riley-auth-api/src/routes/oauth_provider.rs`, line ~4118.

The `consent_decision` handler accepts `Json<ConsentDecision>`, but the endpoint is CSRF-protected (it is in `consent_router()` which is merged into the CSRF-protected block at `mod.rs` line ~3395). The `#[utoipa::path]` annotation uses `request_body = ConsentDecision` (line ~4107), which is correct for JSON. However, this endpoint being behind CSRF protection means clients need to send `X-Requested-With`, which is not documented in the OpenAPI spec. This is a pre-existing issue and not a regression.

### [note] `oauth/token` and `oauth/revoke` accept form-urlencoded but annotations are correct

The `#[utoipa::path]` annotations on `token` (line ~4232) and `revoke` (line ~4504) correctly specify `content_type = "application/x-www-form-urlencoded"`. The `introspect` annotation (line ~4549) also correctly specifies this. PASS.

### [note] `IntrospectRequest` response type is `impl IntoResponse` — no typed OpenAPI response

File: `crates/riley-auth-api/src/routes/oauth_provider.rs`, line ~4559.

The `introspect` handler returns `Result<impl IntoResponse, Error>`. The annotation says `status = 200, description = "Introspection response (active: true/false)"` without a `body` type. This is acceptable for RFC 7662 since the response shape varies between active and inactive cases, making a single schema difficult. Pre-existing, not a regression.

---

## 6. Broader Codebase Observations

These are not regressions from the Phase 5 fixes, but issues noticed during the review:

### [note] Duplicate `http_client` and `oauth_client` in AppState

File: `crates/riley-auth-api/src/server.rs`, lines ~4841, 4847.

`AppState` has both `http_client: reqwest::Client` (used for webhooks, built with SSRF protection) and `oauth_client: reqwest::Client` (used for OAuth token exchange). This separation is intentional and correct — the webhook client has the `SsrfSafeResolver` while the OAuth client does not (it needs to reach providers that may use CDN/non-standard DNS). Just noting the design is sound.

### [note] `consumed_token_cutoff_secs` computed but never used for its original purpose

File: `crates/riley-auth-api/src/server.rs`, line ~4994.

```rust
let consumed_token_cutoff_secs = config.jwt.refresh_token_ttl_secs * 2;
```

This value is computed and then used at line ~5010:
```rust
let cutoff = chrono::Utc::now() - chrono::Duration::seconds(consumed_token_cutoff_secs as i64);
```

But `cutoff` is passed to `cleanup_consumed_refresh_tokens` (line ~5030). This is correct — consumed tokens are kept for 2x the refresh TTL to enable reuse detection, then cleaned up. No issue.

### [note] Refresh cookie path restriction

File: `crates/riley-auth-api/src/routes/auth.rs`, line ~3015.

The refresh cookie's path is set to `/auth`, which means it is only sent on requests to paths starting with `/auth`. This is a good security practice (limits exposure), but it means the `/oauth/token` endpoint at `/oauth/token` will never see the refresh cookie. This is by design — the OAuth token endpoint uses the refresh token in the POST body, not a cookie. Correct.

---

## Final Verdict

All 3 major fixes and 4 minor fixes from Round 09 are correctly implemented. No regressions were introduced. The codebase is in good shape.

**New findings this round:**

| # | Severity | Description | File | Lines |
|---|----------|-------------|------|-------|
| 1 | minor | Admin DELETE endpoints (`remove_client`, `remove_webhook`) return 200 instead of 204, inconsistent with auth DELETE endpoints that were just fixed to return 204. Both annotation and code match each other, but the convention is inconsistent. | `crates/riley-auth-api/src/routes/admin.rs` | ~1533, ~1723 |

**Recommendation:** Ship as-is. The minor inconsistency can be addressed in a future cleanup pass.
