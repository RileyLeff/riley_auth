# Code Review: riley_auth Phase 5 -- OpenAPI/utoipa Implementation

Reviewer: Claude Opus 4.6
Scope: utoipa v5 OpenAPI annotations, ApiDoc assembly, schema registration, endpoint coverage

---

## MAJOR (must fix)

### M1. Five response status codes in annotations contradict actual handler behavior

**Files:** `crates/riley-auth-api/src/routes/auth.rs`

The following endpoints have `status = 204` in their utoipa annotations, but every handler returns `StatusCode::OK` (200):

| Endpoint | Annotation | Actual return |
|---|---|---|
| `POST /auth/logout` (line ~2308) | 204 | `Ok((jar, StatusCode::OK))` at line ~2331 |
| `POST /auth/logout-all` (line ~2340) | 204 | `Ok((jar, StatusCode::OK))` at line ~2362 |
| `DELETE /auth/sessions/{id}` (line ~2432) | 204 | `Ok(StatusCode::OK)` at line ~2470 |
| `DELETE /auth/me` (line ~2640) | 204 | `Ok((jar, StatusCode::OK))` at line ~2677 |
| `DELETE /auth/link/{provider}` (line ~2853) | 204 | `Ok(StatusCode::OK)` at line ~2877 |

An API consumer relying on the spec will expect `204 No Content` and receive `200 OK`. This is a correctness issue for any code-generated client. Either fix the annotations to say `200`, or change the handlers to actually return `StatusCode::NO_CONTENT`.

**Recommendation:** Decide which is the intended behavior. If the intent is 204 (common for delete/logout operations), fix the handlers. If the intent is 200, fix the annotations. Given that some of these handlers return bodies via cookies, 200 may be more appropriate, but choose consistently.


### M2. Missing SecurityScheme definition for "bearer"

**File:** `crates/riley-auth-api/src/routes/mod.rs`, ApiDoc struct (line ~3326)

The `ApiDoc` struct declares `security(("bearer" = []))` and the `userinfo` endpoint also references `security(("bearer" = []))`, but there is no corresponding `SecurityScheme` definition anywhere. In utoipa v5, this means the `components.securitySchemes` section of the generated spec will be empty or absent, even though the spec references a scheme named "bearer".

API consumers (and tools like Swagger UI) will not know how to authenticate. The spec will technically be malformed per OpenAPI 3.x -- a security requirement MUST reference a declared security scheme.

**Fix:** Add a `modifiers` or `security_schemes` section to the `#[openapi(...)]` attribute. Example:

```rust
#[derive(utoipa::OpenApi)]
#[openapi(
    // ... existing config ...
    components(
        schemas(...),
        // Add this:
    ),
    modifiers(&SecurityAddon),
)]
struct ApiDoc;

struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_default();
        components.add_security_scheme(
            "bearer",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::Http::new(
                    utoipa::openapi::security::HttpAuthScheme::Bearer
                )
            ),
        );
    }
}
```

Alternatively, use utoipa's `security_scheme` attribute if supported in v5.


### M3. `/oauth/userinfo` POST method not documented

**File:** `crates/riley-auth-api/src/routes/oauth_provider.rs`

The route registration at line ~3559 registers both GET and POST:
```rust
.route("/oauth/userinfo", get(userinfo).post(userinfo))
```

But the utoipa annotation at line ~4647 only documents `get`:
```rust
#[utoipa::path(
    get,
    path = "/oauth/userinfo",
    ...
)]
```

OIDC Core 1.0 Section 5.3 requires both GET and POST for the UserInfo endpoint. An API consumer reading the spec will not know POST is supported. This is a conformance issue for OIDC client libraries.

**Fix:** Either add a second `#[utoipa::path]` annotation for the POST method (possibly on a wrapper function), or document it in the endpoint description.


---

## MINOR (should fix)

### m1. `SessionResponse` missing from explicit `components(schemas(...))` list

**File:** `crates/riley-auth-api/src/routes/mod.rs`, ApiDoc struct (line ~3292)

`auth::SessionResponse` is used as `body = Vec<SessionResponse>` in the `list_sessions` annotation (line ~2383), and it correctly derives `utoipa::ToSchema`. However, it is the only response type NOT listed in the explicit `components(schemas(...))` section of `ApiDoc`.

While utoipa v5 will likely auto-register it from the path annotation, this is inconsistent with every other response type being explicitly listed. If the path annotation were ever removed or changed, the schema would silently disappear.

**Fix:** Add `auth::SessionResponse` to the schemas list:
```rust
components(schemas(
    // ...existing auth types...
    auth::SessionResponse,
    // ...
))
```


### m2. `auth_callback` and `link_callback` missing query parameter documentation

**File:** `crates/riley-auth-api/src/routes/auth.rs`

Both `auth_callback` (line ~1890) and `link_callback` (line ~2755) accept `Query<CallbackQuery>` with `code` and `state` parameters, but their `params(...)` annotation only documents the `provider` path parameter.

While these are OAuth callback endpoints typically called by the OAuth provider (not directly by API consumers), omitting the query parameters makes the spec incomplete for anyone debugging or implementing custom OAuth flows.

**Fix:** Add the query params:
```rust
params(
    ("provider" = String, Path, description = "OAuth provider name"),
    ("code" = String, Query, description = "Authorization code from provider"),
    ("state" = String, Query, description = "OAuth state parameter"),
),
```


### m3. `delete_account` annotation missing `400` response

**File:** `crates/riley-auth-api/src/routes/auth.rs`, line ~2635

The `delete_account` handler can return `Error::BadRequest("cannot delete the last admin")` (line ~2659), which maps to HTTP 400. The annotation only documents 204 (which is also wrong per M1) and 401.

**Fix:** Add `(status = 400, description = "Cannot delete last admin", body = ErrorBody)` to the responses.


### m4. `list_users` and `get_user` return untyped JSON with no response body schema

**File:** `crates/riley-auth-api/src/routes/admin.rs`

`list_users` returns `Json<Vec<serde_json::Value>>` (line ~1214) and `get_user` returns `Json<serde_json::Value>` (line ~1250). Their annotations document `status = 200` but specify no `body` type.

This means the OpenAPI spec will show these endpoints return 200 with no schema. API consumers cannot generate typed clients for these admin endpoints.

**Fix:** Create typed response structs (e.g., `UserSummary`, `UserDetail`) with `ToSchema` derives, use them as handler return types, and register them in the schemas list. This is more work than the other fixes but significantly improves the spec's usefulness.


### m5. `jwks` and `openid_configuration` annotations have no response body type

**File:** `crates/riley-auth-api/src/routes/mod.rs`

The `jwks` endpoint (line ~3178) and `openid_configuration` endpoint (line ~3197) both return JSON but have no `body` specification in their response annotations. For OIDC, these are well-known formats (JWK Set, Discovery Document) that could at minimum reference a free-form JSON object.

**Fix:** At minimum, add a description noting the response format. Ideally, create `JwksResponse` and `DiscoveryDocument` schemas, though the dynamic nature of these responses makes full typing harder.


### m6. `/metrics` endpoint not in OpenAPI spec

**File:** `crates/riley-auth-api/src/routes/mod.rs`

The `/metrics` endpoint (Prometheus text format, line ~3379) is in the router but absent from the `ApiDoc` paths. While this may be intentional (ops endpoint, not API), it means the spec is not a complete catalog of the server's routes.

**Fix:** Either add it to the spec with an "ops" tag, or add a comment in the `ApiDoc` struct explaining why it's excluded (e.g., `// /metrics is an operational endpoint, intentionally excluded from the API spec`).


### m7. `openapi_spec` endpoint not in ApiDoc paths list

**File:** `crates/riley-auth-api/src/routes/mod.rs`

The `openapi_spec` handler (line ~3332) has a `#[utoipa::path]` annotation but is NOT listed in the `ApiDoc` `paths(...)` section (lines ~3248-3291). This means the `/openapi.json` endpoint will not appear in the generated spec despite having an annotation.

Either add it to the paths list, or remove the `#[utoipa::path]` annotation from `openapi_spec` to avoid the dead code. Including it is common practice (self-documenting spec).


---

## NOTES (observations)

### n1. Visibility split: auth types are `pub`, admin types are `pub(crate)`

Auth route types (`SetupRequest`, `MeResponse`, `LinkResponse`, `UpdateDisplayNameRequest`, `UpdateUsernameRequest`) are `pub`, while admin route types (`UpdateRoleRequest`, `RegisterClientRequest`, etc.) are `pub(crate)`, and oauth_provider types are `pub`.

This works fine within the crate since utoipa processes annotations at compile time within the same crate. However, the inconsistency suggests either the auth types were made `pub` for external consumption (e.g., from riley-auth-cli) or the visibility was set ad-hoc. Not a bug, but worth harmonizing if the visibility conventions matter.


### n2. `PaginationQuery` lacks `ToSchema` derive

**File:** `crates/riley-auth-api/src/routes/admin.rs`, line ~1111

`PaginationQuery` does not derive `ToSchema`. This is fine because its fields are documented as individual `params(...)` in the annotations. However, if pagination were ever used as a request body instead of query params, this would need updating.


### n3. `introspect` response body is not typed

The `introspect` endpoint (line ~4523) returns a dynamic JSON object (`serde_json::json!({...})`) and the annotation specifies no body type for the 200 response. RFC 7662 defines a standard introspection response format. A typed `IntrospectionResponse` struct would improve the spec.


### n4. Test coverage for OpenAPI spec

The test at line ~3428 validates that the spec is valid JSON and has minimum counts for paths (>=25) and schemas (>=15). This is good baseline coverage but doesn't check:
- That all paths in the router are present in the spec
- That response codes match handler behavior
- That referenced schemas actually resolve

Consider adding a test that deserializes the spec into an `utoipa::openapi::OpenApi` struct and performs structural validation.


### n5. `token_type` field uses `&'static str`

**File:** `crates/riley-auth-api/src/routes/oauth_provider.rs`, line ~3495

`TokenResponse.token_type` is `&'static str`. Utoipa will serialize this as a `string` schema, which is correct. However, since the value is always `"Bearer"`, consider using an enum or adding a `#[schema(example = "Bearer")]` annotation to make the spec more descriptive.


### n6. Cookie-based auth not representable in OpenAPI

Many endpoints (all auth and admin routes) authenticate via HTTP-only cookies, not via headers. OpenAPI 3.x supports `apiKey` in `cookie` location for this, but the spec currently only declares a "bearer" security scheme. This means the security requirements on most endpoints are misleading -- they claim Bearer auth when they actually use cookies.

This is a fundamental impedance mismatch between the cookie-based auth model and OpenAPI's security scheme model. Not a bug per se, but an API consumer reading the spec would attempt Bearer auth on endpoints that only accept cookies.

**Suggestion:** Add a second security scheme for cookie auth, or document this prominently in the API description.


### n7. Good coverage overall

The implementation covers 38 of the server's ~40 routes (excluding `/metrics` and arguably `/openapi.json` itself). All request/response types have `ToSchema` derives. The tag organization (auth, oauth, admin, discovery) is clean and logical. The utoipa annotations are consistently formatted. The unit test provides a safety net against malformed specs.


---

## Summary

| Severity | Count | Key themes |
|---|---|---|
| Major | 3 | Status code mismatches (5 endpoints), missing SecurityScheme, undocumented POST on userinfo |
| Minor | 7 | Missing schema registration, missing params, untyped responses |
| Note | 7 | Visibility inconsistency, cookie auth representation, test coverage |

The Phase 5 implementation is structurally sound. The major issues are all straightforward to fix -- M1 is a mechanical status code correction, M2 is adding a SecurityScheme modifier, and M3 requires documenting or annotating the POST method. None require architectural changes.
