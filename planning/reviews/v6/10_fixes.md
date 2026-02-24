# Review Round 09 Fixes

**Commit:** `c11352d`

## Major Fixes

### M1. Status code mismatches (5 endpoints)
Changed `StatusCode::OK` → `StatusCode::NO_CONTENT` in 5 handlers that had `204` annotations:
- `auth_logout`
- `auth_logout_all`
- `revoke_session`
- `delete_account`
- `unlink_provider`

Updated 4 integration test assertions to expect 204.

### M2. Missing SecurityScheme
Added `SecurityAddon` modifier struct that implements `utoipa::Modify` to define the "bearer" HTTP auth scheme in `components.securitySchemes`.

### M3. `/oauth/userinfo` POST undocumented
Added `description` field to the `#[utoipa::path]` annotation noting POST support per OIDC Core 1.0 §5.3. Full separate POST annotation not possible with utoipa's single-method model without a wrapper function.

## Minor Fixes

- **m1:** Added `auth::SessionResponse` to explicit `components(schemas(...))` list
- **m3:** Added `400` response for `delete_account` (last admin guard)
- **m6:** Added comment explaining `/metrics` exclusion from API spec
- **m7:** Added `openapi_spec` to `ApiDoc` paths list

## Deferred (Notes)

- **m2:** `auth_callback`/`link_callback` query params — these are OAuth provider callbacks, not consumer-facing. Low priority.
- **m4:** Typed responses for `list_users`/`get_user` — would improve spec but requires creating new types. Deferred to future work.
- **m5:** Typed responses for `jwks`/`openid_configuration` — dynamic JSON responses are hard to type. Descriptions adequate.
- **n1-n7:** Noted in review_notes_README.md.
