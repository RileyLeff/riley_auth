# Review Round 1 Fixes — 2026-02-22

**Commit**: `43f18f4`

## Major Fixes

### M1. `aud` claim enforcement
- `auth.rs:extract_user` — added `data.claims.aud != state.config.jwt.issuer` check
- `admin.rs:require_admin` — added same aud check
- `oauth_provider.rs:authorize` — enforces aud == issuer on session token

### M2. Authorization code atomic consumption
- `db.rs:consume_authorization_code` — new function: `UPDATE...SET used=true WHERE used=false RETURNING *`
- `oauth_provider.rs:token` — uses atomic consume instead of find + mark_used

### M3. Refresh token atomic rotation
- `db.rs:consume_refresh_token` — new function: `DELETE...WHERE expires_at > now() RETURNING *`
- `auth.rs:auth_refresh` — uses atomic consume
- `oauth_provider.rs:token` (refresh branch) — uses atomic consume

### M4. Database transactions
- `db.rs:create_user_with_link` — new transactional function (user + OAuth link)
- `db.rs:change_username` — new transactional function (history + update)
- `db.rs:soft_delete_user` — wrapped in transaction (delete links + anonymize)
- `auth.rs:auth_setup` — uses `create_user_with_link`
- `auth.rs:update_username` — uses `change_username`

### M5. Mandatory PKCE
- `oauth_provider.rs:authorize` — rejects missing code_challenge, enforces S256

### M6. OAuth links cleaned on soft-delete
- `db.rs:soft_delete_user` — deletes all oauth_links in transaction
- `db.rs:find_oauth_link` — JOINs users WHERE deleted_at IS NULL
- `db.rs:find_oauth_links_by_email` — JOINs users WHERE deleted_at IS NULL
- Username anonymization uses full UUID (not truncated prefix)

### M7. Refresh token scope enforcement
- `auth.rs:auth_refresh` — rejects tokens with `client_id.is_some()`

### M8. Consent enforcement
- `oauth_provider.rs:authorize` — returns `ConsentRequired` for non-auto_approve clients
- `error.rs` — added `ConsentRequired` variant

### M9. CSRF protection
- `routes/mod.rs:require_csrf_header` — middleware requiring `X-Requested-With` on POST/PATCH/PUT/DELETE
- Applied to auth + admin routers; OAuth provider exempt
- `server.rs:build_cors` — added `x-requested-with` to allowed headers

### M10. DB-backed admin role check
- `db.rs:get_user_role` — new function: fresh role from DB
- `admin.rs:require_admin` — now async, queries current role from DB

## Minor Fixes

- **m4**: Added bounds check on ASN.1 bit string content (`jwt.rs`)
- **m5**: `cfg(unix)` guard on SIGTERM handler (`server.rs`)
- **m6**: CORS warning when origins empty (`server.rs`)
- **m7**: Link-accounts redirect uses `url::Url` + `query_pairs_mut()` (`auth.rs`)
- **m11**: Full UUID for anonymized username (`db.rs`)
- **m12**: `InvalidClient` → 401, conflict errors → 409 (`error.rs`)
- Added `subtle` crate for constant-time comparison (`oauth_provider.rs`)
- Cleaned unused imports (`db.rs`, `admin.rs`)
