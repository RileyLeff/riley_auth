# Review Notes — v6

Persistent notes to prevent re-litigating settled decisions.

## Settled Decisions

### avatar_url is intentionally retained
Phase 1 ("Remove Avatar Storage") removes only the upload/storage infrastructure
(StorageConfig, S3 bucket config, update_user_avatar endpoint). The `avatar_url`
field throughout the codebase stores the URL fetched from the OAuth provider
(Google `picture`, GitHub `avatar_url`). This passthrough is intentional and
required for OIDC compliance (`picture` claim in ID tokens and UserInfo).

### Cookie prefix default "auth" is a breaking change
Changed from "riley_auth" to "auth" in v6. Documented in example config.
Existing deployments should set `cookie_prefix = "riley_auth"` explicitly.

### consent_requests uses UUIDv4 intentionally
The `consent_requests` table uses `gen_random_uuid()` (UUIDv4) for the `id`
column, not app-side UUIDv7. This is intentional — consent request IDs appear
in URLs and must be unpredictable to prevent enumeration.

### Test infrastructure uses PG18
The docker-compose.test.yml uses `postgres:18`. This is fine for forward
compatibility. PG14 testing could be added to CI matrix later but is not
blocking.

### Pre-existing minor issues noted but deferred
Round 2 found several pre-existing minor issues not caused by phases 1-3:
- CLI webhook URL validation is more permissive than API (allows http:// for any host)
- cleanup_webhook_deliveries accepts i64 but casts to i32 (cosmetic)
- Missing compound index on refresh_tokens(user_id, client_id) (optimization)
These are tracked for future cleanup but do not block the v6 workflow.

## Phase 4 Review Notes

### XFF trust model is documented, not a code fix
The `extract_client_ip()` function takes the leftmost IP from X-Forwarded-For.
This is safe only when the reverse proxy overwrites (not appends to) the header.
The example config already documents this prominently. Adding a `trusted_proxies`
config is a future enhancement, not a v6 blocker.

### Webhook secrets are stored in plaintext intentionally
HMAC signing keys must be available in raw form to compute signatures. Envelope
encryption would add complexity without meaningful security benefit — if the
DB is compromised, the attacker can read the webhook endpoints too.

### Schema injection pattern is safe
The `SET search_path TO "{schema}"` uses double-quoted identifiers. The charset
validation (`is_ascii_alphanumeric() || c == '_'`) excludes double-quote, making
injection impossible. The pattern is safe as-is.

### preferred_username in ID tokens (OIDC compliance)
The `preferred_username` is always included in ID tokens regardless of scope.
Per OIDC Core 1.0 Section 5.4, it should be gated on the `profile` scope.
Tracked for Phase 5 (OIDC compliance pass) or separate fix.

### Request body size limit deferred
No global request body size limit is configured. Should add
`DefaultBodyLimit::max(1MB)` in a future pass. Not Phase 4 scope.

## Phase 5 Review Notes

### Visibility split between auth/admin/oauth types
Auth route types (SetupRequest, MeResponse, etc.) are `pub` while admin types
are `pub(crate)`. This is because auth types existed before the utoipa pass and
were already public. Admin types were made `pub(crate)` during Phase 5. Both
work fine for utoipa since it processes within the same crate.

### Cookie-based auth not representable in OpenAPI SecurityScheme
Most endpoints authenticate via HTTP-only cookies, not Bearer headers. OpenAPI
3.x can model `apiKey` in `cookie` but the spec declares only a "bearer" scheme.
This is a fundamental impedance mismatch — not a bug. The bearer scheme is
accurate for the /oauth/userinfo endpoint which does use Bearer tokens.

### Untyped admin and discovery responses
`list_users`, `get_user`, `jwks`, and `openid_configuration` return
`serde_json::Value` (dynamic JSON). Creating typed response structs would improve
the spec but is non-trivial for these endpoints. Deferred to future work.

### OAuth callback query params undocumented
`auth_callback` and `link_callback` accept `code` and `state` query params from
the OAuth provider. These are not consumer-facing endpoints (they're redirect
targets) so omitting query param docs is acceptable.
