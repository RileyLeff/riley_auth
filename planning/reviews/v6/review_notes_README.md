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
