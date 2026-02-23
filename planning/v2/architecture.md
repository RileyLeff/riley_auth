# v2 Architecture: Ecosystem Features

v1 nails identity. v2 makes the ecosystem around it richer — giving downstream apps more to work with and operators more control over their deployment's identity.

## Theme

Everything in v2 serves one goal: **make riley_auth a better foundation for a multi-app ecosystem.** Scopes let apps request only what they need. Webhooks let services react to identity events. Session visibility lets users feel in control. OIDC discovery lets standard libraries auto-configure. The cookie prefix lets deployers fully white-label. Rate limit persistence lets you scale horizontally.

No new authentication mechanisms. No built-in UI. No entitlements or billing. Identity, not liability.

---

## 1. Scopes & Permissions

### Problem

The OAuth provider flow issues tokens with `aud` (which app) but no granular scopes. Every app that authenticates against riley_auth gets full access to the user's profile. There's no way for an app to say "I only need to read the username" or for a user to see what an app is requesting.

### Design

**Config-driven scope definitions.** Scopes are declared in `riley_auth.toml`, not hardcoded:

```toml
[scopes]
definitions = [
  { name = "profile:read", description = "View your username and avatar" },
  { name = "profile:write", description = "Update your display name and avatar" },
  { name = "sessions:read", description = "View your active sessions" },
  { name = "sessions:write", description = "Revoke your sessions" },
]
```

**Per-client scope allowlists.** When registering an OAuth client via `/admin/clients`, the operator specifies which scopes that client may request:

```json
{
  "name": "Blog Comments",
  "redirect_uris": ["https://blog.example.com/callback"],
  "allowed_scopes": ["profile:read"],
  "auto_approve": true
}
```

**Scope claim in JWTs.** Granted scopes appear in the access token as a `scope` claim (space-delimited string per RFC 6749). Downstream apps can enforce access locally without calling back to riley_auth.

**Consent data endpoint.** For apps that aren't `auto_approve`, riley_auth provides a `/oauth/consent` endpoint that returns the requested scopes with human-readable descriptions. The deployer's frontend renders the consent UI however it wants — riley_auth provides data, not HTML.

### Database Changes

- `oauth_clients` table: add `allowed_scopes text[]` column
- `authorization_codes` table: add `scopes text` column (space-delimited)
- `refresh_tokens` table: add `scopes text` column

### API Changes

- `GET /oauth/authorize`: accept `scope` query parameter, validate against client's `allowed_scopes`
- `GET /oauth/consent`: return scope descriptions for the pending authorization (used by frontend)
- `POST /oauth/token`: include `scope` in token response
- `POST /admin/clients`: accept `allowed_scopes` field
- Access token JWT: add `scope` claim

---

## 2. Webhooks / Event System

### Problem

When a user creates an account, changes their username, or deletes their account, downstream services have no way to know unless they poll. For an ecosystem of apps sharing one identity provider, this is a gap — apps need to sync user data, provision resources, or trigger workflows in response to identity events.

### Design

**Event types:**
- `user.created` — new account registered
- `user.deleted` — account soft-deleted
- `user.updated` — display name or avatar changed
- `user.username_changed` — username changed (includes old and new)
- `user.role_changed` — admin promoted/demoted a user
- `session.created` — new login
- `link.created` — OAuth provider linked
- `link.deleted` — OAuth provider unlinked

**Webhook registration.** Per-client or global (admin-only). Stored in a new `webhooks` table:

```sql
CREATE TABLE webhooks (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  client_id uuid REFERENCES oauth_clients(id) ON DELETE CASCADE,  -- NULL = global
  url text NOT NULL,
  events text[] NOT NULL,
  secret text NOT NULL,  -- HMAC signing key
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
```

**Delivery.** Async via a background task (tokio::spawn). POST to the registered URL with:
- JSON payload containing event type, timestamp, and relevant data
- `X-Webhook-Signature` header: HMAC-SHA256 of the payload using the webhook's secret
- Retry with exponential backoff (3 attempts, then mark as failed)

**Admin API:**
- `POST /admin/webhooks` — register a webhook
- `GET /admin/webhooks` — list webhooks
- `DELETE /admin/webhooks/{id}` — remove a webhook
- `GET /admin/webhooks/{id}/deliveries` — recent delivery attempts and status

### Database Changes

- New `webhooks` table (above)
- New `webhook_deliveries` table for delivery log (event_id, webhook_id, status, response_code, attempted_at)

---

## 3. Session Visibility API

### Problem

Users have no way to see where they're signed in or revoke specific sessions. The existing `logout-all` is a sledgehammer — there's no scalpel.

### Design

**Enrich refresh tokens with session metadata.** When a refresh token is created, store:
- User-Agent (parsed to device/browser)
- IP address (if `behind_proxy`, use the forwarded IP)
- Created timestamp (already exists)
- Last used timestamp (update on refresh)

**New endpoints:**
- `GET /auth/sessions` — list active sessions for the current user. Returns device info, last used, created at, and whether it's the current session.
- `DELETE /auth/sessions/{id}` — revoke a specific session (delete its refresh token). Cannot revoke the current session (use `/auth/logout` for that).

**No new tables.** Session metadata lives on the `refresh_tokens` table:

```sql
ALTER TABLE refresh_tokens
  ADD COLUMN user_agent text,
  ADD COLUMN ip_address text,
  ADD COLUMN last_used_at timestamptz;
```

riley_auth provides the data. The deployer's frontend builds the UI — a list of sessions with "revoke" buttons, a map of login locations, whatever they want.

---

## 4. Rate Limit Persistence (Redis)

### Problem

Rate limits are in-memory via tower_governor. They reset on restart and don't share state across instances. For a single-instance deployment this is fine; for horizontal scaling or frequent deploys, it means rate limits are effectively unenforced.

### Design

**Optional Redis backend.** If a Redis URL is configured, rate limit state moves to Redis. If not configured, the existing in-memory behavior is preserved (zero new dependencies for simple deployments).

```toml
[rate_limiting]
backend = "redis"         # "memory" (default) or "redis"
redis_url = "env:REDIS_URL"
```

**Implementation.** tower_governor supports custom key stores. Implement a Redis-backed store using the `redis` crate (async, connection pooling). Keys are `rate:{ip}:{endpoint}` with TTL matching the rate limit window.

### Dependencies

- `redis` crate (async feature) — optional, behind a `redis` cargo feature flag
- No Redis required for default deployments

---

## 5. Configurable Cookie Prefix

### Problem

All cookies are hardcoded with the `riley_auth_` prefix. If Bob deploys riley_auth for bob.com, his users see `riley_auth_access` in their browser's cookie inspector. This breaks the "Bob's users never encounter the word Riley" promise from the soul doc.

### Design

**New config option:**

```toml
[server]
cookie_prefix = "bob_auth"  # default: "riley_auth"
```

**Implementation.** Replace the hardcoded constants in `auth.rs`:

```rust
pub const ACCESS_TOKEN_COOKIE: &str = "riley_auth_access";
```

becomes a runtime value derived from `config.server.cookie_prefix`. The cookie names become `{prefix}_access`, `{prefix}_refresh`, `{prefix}_oauth_state`, `{prefix}_pkce`, `{prefix}_setup`.

This is a breaking change for existing deployments (cookies change names, so existing sessions are invalidated). Document the migration path: deploy the new version, users re-authenticate once.

---

## 6. OpenID Connect Discovery

### Problem

riley_auth already serves JWKS at `/.well-known/jwks.json` and issues standard JWTs, but it doesn't publish an OIDC discovery document. Standard OIDC client libraries (which many apps use) can't auto-discover riley_auth's configuration.

### Design

**New endpoint:** `GET /.well-known/openid-configuration`

Returns a JSON document per the [OpenID Connect Discovery spec](https://openid.net/specs/openid-connect-discovery-1_0.html):

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "revocation_endpoint": "https://auth.example.com/oauth/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["profile:read", "profile:write"],
  "code_challenge_methods_supported": ["S256"]
}
```

All values derived from existing config (`public_url`, `jwt.issuer`, scope definitions). No new config needed.

**ID Token.** OIDC requires an `id_token` in the token response. This is essentially the access token with standard OIDC claims (`sub`, `name`, `preferred_username`, `picture`). Add it to the `/oauth/token` response alongside the existing `access_token`.

---

## Implementation Order

Features are ordered by ecosystem impact and dependency:

1. **Scopes & Permissions** — foundational for everything else; consent data needed before webhooks make sense
2. **OIDC Discovery** — small surface area, high interoperability payoff; builds on scopes
3. **Session Visibility** — independent of other features, enriches refresh token table
4. **Webhooks** — depends on having a stable event model (informed by scopes and sessions)
5. **Cookie Prefix** — breaking change, best done when other breaking changes (scopes DB migration) are happening
6. **Rate Limit Persistence** — fully independent, can be done anytime; last because it's an operational concern, not a feature

---

## Out of Scope

These are explicitly **not** in v2:

- **Email/password auth** — violates the soul doc. Authentication is someone else's problem.
- **MFA/TOTP** — same reason. If Google requires MFA, riley_auth gets MFA for free.
- **Account recovery** — if you lose access to all your OAuth providers, that's their problem.
- **Built-in frontend/UI** — riley_auth provides APIs and data. The deployer builds the UI.
- **Entitlements/billing/subscriptions** — identity, not entitlements. A separate service uses riley_auth's identity as its foundation.
- **Renaming away from "riley"** — a branding decision, not an architecture decision. The cookie prefix config is the one code change needed; the rest is a find-and-replace that can happen anytime.
