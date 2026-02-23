# v4 Architecture: OAuth Provider Compliance, Ecosystem Features & Operational Polish

v3 hardened the internals — token families, webhook reliability, SSRF protection, tiered rate limiting, OIDC basics, PII scrubbing. v4 completes the OAuth provider story so riley_auth works correctly as an identity provider for third-party clients, not just first-party auto-approve apps. It also adds ecosystem features (token introspection, back-channel logout, multi-provider account merging) and closes operational gaps from v3.

## Theme

**Make riley_auth a correct, spec-compliant OAuth/OIDC provider that third-party developers can integrate against without surprises — and give the "cinematic universe" of apps the infrastructure to work as a cohesive ecosystem.** v3 got the security right; v4 gets the contracts and the ecosystem right.

---

## 1. UserInfo Endpoint

### Problem

`/auth/me` is session-only — it requires a session cookie and rejects Bearer tokens with client audiences. OIDC Core 1.0 Section 5.3 requires a UserInfo endpoint that accepts OAuth Bearer tokens. Without it, downstream apps can't fetch profile claims for their users, and the discovery document can't advertise `userinfo_endpoint`.

### Design

**New endpoint:** `GET /oauth/userinfo`

- Accepts Bearer token via `Authorization: Bearer <access_token>` header
- Validates the JWT, checks `aud` matches a registered client (not the issuer)
- Returns profile claims based on granted scopes:
  - `openid`: `sub` (user UUID)
  - `profile`: `preferred_username`, `name`, `picture`, `updated_at`
  - `email`: `email` (from primary oauth_link)
- Response format: JSON (application/json)
- Also supports POST per OIDC spec

**Discovery document update:**
- Add `userinfo_endpoint: "{issuer}/oauth/userinfo"`
- Add `claims_supported: ["sub", "preferred_username", "name", "picture", "email", "updated_at"]`
- Add `scopes_supported: ["openid", "profile", "email"]` (plus deployer-defined scopes)

**No changes to `/auth/me`** — it remains the session-only profile endpoint for first-party apps.

---

## 2. Authorize Endpoint Error Redirects

### Problem

RFC 6749 Section 4.1.2.1 requires that authorization errors (after validating `client_id` and `redirect_uri`) be communicated back to the client via redirect with `?error=...` query parameters. Currently, `/oauth/authorize` returns HTTP error responses directly, which breaks the OAuth flow for third-party clients — their redirect handler never fires, and the user sees a raw error page from the auth server.

### Design

**Error classification:**

1. **Pre-redirect errors** (return HTTP response directly):
   - Invalid/missing `client_id` → 400
   - Invalid/missing `redirect_uri` → 400
   - `redirect_uri` not registered for client → 400
   These cannot redirect because we don't trust the redirect target.

2. **Post-redirect errors** (redirect back with error params):
   - `response_type` not supported → `?error=unsupported_response_type`
   - Invalid scope → `?error=invalid_scope&error_description=...`
   - User not authenticated → `?error=login_required`
   - Consent required (non-auto-approve) → `?error=consent_required`
   - Server error → `?error=server_error`

**Redirect format:** `{redirect_uri}?error={code}&error_description={desc}&state={state}`

The `state` parameter is always echoed back (if provided) to allow the client to correlate the error.

---

## 3. Consent UI Support

### Problem

Non-auto-approve clients currently get `ConsentRequired` with no way forward. For riley_auth to serve as an identity provider for third-party apps, users need a way to grant consent.

### Design

**riley_auth does not provide a UI** (per soul doc: "riley_auth provides APIs, deployer builds UI"). Instead, it provides the API surface for a deployer-built consent page.

**New endpoint:** `GET /oauth/consent`

- Returns the consent context as JSON:
  ```json
  {
    "client": { "name": "Cool App", "client_id": "..." },
    "scopes": [
      { "name": "profile", "description": "Read your username and avatar" },
      { "name": "email", "description": "Read your email address" }
    ],
    "redirect_uri": "https://coolapp.com/callback",
    "state": "..."
  }
  ```
- Requires an active session (cookie auth)
- The consent context is stored server-side (tied to the authorization request via a consent token/cookie)

**New endpoint:** `POST /oauth/consent`

- Body: `{ "approved": true }` or `{ "approved": false }`
- If approved: issues authorization code and redirects to `redirect_uri`
- If denied: redirects with `?error=access_denied`
- Requires the consent token/cookie from the GET

**Authorize flow change:**
- For non-auto-approve clients, `/oauth/authorize` redirects to a configurable `consent_url` (deployer's frontend) with a consent token
- The frontend calls `GET /oauth/consent` to render the UI, then `POST /oauth/consent` with the decision

**Config:**
```toml
[oauth]
consent_url = "https://auth.example.com/consent"
```

---

## 4. Scope Downscoping on Refresh

### Problem

RFC 6749 Section 6 allows clients to request a narrower scope set when refreshing a token. This is useful for clients that want to drop privileges after initial setup (e.g., request `email` during onboarding, then refresh with only `profile` for ongoing use).

### Design

**Token endpoint change:**

When `grant_type=refresh_token` and a `scope` parameter is provided:
1. Parse requested scopes
2. Verify each requested scope is a subset of the original grant's scopes
3. If any scope is not in the original set → `invalid_scope` error
4. Issue new tokens with the narrower scope set
5. Store the narrowed scopes on the new refresh token

If no `scope` parameter is provided, behavior is unchanged (inherit original scopes).

---

## 5. Webhook Replay Protection

### Problem

Current HMAC signatures cover only the payload body. An attacker who intercepts a webhook delivery can replay it indefinitely. Industry standard (Stripe, GitHub) includes a timestamp in the signed content with a tolerance window.

### Design

**Signature format change:**

Current: `sha256=HMAC(secret, body)`

New: `sha256=HMAC(secret, "{timestamp}.{body}")`

Where `timestamp` is the Unix epoch seconds of the delivery attempt. The signature header becomes:

```
X-Signature-256: t=1234567890,sha256=<hex_digest>
```

**Receiver guidance:** Receivers should:
1. Extract `t` and `sha256` from the header
2. Verify the signature against `"{t}.{body}"`
3. Reject if `|now - t| > tolerance` (recommended: 300 seconds)

**Breaking change:** This changes the signature format. Existing receivers will break unless updated. Options:
- **Option A:** Add a version field to webhook config (`signature_version: "v2"`) and support both formats during migration
- **Option B:** Ship as a breaking change, document in release notes

Recommend Option B — riley_auth has no public userbase yet.

---

## 6. Stuck Outbox Recovery

### Problem

If the server crashes while a webhook outbox entry is in "processing" status, that entry is permanently stuck — the delivery worker only polls "pending" entries, and the cleanup worker only removes "delivered"/"failed" entries.

### Design

**Maintenance worker addition:**

In `run_maintenance_cycle`, after existing cleanup steps, add:

```sql
UPDATE webhook_outbox
SET status = 'pending', next_attempt_at = now()
WHERE status = 'processing'
  AND updated_at < now() - interval '5 minutes'
```

This resets entries that have been stuck in "processing" for more than 5 minutes back to "pending" for retry. The 5-minute threshold is well above the 10-second HTTP timeout, so it won't interfere with active deliveries.

**Config:**
```toml
[webhooks]
stuck_processing_timeout_secs = 300
```

---

## 7. Account Linking Confirmation Endpoint

### Problem

When `auth_callback` detects an email collision (a new OAuth provider matches an existing user's email), it redirects to `/link-accounts` with a setup token. But there's no API endpoint to confirm the link for an already-authenticated user. The frontend has to start a fresh `/auth/link/{provider}` flow, making the setup token a signal with no actionable API.

### Design

**New endpoint:** `POST /auth/link/confirm`

- Requires both: active session (cookie) AND setup token (from the redirect)
- Validates that the setup token's provider identity isn't already linked
- Creates the oauth_link between the authenticated user and the new provider
- Clears the setup cookie
- Returns the updated user profile

This completes the link suggestion flow: callback detects collision → redirect with setup token → frontend shows "link this account?" → user confirms → `POST /auth/link/confirm`.

---

## 8. Nonce Preservation on Refresh

### Problem

OIDC Core 1.0 Section 12.1 says refreshed ID tokens SHOULD contain the original nonce. Currently, refresh passes `None` for nonce, which is a spec deviation.

### Design

**Database change:**
```sql
ALTER TABLE refresh_tokens ADD COLUMN nonce text;
```

**Flow change:**
- When a refresh token is created from an auth code exchange that included a nonce, store the nonce on the refresh token
- When refreshing with `openid` scope, include the stored nonce in the new ID token
- The nonce propagates through rotations (new refresh token inherits nonce from consumed token)

---

## 9. Token Introspection (RFC 7662)

### Problem

Downstream apps currently validate tokens by fetching the JWKS and verifying JWTs locally. This works but has two drawbacks: (1) every app implements JWT validation slightly differently, and (2) token revocations (user deletion, session termination) aren't visible until the JWT expires. The soul doc's ethos is "roll all the auth stuff into one safe, simple place" — token validation should be no exception.

### Design

**New endpoint:** `POST /oauth/introspect`

- Accepts `token` parameter (form-encoded, per RFC 7662)
- Authenticated via client credentials (client_id + client_secret in Basic auth or POST body)
- Returns:
  ```json
  {
    "active": true,
    "sub": "user-uuid",
    "client_id": "requesting-client-id",
    "scope": "profile email",
    "aud": "target-client-id",
    "iss": "https://auth.example.com",
    "exp": 1234567890,
    "iat": 1234567800,
    "username": "riley",
    "token_type": "Bearer"
  }
  ```
- If the token is expired, revoked, or invalid: `{ "active": false }`
- The introspecting client must be registered (client credentials verified)
- A client can introspect tokens issued for any audience (resource server pattern), or this can be restricted — configurable

**Revocation visibility:** Because introspection checks the database (user exists, not soft-deleted, session not revoked), revocations take effect immediately — unlike JWT-only validation which waits for expiry.

**Coexistence with JWKS:** Both approaches remain available. High-throughput apps use JWKS for local validation. Apps needing instant revocation use introspection. Deployer chooses per-app.

**Discovery document update:**
- Add `introspection_endpoint: "{issuer}/oauth/introspect"`

---

## 10. OIDC Back-Channel Logout

### Problem

When a user logs out of riley_auth (or their session is revoked), downstream apps don't know until their cached tokens expire. In the "cinematic universe" where multiple apps share one identity, a user who clicks "log out" expects to be logged out everywhere — not just from the app they're looking at.

### Design

**Standards-compliant OIDC Back-Channel Logout (OpenID Connect Back-Channel Logout 1.0).**

**Database change:**
```sql
ALTER TABLE clients ADD COLUMN backchannel_logout_uri text;
ALTER TABLE clients ADD COLUMN backchannel_logout_session_required boolean NOT NULL DEFAULT false;
```

**Logout token format:**
A signed JWT (same RS256 key as ID tokens) with claims:
```json
{
  "iss": "https://auth.example.com",
  "sub": "user-uuid",
  "aud": "client-id",
  "iat": 1234567890,
  "jti": "unique-token-id",
  "events": {
    "http://schemas.openid.net/event/backchannel-logout": {}
  },
  "sid": "session-id"  // if backchannel_logout_session_required
}
```

**Dispatch triggers:**
- `POST /auth/logout` (single session)
- `POST /auth/logout-all` (all sessions for user)
- `DELETE /admin/users/{id}` (user deletion)
- Session revocation via admin

**Delivery mechanism:**
Reuse the webhook outbox infrastructure. When a logout event fires:
1. Find all clients with a `backchannel_logout_uri` that the user has active tokens for
2. For each client, enqueue a logout token delivery to the outbox
3. The delivery worker POSTs the logout token as `application/x-www-form-urlencoded` with `logout_token=<jwt>` (per spec)

This piggybacks on the existing outbox reliability (retries, bounded concurrency, delivery logging) without building a separate delivery system.

**Discovery document update:**
- Add `backchannel_logout_supported: true`
- Add `backchannel_logout_session_supported: true`

**Config:**
```toml
[oauth]
backchannel_logout_max_retry_attempts = 3
```

---

## 11. Multi-Provider Account Merging

### Problem

A user signs in with GitHub, creates an account. Months later, they sign in with Google using the same email. Currently `auth_callback` detects the email collision and redirects to `/link-accounts`, but the user has no session — they're trying to sign in, not link. The flow dead-ends.

### Design

**Configurable trust-based merging.** The deployer controls how aggressively riley_auth merges accounts based on email matching.

**Config:**
```toml
[auth]
# "none" — never auto-merge, always redirect to link-accounts (current behavior)
# "verified_email" — auto-merge if the OAuth provider reports the email as verified
# Default: "none"
account_merge_policy = "verified_email"
```

**Flow when `account_merge_policy = "verified_email"`:**

1. User signs in with Google. `auth_callback` gets profile with `email = "riley@example.com"`.
2. No existing oauth_link for this Google ID.
3. Find existing user(s) with matching email via oauth_links.
4. If exactly one match AND the provider reports email as verified:
   - Auto-create the oauth_link between the existing user and the new provider
   - Issue session tokens for the existing user
   - Dispatch `provider.linked` webhook event
   - Redirect to success URL
5. If multiple matches or email not verified:
   - Fall back to current behavior (redirect to `/link-accounts` with setup token)

**Provider email verification:**
- GitHub: Check `email_verified` field from user API (need to fetch this — currently not stored)
- Google: The `email_verified` claim is in the ID token / userinfo response
- Other providers: Add an `email_verified` field to the provider profile struct

**Database change:**
```sql
ALTER TABLE oauth_links ADD COLUMN email_verified boolean NOT NULL DEFAULT false;
```

Store the verification status at link creation time so we have it for future merge decisions.

**Security consideration:** Email-trust merging assumes OAuth providers correctly verify email ownership. Google and GitHub do. For less-trusted providers, the deployer sets `account_merge_policy = "none"`. The merge only fires when the new provider reports `email_verified = true` — if the provider doesn't confirm verification, no merge.

**Webhook event:** `provider.linked` — dispatched when an account merge auto-links a new provider.

---

## Implementation Order

1. **Stuck Outbox Recovery** — tiny change, clears operational debt first
2. **Nonce Preservation on Refresh** — small schema change, clears spec debt
3. **Scope Downscoping on Refresh** — small token endpoint change
4. **Webhook Replay Protection** — breaking change, do early before anyone integrates
5. **Account Linking Confirmation** — completes the link suggestion flow
6. **UserInfo Endpoint** — unblocks OIDC conformance, needed before back-channel logout
7. **Authorize Error Redirects** — prerequisite for third-party clients
8. **Consent UI Support** — completes the third-party OAuth flow
9. **Token Introspection** — centralizes token validation for the ecosystem
10. **OIDC Back-Channel Logout** — depends on outbox infra + client schema changes
11. **Multi-Provider Account Merging** — biggest design surface, benefits from all prior work being stable

**Grouping:**
- Phases 1-5: Quick wins and operational polish (clear accumulated debt)
- Phases 6-8: Third-party OAuth provider compliance
- Phases 9-11: Ecosystem features (the "cinematic universe" infrastructure)

**Review strategy:**
- Standard review after each phase
- Exhaustive review at phase 5 (debt cleared), phase 8 (OAuth compliance), and phase 11 (final)

---

## Out of Scope

Still not in v4:
- **Email/password auth** — violates the soul doc
- **MFA/TOTP** — delegated to OAuth providers
- **Built-in frontend/UI** — riley_auth provides APIs, deployer builds UI
- **Dynamic client registration (RFC 7591)** — against the soul doc's API-only approach
- **Database-stored scope definitions** — config-only is working
- **Account recovery** — OAuth provider's problem
- **Trusted proxy list** — current leftmost-with-overwrite approach is documented and sufficient
- **CLI webhook dispatch** — CLI remains an out-of-band maintenance tool
- **Observability/metrics** — revisit when there's production load to observe
