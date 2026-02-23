# v4 Implementation Plan

11 phases, grouped into 3 tracks. Standard review after each phase. Exhaustive review at milestones (phases 5, 8, 11).

---

## Phase 1: Stuck Outbox Recovery

**Steps:**
1. Add `stuck_processing_timeout_secs` config field (default 300) to `WebhooksConfig`
2. Add `reset_stuck_outbox_entries()` function to `db.rs`
3. Call it in `run_maintenance_cycle` after existing cleanup
4. Integration test: insert a "processing" entry with old `updated_at`, run maintenance, verify it's reset to "pending"

**Review:** Standard (1 round)

---

## Phase 2: Nonce Preservation on Refresh

**Steps:**
1. Database migration: `ALTER TABLE refresh_tokens ADD COLUMN nonce text`
2. `cargo clean -p riley-auth-core` (sqlx embed)
3. Update `store_refresh_token()` to accept and store nonce
4. In token endpoint (auth_code grant): pass nonce from auth code to refresh token
5. In token endpoint (refresh grant): read nonce from consumed token, pass to new token + ID token
6. Update `consume_session_refresh_token` and `consume_client_refresh_token` to return nonce
7. Integration test: authorize with nonce → exchange → refresh → verify nonce in refreshed ID token

**Review:** Standard (1 round)

---

## Phase 3: Scope Downscoping on Refresh

**Steps:**
1. In token endpoint (refresh grant): accept optional `scope` parameter
2. Parse and validate requested scopes are subset of token's current scopes
3. If valid, issue new tokens with narrowed scope set
4. If invalid (scope not in original set), return `invalid_scope` error
5. Integration test: authorize with `profile email` → refresh with `profile` only → verify narrowed scopes

**Review:** Standard (1 round)

---

## Phase 4: Webhook Replay Protection

**Steps:**
1. Update `sign_payload()` in `webhooks.rs` to include timestamp: `HMAC(secret, "{timestamp}.{body}")`
2. Update signature header format: `X-Signature-256: t={ts},sha256={hex}`
3. Update `deliver_outbox_entry` to pass timestamp to signing
4. Update webhook delivery integration test to verify new signature format
5. Update unit test for `sign_payload`

**Review:** Standard (1 round)

---

## Phase 5: Account Linking Confirmation

**Steps:**
1. Add `POST /auth/link/confirm` endpoint
2. Requires active session (cookie) + setup token (cookie from redirect)
3. Decode setup token, validate provider identity isn't already linked
4. Create oauth_link between authenticated user and setup token's provider
5. Clear setup cookie, dispatch `provider.linked` webhook
6. Return updated user profile
7. Integration test: create user → simulate email collision redirect → confirm link → verify two providers on one account

**Review:** Exhaustive (milestone — debt cleared)

---

## Phase 6: UserInfo Endpoint

**Steps:**
1. Add `GET /oauth/userinfo` endpoint (and POST variant)
2. Accept `Authorization: Bearer <token>` header
3. Validate JWT: check signature, expiry, and `aud` matches a registered client
4. Fetch user profile from DB
5. Return claims filtered by granted scopes (openid→sub, profile→username/name/picture, email→email)
6. Fetch email from primary oauth_link
7. Update discovery document: add `userinfo_endpoint`, `claims_supported`, `scopes_supported`
8. Integration test: full OAuth flow → use access token to call /oauth/userinfo → verify claims

**Review:** Standard (1 round)

---

## Phase 7: Authorize Error Redirects

**Steps:**
1. Refactor `authorize` endpoint error handling:
   - Pre-redirect errors (invalid client_id, invalid redirect_uri): return HTTP 400 directly
   - Post-redirect errors (bad response_type, invalid scope, unauthenticated, consent required): redirect with `?error=...&state=...`
2. Add helper function `redirect_error(redirect_uri, error_code, description, state)` → `Redirect`
3. Validate client_id and redirect_uri FIRST, before any other checks
4. Integration tests: verify each error type returns correct format (HTTP vs redirect)

**Review:** Standard (1 round)

---

## Phase 8: Consent UI Support

**Steps:**
1. Add `consent_url` to `OAuthConfig` (optional, no default)
2. Database: create `consent_requests` table (id, client_id, user_id, scopes, redirect_uri, state, code_challenge, code_challenge_method, nonce, created_at, expires_at)
3. Modify `authorize`: for non-auto-approve clients, store consent request in DB, redirect to `consent_url?consent_id={id}`
4. Add `GET /oauth/consent` — requires session cookie + consent_id, returns consent context JSON
5. Add `POST /oauth/consent` — requires session cookie + consent_id, body `{approved: bool}`
   - If approved: issue auth code, redirect to stored redirect_uri
   - If denied: redirect with `?error=access_denied`
6. Consent requests expire after 10 minutes
7. Integration tests: non-auto-approve client → consent flow → approve → verify auth code; deny → verify error redirect

**Review:** Exhaustive (milestone — OAuth compliance complete)

---

## Phase 9: Token Introspection

**Steps:**
1. Add `POST /oauth/introspect` endpoint
2. Authenticate via client credentials (Basic auth or POST body client_id + client_secret)
3. Accept `token` form parameter
4. Decode JWT, verify signature
5. Check token is not expired
6. Check user exists and is not soft-deleted
7. Return RFC 7662 response: `{active, sub, client_id, scope, aud, iss, exp, iat, username, token_type}`
8. Invalid/expired/revoked tokens → `{active: false}`
9. Update discovery document: add `introspection_endpoint`
10. Integration test: issue token → introspect → verify claims; delete user → introspect → verify inactive

**Review:** Standard (1 round)

---

## Phase 10: OIDC Back-Channel Logout

**Steps:**
1. Database migration: add `backchannel_logout_uri text` and `backchannel_logout_session_required boolean` to `clients`
2. Add `backchannel_logout_max_retry_attempts` to config
3. Create `build_logout_token()` — JWT with `iss, sub, aud, iat, jti, events, sid` claims
4. Add `dispatch_backchannel_logout()` function:
   - Find all clients with `backchannel_logout_uri` that the user has active refresh tokens for
   - For each: build logout token, enqueue to webhook outbox (reuse existing infra)
5. Call dispatch on: logout, logout-all, admin delete_user, session revocation
6. Delivery: POST `logout_token=<jwt>` as `application/x-www-form-urlencoded` to the client's URI
7. Update admin API: accept `backchannel_logout_uri` on client registration/update
8. Update discovery document: `backchannel_logout_supported`, `backchannel_logout_session_supported`
9. Integration test: register client with logout_uri → create session → logout → verify logout token delivered

**Review:** Standard (1 round)

---

## Phase 11: Multi-Provider Account Merging

**Steps:**
1. Add `account_merge_policy` config field (enum: "none", "verified_email"; default "none")
2. Database migration: add `email_verified boolean DEFAULT false` to `oauth_links`
3. Update provider profile fetching to capture `email_verified` status:
   - GitHub: check user API response
   - Google: check ID token / userinfo `email_verified` claim
   - Generic: add `email_verified` field to `ProviderProfile`
4. Store `email_verified` in oauth_links at link creation
5. Update `auth_callback`:
   - When email collision detected AND `account_merge_policy == "verified_email"`:
     - Check new provider reports `email_verified == true`
     - Check exactly one existing user matches the email
     - Auto-create oauth_link, issue session, dispatch `provider.linked` webhook
   - Otherwise: fall back to current redirect-to-link-accounts behavior
6. Integration test: create user via GitHub → sign in via Google with same email → verify auto-merge
7. Integration test: `account_merge_policy = "none"` → verify no auto-merge (redirect to link-accounts)

**Review:** Exhaustive (final milestone — v4 complete)
