# Fixes for Review Round 13 — Phase 4 Exhaustive R1

**Commits:** 736f243, d401fcf

## Major Fixes

**M1: UserInfo endpoint non-functional for OIDC clients** — Fixed (removed)
- Removed `userinfo_endpoint` from discovery document
- `/auth/me` is a session-only endpoint that rejects Bearer tokens and client audiences
- A proper OIDC UserInfo endpoint is future work

**M2: OAuth error responses use `detail` instead of `error_description`** — Fixed
- Renamed `ErrorBody.detail` to `ErrorBody.error_description`
- Now aligns with RFC 6749 Section 5.2
- Updated integration test assertion

## Minor Fixes

**m3: Missing test for authorization code replay** — Fixed
- Added `oauth_authorization_code_replay_rejected` integration test

**m4: Missing test for PKCE verification failure** — Fixed
- Added `oauth_pkce_wrong_verifier_rejected` integration test

**m6: Empty string display names allowed** — Fixed
- `update_display_name` now treats empty/whitespace-only input as clearing the display name (sets to NULL)
- `update_user_display_name` in db.rs changed to accept `Option<&str>`

## Deferred (with reasoning)

**m1: Authorize endpoint errors not redirected** — Deferred to future work
- All current clients are auto_approve first-party; error redirect flow is only needed for third-party consent flows
- Implementing RFC 6749 Section 4.1.2.1 error redirects is architectural work

**m2: Nonce not carried forward on refresh** — Noted in review_notes
- OIDC Core 1.0 Section 12.1 says SHOULD, not MUST
- Would require adding nonce column to refresh_tokens + migration

**m5: Missing test for expired auth code** — Deferred
- Testing expiry requires time manipulation; the `consume_authorization_code` SQL already checks `expires_at > now()`

**m7: No pagination on list_clients/list_webhooks** — Noted
- Admin-only endpoints with naturally small result sets

## Tests

All 104 tests pass (60 integration + 36 unit + 8 Redis).
