# Exhaustive Review Round 2 — 2026-02-23

**Models**: Gemini, Claude Opus 4.6 (Codex not attempted — failed in R1)
**Context**: ~113k tokens
**Scope**: Full codebase, post-R1 fixes

## Model Results

- **Gemini**: Found 3 MAJORs (1 reclassified), 4 MINORs, 3 NOTEs
- **Claude**: Found 0 MAJORs, 4 MINORs, 8 NOTEs (1 self-retracted)

## Findings

### Major

**MAJOR-R2-01: Username hold blocks owner from reverting** [gemini-only]
- File: `db.rs` — `is_username_held()`
- The hold check only looks at `old_username` + `held_until`, not `user_id`. The legitimate owner cannot reclaim their own previous username during the hold period.
- **Action**: Fix — add `user_id` parameter, exclude the requesting user's holds.

### Minor

**MINOR-R2-01: Misleading error in create_user_with_link race** [gemini-only]
- File: `auth.rs` — `auth_setup`
- Unique violation from oauth_links table maps to `UsernameTaken` error. Narrow race (pre-checks cover common case), but misleading if hit.
- **Action**: Fix — distinguish which constraint was violated.

**MINOR-R2-02: Role demotion doesn't invalidate tokens** [claude-only]
- File: `admin.rs` — `update_role()`
- After demoting admin→user, the demoted user retains access tokens with `role: admin` until TTL. `require_admin` re-checks DB (mitigating admin endpoints), but external consumers trusting JWT are exposed.
- **Action**: Fix — call `delete_all_refresh_tokens` after demotion to force re-auth.

**MINOR-R2-03: Webhook URL not SSRF-checked at registration** [claude-only]
- File: `admin.rs` — `register_webhook()`
- Private IP URLs are accepted at registration, caught only at delivery time.
- **Action**: Document — defense-in-depth improvement, but not blocking. Delivery-time check is the real protection.

**MINOR-R2-04: OAuth provider routes bypass CSRF** [claude-only]
- Correct by design — client-secret-authenticated, not browser-initiated.
- **Action**: Document with inline comment.

**MINOR-R2-05: No CSRF test for admin endpoints** [gemini-only]
- Test coverage gap. Existing test only covers PATCH /auth/me.
- **Action**: Note — would improve test coverage but not blocking.

**MINOR-R2-06: No client_secret_basic support** [gemini-only]
- Only `client_secret_post` is supported.
- **Action**: Note for future work. Current clients are first-party.

**MINOR-R2-07: OAuth authorize returns 401 for unauthenticated** [gemini-only]
- UX improvement for Phase 8 (Consent UI Support).
- **Action**: Note — planned for later phases.

### Notes

- Gemini MAJOR-05 reclassified as NOTE: session scopes hardcoded to `&[]` is by design (sessions use role-based auth).
- Claude MINOR-01/NOTE-01: logout-all/revoke_session don't record consumed tokens — accepted per v3 review notes.
- Claude MINOR-04: webhook dispatch outside soft-delete transaction — systemic pattern, accepted.
- Claude MINOR-05: logout-all in Standard tier — acceptable, authenticated-only endpoint.
- Claude MINOR-06: username change doesn't invalidate old access tokens — inherent JWT statelessness.
- Claude MINOR-08: no return_to support — UX feature request.
- Claude NOTE-02: setup token cross-tab overwrite — noted, accepted.
- Claude NOTE-04/NOTE-05: rate limiter notes — informational.
