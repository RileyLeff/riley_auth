# Fixes for Review Round 2 — 2026-02-23

**Commit**: c26641e

## Fixes

### MAJOR-R2-01: Username hold allows owner reclamation [gemini]
- Modified `is_username_held()` to accept `requesting_user_id` parameter
- Added `AND user_id != $2` to exclude the requesting user's own holds
- `auth_setup` passes `Uuid::nil()` (new user, all holds apply)
- `update_username` passes real `user_id` (owner can reclaim their name)
- Updated test to pass `Uuid::nil()` for third-party perspective

### MINOR-R2-01: Constraint disambiguation in auth_setup [gemini]
- Added `unique_violation_constraint()` helper to error.rs
- `auth_setup` now checks constraint name: `oauth_links` → `ProviderAlreadyLinked`, else → `UsernameTaken`

### MINOR-R2-02: Role demotion forces re-auth [claude]
- `update_role` now calls `delete_all_refresh_tokens` after role change
- Forces re-authentication so user gets fresh tokens with updated role claim

## Accepted (No Code Change)

- **Gemini MAJOR-05** (session scopes empty): By design — sessions use role-based auth, not scopes. Reclassified as NOTE.
- **Claude MINOR-01/NOTE-01**: logout-all consumed tokens — accepted per v3 review notes.
- **Claude MINOR-02**: OAuth CSRF bypass — correct by design.
- **Claude MINOR-03**: Webhook SSRF at registration — delivery-time check is sufficient.
- **Gemini MINOR-10**: Webhook verification helper — feature request, not a bug.
- **Gemini MINOR-11**: client_secret_basic support — future work for third-party clients.
- **Gemini MINOR-13**: OAuth authorize 401 — Phase 8 (Consent UI) will address.
