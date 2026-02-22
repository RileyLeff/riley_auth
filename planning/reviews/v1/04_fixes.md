# Round 2 Fixes Summary

Commit: d582173 (R2 fixes), 44eefd1 (review artifacts)

## Major Fixes
- **M1**: Atomic `unlink_provider` — `delete_oauth_link_if_not_last` uses `DELETE...WHERE (SELECT COUNT(*) > 1)` to prevent TOCTOU
- **M2**: Admin self-demotion guard — `update_role` checks `count_admins` before allowing demotion
- **M3**: Fully atomic `soft_delete_user` — includes refresh token deletion inside same transaction; returns `bool` for affected-row check

## Minor Fixes
- **m1**: Unique constraint handling (23505) in `auth_setup`, `update_username`, `link_callback`
- **m2**: OAuth revoke ownership — `delete_refresh_token_for_client` scopes revocation to requesting client
- **m4**: `allow_changes` enforced in `update_username`
- **m7**: Pagination cap — `list_users` clamps limit to 500
- **m10**: Display name validation — max 200 chars
