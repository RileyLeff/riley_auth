# Round 3 Fixes Summary

Commit: 0151755

## Major Fixes

### M1: Atomic `unlink_provider` with `SELECT FOR UPDATE`
- Rewrote `delete_oauth_link_if_not_last` to use a transaction with `SELECT id, provider FROM oauth_links WHERE user_id = $1 FOR UPDATE`
- Locks all user's links to serialize concurrent unlink attempts
- Returns new `UnlinkResult` enum: `Deleted`, `LastProvider`, `NotFound`
- Route handler now pattern-matches on `UnlinkResult` for correct error codes
- Removed unused `count_oauth_links` function

### M2: Atomic admin role demotion with `SELECT FOR UPDATE`
- Rewrote `update_user_role` to use a transaction with `SELECT id FROM users WHERE role = 'admin' AND deleted_at IS NULL FOR UPDATE`
- Locks all admin rows to serialize concurrent demotion attempts
- Returns new `RoleUpdateResult` enum: `Updated(User)`, `LastAdmin`, `NotFound`
- Removed separate `count_admins` function (inlined into atomic operation)
- Updated admin API endpoint to pattern-match on `RoleUpdateResult`
- Updated CLI `Promote` and `Demote` to handle `RoleUpdateResult`

## Minor Fixes
- **m1**: `unlink_provider` now returns `NotFound` (not `LastProvider`) when provider doesn't exist
- **m2**: Pagination `limit` and `offset` both clamped to non-negative values
- **m3**: CLI `Demote` now uses atomic last-admin guard
- **m4**: CLI `Delete` no longer double-deletes refresh tokens
