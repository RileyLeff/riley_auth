# Round 4 Fixes Summary

Commit: b20fc3d

## Major Fixes

### M1: Last-admin delete guard
- `soft_delete_user` now checks if the target user is an admin using `SELECT role FROM users WHERE id = $1 FOR UPDATE`
- If admin, locks all admin rows with `SELECT FOR UPDATE` and rejects if count <= 1
- Returns `DeleteUserResult` enum: `Deleted`, `LastAdmin`, `NotFound`
- Updated admin `delete_user`, auth `delete_account`, and CLI `delete` to handle enum

## Minor Fixes

### m1: PII cleanup in soft_delete_user
- Added `DELETE FROM username_history WHERE user_id = $1` to the transaction

### m2: Authorization code cleanup in soft_delete_user
- Added `DELETE FROM authorization_codes WHERE user_id = $1` to the transaction

### m3: Index mismatch
- Changed `idx_oauth_links_provider_email` to use `lower(provider_email)` to match query expression
