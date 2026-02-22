# Round 6 Fixes

## Major

### M1: Deleted user link creation (c5591bf)
Added `db::find_user_by_id` check in `link_callback` before creating OAuth links. Returns `UserNotFound` if the user has been soft-deleted since their JWT was issued.

### M2: Multi-provider unlink bypass (c5591bf)
Changed the last-provider guard in `delete_oauth_link_if_not_last` from:
```rust
if links.len() <= 1 { return LastProvider }
```
To:
```rust
let same_provider_count = links.iter().filter(|(_, p)| p == provider).count();
if links.len() - same_provider_count < 1 { return LastProvider }
```
This correctly handles the case where a user has multiple links for the same provider.

## Dismissed

### Token issuance TOCTOU
Not a real issue — orphaned refresh tokens can never be used because `auth_refresh` checks `find_user_by_id` which filters `deleted_at IS NULL`. Standard JWT tradeoff, not actionable.
