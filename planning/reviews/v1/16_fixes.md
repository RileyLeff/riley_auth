# R8 Fixes

## [Major] READ COMMITTED snapshot race in `create_oauth_link`
**Commit**: 4d0df05
**What changed**: Replaced `INSERT...SELECT FROM users WHERE deleted_at IS NULL` (lock-free) with an explicit transaction using `SELECT ... FOR SHARE` on the user row before the INSERT.

**Why FOR SHARE**:
- Blocks if `soft_delete_user` holds `FOR UPDATE` — we wait until delete completes, then see `deleted_at IS NOT NULL` and return `UserNotFound`
- If user is alive, our `FOR SHARE` lock prevents `soft_delete_user` from acquiring `FOR UPDATE` until our transaction commits — the INSERT is guaranteed to execute while the user is still active
- `FOR SHARE` (not `FOR UPDATE`) allows concurrent `create_oauth_link` calls to proceed in parallel — no unnecessary serialization between link creations

**Tests**: All 15 pass.
