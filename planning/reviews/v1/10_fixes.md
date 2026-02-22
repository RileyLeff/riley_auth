# Round 5 Fixes

## Major

### M1: Deadlock in soft_delete_user and update_user_role (5f8d69f)
**Both functions** now use a single combined query to lock the target user and all admin rows with consistent `ORDER BY id`:

```sql
SELECT id, role FROM users
WHERE (id = $1 OR role = 'admin') AND deleted_at IS NULL
ORDER BY id FOR UPDATE
```

This eliminates the circular wait between concurrent delete/demote operations on different admin users.

## Minor

- m1 (rate limiting): Deferred to Phase 8
- m2 (scheduled cleanup): Deferred to Phase 8
- m3 (redundant UNIQUE): Noted, low priority
- m4 (case_sensitive config): Documentation issue, noted
