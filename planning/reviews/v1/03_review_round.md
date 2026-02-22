# Review Round 2 — 2026-02-22

**Models**: Codex (o4-mini full-auto), Gemini (gemini-2.5-pro), Claude (opus-4.6 subagent)
**Context**: ~120k tokens (full codebase)
**Mode**: Parallel, all three successful

**M1-M10 Verification**: All 10 original findings confirmed fixed by all three reviewers.

---

## Major (must fix)

### M1. `unlink_provider` TOCTOU race — can leave user with zero providers [consensus: codex + claude]
- **Location**: `auth.rs:unlink_provider` (count then delete)
- **Impact**: Two concurrent unlink requests both see count=2, both proceed, user ends up with zero providers and no way to log in
- **Fix**: Atomic `DELETE...WHERE (SELECT COUNT(*) > 1)` or `SELECT FOR UPDATE` in transaction

### M2. Admin can self-demote — last admin lockout [claude-only]
- **Location**: `admin.rs:update_role`, `admin.rs:delete_user`
- **Impact**: Sole admin can demote themselves or delete their account, leaving system with no admin. Only recovery is CLI.
- **Fix**: Check if requesting admin is the target; if so, verify at least one other admin exists

### M3. Admin `delete_user` non-atomic with refresh token cleanup [claude-only]
- **Location**: `admin.rs:delete_user` (and `auth.rs:delete_account`)
- **Impact**: Crash between `delete_all_refresh_tokens` and `soft_delete_user` leaves user with no tokens but still active
- **Fix**: Move refresh token deletion inside `soft_delete_user` transaction

---

## Minor (should fix)

### m1. Unique constraint violations surface as 500 [consensus: codex + claude]
- **Location**: `auth.rs:auth_setup`, `auth.rs:update_username`, `auth.rs:link_callback`
- **Impact**: Concurrent requests bypass pre-checks; DB unique violation → 500 instead of 409
- **Fix**: Catch sqlx unique constraint error (code 23505) and map to `UsernameTaken` / `ProviderAlreadyLinked`

### m2. OAuth revoke doesn't verify token ownership [consensus: gemini + claude]
- **Location**: `oauth_provider.rs:revoke`
- **Impact**: Authenticated client A could revoke client B's tokens (if it knows the token value)
- **Fix**: Add `AND client_id = $2` to revoke query

### m3. Username policy checks non-atomic [codex-only]
- **Location**: `auth.rs:update_username` (cooldown + hold check before tx)
- **Impact**: Concurrent requests could bypass cooldown
- **Fix**: Move all checks inside the transaction with `SELECT FOR UPDATE`

### m4. `allow_changes` config flag ignored [codex-only]
- **Location**: `config.rs:91`, `auth.rs:update_username`
- **Fix**: Check `config.usernames.allow_changes` at start of `update_username`

### m5. Regex recompilation on every username validation [claude-only]
- **Location**: `auth.rs:validate_username`
- **Fix**: Pre-compile regex at startup, store in `AppState`

### m6. `link_callback` TOCTOU on duplicate check [claude-only]
- **Location**: `auth.rs:link_callback`
- **Fix**: Use `INSERT...ON CONFLICT DO NOTHING` or catch unique violation

### m7. No pagination limit cap [claude-only]
- **Location**: `admin.rs:PaginationQuery`
- **Fix**: Clamp limit to max (e.g., 500)

### m8. Admin delete returns success for nonexistent users [codex-only]
- **Location**: `admin.rs:delete_user`
- **Fix**: Check affected rows from `soft_delete_user`

### m9. Setup token not purpose-bound [claude-only]
- **Location**: `auth.rs:create_setup_token`
- **Fix**: Use distinct purpose values for new-account vs link-account flows

### m10. No display_name length validation [claude-only]
- **Location**: `auth.rs:update_display_name`
- **Fix**: Add max length check (e.g., 200 chars)

---

## Notes (observations/tradeoffs)

1. No periodic cleanup of expired auth codes triggered automatically [claude]
2. Soft-deleted users' access tokens remain valid until JWT expiry (~15min) [claude]
3. `reqwest::Client::new()` per OAuth request is wasteful; share in AppState [claude]
4. No rate limiting on any endpoint; `RateLimited` error exists but unused [claude]
5. CORS permissive when origins empty has warning but could be hard error in prod [claude]
6. OAuth state comparison uses `==` not constant-time, but state is in HttpOnly cookie so practical risk is low [claude, downgraded from major]
7. Deleted username uniqueness in DB is a conscious design choice, not a bug [gemini]
