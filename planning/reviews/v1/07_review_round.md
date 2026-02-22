# Review Round 4 — Merged Parallel Review

**Models**: Gemini 2.5 Pro, Claude subagent (Opus 4.6). Codex failed (no output, graceful degradation).
**Scope**: Full codebase review to verify R3 concurrency fixes and check for convergence

## R3 Fix Verification
- **Atomic unlink_provider (SELECT FOR UPDATE)**: Correct [consensus]
- **Atomic admin role demotion (SELECT FOR UPDATE)**: Correct [consensus]
- **CLI last-admin guard**: Correct [consensus]
- **Negative pagination clamp**: Correct [consensus]

## Major (must-fix)

### M1: Last-admin delete bypass [consensus: Gemini (major) + Claude (minor)]
`DELETE /admin/users/{id}` and `DELETE /auth/me` can delete the last admin, leaving the system with zero administrators. The last-admin guard was only added to role demotion, not to user deletion.

**Fix**: `soft_delete_user` now checks if the target is the last admin using `SELECT FOR UPDATE`, returning `DeleteUserResult::LastAdmin` to reject the operation.

## Minor

### m1: PII leak in username_history on soft delete [gemini-only]
`soft_delete_user` anonymized the users table but left old usernames in `username_history` linked to the user's UUID.

**Fix**: Added `DELETE FROM username_history WHERE user_id = $1` to the `soft_delete_user` transaction.

### m2: Authorization code cleanup on soft delete [consensus]
`soft_delete_user` revoked refresh tokens but not outstanding authorization codes.

**Fix**: Added `DELETE FROM authorization_codes WHERE user_id = $1` to the `soft_delete_user` transaction.

### m3: Index mismatch on provider_email [gemini-only]
`find_oauth_links_by_email` uses `lower(provider_email)` but the index was on `provider_email` (non-functional), causing seq scans.

**Fix**: Changed index to `lower(provider_email)` in migration.

### m4: Username cooldown TOCTOU [gemini-only]
Cooldown check in `update_username` happens before the transaction, allowing concurrent rapid requests to bypass it.

**Status**: Note — the `change_username` function already uses a transaction for the actual update. The cooldown check is advisory (not a security boundary) and the unique constraint prevents duplicate usernames. Marking as note per review_notes_README.md.

## Notes
- OAuth state comparison (non-constant-time) — settled design decision, see review_notes
- Regex recompilation — settled design decision, see review_notes
- display_name byte vs char length — settled design decision, see review_notes
- No rate limiting — Phase 8 item
- Permissive CORS default — logged with tracing::warn, development convenience

## Verdict
**1 major finding** — NOT a clean pass. Fixes applied in commit b20fc3d.
