# Review Round 3 — Merged Parallel Review

**Models**: Gemini 2.5 Pro, Claude subagent (Opus 4.6), Codex (o4-mini)
**Scope**: Full codebase review to verify R2 fixes and check for convergence

## R2 Fix Verification
- Atomic `soft_delete_user`: **Correct** [consensus]
- `23505` unique constraint handling: **Correct** [consensus]
- Revoke ownership scoping: **Correct** [consensus]
- `allow_changes` enforcement: **Correct** [consensus]
- Pagination cap: **Partial** — upper bound capped but negative values not clamped [codex-only]
- Display name max length: **Correct** [consensus]
- Atomic `unlink_provider`: **NOT complete** — still raceable [codex-only, see M1]
- Admin self-demotion guard: **NOT complete** — still raceable [consensus Claude+Codex, see M2]

## Major (must-fix)

### M1: `unlink_provider` concurrent race [codex-only]
`delete_oauth_link_if_not_last` uses `DELETE...WHERE (SELECT COUNT(*) > 1)` but the subquery uses the statement's snapshot under READ COMMITTED. Two concurrent unlinks on different providers can both see `COUNT=2` and both succeed, leaving 0 links. Also, the DELETE targets all links for a provider (by name), not a specific link.

**Fix**: Rewrite to use `SELECT id, provider FROM oauth_links WHERE user_id = $1 FOR UPDATE` within a transaction, count in application, then delete. Return `UnlinkResult` enum for proper error differentiation.

### M2: Admin demotion TOCTOU race [consensus: Claude+Codex]
`update_role` uses check-then-act: `count_admins` then `update_user_role` in separate statements. Two admins demoting concurrently (self or each other) can both pass the count check.

**Fix**: Rewrite `update_user_role` to use `SELECT FOR UPDATE` on all admin rows within a transaction, check count, then update. Returns `RoleUpdateResult` enum. Applied to both API endpoint and CLI `demote` command.

## Minor

### m1: Unlink returns wrong error for absent provider [codex-only]
When delete fails, handler checks total link count and returns `LastProvider` even when the provider doesn't exist. Should return `NotFound`.

**Fix**: New `UnlinkResult::NotFound` variant handles this case.

### m2: Negative pagination values reach SQL [codex-only]
`limit` was upper-capped but not lower-capped; `offset` was unchecked. Negative values cause DB errors.

**Fix**: Clamp both: `limit.max(0).min(MAX_LIMIT)` and `offset.max(0)`.

### m3: CLI `Demote` has no last-admin guard [claude-only]
CLI `demote` command called `update_user_role` directly without any guard.

**Fix**: CLI now uses the same atomic `update_user_role` which returns `RoleUpdateResult::LastAdmin`.

### m4: CLI `Delete` double-deletes refresh tokens [note]
CLI called `delete_all_refresh_tokens` then `soft_delete_user`, but the latter already deletes tokens in its transaction.

**Fix**: Removed redundant `delete_all_refresh_tokens` call from CLI.

### m5: OAuth state comparison not constant-time [claude-only]
`auth_callback` compares state with `!=` (timing leak). Low risk since state is random and single-use.

**Status**: Note — timing side-channel on random, single-use nonce is not exploitable in practice.

### m6: `display_name.len()` checks bytes not chars [claude-only]
Multi-byte UTF-8 characters could make the limit stricter than intended.

**Status**: Note — this is conservative (shorter limit for multi-byte), not a security issue. `.chars().count()` would be more precise but `.len()` is fine for a display name limit.

### m7: `validate_username` recompiles regex on every call [claude-only]
The regex pattern is compiled from config on each validation call.

**Status**: Note — performance concern, not a bug. Could use `OnceLock` or `LazyLock` in the future if profiling shows it matters.

## Notes
- Gemini returned 0 findings (full clean pass)
- Codex found both majors
- Claude subagent found the admin TOCTOU as minor severity, plus several minors/notes

## Verdict
**2 major findings** — NOT a clean pass. Fixes applied in commit 0151755.
