# Review Round 17 — Phase 6 Standard Review R1

**Date:** 2026-02-24
**Type:** Standard review (Phase 6 — Codebase Organization)
**Models:** Claude Opus 4.6 only
**Context:** ~161k tokens (full codebase)

## Findings

### Major

None.

### Minor

1. **[claude-only] `db::update_username` unused — bypasses history tracking** — Standalone function never called; `db::change_username` handles username updates atomically with history. Potential footgun if used directly. PRE-EXISTING dead code, not introduced by refactoring. Phase 7+ candidate for removal.

2. **[claude-only] `db::record_username_change` unused as standalone** — Only the transactional `change_username` calls the history insert inline. Standalone function never called. PRE-EXISTING.

3. **[claude-only] `db::update_user_avatar` unused** — Reserved for future avatar upload feature. PRE-EXISTING.

4. **[claude-only] `db::delete_consent_request` unused** — Codebase uses `consume_consent_request` and `cleanup_expired_consent_requests`. PRE-EXISTING.

5. **[claude-only] `db::create_user` only needed for tests** — All production creation uses `create_user_with_link`. PRE-EXISTING.

6. **[claude-only] `Webhook.secret` skip_serializing annotation could mislead** — Admin handlers use separate response types; annotation on model struct doesn't reflect full behavior. Documentation improvement.

### Notes

1. Module organization is clean — all submodules reference shared types via `super::`, no inter-submodule dependencies
2. Re-export strategy (`pub use submodule::*`) is correct — all callers unchanged
3. Test infrastructure correctly shares state via `OnceLock<TestServer>`
4. Cleanup functions in `mod.rs` (rather than domain submodules) is a defensible choice
5. "consumed_refresh_tokens not cleaned by maintenance worker" tradeoff is OUTDATED — maintenance_worker now calls `cleanup_consumed_refresh_tokens` with cutoff of 2x refresh TTL
6. `Webhook` struct has `Deserialize` derive unlike other models — needed for delivery logic

## Summary

Phase 6 refactoring is behaviorally transparent. 0 major, 6 minor (all pre-existing dead code exposed by the split). No fixes needed for the refactoring itself. Dead code cleanup deferred to a future phase.
