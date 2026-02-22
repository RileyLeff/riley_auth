# Review Notes — Design Decisions & Tradeoffs

This file records architectural tradeoffs flagged during review that are intentional, and settled design decisions to prevent re-litigation.

## OAuth state comparison (non-constant-time)
**Flagged by**: Claude R3 (minor)
**Decision**: Keep `!=` comparison. OAuth state is a random 32-byte nonce, single-use, and stored in an HttpOnly cookie. A timing side-channel on a random single-use nonce is not exploitable — there's nothing to learn from timing because the attacker doesn't control which state to compare against.

## `display_name.len()` checks bytes not chars
**Flagged by**: Claude R3 (minor)
**Decision**: Keep byte-length check. This is conservative — multi-byte characters make the effective limit shorter, not longer. A display name of 200 bytes is a reasonable limit. If we ever need precise character counting, we can switch to `.chars().count()`, but it's not a security issue.

## `validate_username` recompiles regex per call
**Flagged by**: Claude R3 (minor)
**Decision**: Acceptable for now. Username validation happens rarely (account creation, username change). If profiling shows this matters, can use `OnceLock` or `LazyLock` to cache the compiled regex. Not a correctness issue.

## `/oauth/revoke` swallows DB errors
**Flagged by**: Codex R3 (note)
**Decision**: Intentional per RFC 7009. The revocation endpoint SHOULD return 200 for both valid and invalid tokens. Silencing DB errors means we return 200 even if the DB is down, which is technically wrong but follows the spec's philosophy of "always succeed." The tradeoff is acceptable for a revocation endpoint — the worst case is a token that should have been revoked remains valid until expiry.

## Soft delete uses `deleted_{uuid}` username pattern
**Decision**: This prevents username collisions between deleted and active users. The username becomes `deleted_<uuid>`, which is blocked by the `validate_username` regex pattern, preventing anyone from registering this as a real username.

## Username cooldown TOCTOU
**Flagged by**: Gemini R4 (minor)
**Decision**: The cooldown check happens before the transaction, but this is not a security boundary — it's a UX/abuse-prevention measure. The actual username update is atomic (unique constraint enforced by the DB), and the cooldown is advisory. Moving the check inside the transaction would require refactoring for marginal benefit. The worst case is a user changing their username slightly faster than the cooldown period in a narrow race window.
