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

## Redundant UNIQUE constraint on username column
**Flagged by**: Gemini R5 (minor)
**Decision**: Keep for now. The column-level UNIQUE and the filtered functional index `idx_users_username_lower` overlap. The filtered index provides the real enforcement for active users (case-insensitive, soft-delete aware). The column-level UNIQUE is stricter (includes deleted users) but harmless since deleted usernames use the `deleted_{uuid}` pattern which can't collide. Removing it would be clean but low priority.

## `case_sensitive` config option
**Flagged by**: Gemini R5 (minor)
**Decision**: The DB always enforces case-insensitive uniqueness via the `lower()` index. The config option controls application-layer behavior (e.g., whether the API treats "Admin" and "admin" as the same username for lookup). Could use a documentation note but not a bug.

## Token issuance TOCTOU (user deleted between fetch and token store)
**Flagged by**: Codex R6 (major)
**Decision**: Dismissed. If a user is soft-deleted between `find_user_by_id` and `store_refresh_token`, the orphaned refresh token can never be used — the next `auth_refresh` call checks `find_user_by_id` (which filters `deleted_at IS NULL`) and returns UserNotFound. The access token expires naturally within the short TTL. This is the standard JWT tradeoff — not a bug, not fixable without making JWTs stateful (defeating their purpose).

## JWT audience defaults (`validate_aud = false`)
**Flagged by**: Gemini R7 (minor), Gemini R8 (minor)
**Decision**: Defense-in-depth improvement only. All current call sites correctly check audience: session routes verify `aud == issuer`, OAuth provider routes verify `aud == client_id`. The risk is a future developer adding a new route without audience checking. Low priority since the entire auth module is small and well-understood.

## `auth_setup` maps all unique violations to username_taken
**Flagged by**: Gemini R6 (minor)
**Decision**: Acceptable. The username is pre-checked before the transaction, so the only unique violation that can realistically occur is the username constraint. If some exotic race causes a different unique violation, returning "username taken" is a safe and non-leaking error.

## Manual ASN.1/DER parsing in JWKS endpoint
**Flagged by**: Gemini R9 (minor)
**Decision**: The `extract_rsa_components` function manually parses the DER structure to extract modulus and exponent. While the `rsa` crate (transitive dependency) could provide this more robustly, the current implementation works correctly for the standard RSA key format we generate. Not a security vulnerability — worst case is a broken JWKS endpoint, not a bypass. Can improve later.

## kid generation from full PEM content
**Flagged by**: Gemini R9 (minor)
**Decision**: The key ID is SHA-256 of the full PEM file. This means whitespace/comment changes would alter the kid. In practice we control key generation and PEM format is stable. For a v1 single-key deployment this is fine. Could improve to hash only DER bytes in a future iteration.
