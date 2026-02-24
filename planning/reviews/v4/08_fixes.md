# Fixes for Review Round 07 — Phase 6 — 2026-02-23

All 6 actionable findings fixed in a single commit.

## Fixes Applied

| Finding | Severity | Fix | Commit |
|---------|----------|-----|--------|
| #1 Require `openid` scope | MAJOR | Added `openid` scope check returning 403 Forbidden | 1ab2431 |
| #2 Case-insensitive Bearer | MINOR | Changed to `eq_ignore_ascii_case` on first 7 chars | 1ab2431 |
| #3 `email_verified` claim | MINOR | Added `email_verified: true` when email is present | 1ab2431 |
| #4 Deterministic email ordering | MINOR | Added `ORDER BY created_at` to `find_oauth_links_by_user` | 1ab2431 |
| #5 Deleted user → 401 | MINOR | Changed `UserNotFound` to `InvalidToken` on deleted user | 1ab2431 |
| #6 `claims_supported` | MINOR | Added `email_verified` to discovery document | 1ab2431 |

## Notes Documented

- #7 (`profile`/`email` scopes): Added to review_notes_README.md as design decision
- #8 (`WWW-Authenticate`): Accepted as minor spec deviation, low impact

## Test Results

87 integration + 22 unit tests pass. New test: `userinfo_rejects_token_without_openid_scope`.
