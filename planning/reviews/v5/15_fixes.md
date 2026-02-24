# Fixes for Review Round 14 (Phase 5 Exhaustive R1)

## Fix 1: Auth code reuse test (MINOR-12a)

**Commit:** 9604e72
**Finding:** Missing test for authorization code reuse detection (RFC 6749 §4.1.2)
**Fix:** Added `authorization_code_reuse_rejected` integration test that:
- Obtains an authorization code via the authorize endpoint
- Exchanges it successfully at the token endpoint
- Attempts to exchange the same code again
- Asserts the second exchange returns 400 Bad Request

## Reclassifications

- **MAJOR-1** (auth code UPDATE-mark): Reclassified as NOTE — pre-existing accepted design decision, documented in review_notes_README.md.
- **MAJOR-2** (webhook secrets plaintext): Reclassified as NOTE — pre-existing accepted tradeoff, documented in review_notes_README.md.
- **MINOR-12f** (no prompt=consent test): FALSE POSITIVE — test `prompt_consent_with_auto_approve_issues_code` exists.

## No-action items

MINOR-4 (rate limiter counter), MINOR-5 (Redis precision), MINOR-8 (token response scope), MINOR-9 (username TOCTOU), MINOR-10 (schema quoting) — reviewer self-acknowledged no fix needed.

MINOR-1, MINOR-2, MINOR-3, MINOR-6, MINOR-7 — pre-existing documented items.

MINOR-11 (Keys alias) — deferred to Phase 6 (codebase organization).
