# Review Round 23 — Phase 11 Exhaustive Review R1

**Date:** 2026-02-24
**Models:** Claude subagent only (~142k tokens, Codex rate-limited, Gemini exit 13)
**Scope:** Full codebase, exhaustive review for final v4 milestone

## Findings

### Major: 1

- **M1**: Phase 11 auto-merge does not verify the existing link's `email_verified` status. Only the new provider's email_verified is checked. If an existing link has `email_verified = false`, a verified new login could merge into the wrong account.
  - **Fix:** Filter `matching_links` by `email_verified = true` before collecting user IDs for merge. Added `verified_links` filter in `auth_callback`.
  - **Commit:** 5cff11a

### Minor: 0 (new)

All other MINOR findings were either already handled or settled in previous reviews:
- find_oauth_links_by_email already JOINs users and filters `deleted_at IS NULL`
- Base64 decode order in introspect: settled (functionally correct per review_notes)
- list_webhook_deliveries: API layer already clamps via `MAX_LIMIT`
- Setup token reusability: settled (mitigated by unique constraint)

### Notes
- n1: Client secrets SHA-256: settled decision (machine-generated high-entropy)
- n2: Webhook secrets plaintext: settled decision (needed for HMAC computation)
- n3: db.rs/auth.rs/integration.rs could be split for maintainability (organizational, not correctness)
- n4: OAUTH_CLIENT lacks explicit timeout (minor hardening)
- n5: Scope downscoping is permanent per token family (working as designed)

## Test Coverage

Added `account_merge_skips_unverified_existing_link` integration test verifying that auto-merge does not proceed when existing links are unverified.

## Result

1 MAJOR fixed (5cff11a). Running R2 for convergence.
