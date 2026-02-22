# Review Round 7 — Merged Parallel Review

**Models:** Claude subagent, Gemini 2.5 Pro, Codex
**Scope:** Full codebase review after R6 fixes
**Goal:** Clean pass #1 (need 2 consecutive)

## Consensus

- Claude: 0 major, 0 minor — clean pass
- Gemini: 0 major, 2 minor — clean pass (minors don't reset counter)
- Codex: 2 major, 1 minor — NOT a clean pass

## Major Findings

### M1 [Codex-only]: Deleted-user link TOCTOU (check-then-insert race)
The R6 `find_user_by_id` check in `link_callback` happens in a separate statement before `create_oauth_link`. A concurrent `soft_delete_user` between the two could create an orphaned link that blocks `UNIQUE(provider, provider_id)`.

**Fix (0856d44):** Made `create_oauth_link` atomic by using `INSERT ... SELECT FROM users WHERE id = $1 AND deleted_at IS NULL RETURNING *`. The insert only succeeds if the user is active. Removed the now-redundant `find_user_by_id` check from `link_callback`.

### M2 [Codex-only]: Cookie removal path/domain mismatch
Cookies were set with explicit `path` (access: `/`, refresh: `/auth`) and optional `domain`, but removed with `Cookie::from(name)` which has no path/domain. Per RFC 6265, browsers won't clear cookies unless path/domain match.

**Fix (0856d44):** Added `removal_cookie(name, path, config)` helper that builds a removal cookie with matching path and domain. All 10 removal sites updated.

## Minor Findings

### m1 [Gemini]: link_callback TOCTOU
Same issue as M1 — fixed by the atomic insert.

### m2 [Gemini]: Permissive JWT audience defaults
`verify_access_token` sets `validate_aud = false`, relying on per-route audience checks. While currently correct (all routes check), a future route that forgets the check would accept cross-context tokens. Noted as a defense-in-depth improvement.

### m3 [Codex]: auth_setup maps all unique violations to username_taken
`create_user_with_link` can fail from either `UNIQUE(username)` or `UNIQUE(provider, provider_id)`, but both are mapped to `UsernameTaken`. In practice, `auth_callback` pre-checks the link, making the provider violation nearly impossible. Noted.

## Notes

- Gemini noted coarse-grained unlinking (deletes all same-provider links) — acceptable design
- Gemini noted strict refresh rotation without grace period — most secure approach, acceptable trade
- Claude confirmed R6 fixes and broader codebase clean
