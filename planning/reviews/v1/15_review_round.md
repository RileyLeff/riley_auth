# Review Round 8 — Clean Pass Attempt #1

**Models**: Claude subagent + Gemini + Codex (all 3 participated)
**Codebase**: Full (via dirgrab)
**Focus**: Verify R7 fixes (atomic link creation, cookie removal path/domain), hunt remaining TOCTOU/concurrency/security issues

## Results by Model

### Claude Subagent
- **Major**: 0
- **Minor**: 0
- **Notes**: 0
- **Verdict**: CLEAN PASS

### Gemini
- **Major**: 0
- **Minor**: 1 (username hold TOCTOU — already settled in review_notes_README.md)
- **Notes**: 2 (unique constraint on deleted users, redundant removal logic in auth_callback)
- **Verdict**: CLEAN PASS (minor is a settled decision)

### Codex
- **Major**: 1
- **Minor**: 0
- **Notes**: 0
- **Verdict**: NOT a clean pass

## Merged Findings

### [Major] [Codex-only] READ COMMITTED snapshot race in `create_oauth_link`
**Location**: `crates/riley-auth-core/src/db.rs` — `create_oauth_link`
**Issue**: The R7 fix (`INSERT ... SELECT FROM users WHERE deleted_at IS NULL`) doesn't lock the user row. Under PostgreSQL READ COMMITTED isolation:
1. `create_oauth_link` reads snapshot where `deleted_at IS NULL`
2. Concurrently, `soft_delete_user` locks user row, sets `deleted_at`, deletes OAuth links, commits
3. `create_oauth_link`'s INSERT waits on FK lock, then succeeds (FK row still exists, soft delete doesn't remove it)
4. Result: orphaned OAuth link on deleted user, permanently blocking re-link via `UNIQUE(provider, provider_id)`

**Fix**: Wrap in explicit transaction, use `SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL FOR SHARE` before INSERT. `FOR SHARE` serializes against `soft_delete_user`'s `FOR UPDATE` without blocking concurrent link creations.
**Fixed in**: 4d0df05

### [Minor] [Gemini-only] Username hold TOCTOU (settled)
Already documented in `review_notes_README.md` — advisory cooldown, not a security boundary.

### [Note] [Gemini-only] Unique constraint on deleted users
`soft_delete_user` changes username to `deleted_{uuid}`, freeing the original in the unique constraint. Working as intended.

### [Note] [Gemini-only] Redundant removal logic in auth_callback
`CookieJar::remove` creates a tombstone cookie (expiry in 1970). Correct behavior for clearing state/pkce cookies after OAuth flow.

## Round Result
**NOT a clean pass** — 1 major found (Codex), fixed in 4d0df05. Need to reset clean-pass counter and achieve 2 consecutive passes.
