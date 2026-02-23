# Review Round 2 — Phase 1 Exhaustive Review (2026-02-22)

**Models**: Gemini, Claude (Codex rate-limited, skipped)
**Context**: ~55k tokens

## Round 1 Fix Verification

Both models confirmed all five round 1 fixes are correctly implemented with no regressions:
1. Scope name format validation — correct
2. Scope deduplication via BTreeSet — correct
3. Client allowed_scopes validation against config — correct
4. Constant-time OAuth state comparison — correct
5. Consent endpoint scope validation — correct

## Findings

### Major

**None.** No new major bugs found by either model.

The only item flagged as "major" was the standard JWT stateless tradeoff: soft-deleted users retain valid access tokens until expiry (default 15 minutes). This is inherent to all JWT-based systems. The codebase correctly handles it:
- `find_user_by_id` filters `WHERE deleted_at IS NULL`, so operations on deleted users fail with UserNotFound
- Admin endpoints (`require_admin`) check the DB for current role on every request
- This is a documented design decision, not a bug

### Minor

**1. [consensus] Expired token/code cleanup functions exist but are never called**
Files: `db.rs` (`cleanup_expired_tokens`, `cleanup_expired_auth_codes`), `main.rs`
The cleanup functions are defined but no background task or cron integration calls them.
**Deferred**: This is a Phase 3+ concern. Document for operators.

**2. [claude-only] CLI register-client doesn't validate scopes against config**
File: `crates/riley-auth-cli/src/main.rs`
The CLI bypasses API-level validation. Since it's operator-only, this is low risk.
**Deferred**: Will address when CLI is next touched.

**3. [claude-only] No redirect_uri format validation in admin client registration**
Repeated from round 1. Admin-only endpoint, low risk.
**Deferred**: Document as future hardening.

**4. [claude-only] display_name length check uses bytes, not characters**
`String::len()` is bytes. 200-byte limit is fine for practical purposes.
**Deferred**: Cosmetic, not blocking.

**5. [claude-only] OAuthClient derives Serialize with client_secret_hash**
Repeated from round 1. Not currently exposed in any API response.
**Deferred**: Document as future hardening.

**6. [claude-only] Regex recompilation on every username validation**
Repeated from round 1. Rust's regex crate is ReDoS-immune. Performance impact negligible.
**Deferred**: Optimization, not blocking.

**7. [claude-only] Client name validation missing**
Repeated from round 1. Admin-only, low risk.
**Deferred**: Future hardening.

**8. [gemini-only] Soft-delete anonymization may fail if max_length < 23**
Default is 24, minimum practical is 23. Edge case with non-default config.
**Deferred**: Document minimum requirement.

### Notes

- OAuth provider routes correctly exempt from CSRF (client credential auth, not cookie auth)
- Username change TOCTOU mitigated by unique constraint on final write — is_username_held is advisory
- Client secret SHA-256 is appropriate for high-entropy (256-bit random) secrets
- Refresh token replay detection (revoke family on reuse) is a future enhancement, not required
- Session token audience (aud = issuer) is collision-proof since client_ids are randomly generated
- GitHub PKCE support works but grant_type parameter only sent for Google
- __Host- cookie prefix would improve security but conflicts with cookie_domain support
