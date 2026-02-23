# Review Round 1 — Phase 3 Exhaustive Review (2026-02-22)

**Models**: Gemini, Claude
**Context**: ~62k tokens

## Findings

### Major

**1. [claude-only] IP address not validated before storage**
File: `crates/riley-auth-api/src/routes/auth.rs`, `extract_client_ip`
X-Forwarded-For value stored without validating it's a real IP address. TEXT column is unbounded.
**Action**: Parse through `std::net::IpAddr`, fall back to raw string with length limit.

**2. [claude-only] User-Agent not length-limited**
File: `crates/riley-auth-api/src/routes/auth.rs`, callers of `issue_tokens`
No truncation on User-Agent before DB storage. Storage-based DoS vector.
**Action**: Truncate to 512 chars in `issue_tokens`.

**3. [claude-only] Wrong HTTP status for session not found**
File: `crates/riley-auth-api/src/routes/auth.rs`, `revoke_session`
Returns 400 instead of 404 when session doesn't exist or belongs to another user.
**Action**: Change to 404.

**4. [claude-only] last_used_at never populated**
File: `crates/riley-auth-api/src/routes/auth.rs`, `auth_refresh`
`db::touch_refresh_token` exists but is never called. `last_used_at` always NULL.
**Action**: Set `last_used_at = now()` on new token during refresh rotation.

### Minor

**1. [consensus] Missing integration test for metadata capture during auth_refresh**
Both models noted session tests use direct DB insertion for metadata rather than testing the actual HTTP path.
**Deferred**: Hard to test auth_callback (requires OAuth), but auth_refresh path could be tested.

**2. [claude-only] OIDC discovery missing `userinfo_endpoint`**
RECOMMENDED per OIDC Discovery 1.0 Section 3. No /userinfo endpoint exists yet.
**Deferred**: Future enhancement when /userinfo is added.

**3. [claude-only] ID token TTL coupled to access token TTL**
Could have separate `id_token_ttl_secs` config option.
**Deferred**: Acceptable for now; both are short-lived.

**4. [claude-only] "openid" not in scopes_supported**
OIDC spec says scopes_supported MUST include "openid" if ID tokens are issued.
**Action**: Add "openid" to discovery doc.

**5. [claude-only] Two DB queries in list_sessions where one would suffice**
Could combine list + current-session lookup into one query.
**Deferred**: Performance optimization, not blocking.

**6. [claude-only] CLI register-client skips scope validation**
Repeated from Phase 1 review. Admin-only, low risk.
**Deferred**: Will address when CLI is next touched.

### Notes

- Regex recompilation in validate_username (repeated observation)
- unsafe impl Sync for TestServer (safe, documented)
- Constant-time comparison on SHA-256 hashes is defense-in-depth
- Authorization code cleanup functions exist but not scheduled
- Session list not paginated (acceptable for typical usage)
- ID tokens issued unconditionally (intentional simplification)
- Current session detection via refresh cookie hash is sound
- IP extraction behind proxy correctly takes first X-Forwarded-For entry
