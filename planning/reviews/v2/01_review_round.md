# Review Round 1 — Phase 1 Exhaustive Review (2026-02-22)

**Models**: Gemini, Claude (Codex hit rate limits — empty output)
**Context**: ~52k tokens

## Findings

### Major

**1. [consensus] Duplicate scopes not deduplicated in authorization flow**
Severity: major
File: `crates/riley-auth-api/src/routes/oauth_provider.rs` (`authorize`)

The authorize endpoint splits the `scope` query parameter by whitespace but never deduplicates. A request for `scope=read:profile read:profile` stores `["read:profile", "read:profile"]` in the authorization code, refresh token, and JWT `scope` claim. While not a direct privilege escalation, this produces malformed state that could confuse downstream resource servers.

Fix: Collect into a `BTreeSet` before storing.

---

**2. [consensus] Client allowed_scopes not validated against config definitions at registration**
Severity: major
Files: `crates/riley-auth-api/src/routes/admin.rs` (`register_client`), `crates/riley-auth-cli/src/main.rs`

When registering an OAuth client, `allowed_scopes` are stored without verifying each scope exists in `config.scopes.definitions`. An admin can register a client with `allowed_scopes: ["admin:nuclear"]` even if no such scope is defined. If a scope with that name is later added to config, the client retroactively gains access without explicit approval.

Fix: Validate against config definitions at registration time in both API and CLI.

---

**3. [claude-only] No validation of scope name format — injection risk**
Severity: major
Files: `crates/riley-auth-api/src/routes/admin.rs`, `crates/riley-auth-core/src/config.rs`

Scope names from admin client registration and config are never validated against a safe character set. An `allowed_scopes` entry containing whitespace (e.g., `"read:profile write:profile"` as a single string) would be split into two scopes at the authorize endpoint's `split_whitespace()`, effectively granting an extra scope. Special characters could also cause issues with PostgreSQL text[] columns.

Fix: Add scope name validation (e.g., `^[a-z][a-z0-9:._-]*$`) at config parse time and client registration.

---

**4. [claude-only] OAuth state comparison uses non-constant-time equality**
Severity: major (security hardening)
File: `crates/riley-auth-api/src/routes/auth.rs` (`auth_callback`, `link_callback`)

The OAuth state parameter comparison uses plain `!=` while the codebase already uses `subtle::ConstantTimeEq` for client secrets. While the 32-byte random state makes timing attacks impractical, consistency with the existing security pattern is important.

Fix: Use `subtle::ConstantTimeEq` for state comparison.

---

**5. [gemini-only] Silent authorization via GET /oauth/authorize for auto_approve clients**
Severity: major (design consideration)
File: `crates/riley-auth-api/src/routes/oauth_provider.rs` (`authorize`)

Since the OAuth provider router is exempt from CSRF middleware (correctly — it uses client credentials not cookies), a malicious page can trigger a GET to `/oauth/authorize` for a logged-in user. With `auto_approve=true`, the user is silently authorized and redirected with a code. The code goes to a registered redirect_uri so it can't be intercepted, but the user didn't explicitly consent.

**Assessment**: This is somewhat by design — `auto_approve` is meant for first-party clients that the deployer trusts. The consent UI (future phase) will handle non-auto-approve clients. Documenting this tradeoff is sufficient for now.

---

### Minor

**6. [claude-only] Consent endpoint silently drops disallowed scopes**
Severity: minor (API inconsistency)
File: `crates/riley-auth-api/src/routes/oauth_provider.rs` (`consent`)

The consent endpoint silently skips scopes not in the client's `allowed_scopes`, while the authorize endpoint returns an explicit error. This inconsistency means the consent UI would show a subset without warning.

Fix: Return an error for disallowed scopes, matching the authorize endpoint.

---

**7. [gemini-only] Token endpoint doesn't re-validate scopes against current config**
Severity: minor
File: `crates/riley-auth-api/src/routes/oauth_provider.rs` (`token`, authorization_code grant)

If a scope is removed from config while an auth code is in-flight, the JWT will still contain the deleted scope.

**Assessment**: Config changes require a server restart, and auth codes have a 5-minute TTL. The window is tiny. Note for documentation but not a practical concern.

---

**8. [claude-only] Regex recompilation on every username validation**
Severity: minor (performance)
File: `crates/riley-auth-api/src/routes/auth.rs` (`validate_username`)

The username regex is compiled from config on every invocation. Should be compiled once at startup.

---

**9. [claude-only] Empty client name not validated**
Severity: minor
File: `crates/riley-auth-api/src/routes/admin.rs` (`register_client`)

No validation on client name — empty strings, whitespace-only, or extremely long values are accepted.

---

**10. [claude-only] Redirect URIs not validated for format/scheme**
Severity: minor (security hardening)
File: `crates/riley-auth-api/src/routes/admin.rs` (`register_client`)

Redirect URIs are stored without format validation. Could store `javascript:alert(1)`.

---

**11. [claude-only] OAuthClient model exposes client_secret_hash via Serialize**
Severity: minor (information leak risk)
File: `crates/riley-auth-core/src/db.rs` (`OAuthClient` struct)

The struct derives Serialize including `client_secret_hash`. While not currently exposed via API responses, a future code change could accidentally leak it.

---

**12. [claude-only] No upper bound on scope count per request**
Severity: minor (DoS)
File: `crates/riley-auth-api/src/routes/oauth_provider.rs` (`authorize`)

No limit on how many scopes a client can request.

---

**13. [claude-only] unsafe impl Sync for TestServer**
Severity: minor (code quality)
File: `crates/riley-auth-api/tests/integration.rs`

If all fields are truly Send + Sync, the compiler should derive it. The unsafe impl suggests something isn't.

---

**14. [claude-only] Session metadata columns not populated**
Severity: minor
File: `crates/riley-auth-api/src/routes/auth.rs` (`issue_tokens`)

The user_agent and ip_address columns exist but are always stored as None.

**Assessment**: These are for Phase 3 (Session Visibility). The columns exist in migration 002 for forward compatibility. Not a bug.

---

**15. [claude-only] No test for admin client registration with allowed_scopes**
Severity: minor (test gap)
File: `crates/riley-auth-api/tests/integration.rs`

No test verifies that scopes passed via admin API are persisted and returned.

---

### Notes

- Scope definitions are config-only (not DB) — reasonable for Phase 1, document for future
- Authorization codes mark `used=true` rather than deleting — good for audit, cleaned up on expiry
- JWT `scope` claim is space-delimited string per RFC 6749 — correct
- No scope downscoping on refresh — acceptable for Phase 1
- Session/client refresh token cross-usage correctly prevented in both directions
- CSRF exemption for OAuth provider router is correct (client credential auth, not cookie auth)
- Token response format follows OAuth 2.0 spec correctly
- Constant-time comparison for client secrets is well-implemented
- Database deadlock prevention with `ORDER BY id FOR UPDATE` is high quality
