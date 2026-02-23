# Phase 8 Exhaustive Review — Round 1

**Models**: Claude subagent, Gemini 2.5 Pro, Codex
**Scope**: Full codebase (all Rust sources, SQL migrations, Dockerfile, config, tests)

---

## Major Findings

### 1. SQL Injection via Schema Name [consensus: Claude + Codex]
- **Location**: `crates/riley-auth-core/src/db.rs:21`
- **Description**: `format!("SET search_path TO {}", schema)` interpolates config value directly into SQL. A malicious schema value (e.g., `public; DROP TABLE users`) would execute arbitrary SQL on every new connection.
- **Fix**: Validate schema name against `^[a-zA-Z_][a-zA-Z0-9_]*$` before use.

### 2. Gemini: Authentication Bypass via ct_eq Inversion — **FALSE POSITIVE**
- **Location**: `crates/riley-auth-api/src/routes/oauth_provider.rs:162,200,301`
- **Description**: Gemini claims `ct_eq().unwrap_u8() == 0` is inverted. This is **incorrect**. `unwrap_u8()` returns 1 for equal, 0 for not-equal. Checking `== 0` means "if NOT equal → error". The code is correct.
- **Verified**: By reading `subtle` crate documentation and the actual code logic.

### 3. Gemini: Unverified Email Account Takeover — **Downgraded to Note**
- **Location**: `crates/riley-auth-api/src/routes/auth.rs:180-196`
- **Description**: Gemini claims unverified email could lead to account takeover via the linking suggestion flow. However, the flow only redirects to a frontend `/link-accounts` page — it does NOT auto-link. The user must explicitly consent. Google only returns verified emails. For GitHub, the `fetch_github_primary_email` doesn't check the `verified` field, but the worst case is suggesting a link the user can decline.
- **Note**: Checking `email_verified` from providers would be good hygiene for a future iteration.

### 4. Gemini: Fragile ASN.1 Parsing — **Already Settled (R9)**
- **Location**: `crates/riley-auth-core/src/jwt.rs`
- **Description**: Settled in review notes as Minor. Admin-controlled input, works correctly for standard RSA keys.

---

## Minor Findings

### 1. `behind_proxy` Config Not Wired to Rate Limiter [consensus: Claude + Codex]
- **Location**: `crates/riley-auth-core/src/config.rs:31`, `crates/riley-auth-api/src/routes/mod.rs:62-81`
- **Description**: `behind_proxy` field exists but is never used. Rate limiter extracts peer IP from `ConnectInfo<SocketAddr>`. Behind a reverse proxy, all requests appear from the proxy IP, making rate limiting useless (or blocking everyone).
- **Fix**: Wire `behind_proxy` to configure `tower_governor`'s key extractor for `X-Forwarded-For`.

### 2. Dockerfile Runs as Root [consensus: Gemini + Codex]
- **Location**: `Dockerfile:8-13`
- **Description**: No `USER` directive in the final stage. Container runs as root.
- **Fix**: Add non-root user.

### 3. Token Revocation Swallows DB Errors [Codex-only]
- **Location**: `crates/riley-auth-api/src/routes/oauth_provider.rs:307`
- **Description**: `let _ = db::delete_refresh_token_for_client(...)` silently ignores ALL errors, including DB connection failures. RFC 7009 says return 200 for valid/invalid tokens, but a DB failure means the token isn't actually revoked while the client believes it is.
- **Decision**: Already settled in review notes as intentional per RFC 7009. Add a `tracing::warn!` log for the error case for observability.

### 4. Integration Test Coverage Gaps [consensus: Claude + Gemini + Codex]
- **Description**: Missing tests for rate limiting, PKCE failure, auth code replay, unlink/last-provider, admin self-deletion, expired refresh tokens.
- **Note**: Tracked for future improvement. The 21 existing tests cover the happy paths and key security scenarios.

### 5. OAuth Refresh Token Consumed Before Client Binding Check [Codex-only]
- **Location**: `crates/riley-auth-api/src/routes/oauth_provider.rs:244-252`
- **Description**: `consume_refresh_token` runs before `client_id` verification. A different authorized client could burn another client's refresh token. However, the attacker needs valid client credentials + the victim's refresh token — extremely narrow window.
- **Note**: This follows the same consume-first-validate-later pattern as auth codes, which is standard. Low priority.

### 6. OAuth Auth Code Consumed Before Validation [Codex-only]
- **Location**: `crates/riley-auth-api/src/routes/oauth_provider.rs:173-202`
- **Description**: Auth code is consumed atomically before redirect_uri/client_id/PKCE checks. This is the RFC-recommended approach — consume to prevent replay, then validate. Correct behavior.

### 7. Sensitive OAuth Params May Appear in Trace Logs [Codex-only]
- **Location**: `crates/riley-auth-api/src/server.rs:37`
- **Description**: Default `TraceLayer` may log callback URLs containing `code` and `state`. These are single-use and short-lived, so impact is minimal. Note for log hygiene.

### 8. Rate Limiting Applied Globally [Claude-only]
- **Location**: `crates/riley-auth-api/src/routes/mod.rs:76-81`
- **Description**: Rate limiter covers all endpoints including `/health` and `/.well-known/jwks.json`. Monitoring polling could exhaust the budget.
- **Note**: For v1 this is acceptable. Can split rate limit layers per route group later.

---

## Notes

- Username TOCTOU and cooldown TOCTOU: already settled in review notes
- `case_sensitive` config option not fully honored: already settled in review notes
- No cleanup background task for expired tokens: noted, not a security issue
- Dockerfile lacks `HEALTHCHECK` instruction and `.dockerignore`: noted for future
- Hardcoded rate limit params (30 burst / 2 per second): acceptable for v1
- Permissive CORS default with warning: `CorsLayer::permissive()` does NOT set `allow_credentials`, so browsers block credentialed cross-origin requests. Safer than it appears.
- Config path fallthrough (Codex note): intentional design for config resolution order

---

## Action Items

**Must Fix (Major):**
1. SQL injection via schema name — add regex validation

**Should Fix (Minor):**
2. Wire `behind_proxy` to rate limiter
3. Dockerfile non-root user
4. Log revocation DB errors (settle existing note, add `tracing::warn!`)
