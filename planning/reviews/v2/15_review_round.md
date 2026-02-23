# Review Round 2 — 2026-02-23

**Models**: Codex, Claude (Gemini hit rate limits — 429)
**Context**: ~75k tokens

## Round 1 Fix Verification

All 5 round 1 fixes verified correct by both models:
1. Webhook secret redaction in list endpoint — CLEAN
2. Webhook URL scheme validation — CLEAN
3. client_id-scoped webhook dispatch — CLEAN
4. Scope downgrade prevention on refresh — CLEAN
5. CLI scope validation — CLEAN

## Major Findings

**None.** All candidate major findings were either false positives, documented tradeoffs, or more accurately minor/note severity:

- **Codex flagged: client_id webhook scoping "ineffective"** — FALSE POSITIVE. Global events (`user.created`, etc.) intentionally go to ALL webhooks regardless of their client_id. The client_id filter only activates for client-specific events (via `dispatch_event_for_client`). Documented in `review_notes_README.md`: "Global events (user.created, etc.) still go to all webhooks."

- **Claude flagged: deleted users retain access via unexpired JWT** — Downgraded to MINOR. This is inherent to stateless JWT design. Window bounded by access_token_ttl (default 15 min). Standard mitigation is short TTL. Adding a DB check per request defeats JWT purpose.

- **Claude flagged: SSRF via private IPs** — Downgraded to MINOR. Admin-only endpoint. Admins already have full system access. No user-facing attack vector.

- **Codex flagged: token-burn DoS (consume before validation)** — Downgraded to MINOR. Consume-first pattern is intentional for TOCTOU race prevention. Attacker needs the token value (HttpOnly cookie or short-lived code).

## Minor Findings

### M1. CLI webhook URL validation parity gap [consensus: Codex + Claude]
**Files**: `crates/riley-auth-cli/src/main.rs:292`
API validates webhook URL scheme (https/http only), CLI does not. CLI can persist `file://` or other invalid schemes.
**Fix**: Add same `url::Url::parse` + scheme check to CLI RegisterWebhook.

### M2. CLI webhook listing byte slicing panic [codex-only]
**File**: `crates/riley-auth-cli/src/main.rs:284`
`&hook.url[..38]` panics on non-ASCII URLs. Use `hook.url.chars().take(38).collect::<String>()` or similar.

### M3. Deleted user access token window [claude-only]
**File**: `crates/riley-auth-api/src/routes/auth.rs` (extract_user)
Soft-deleted user's JWT remains valid for up to access_token_ttl. Standard JWT tradeoff.
**Recommendation**: Document the tradeoff. Consider reducing default TTL.

### M4. Webhook SSRF via private IPs [consensus: Codex + Claude]
**Files**: `crates/riley-auth-api/src/routes/admin.rs:404`, `crates/riley-auth-core/src/webhooks.rs` (deliver_webhook)
URL scheme validation doesn't prevent `http://127.0.0.1`, `http://169.254.169.254`, etc.
**Recommendation**: Add DNS resolution + private IP filtering. Admin-only, so low urgency.

### M5. Refresh token consumed before client binding check [codex-only]
**Files**: `crates/riley-auth-api/src/routes/auth.rs:298-303`, `crates/riley-auth-api/src/routes/oauth_provider.rs:368-373`
Consume-first prevents TOCTOU race but allows burn-DoS. Attacker needs token value.
**Recommendation**: Accept as intentional. Document in review notes.

### M6. Auth code consumed before redirect/client validation [codex-only]
**File**: `crates/riley-auth-api/src/routes/oauth_provider.rs:276-286`
Same pattern as M5. Consume-first prevents replay race.
**Recommendation**: Accept as intentional. Document in review notes.

### M7. display_name length check uses bytes, not chars [claude-only]
**File**: `crates/riley-auth-api/src/routes/auth.rs` (update_display_name)
`body.display_name.len()` is bytes. Multi-byte UTF-8 chars could be over-rejected.

### M8. Scope revocation not enforced on auth-code exchange [codex-only]
**File**: `crates/riley-auth-api/src/routes/oauth_provider.rs:312`
Auth-code exchange uses stored scopes directly. If a scope is revoked between code issuance and exchange (max 10 min window), the first access token carries the old scope. Refresh correctly intersects.
**Recommendation**: Narrow window makes this very low risk. Accept as-is.

### M9. OAuthClient Serialize exposes client_secret_hash [claude-only]
**File**: `crates/riley-auth-core/src/db.rs` (struct OAuthClient)
Derives Serialize with public `client_secret_hash` field. Not currently serialized directly, but future developer could accidentally leak.
**Recommendation**: Add `#[serde(skip_serializing)]` to sensitive fields.

### M10. No periodic cleanup of expired tokens/codes [claude-only]
**Files**: `crates/riley-auth-core/src/db.rs` (cleanup_expired_tokens, cleanup_expired_auth_codes)
Functions exist but are never called. Expired rows accumulate.
**Recommendation**: Add background cleanup task in serve(). v3 item.

### M11. auth_setup maps all unique violations to UsernameTaken [codex-only]
**File**: `crates/riley-auth-api/src/routes/auth.rs:253`
OAuth-link conflicts also map to UsernameTaken. Misleading in edge cases.

## Notes

1. [claude] Setup token has no `aud` claim (uses custom `purpose` field instead)
2. [claude] access_token_ttl_secs = 0 not validated (allows instant-expiry tokens)
3. [claude] Webhook delivery retries reuse same HMAC signature (standard behavior)
4. [claude] No OIDC userinfo endpoint (acceptable for v2)
5. [claude] Refresh cookie path `/auth` covers more endpoints than needed (no practical narrowing possible)
6. [claude] OAuth callback always redirects to public_url root (no return_to support)
7. [codex] SSRF comment in admin.rs overstates protection — only scheme validated, comment mentions "internal endpoints"
8. [claude] Webhook secrets stored plaintext in DB (inherent to HMAC signing design)
9. [claude] Constant-time comparison depends on equal-length inputs (both are always SHA-256 hex, so fine)
10. [claude] Admin self-demotion leaves stale role in JWT until next refresh (require_admin re-checks DB, so admin endpoints are safe)

## Test Coverage Gaps

1. No test for soft-deleted user attempting to use existing access token
2. No test for client-bound refresh token rejected at session endpoint
3. No test for webhook URL scheme validation (round 1 fix untested)
4. No negative PKCE test (wrong code_verifier rejection)
5. No test for cross-user session isolation
6. No test for display_name length validation
7. No test for username change cooldown enforcement
8. No CLI-level tests (webhook registration, scope validation)
9. No test for consent endpoint with invalid client_id
10. No test for setup token expiry

## Verdict

**0 major findings. Round 2 is clean.** All candidate majors are either false positives, documented tradeoffs, or appropriately classified as minor. The codebase is in good shape. One more clean round needed for convergence.
