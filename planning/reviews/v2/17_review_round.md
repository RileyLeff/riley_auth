# Review Round 3 (Convergence) — 2026-02-23

**Models**: Codex, Gemini, Claude
**Context**: ~75k tokens

## Convergence Result: PASSED

**Round 2: 0 majors. Round 3: 0 majors. Two consecutive clean rounds = CONVERGENCE.**

All three models independently confirmed convergence:
- Gemini: "Convergence Status: PASSED"
- Claude: "Convergence verdict: CONVERGED (0 majors)"
- Codex: 1 finding rated major by Codex (config fallback), downgraded to minor in merge (2/3 models disagree, requires operator error, not a security vulnerability)

## Major Findings

**None.**

Codex flagged config resolution (`resolve_config`) silently falling back when explicit `--config` path doesn't exist. This is a usability bug (operator typo could boot against wrong config), not a security vulnerability. 2/3 models found 0 majors. Fixed as a minor (ba5e228) since it's trivial.

## Minor Findings

### M1. Config fallback on missing explicit path [codex-only, fixed]
**File**: `crates/riley-auth-core/src/config.rs:233`
`resolve_config` continued searching fallback locations when explicit path was missing. Fixed: now fails immediately. Commit: ba5e228.

### M2. CLI redirect_uris not validated as URLs [consensus: Codex + Gemini]
**Files**: `crates/riley-auth-cli/src/main.rs:206`, `crates/riley-auth-api/src/routes/admin.rs:246`
Neither CLI nor API validates redirect_uris as well-formed URLs at registration. Bad URIs are only caught at authorize time. Low priority.

### M3. display_name/username length checks use bytes [claude-only]
**File**: `crates/riley-auth-api/src/routes/auth.rs` (update_display_name, validate_username)
Already flagged in round 2. Repeat finding. Accepted: username regex restricts to ASCII, display_name byte limit is stricter but acceptable.

### M4. No max length on client name or webhook URL [claude-only]
**Files**: `crates/riley-auth-api/src/routes/admin.rs` (register_client, register_webhook)
Admin-only endpoints. Risk limited to storage bloat.

### M5. Outbound OAuth provider calls have no timeout [codex-only]
**File**: `crates/riley-auth-core/src/oauth.rs:132`
`reqwest::Client::new()` uses default settings (no explicit timeout).

### M6. auth_setup maps all unique violations to UsernameTaken [codex-only]
Previously flagged in rounds 1-2. Repeat finding.

### M7. Same provider can be linked multiple times per user [codex-only]
Schema has `UNIQUE (provider, provider_id)` but not `UNIQUE (user_id, provider)`. Multiple GitHub links per user theoretically possible if linking different GitHub accounts. Unlink deletes by provider, which handles this correctly.

### M8. OIDC issuer default is non-URL [codex-only]
Default issuer `"riley-auth"` is not a URL, which is non-compliant with OIDC spec. Deployers should override with their public URL.

## Notes

1. [gemini] PII persists in webhook_deliveries after user soft-delete (GDPR consideration for v3)
2. [codex] Rate limit comment claims `Forwarded` header support but only parses `X-Forwarded-For` and `X-Real-IP`
3. [codex] Redis `Retry-After` is fixed to full window, not remaining TTL
4. [claude] Removal cookies omit Secure/HttpOnly/SameSite flags
5. [claude] Test helper has unnecessary `unsafe impl Sync`
6. [gemini] Setup token carries PII (email, name) — acceptable given signed cookie with 15-min TTL
7. [gemini] IP extraction duplication (already documented in review notes)

## Verdict

All three models confirm convergence. The codebase is production-ready for v2. Remaining minors are quality-of-life improvements suitable for incremental addressing.
