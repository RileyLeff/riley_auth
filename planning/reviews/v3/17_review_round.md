# Review Round 17 — 2026-02-23 (Phase 4 Exhaustive R3 — Convergence)

**Models**: Claude + Gemini (partial — Gemini hit 429 rate limits mid-review but produced findings before failing)
**Context**: ~97k tokens
**Scope**: Full codebase, NEW issues only

## Findings

### Major

None. **This is the second consecutive round with 0 majors — convergence achieved.**

### Minor

1. **[claude-only] `validate_username` recompiles regex on every call**
   - File: `crates/riley-auth-api/src/routes/auth.rs`
   - Phase 7.1 planned work — cache compiled regex in AppState.

2. **[claude-only] `update_display_name` checks byte length, not character length**
   - File: `crates/riley-auth-api/src/routes/auth.rs`
   - Phase 7.2 planned work — use `chars().count()`.

3. **[claude-only] OAuth `exchange_code`/`fetch_profile` create new reqwest::Client each time**
   - File: `crates/riley-auth-core/src/oauth.rs`
   - Related to accepted "unused http_client in AppState" note. Will be addressed when threading AppState client through OAuth functions.

4. **[gemini-only] `is_username_held` blocks original owner from reclaiming username**
   - File: `crates/riley-auth-core/src/db.rs`, `crates/riley-auth-api/src/routes/auth.rs`
   - QoL improvement — could add `exclude_user_id` parameter. Not a security issue.

5. **[gemini-only] `unlink_provider` deletes all links for a provider (not surgical)**
   - File: `crates/riley-auth-core/src/db.rs`
   - Edge case for users with multiple accounts from same provider. Low impact.

6. **[gemini-only] Non-atomic webhook enqueuing (dispatch after transaction commit)**
   - File: `crates/riley-auth-api/src/routes/admin.rs`
   - Could lose notification if crash between commit and enqueue. Low probability.

### Notes

1. **[gemini-only] redirect_uri validation missing IPv6 localhost `[::1]`** — minor dev friction.
2. **[gemini-only] Mutex poisoning could cascade** — parking_lot would prevent, but std::sync::Mutex with `.expect()` is standard Rust practice.
3. **[gemini-only] RSA parser overflow on 32-bit systems** — theoretical, production targets 64-bit.
4. **[gemini-only] Redundant setup cookie in linking suggestion flow** — architectural note.
5. **[gemini-only] `public_url` join hygiene (double slashes)** — discovery document already trims trailing slashes; other redirects should too.
6. **[claude-only] validate_username length checks use bytes (safe for ASCII-only regex)** — documentation concern only.

## Convergence

- **R2**: 0 majors (Claude-only, Gemini failed)
- **R3**: 0 majors (Claude + Gemini partial)
- **2 consecutive rounds with 0 major bugs. Phase 4 exhaustive review is complete.**

All minors found are either Phase 7 planned work or QoL improvements that don't affect correctness or security.
