# Fixes — Review Round 2 (2026-02-23)

Commit: 0b32c10

## Minor Fixes Applied

### M1. CLI webhook URL validation (consensus: Codex + Claude)
Added `url::Url::parse` + scheme check to CLI `RegisterWebhook` command, matching the API endpoint's validation. Added `url` dependency to riley-auth-cli Cargo.toml.

### M2. CLI webhook listing byte slicing (codex-only)
Changed `&hook.url[..38]` to `&hook.url[..hook.url.floor_char_boundary(38)]` to prevent panic on non-ASCII URLs.

### M9. Sensitive field serialization guards (claude-only)
Added `#[serde(skip_serializing)]` to:
- `OAuthClient.client_secret_hash`
- `Webhook.secret`

These structs already had separate response types (WebhookListResponse, ClientResponse) that exclude sensitive fields, but the skip annotations provide defense-in-depth against accidental direct serialization.

## Documented as Tradeoffs (not fixed)

All remaining findings documented in `review_notes_README.md`:
- M3: Deleted user access token window (stateless JWT tradeoff)
- M4: Webhook SSRF via private IPs (admin-only, v3 improvement)
- M5/M6: Consume-first token pattern (intentional TOCTOU prevention)
- M7: display_name byte-length check (functionally correct, minor UX inconsistency)
- M8: Scope revocation on auth-code exchange (negligibly narrow window)
- M10: No periodic cleanup task (v3 item)
- M11: auth_setup unique violation mapping (edge case, misleading but harmless)
