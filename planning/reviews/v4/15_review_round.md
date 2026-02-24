# Review Round — Phase 9 Token Introspection (2026-02-23)

**Models**: Claude subagent only (Gemini CLI failed — piping issue with exit code 127/1)
**Context**: ~132k tokens

## Findings

### Major

**MAJOR-01 [claude-only]**: Session tokens (aud == issuer) not rejected in introspect handler. Any OAuth client could introspect first-party session tokens, leaking user info. Guard added: `claims.aud == issuer → active: false`.
- **Fixed:** bf7dcae

**MAJOR-02 [claude-only]**: Cross-client introspection — any authenticated client can introspect tokens from any other client. **Accepted as intentional** — this is a resource-server model where backends validate tokens from multiple clients. Documented in review_notes_README.md.

### Minor

**MINOR-01 [claude-only]**: `/oauth/introspect` not in Auth rate limit tier. Falls to Standard (60/min) instead of Auth (15/min).
- **Fixed:** bf7dcae

**MINOR-02 [claude-only]**: No `Cache-Control: no-store` / `Pragma: no-cache` headers on introspection responses.
- **Fixed:** bf7dcae

**MINOR-03 [claude-only]**: Basic auth does not URL-decode credentials per RFC 7617. **Accepted** — client IDs and secrets are server-generated, never contain special characters. Would require adding percent-encoding dependency.

**MINOR-04 [claude-only]**: Base64 fallback order tries URL-safe before standard in Basic auth. **Accepted** — harmless; standard-encoded values with `+` or `/` will fail URL-safe decode and fall through to STANDARD correctly.

### Notes

- N1: Missing expired token test — would require short TTL + sleep or crafted past-exp JWT. Existing `verify_access_token` already has test coverage for expiry.
- N2: `token_type_hint` parameter from RFC 7662 not supported — acceptable since only JWT access tokens exist.
- N3: Refresh token introspection not supported — by design (opaque tokens, would need DB lookup).
- N4: `client_id` in response set to `claims.aud` — correct for this system where aud == requesting client's client_id.
