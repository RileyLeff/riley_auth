# Phase 4 R1 Fixes (2026-02-23)

**Commit:** a495903

All 3 minor items fixed:

1. **Issuer escaping** — `www_authenticate_value()` now escapes `\` and `"` in the issuer value before embedding in the realm quoted-string. Order matters: `\` first, then `"`.

2. **any_expired semantics** — Changed `last_expired` to `any_expired` with `|=` operator so an expired signature on ANY key during fallback verification is correctly reported as `ExpiredToken`.

3. **Expired token integration test** — New `userinfo_expired_token_www_authenticate` test constructs a manually-expired JWT, sends it to `/oauth/userinfo`, and asserts both `error="invalid_token"` and `error_description="token expired"` in the WWW-Authenticate header.
