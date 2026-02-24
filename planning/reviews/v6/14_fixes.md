# Phase 6 Review Round 1 — Fixes

**Commit**: `d49c736`

## Fixed

### Major
- M1: Fixed `/auth/login/{provider}` → `/auth/{provider}` in README
- M2: Fixed `PATCH /auth/me/display-name` → `PATCH /auth/me` in README
- M3: Fixed `/oauth/consent/{id}` → `/oauth/consent?consent_id={id}` in README
- M4: Fixed `/auth/login/google` → `/auth/google` in deployment guide

### Minor
- m5: Added 6 missing auth endpoints to README table (setup, logout-all, link/{provider}, link/confirm, callbacks)
- m6: Added `/metrics` to discovery endpoint table
- m7: Added `--output` and `--key-size` to `generate-keys` CLI entry
- m8: Added `--scopes` and `--auto-approve` to `register-client` CLI entry
- m9: Added `--client-id` to `register-webhook` CLI entry
- m10: Added `email_verified` to profile_mapping example in example TOML
- m11: Added `stuck_processing_timeout_secs` and `backchannel_logout_max_retry_attempts` to webhooks section

### Notes
- N12: Replaced Docker Compose "run migrations" step with note that `serve` auto-runs migrations

## Test Results

All 226 tests pass (41 core unit + 27 API unit + 158 integration).
