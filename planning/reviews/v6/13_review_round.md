# Phase 6 Review Round 1 — 2026-02-24

**Models**: Claude subagent only (Codex/Gemini unavailable)
**Context**: ~200k tokens
**Focus**: Documentation accuracy — verifying all claims against the actual codebase

## Findings

### Major

1. **README.md — Login route path wrong** [claude-only]
   - Documented as `/auth/login/{provider}`, actual is `/auth/{provider}`
   - Users following README would get 404s

2. **README.md — Display name update path wrong** [claude-only]
   - Documented as `PATCH /auth/me/display-name`, actual is `PATCH /auth/me`

3. **README.md — Consent endpoint path wrong** [claude-only]
   - Documented as `/oauth/consent/{id}` (path param), actual is `/oauth/consent?consent_id={id}` (query param)

4. **docs/deployment.md — First-time setup login URL wrong** [claude-only]
   - References `/auth/login/google`, actual is `/auth/google`

### Minor

5. **README.md — Auth endpoint table missing 6 routes** [claude-only]
   - Missing: `/auth/setup`, `/auth/logout-all`, `/auth/link/{provider}` GET, `/auth/link/confirm`, `/auth/{provider}/callback`, `/auth/link/{provider}/callback`

6. **README.md — Discovery table missing `/metrics`** [claude-only]
   - Featured in features list but not in endpoint table

7. **README.md — `generate-keys` CLI entry incomplete** [claude-only]
   - Missing `--output` and `--key-size` flags

8. **README.md — `register-client` CLI entry incomplete** [claude-only]
   - Missing `--scopes` and `--auto-approve` flags

9. **README.md — `register-webhook` CLI entry incomplete** [claude-only]
   - Missing `--client-id` flag

10. **riley_auth.example.toml — Manual provider missing `email_verified`** [claude-only]
    - `ProfileMapping` struct has `email_verified: Option<String>` not shown in example

11. **riley_auth.example.toml — Webhooks section missing 2 options** [claude-only]
    - `stuck_processing_timeout_secs` (default: 300) and `backchannel_logout_max_retry_attempts` (default: 3)

### Notes

12. **docs/deployment.md — Docker Compose migration step redundant** [claude-only]
    - `serve` auto-runs migrations; separate step works but is misleading

## Verified Correct

- All claimed features are actually implemented
- Dockerfile, docker-compose.yml, config structs accurate
- Quick Start section correct
- Key rotation procedure correct
- Backup instructions correct
- Config resolution order correct
