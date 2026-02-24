# Review Round 16 — Phase 5 Exhaustive Review R2 (Convergence)

**Date:** 2026-02-24
**Type:** Exhaustive review R2 (convergence check)
**Models:** Claude Opus 4.6 only (Codex: empty output, Gemini: CLI crash)
**Context:** ~161k tokens (full codebase)

## Result: CONVERGED (0 major in R1 + 0 major in R2)

## Findings

### Major

None.

### Minor

1. **[claude-only] BCL uses fire-and-forget spawned tasks, not outbox** — Back-channel logout notifications use `tokio::spawn` with in-memory retries. Lost on server crash. Mitigated: spec says RPs SHOULD NOT rely solely on BCL; refresh tokens are already revoked in DB. PRE-EXISTING (documented in v4 Phase 10 notes: "Backchannel logout is fire-and-forget (not outbox-based)").

2. **[claude-only] `reset_stuck_outbox_entries` uses `next_attempt_at` as staleness indicator** — `next_attempt_at` is not updated when entry is claimed, so entries queued for a long time could be immediately reset. PRE-EXISTING (documented in v4 Phase 8 notes: "Stuck outbox next_attempt_at check").

### Notes

1. `id_token_hint` not supported with `prompt=none` (optional per spec)
2. bcrypt cost factor not configurable (fine for machine-generated secrets)
3. `cleanup_consumed_refresh_tokens` cutoff is correctly 2x refresh_token_ttl
4. GitHub private emails handled gracefully (returns None)

## Previously Accepted Tradeoffs Confirmed

All 6 pre-existing accepted tradeoffs from R1 re-confirmed. No re-flagging.

## Areas Reviewed With No Issues

All 15 security-critical areas reviewed clean: CSRF, token isolation, refresh rotation, key rotation, scope validation, PKCE, rate limiting, SSRF, soft delete, consent flow, prompt parameter, WWW-Authenticate, OIDC Discovery, migrations, integration tests.

## Convergence

- R1: 0 new major (2 pre-existing reclassified)
- R2: 0 new major
- **2 consecutive rounds with 0 major → CONVERGED**
