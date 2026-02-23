# v3 Workflow State

**Current Phase:** 6 — Webhook SSRF Hardening (STARTING)
**Current Step:** 6.1 Config — Private IP Policy
**Status:** Phase 5 complete (standard review, 1 minor fixed). Starting Phase 6.

## Progress

| Phase | Step | Description | Status |
|-------|------|-------------|--------|
| 1 | 1.1 | Database Migration — Family Tracking | Done |
| 1 | 1.2 | Core — Token Rotation with Reuse Detection | Done |
| 1 | 1.3 | API — Wire Up Reuse Detection | Done |
| 1 | 1.4 | Tests — Token Families | Done |
| 1 | review | Exhaustive review (4 rounds, converged R3+R4) | Done |
| 2 | 2.1 | Database Migration — Outbox | Done |
| 2 | 2.2 | Config — Webhook Tuning | Done |
| 2 | 2.3 | Core — Outbox Writer | Done |
| 2 | 2.4 | Core — Delivery Worker | Done |
| 2 | 2.5 | Tests — Webhook Reliability | Done |
| 2 | review | Standard review (1 round, all findings fixed) | Done |
| 3 | 3.1 | Config — Rate Limit Tiers | Done |
| 3 | 3.2 | Middleware — Tiered Rate Limiter | Done |
| 3 | 3.3 | CORS Preflight Exemption | Done |
| 3 | 3.4 | Tests — Tiered Rate Limiting | Done |
| 3 | review | Standard review (2 rounds, converged) | Done |
| 4 | 4.1 | Database Migration — Nonce Column | Done |
| 4 | 4.2 | Nonce Support | Done |
| 4 | 4.3 | Conditional ID Token Issuance | Done |
| 4 | 4.4 | Discovery Document Updates | Done |
| 4 | 4.5 | Tests — OIDC | Done |
| 4 | review | Exhaustive review (3 rounds, converged R2+R3, Claude+Gemini partial) | Done |
| 5 | 5.1 | Config — Maintenance | Done |
| 5 | 5.2 | Cleanup Functions | Done |
| 5 | 5.3 | Background Worker | Done |
| 5 | 5.4 | Tests — Cleanup | Done |
| 5 | review | Standard review (1 round, 1 minor fixed) | Done |
| 6 | 6.1-6.4 | Webhook SSRF Hardening | In Progress |
| 7 | 7.1-7.7 | Quality-of-Life Fixes | Pending |
| 7 | review | Exhaustive review (final) | Pending |

## Blockers

None.

## Recent Activity

- Phase 5 implementation complete: maintenance config, batched cleanup functions, background worker, 5 cleanup tests (c70d2f0, 86051be, 990e8f3, 6138975)
- Phase 5 review: 1 minor (config validation), 1 note (auth code test) — both fixed (d33192f)
- Total tests: 103 (65 integration + 38 unit)
