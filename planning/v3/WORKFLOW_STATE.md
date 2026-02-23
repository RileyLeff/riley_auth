# v3 Workflow State

**Current Phase:** 5 — Background Cleanup Task (STARTING)
**Current Step:** 5.1 Config — Maintenance
**Status:** Phase 4 exhaustive review converged (3 rounds, 0 majors in R2+R3). Starting Phase 5.

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
| 5 | 5.1-5.4 | Background Cleanup Task | Pending |
| 6 | 6.1-6.4 | Webhook SSRF Hardening | Pending |
| 7 | 7.1-7.7 | Quality-of-Life Fixes | Pending |
| 7 | review | Exhaustive review (final) | Pending |

## Blockers

None.

## Recent Activity

- Phase 4 R1: 2 majors fixed (remove userinfo_endpoint, rename detail→error_description) (736f243)
- Phase 4 R1: 4 minors fixed (auth code replay test, PKCE test, empty display name) (d401fcf)
- Phase 4 R2: 4 minors fixed (CHECK constraint, redirect_uri validation, CORS warning, remove unsafe Sync) (c00526c)
- Phase 4 R3: 0 majors, convergence achieved. Review artifacts filed (704acf4)
- Total tests: 105 (61 integration + 36 unit + 8 redis)
