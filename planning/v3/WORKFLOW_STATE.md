# v3 Workflow State

**Current Phase:** 7 — Quality-of-Life Fixes (EXHAUSTIVE REVIEW)
**Current Step:** Exhaustive review R2 (need 2 consecutive rounds with 0 majors)
**Status:** R1 found 1 major (PII scrub path) + 5 minors — all fixed. Running R2.

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
| 6 | 6.1-6.4 | Webhook SSRF Hardening | Done |
| 6 | review | Standard review (1 round, 1 major + 3 minors fixed) | Done |
| 7 | 7.1-7.7 | Quality-of-Life Fixes | Done |
| 7 | review R1 | Exhaustive R1 (Gemini + Claude, 1 major + 5 minors fixed) | Done |
| 7 | review R2 | Exhaustive R2 | In Progress |

## Blockers

None.

## Recent Activity

- Phase 6 SSRF hardening: private IP blocking, SsrfSafeResolver, redirect disable (cb43e85)
- Phase 6 review fixes: IPv4-mapped IPv6 bypass, multicast, redirect SSRF (6d36916)
- Phase 7 QoL fixes: cached regex, char count, IP extraction consolidation, PII scrub (0e7e227)
- Phase 7 exhaustive R1: 1 major (PII scrub path) + 5 minors fixed (eb3e09e)
- Total tests: 91 (69 integration + 22 unit)
