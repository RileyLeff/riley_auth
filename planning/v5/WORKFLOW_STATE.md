# v5 Workflow State

**Current Phase:** 3 — OIDC Compliance: auth_time (REVIEW COMPLETE)
**Current Step:** Phase 3 review converged (2 rounds, 0 major in round 2)
**Status:** Phase 3 done. 34 unit + 117 integration tests pass. Ready for Phase 4.

## Progress

| Phase | Step | Description | Status |
|-------|------|-------------|--------|
| 1 | 1.1 | Config: KeyConfig struct and JwtConfig migration | Done |
| 1 | 1.2 | jwt.rs: KeyEntry and KeySet | Done |
| 1 | 1.3 | CLI: generate-keys algorithm flag | Done |
| 1 | 1.4 | Wire up: server.rs, main.rs, AppState | Done |
| 1 | 1.5 | Discovery document: dynamic alg_values_supported | Done |
| 1 | 1.6 | Update existing tests | Done |
| 1 | 1.7 | Update example config | Done |
| 1 | review | Standard review (2 rounds, Claude-only, converged) | Done |
| 2 | 2.1 | Extract shared credential extraction | Done |
| 2 | 2.2 | Apply to token endpoint | Done |
| 2 | 2.3 | Apply to revocation endpoint | Done |
| 2 | 2.4 | Update discovery document | Done |
| 2 | 2.5 | Integration tests (5 new + 1 discovery update) | Done |
| 2 | review | Standard review (2 rounds, Claude-only, converged) | Done |
| 3 | 3.1 | Migration 012_auth_time + 013_backfill | Done |
| 3 | 3.2 | DB: RefreshTokenRow + store_refresh_token | Done |
| 3 | 3.3 | JWT: IdTokenClaims + sign_id_token | Done |
| 3 | 3.4 | Update all call sites (auth.rs, oauth_provider.rs, tests) | Done |
| 3 | 3.5 | Discovery document: claims_supported | Done |
| 3 | 3.6 | Integration test: auth_time preserved across refresh | Done |
| 3 | review | Standard review (2 rounds, Claude-only, converged) | Done |
| 4 | 4.1-4.4 | WWW-Authenticate headers | Pending |
| 4 | review | Standard review | Pending |
| 5 | 5.1-5.6 | Authorize prompt parameter | Pending |
| 5 | review | Exhaustive review (crypto + OIDC spec complete) | Pending |
| 6 | 6.1-6.3 | Codebase organization | Pending |
| 6 | review | Standard review | Pending |
| 7 | 7.1-7.6 | Observability | Pending |
| 7 | review | Standard review | Pending |
| 8 | 8.1-8.3 | Production defaults & deployment polish | Pending |
| 8 | review | Exhaustive review (pre-conformance) | Pending |
| 9 | 9.1-9.4 | OIDC conformance testing | Pending |

## Blockers

None.

## Recent Activity

- Phase 2 complete: client_secret_basic on token/revoke/introspect (631bbb0)
- Phase 2 review: 2 rounds, converged (d5a121a, eb6536a)
- Phase 3 complete: auth_time in ID tokens + refresh propagation (eb865d4, 426d3cc)
- Phase 3 review R1: 0 major, 4 minor (comments + backfill). Fixed all (cd01b86)
- Phase 3 review R2: 0 major, 0 minor. Converged.
