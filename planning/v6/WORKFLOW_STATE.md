# v6 Workflow State

**Current Phase:** 4 — Generic OAuth Provider Pipeline (STARTING)
**Current Step:** 4.1 Define new config structs
**Status:** Phases 1-3 complete, review converged (2 rounds, 0 major). Starting Phase 4.

## Progress

| Phase | Step | Description | Status |
|-------|------|-------------|--------|
| 1 | 1.1-1.4 | Remove avatar storage (config, db, example, tests) | Done |
| 1 | commit | `6d01d49` | Done |
| 2 | 2.1-2.4 | PG14+ UUID migration (migrations, INSERTs, tests) | Done |
| 2 | commit | `a52d77a` | Done |
| 3 | 3.1-3.6 | Security defaults (CORS, cookie prefix, issuer, tests) | Done |
| 3 | commit | `5b9ef6e` | Done |
| 1-3 | review R1 | Claude-only (Codex rate-limited, Gemini shell error). 0 real major, 6 minor fixed. | Done |
| 1-3 | fixes | `a2f8faa` — MinIO, CLAUDE.md, build_cors, consent desc, example config | Done |
| 1-3 | review R2 | Claude-only. 0 major, 1 in-scope minor fixed, 4 pre-existing noted. | Done |
| 1-3 | fixes | `9c4c88a` — migration 009 comment | Done |
| 1-3 | converge | **2 consecutive rounds with 0 major bugs** | Done |
| 4 | 4.1 | Define new config structs | Pending |
| 4 | 4.2 | Built-in presets (Google, GitHub) | Pending |
| 4 | 4.3 | Provider resolution + OIDC discovery | Pending |
| 4 | 4.4 | Generic profile parsing | Pending |
| 4 | 4.5 | Refactor oauth.rs | Pending |
| 4 | 4.6 | Refactor auth routes | Pending |
| 4 | 4.7 | Update AppState + server startup | Pending |
| 4 | 4.8 | Update example config | Pending |
| 4 | 4.9 | Unit tests | Pending |
| 4 | 4.10 | Integration tests | Pending |
| 4 | review | Exhaustive review | Pending |
| 5 | 5.1-5.5 | OpenAPI documentation (utoipa) | Pending |
| 5 | review | Standard review | Pending |
| 6 | 6.1-6.5 | Documentation (README, deployment, docker) | Pending |
| 6 | review | Review for accuracy | Pending |

## Blockers

None.

## Recent Activity

- Phases 1-3 implemented and committed (`6d01d49`, `a52d77a`, `5b9ef6e`)
- Review round 1: Claude-only, 6 minors fixed (`a2f8faa`)
- Review round 2: Claude-only, 1 minor fixed (`9c4c88a`), converged
- All 219 tests passing (35 core unit + 26 API unit + 158 integration)
