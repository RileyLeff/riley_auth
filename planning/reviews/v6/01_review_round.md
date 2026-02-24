# Review Round 1 — 2026-02-24

**Models**: Claude Opus 4.6 only (Codex rate-limited, Gemini shell error)
**Context**: ~184k tokens

## Findings

### Major

1. **[claude-only] avatar_url still pervasive (Finding 1)** — `avatar_url` remains throughout the codebase (DB schema, Rust model, OAuth profile parsing, JWT claims, OIDC UserInfo). **Verdict: Intentional.** Phase 1 removes the *upload/storage* infrastructure (StorageConfig, S3, update_user_avatar). The provider-sourced avatar URL passthrough is retained by design. No action needed.

### Minor

2. **[claude-only] MinIO still in docker-compose.test.yml (Finding 2)** — Removed. Commit: `a2f8faa`
3. **[claude-only] CLAUDE.md references PG18 with uuidv7() (Finding 3)** — Updated to PG14+. Commit: `a2f8faa`
4. **[claude-only] build_cors comment misleading (Finding 7)** — Fixed comment, refactored to accept `&[String]`, added 3 unit tests. Commit: `a2f8faa`
5. **[claude-only] Cookie prefix breaking change undocumented (Finding 9)** — Added migration note to example config. Commit: `a2f8faa`
6. **[claude-only] No unit tests for build_cors (Finding 11)** — Added 3 tests (empty, wildcard, explicit). Commit: `a2f8faa`
7. **[claude-only] Consent scope says "avatar" (Finding 12)** — Changed to "profile picture". Commit: `a2f8faa`

### Notes

8. **[claude-only] Test docker-compose uses PG18 (Finding 4)** — Acceptable; consider CI matrix for PG14 in the future.
9. **[claude-only] UUID migration complete and correct (Finding 5)** — Positive confirmation. All INSERT statements accounted for.
10. **[claude-only] Migration 004 gen_random_uuid() DEFAULT (Finding 6)** — Only for backfill; app code provides explicit values.
11. **[claude-only] CORS allow_methods correctly omits OPTIONS/PUT (Finding 8)** — tower-http handles OPTIONS internally.
12. **[claude-only] jwt.issuer validation correct (Finding 10)** — Positive confirmation.
13. **[claude-only] Test cookie names hardcoded (Finding 13)** — Acceptable for now; would break only if default changes again.
14. **[claude-only] family_id generation consistent (Finding 14)** — Positive confirmation.
15. **[claude-only] Config validation only in from_path (Finding 15)** — Acceptable for internal library.
