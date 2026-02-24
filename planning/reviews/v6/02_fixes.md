# Fixes for Review Round 1

**Commit**: `a2f8faa`

## Fixed

1. **MinIO removed** from docker-compose.test.yml (Finding 2)
2. **CLAUDE.md updated** to reference PG14+ instead of PG18 (Finding 3)
3. **build_cors comment fixed** and function refactored to take `&[String]` for testability (Finding 7)
4. **Cookie prefix breaking change** documented in example config header (Finding 9)
5. **build_cors unit tests** added: empty origins, wildcard, explicit list (Finding 11)
6. **Consent scope description** changed from "avatar" to "profile picture" (Finding 12)

## Noted (no action)

- Finding 1: avatar_url intentionally retained (provider URL passthrough, not upload)
- Finding 4: PG18 in test compose is fine for forward compat
- Finding 13: Hardcoded test cookie names are acceptable
- Finding 15: Config validation scope is appropriate for internal library
