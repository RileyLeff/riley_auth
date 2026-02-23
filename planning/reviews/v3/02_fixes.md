# Fixes for Review Round 01

**Commit:** d4da005

## Fixed (Major)

1. **Client-bound token consumed at session endpoint** (finding #1)
   - Added `consume_session_refresh_token()` to `db.rs` with `AND client_id IS NULL`
   - Updated `auth_refresh()` to use the new function
   - Client-bound tokens are now rejected without being consumed

## Fixed (Minor)

2. **Missing index on consumed_refresh_tokens(family_id)** (finding #5)
   - Added `idx_consumed_refresh_tokens_family_id` to migration 004

3. **Migration default gen_random_uuid() → uuidv7()** (finding #6)
   - Changed to `DEFAULT uuidv7()` for consistency

## Deferred to Later Phases

- **redirect_uris validation** → Phase 7.6
- **Display-name bytes vs chars** → Phase 7.2
- **OAuth HTTP timeout** → Note for Phase 7
- **OIDC issuer as URL** → Phase 4 (OIDC compliance)
- **CLI webhook client_id validation** → Phase 7
- **Orphaned consumed records on logout** → Phase 5 (cleanup task)
- **IP extraction consolidation** → Phase 7.4

## Accepted as Design Tradeoffs

- Race condition on concurrent same-token use: atomic DELETE prevents double-spend; only one request wins. Not a security hole.
- In-flight rotation surviving family revocation: window is vanishingly small; the escaped token would be caught on next reuse. Documenting as accepted tradeoff.
- X-Forwarded-For first-IP logic: behind_proxy flag exists; consolidation in Phase 7.
