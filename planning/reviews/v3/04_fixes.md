# Fixes for Review Round 02

**Commit:** f115314

## Fixed (Major)

1. **OAuth token endpoint consuming unrelated tokens** (finding #1)
   - Added `consume_client_refresh_token()` to `db.rs` with `AND client_id = $2`
   - Updated OAuth `refresh_token` grant to use the new function
   - Session tokens and other clients' tokens are now rejected without being consumed

## Deferred

- `ct_eq` length check on state param → accepted tradeoff (low risk)
- OIDC id_token without openid scope → Phase 4
- openssl binary in Docker → Phase 7 note
