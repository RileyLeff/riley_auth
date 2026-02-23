# Fixes for Review Round 03

**Commit:** 83a989a

## Fixed (Minor)

1. **Dead code `consume_refresh_token` removed**
   - Replaced by `consume_session_refresh_token` and `consume_client_refresh_token`
   - Prevents future accidental use of the unscoped variant

2. **Cross-endpoint isolation regression tests added**
   - `cross_endpoint_client_token_at_session_endpoint`: client-bound token → /auth/refresh is rejected, token survives
   - `cross_endpoint_session_token_at_oauth_endpoint`: session token → /oauth/token is rejected, token survives

## Deferred

- Logout/revoke not recording consumed token → accepted as minor gap
- Periodic cleanup task → Phase 5
- delete_all_refresh_tokens nuclear behavior → documented as intentional
