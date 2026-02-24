# Fixes for Review Round 18 (Phase 10 R1)

**Commit:** 2c76c1a

## m1 Fix: session_supported discovery and reject session_required registration

**Problem:** Discovery document advertised `backchannel_logout_session_supported: true` but the server never includes `sid` claims in logout tokens. Clients registering with `backchannel_logout_session_required: true` would receive non-compliant logout tokens.

**Fix:**
1. `routes/mod.rs`: Changed `backchannel_logout_session_supported` from `true` to `false` in OIDC discovery document
2. `routes/admin.rs`: Added validation to reject `backchannel_logout_session_required: true` at client registration with clear error message ("sid not implemented")
3. `tests/integration.rs`: Added `backchannel_logout_rejects_session_required` test, updated discovery test assertion to expect `false`

**Tests:** 144 total (106 integration + 16 core + 22 API unit) — all passing.
