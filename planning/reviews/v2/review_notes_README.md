# Review Notes — v2

Architectural tradeoffs and design decisions documented during review. Future sessions should reference this to avoid re-litigating settled decisions.

## Phase 1 — Scopes & Permissions

### Scope definitions are config-only, not database-stored
Scope definitions live in `riley_auth.toml`, not the database. This means:
- Adding/removing scopes requires config change + restart
- Multi-instance deployments need consistent configs
This is intentional for Phase 1. Database-stored scopes may come in a future phase.

### No scope downscoping on refresh token rotation
RFC 6749 Section 6 allows narrowing scope on refresh. We don't support this — refreshed tokens inherit the same scopes. Acceptable for Phase 1.

### Admin self-deletion is allowed
An admin can delete themselves via `DELETE /admin/users/{id}` (as long as another admin exists). This is by design — the admin knowingly invoked the endpoint. The `DELETE /auth/me` endpoint also exists for self-deletion. No guard needed.

### Silent authorization for auto_approve clients via GET
The authorize endpoint (`GET /oauth/authorize`) silently issues auth codes for `auto_approve=true` clients without a consent step. This is intentional — `auto_approve` is for first-party clients trusted by the deployer. The consent UI (future phase) handles non-auto-approve clients. The auto-approve behavior is comparable to how first-party apps work with Auth0/Okta.

### OAuth state comparison hardened to constant-time
Even though the 32-byte random state makes timing attacks impractical, we now use `subtle::ConstantTimeEq` for consistency with the client secret comparison pattern. Belt and suspenders.

### Session metadata columns (user_agent, ip_address) intentionally empty in Phase 1
Migration 002 adds these columns for Phase 3 (Session Visibility). They store `None` until Phase 3 wires up the request headers. Not a bug.

### Regex recompilation in validate_username
The username regex is compiled from config on every call. Performance impact is negligible for typical auth traffic patterns. Could be optimized with `LazyLock` if it becomes a bottleneck, but not worth the complexity now.
