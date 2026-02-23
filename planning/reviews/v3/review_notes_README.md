# Review Notes — v3

Architectural tradeoffs and design decisions documented during review. Future sessions should reference this to avoid re-litigating settled decisions.

## Carried Forward from v2

### Admin self-deletion is allowed
An admin can delete themselves via `DELETE /admin/users/{id}` (as long as another admin exists). By design.

### Silent authorization for auto_approve clients via GET
Standard OAuth behavior. Protection comes from `state` parameter and `redirect_uri` validation.

### OAuth state comparison hardened to constant-time
Belt and suspenders with `subtle::ConstantTimeEq`.

### /oauth/authorize CSRF is standard OAuth behavior (NOT a bug)
The authorize endpoint is always an unauthenticated GET. Protection comes from `state` parameter and `redirect_uri` validation. Auto_approve is for first-party clients only.

### Deleted user access token window is a stateless JWT tradeoff
Soft-deleted users retain valid access tokens for up to `access_token_ttl_secs` (default 15 min). Inherent to JWT-based auth.

### Consume-first pattern for tokens and auth codes is intentional
Atomic consume before validating binding prevents TOCTOU races. The "burn" risk requires the attacker to already possess the token value.

### Scope revocation not enforced on auth-code exchange (narrow window)
Auth-code exchange uses scopes stored at authorization time. Max 10-min window. Refresh correctly intersects with current allowed_scopes.

### Scope definitions are config-only, not database-stored
Intentional. Database-stored scopes are out of scope for v3.

### No scope downscoping on refresh token rotation
RFC 6749 Section 6 allows narrowing. Not supported. Out of scope for v3.
