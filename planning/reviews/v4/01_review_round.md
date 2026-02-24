# Exhaustive Review Round 1 — 2026-02-23

**Models**: Gemini, Claude Opus 4.6 (Codex failed — no output file produced)
**Context**: ~113k tokens
**Scope**: Full codebase, v4 Phases 1-5 milestone ("debt cleared")

## Model Results

- **Gemini**: APPROVED — no major issues found. Noted setup token binding not bound to session (acceptable risk profile). Noted missing "List Authorized Apps" endpoint (planned).
- **Claude**: STRONG — found 4 MAJOR (1 reclassified to MINOR), 12 MINOR, 12 NOTES.
- **Codex**: FAILED — no output file produced.

## Findings

### Major

**MAJOR-01: Setup token binding verification is tautological** [claude-only]
- File: `auth.rs` — `decode_setup_token`
- The binding hash is computed from profile data inside the token and verified against the binding also inside the token. The JWT signature already prevents tampering. The binding adds no security beyond what the signature provides.
- **Action**: Remove the tautological binding field and check. The JWT signature is sufficient.

**MAJOR-02: Setup tokens are replayable across endpoints** [claude-only]
- File: `auth.rs` — `auth_setup`, `link_confirm`
- Setup tokens are not invalidated server-side after use. Within the 15-min TTL, the same token could theoretically be used at both endpoints.
- **Mitigations**: HttpOnly+Secure cookies, short TTL, CSRF protection, link_confirm requires dual auth (session + setup token).
- **Action**: Document as accepted design decision. The attack requires cookie theft, which defeats all cookie-based auth. Adding consumed_setup_tokens table would add DB complexity for minimal gain.

**MAJOR-03: auth_refresh doesn't preserve nonce** [claude-only]
- File: `auth.rs` line ~410 — passes `None` instead of `token_row.nonce.as_deref()`
- Breaks Phase 2 design symmetry. Session tokens don't use OIDC nonces currently, but the inconsistency is a latent bug.
- **Action**: Fix — pass `token_row.nonce.as_deref()` for consistency.

**MAJOR-04: Client secret uses SHA-256 not bcrypt/argon2** [claude-only]
- File: `oauth_provider.rs` — `token`, `revoke`
- Client secrets are 256-bit random, making brute-force infeasible regardless of hash function.
- **Action**: Document as accepted design decision. SHA-256 is appropriate for high-entropy machine-generated secrets.

### Minor

**MINOR-01: Rate limiter bypassed when IP extraction fails** [claude-only]
- Fail-open design. ConnectInfo should always be present. Document as intentional.

**MINOR-02: Refresh cookie path sent on unnecessary routes** [claude-only] (reclassified from MAJOR-05)
- Path="/auth" sends cookie to all /auth/* routes. Only /auth/refresh needs it.
- Note for future narrowing. Breaking change for existing deployments.

**MINOR-03: No pagination limit=0 documentation** [claude-only]
- No code change needed. Functional behavior is correct.

**MINOR-04: Admin self-deletion not prevented** [claude-only]
- Admin can delete themselves via admin endpoint if not last admin. Acceptable.

**MINOR-05: Webhook secret stored plaintext** [claude-only]
- Inherent HMAC constraint. Document threat model.

**MINOR-06: OAuth redirect GET no CSRF** [claude-only]
- Correct — state+PKCE already protect against login CSRF.

**MINOR-07: Consent endpoint returns error for non-auto-approve** [claude-only]
- Planned for Phase 8 (Consent UI Support).

**MINOR-08: CORS permissive in dev** [claude-only]
- Correct behavior — permissive mode doesn't set credentials.

**MINOR-09: Setup cookie max_age (10 min) vs JWT TTL (15 min) mismatch** [claude-only]
- **Action**: Fix — align cookie max_age to 15 minutes to match JWT TTL.

**MINOR-10: link_callback no email collision handling** [claude-only]
- Correct by design — link_callback is for explicit provider linking.

**MINOR-11: No IPv6 loopback in redirect URI** [claude-only]
- Note for future enhancement.

**MINOR-12: delete_all_refresh_tokens doesn't record consumed** [claude-only]
- Tokens are deleted, so replay would fail with "not found." Low impact.

### Notes

NOTE-01 through NOTE-12: See full Claude review for details. Key observations:
- JWT leeway=0 is intentionally strict (NOTE-01)
- Schema name injection protection is solid (NOTE-02)
- Soft delete PII scrubbing is thorough (NOTE-03)
- In-memory rate limiter state lost on restart — Redis recommended for prod (NOTE-04)
- Outbox backoff formula is correct (NOTE-11)
- Two separate token consume functions prevent cross-endpoint destruction (NOTE-10)

### Test Coverage Gaps

GAP-01 through GAP-08: See full Claude review. Key gaps:
- No test for setup token replay across endpoints (GAP-01)
- No test for admin scope revocation during refresh (GAP-02)
- No test for stuck outbox recovery (GAP-03)
