# Review Round 2 (Exhaustive) — Phase 8 Milestone — 2026-02-24

**Models**: Gemini, Claude (Opus 4.6)
**Context**: ~128k tokens (full codebase)
**Scope**: Full codebase review, Phase 8 (Consent UI Support) milestone

## Summary

Gemini declared the codebase **STABLE** with zero MAJORs. Claude found 3 items
labeled MAJOR but upon review they are MINOR/NOTE severity. **Merged: 0 MAJORs.**

## Findings

### Major

None. Claude's three "MAJORs" were downgraded (see rationale below):

- **logout-all revokes OAuth client tokens** [claude-only] → NOTE. Design
  decision — revoking all tokens on "logout all" is the safer security default.
  The function `delete_all_refresh_tokens` does what it says.
- **Consent redirect_uri not re-validated at approval time** [claude-only] →
  MINOR. Valid defense-in-depth edge case (admin changes client config during
  10-minute consent window). Fixed by adding re-validation in consent_decision.
- **ID token exp coupled to access_token_ttl_secs** [claude-only] → NOTE. OIDC
  only requires `exp` to be present. Using access token TTL is a common approach
  and the architecture plan doesn't specify a separate TTL.

### Minor

1. **ConsentResponse missing expires_at** [claude-only] — Consent UI cannot show
   remaining time. **Fixed**: Added `expires_at: String` (RFC 3339) to response.
2. **Consent redirect_uri re-validation** [claude-only] — See above. **Fixed**:
   Added re-validation check in `consent_decision`.
3. **Rate limit tier for /oauth/token** [claude-only] — Falls under `standard`
   tier (60/min) rather than `auth` tier (15/min). Pre-existing.
4. **Stuck outbox next_attempt_at check** [claude-only] — Uses `next_attempt_at`
   instead of processing start time. Pre-existing.
5. **Email in redirect URL query param** [claude-only] — PII in URL on email
   collision. Pre-existing.
6. **CORS missing PUT method** [claude-only] — No current routes use PUT.
   Pre-existing, future-proofing.
7. **Webhook URL private IP validation at registration** [claude-only] — Only
   checked at delivery time, not registration. Pre-existing.
8. **Byte count vs char count in client name validation** [gemini-only] —
   `body.name.len()` checks bytes not chars. Pre-existing.

### Notes

1. **auth_time not in refreshed ID tokens** [claude-only] — OIDC compliance gap.
2. **Consumed tokens not recorded on bulk delete** [claude-only] — No security
   impact (tokens deleted, replay fails at consume step).
3. **Cookie Secure flag always set** [claude-only] — Dev friction on localhost.
4. **openssl CLI dependency for key generation** [claude-only] — Docker image
   may not have it.
5. **Test coverage gaps** [claude-only] — Concurrent consent approval, PKCE via
   consent, scope downscoping on refresh, stuck outbox reset.
6. **Strong security positives** [gemini] — Audience separation, demotion
   protection, SSRF resolver, token family revocation all verified correct.
7. **Phase 8 verified correct** [consensus] — Atomic consent consumption, CSRF
   protection, UUIDv4 for consent_id all confirmed.

## Round 1 Fix Verification

Both models confirmed Round 1 fixes were correctly implemented:
- TOCTOU race → atomic `DELETE ... RETURNING *` ✓
- CSRF on consent POST → consent_router in csrf_protected group ✓
- gen_random_uuid() comment ✓
- Scope fallback description ✓
