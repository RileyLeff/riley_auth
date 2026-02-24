# Review Round 5 — Phase 4 Exhaustive R1 (2026-02-24)

**Models**: Claude subagent only (Codex rate-limited, Gemini exit 13)
**Context**: ~190k tokens (full codebase)
**Focus**: Phase 4 Generic OAuth Provider Pipeline + full codebase

## Findings

### Major

1. **M1: Schema injection via double-quoted identifier** [claude-only]
   - `db/mod.rs` — `SET search_path TO "{schema}"`
   - Current charset validation (alphanumeric + underscore) is actually safe — double-quote cannot be injected
   - **Verdict: Not a real bug** — noted for defense-in-depth awareness

2. **M2: Unbounded in-memory rate limiter growth** [claude-only]
   - `rate_limit.rs` — `HashMap<IpAddr, WindowEntry>` has no size cap
   - Under DDoS with diverse IPs, memory grows without bound
   - **Fixed in `491e86b`** — added `MAX_ENTRIES_PER_TIER = 100_000` cap

### Minor

3. **m1: XFF trust model** — takes leftmost IP, only safe if proxy overwrites (not appends). Config comments warn about this. Note for `review_notes_README.md`.
4. **m3: Missing updated_at in userinfo** — **False positive**: already implemented in `oauth_provider.rs:1229-1230`
5. **m4: Webhook secrets stored plaintext** — Intentional: HMAC signing keys must be available in raw form. Note.
6. **m5: CLI list-users limited to 100** — Cosmetic; add `--limit` flag later (not Phase 4).
7. **m6: Consumed token retention not configurable** — Nice-to-have config option. Not Phase 4.
8. **m7: SameSite not set on OAuth cookies** — **False positive**: `SameSite::Lax` already explicitly set on all temp cookies.
9. **P4-1: OIDC discovery doesn't validate issuer** — Legit defense against misconfiguration. Low priority.
10. **P4-4: No timeout on OIDC discovery** — **Fixed in `491e86b`** — 10s timeout added.
11. **P4-5: reqwest client created per call** — **Fixed in `491e86b`** — `oauth_client` in AppState, passed to `exchange_code`/`fetch_profile`.
12. **E3: No request body size limit** — Valid concern. Not Phase 4 specific.
13. **E5: PII scrubbing may miss nested payloads** — Valid concern for future webhook event shapes. Note.
14. **E7: preferred_username leaks without profile scope** — OIDC compliance. Should fix.
15. **T2: No OIDC discovery error tests** — Test gap, hard to test without mock server.
16. **T5: No rate limit proxy tests** — Test gap.

### Notes

- M3 (backchannel logout jti): Spec-compliant as-is; RP responsibility
- M4 (consent_id guessability): Well-designed; user_id check prevents cross-user attacks
- P4-2 (preset name override): Confusing but not a bug; admin controls config
- P4-3 (numeric ID handling): Positive finding — correctly handles both string and numeric IDs
- E1 (JWT token binding): Standard JWT tradeoff, mitigated by short TTL
- E2 (admin role DB check): Intentionally secure pattern
- E4 (cleanup deadlock): Theoretical; single maintenance worker makes it unlikely
- E6 (metrics token length timing): Negligible impact for metrics endpoint
- E8 (auth_time migration edge): One-time upgrade issue
- E9 (IPv6 loopback redirect): Minor omission
- T1 (concurrent family revocation): DB transaction provides atomicity
- T3 (custom profile_mapping integration test): Unit tests cover this; nice-to-have
- 8 positive findings about security practices (token family reuse detection, SSRF protection, consent atomicity, etc.)
