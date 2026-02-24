# Review Round 1 — 2026-02-24

**Models**: Claude (Codex rate-limited, Gemini exit 13)
**Context**: ~148k tokens
**Phase**: 1 — JWKS Key Rotation & Algorithm Agility

## Findings

### Major

1. **M1** [claude-only] `decode_setup_token` only verifies against the active key, not all keys. During key rotation, outstanding setup tokens signed with the old key would fail verification.
   - File: `crates/riley-auth-api/src/routes/auth.rs`, `decode_setup_token()`
   - **Fixed**: 68c86e3 — now uses `keys.verify_token()` with kid lookup + fallback

2. **M2** [claude-only] `algorithms()` calls `dedup()` without `sort()` — non-consecutive duplicates wouldn't be removed.
   - File: `crates/riley-auth-core/src/jwt.rs`, `algorithms()`
   - **Fixed**: 68c86e3 — added `algs.sort()` before `algs.dedup()`

3. **M3** [claude-only] Duplicate kid values in `from_configs` silently overwrite in HashMap — second key with same kid replaces the first.
   - File: `crates/riley-auth-core/src/jwt.rs`, `from_configs()`
   - **Fixed**: 68c86e3 — added explicit duplicate kid validation with clear error

### Minor

1. **m1** [claude-only] No validation leeway on token expiry. Noted but not fixed — zero leeway is more secure.

2. **m2** [claude-only] `validate_aud = false` in verify_token. Intentional — aud is enforced at call site.

3. **m3** [claude-only] `decoding_key()` method exposed single-key access, inconsistent with multi-key design.
   - **Fixed**: 68c86e3 — removed unused method

4. **m4** [claude-only] ES256 `key_size` parameter silently ignored.
   - **Fixed**: 68c86e3 — added `tracing::warn` when key_size provided for ES256

5. **m5** [claude-only] `from_pem_files` doesn't document RS256 assumption.
   - **Fixed**: 68c86e3 — added doc comment

6. **m6** [claude-only] OpenSSL dependency for key generation. Noted — accepted per existing review notes.

7. **m7** [claude-only] JWKS endpoint missing `application/jwk-set+json` Content-Type. Noted — `application/json` is commonly accepted.

### Notes

1. **N1** [claude-only] `validate_aud = false` is intentional design (different token types have different aud semantics).
2. **N2** [claude-only] Linear fallback in verify_token acceptable for expected key counts (2-3).
3. **N3** [claude-only] Computed kid from SHA-256 thumbprint is good practice.
4. **N4** [claude-only] `from_pem_files` delegates to `from_configs` — clean refactoring.
5. **N5** [claude-only] JWKS Cache-Control header is a good addition.
6. **N6** [claude-only] Legacy flat config lacks deprecation warning.
   - **Fixed**: 68c86e3 — added `tracing::warn` in `resolved_keys()` for flat format

### Test Coverage Gaps (fixed in 68c86e3)

- **T1**: Kid-based secondary key lookup — new test `verify_token_by_kid_secondary_key`
- **T3**: `resolved_keys()` backward compat — new tests `resolved_keys_new_format`, `resolved_keys_legacy_flat_format`, `resolved_keys_no_keys_errors`
- **T7**: Duplicate kid rejection — new test `duplicate_kid_rejected`
- Empty configs rejection — new test `empty_configs_rejected`
