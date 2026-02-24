# Review Round 2 — 2026-02-24

**Models**: Claude (Codex rate-limited, Gemini exit 13)
**Context**: ~148k tokens (direct file reads)
**Phase**: 1 — JWKS Key Rotation & Algorithm Agility (verification round)

## Fix Verification

All 7 fixes from Round 1 confirmed correctly implemented:
- M1: `decode_setup_token()` uses `verify_token()` ✓
- M2: `algorithms()` sorts before dedup ✓
- M3: `from_configs()` rejects duplicate kid ✓
- m3: `decoding_key()` removed ✓
- m4: ES256 key_size warning ✓
- m5: doc comment on `from_pem_files` ✓
- N6: deprecation warning for legacy config ✓

No regressions introduced by fixes.

## Findings

### Major

None found.

Security properties confirmed sound:
- Algorithm confusion prevented: `Validation::new(entry.algorithm)` pins expected algorithm per key
- Kid spoofing not exploitable: kid only selects from server-held keys
- Setup token integrity maintained: full signature + issuer + expiry + purpose validation

### Minor

1. **m1** [claude-only] Integration tests create setup tokens without kid in header (lines 5401, 5468 of integration.rs). Only exercises fallback path in `verify_token`. Should mirror production `create_setup_token` which sets kid.
   - **Fixed**: 11713a4

2. **m2** [claude-only] `verify_token` doesn't explicitly cross-check token header `alg` against kid-matched key's algorithm. Safe in practice (jsonwebtoken crate enforces), but an explicit early check is defense-in-depth.
   - **Fixed**: 11713a4

### Notes

1. **N1** `validate_aud = false` is intentional — different token types have different audience semantics. Comment added for clarity.
2. **N2** Linear fallback for unknown kids is O(N) — fine for 2-3 keys.
3. **N3** Test coverage is good across key types, rotation, JWKS format.
4. **N4** `create_setup_token` manually constructs header (acceptable, self-contained).
5. **N5** Defensive `_ => format!("{:?}", e.algorithm)` branch in `algorithms()` is unreachable but safe.
