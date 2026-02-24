# Fixes for Review Round 1 — 2026-02-24

**Commit**: 68c86e3

## Major Fixes

- **M1**: `decode_setup_token` → uses `keys.verify_token::<SetupClaims>()` for kid lookup + fallback
- **M2**: `algorithms()` → `algs.sort(); algs.dedup();`
- **M3**: `from_configs` → duplicate kid check with `Error::Config` on collision

## Minor Fixes

- **m3**: Removed `decoding_key()` method (no callers after M1 fix)
- **m4**: `tracing::warn` when `key_size.is_some()` for ES256
- **m5**: Doc comment on `from_pem_files` RS256 assumption
- **N6**: `tracing::warn` in `resolved_keys()` for legacy flat config format

## New Tests

- `verify_token_by_kid_secondary_key` — signs with RSA secondary key, verifies via kid lookup
- `duplicate_kid_rejected` — two keys with same kid returns error
- `empty_configs_rejected` — empty config slice returns error
- `resolved_keys_new_format` — `[[jwt.keys]]` config parsed correctly
- `resolved_keys_legacy_flat_format` — flat config assumed RS256
- `resolved_keys_no_keys_errors` — no keys config returns error

## Test Results

34 unit + 111 integration = 145 tests passing.
