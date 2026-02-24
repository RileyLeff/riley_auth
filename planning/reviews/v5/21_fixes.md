# Fixes for Review Round 20
**Commit:** d3efa63

## Fixed

1. **[S-1] Constant-time bearer token comparison** — Replaced `==` with `subtle::ConstantTimeEq` in `metrics.rs`.
2. **[E-2] public_url trailing slash normalization** — Added `while` loop in `Config::from_path` to strip trailing slashes.
3. **[E-3] Client name whitespace validation** — Changed `body.name.is_empty()` to `body.name.trim().is_empty()` in `admin.rs`.
4. **[C-1] Path normalization cardinality cap** — `normalize_path` now returns `/unknown` for paths deeper than 4 segments.
5. **[T-2] Adversarial path normalization tests** — Added `normalize_caps_deep_paths` and `normalize_handles_edge_cases` unit tests.

## Deferred (with rationale)

- **[S-2]** Token resolved per-request: low-frequency endpoint, resolve() is cheap for literal values.
- **[C-5]** Backchannel logout token expiry during retries: default retry count (3) is safe; 13s total backoff << 2-min validity.
- **[A-1]** 200 vs 204 inconsistency: existing behavior across many endpoints, changing would be a breaking API change.
- **[A-4]** Plain-text metrics errors: intentional for Prometheus scraper compatibility.
- **[E-1]** JWT TTL upper bounds: would be a warning, not error; very low risk.
- **[T-1][T-7]** Additional metrics tests: diminishing returns; core functionality is well tested.
