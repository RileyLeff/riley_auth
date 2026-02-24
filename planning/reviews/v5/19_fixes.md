# Fixes — Phase 6 Review R1+R2

**Date:** 2026-02-23

## Fixes Applied

### From R1 (Round 17)
- No fixes needed — 0 major, 6 minor (all pre-existing dead code, documented in review_notes_README.md)

### From R2 (Round 18)
1. **Fixed `scripts/test-integration.sh`** — Updated `cargo test --test integration` → `cargo test -p riley-auth-api` (bc8f8c2)
2. **Fixed `common/mod.rs` doc comment** — Updated stale `--test integration` reference (bc8f8c2)
3. **Updated `review_notes_README.md`** — Superseded outdated `consumed_refresh_tokens` note, added Phase 6 observations (bc8f8c2)

## Convergence

2 consecutive rounds with 0 major issues. Phase 6 standard review complete.
