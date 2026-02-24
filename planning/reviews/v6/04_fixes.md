# Fixes for Review Round 2

**Commit**: `9c4c88a`

## Fixed

1. **Migration 009 comment** — Changed `uuidv7()` reference to "app-side UUIDv7" since `uuidv7()` is not a PostgreSQL function (M3)

## Deferred (pre-existing, not from phases 1-3)

- M1: CLI webhook URL validation — will address in Phase 6 (documentation) or a future cleanup pass
- M2: cleanup_webhook_deliveries i64→i32 — cosmetic type mismatch, no risk
- M4: Compound index on refresh_tokens — optimization, not correctness
- M5: Backoff naming — observation only
