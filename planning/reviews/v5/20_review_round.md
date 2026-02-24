# Review Round 20 — Phase 7 Exhaustive Review R1
**Date:** 2026-02-24
**Models:** Claude subagent only (Codex rate-limited, Gemini unavailable)
**Context:** ~167k tokens (full codebase)
**Scope:** Entire codebase, focused on Phase 7 metrics

## Findings

### Major (1)

1. **[S-1][claude-only] Metrics bearer token not constant-time** — `metrics.rs:103` used `==` for token comparison, vulnerable to timing attack. All other secret comparisons in the codebase use `subtle::ConstantTimeEq`.
   - **Fixed:** d3efa63

### Minor (13)

1. **[S-2][claude-only] Metrics bearer token resolved on every request** — `metrics.rs:89-95` calls `resolve()` each scrape. Could cache at startup. *Deferred — low frequency endpoint, not a correctness issue.*
2. **[S-3][claude-only] /metrics not explicitly rate-limited** — Falls into "standard" tier by default. *Note: bearer token protection is recommended for production.*
3. **[C-1][claude-only] Metric cardinality from arbitrary paths** — Unknown paths (404s) recorded as-is. **Fixed:** d3efa63 — caps depth at 4 segments.
4. **[C-5][claude-only] Backchannel logout token can expire during retries** — With high retry count and 2-min token expiry, backoff could exceed validity. *Deferred — default retry count (3) is safe; edge case with custom config.*
5. **[A-1][claude-only] Inconsistent success status codes** — Some mutating endpoints return 200 instead of 204 for no-body responses. *Note: stylistic, existing behavior, not changing.*
6. **[A-4][claude-only] /metrics returns plain-text errors** — Other endpoints return JSON. *Intentional: metrics is consumed by Prometheus, not API clients.*
7. **[E-1][claude-only] No upper bound validation on JWT TTLs** — *Deferred — would be a warning, not error; low risk of misconfiguration.*
8. **[E-2][claude-only] public_url trailing slash not normalized** — **Fixed:** d3efa63 — stripped at config load time.
9. **[E-3][claude-only] Client name whitespace-only validation gap** — **Fixed:** d3efa63 — uses `trim().is_empty()`.
10. **[M-9][claude-only] Global Prometheus recorder makes tests fragile** — *Addressed by OnceLock pattern in tests/metrics.rs.*
11. **[T-1][claude-only] No test for 429 in metrics** — *Deferred — would require rate-limiting the test server.*
12. **[T-2][claude-only] No adversarial path normalization tests** — **Fixed:** d3efa63 — added deep path, edge case tests.
13. **[T-7][claude-only] Metrics test doesn't verify specific labels** — *Deferred — Prometheus output format varies; name presence is sufficient.*

### Notes (17)

Verified correct: webhook backoff formula, consumed token cutoff, middleware ordering, rate limit tier label design. Various enrichment opportunities noted (audience labels on token metrics, auth code counters, user event counters). See full review in claude_output.txt.
