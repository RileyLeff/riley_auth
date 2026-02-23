# Review Round 5 Fixes — 2026-02-23

**Commit:** e1ff9c0

## Major Fixes

1. **Atomic row claiming** (Finding #1) — Replaced `SELECT ... FOR UPDATE SKIP LOCKED` with a CTE `UPDATE ... SET status='processing' RETURNING`. Rows are atomically transitioned to 'processing' before delivery, preventing duplicate pickup by concurrent workers.

2. **Durable enqueue** (Finding #2) — `dispatch_event` is now `async` and awaits the INSERT. Removed `tokio::spawn` fire-and-forget. All 10 callers updated. Sub-millisecond latency impact on HTTP responses.

3. **Atomic multi-webhook enqueue** (Finding #3) — Replaced for-loop of individual INSERTs with a single `INSERT INTO webhook_outbox SELECT ... FROM webhooks WHERE ...` statement. All-or-nothing semantics.

4. **Config validation** (Finding #4) — Added `max_concurrent_deliveries >= 1` validation in `Config::from_path()`.

## Minor Fixes

5. **Graceful shutdown drain** (Finding #5) — Worker acquires all semaphore permits before returning, ensuring in-flight delivery tasks complete.

6. **Inactive webhook handling** (Finding #6) — `deliver_outbox_entry` returns `"permanent: ..."` errors for deleted/inactive webhooks. Worker marks these as failed immediately instead of retrying.

7. **Removed body_bytes.clone()** (Finding #7) — Unnecessary clone removed.

8. **Fixed stale doc comment** (Finding #8) — Updated `deliver_outbox_entry` comment to match `Result<(), String>` signature.

9. **Removed flaky timing** (Finding #9) — `webhook_delivery_recorded_on_event` no longer uses fixed 500ms sleep; `dispatch_event` is awaited directly.

10. **Event timestamp** (Finding #10) — Webhook payload now uses `entry.created_at` (event time) instead of `Utc::now()` (delivery time).

11. **Status-guarded mutations** (Finding #11) — `mark_outbox_delivered`, `mark_outbox_failed`, `record_outbox_attempt` all require `status = 'processing'` and return `Result<bool>` indicating whether the update applied.

## Deferred (Planned Work)

- **SSRF hardening** (N1) — Phase 6 of v3 architecture.
- **Outbox cleanup scheduling** (N4) — Phase 5 (Background Cleanup Task).
- **Webhook secret encryption** (N2) — Accepted tradeoff: secrets must be available for HMAC signing; envelope encryption adds significant complexity for marginal benefit given admin-only DB access.
