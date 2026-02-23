# Review Round 5 (Phase 2 Post-Implementation) — 2026-02-23

**Models**: Codex, Gemini, Claude
**Context**: ~87k tokens
**Scope**: Phase 2 Webhook Reliability (migration 005, config, outbox writer, delivery worker, server integration, tests)

## Findings

### Major

**1. [consensus] `FOR UPDATE SKIP LOCKED` without transaction → duplicate delivery**
- **Files**: `db.rs:fetch_pending_outbox_entries`, `webhooks.rs:delivery_worker`
- **All three models** flagged this. The `SELECT ... FOR UPDATE SKIP LOCKED` runs via `pool.fetch_all()` as auto-commit — locks are released immediately when the statement finishes. The worker then processes entries in separate spawned tasks, while the next poll cycle can pick up the same still-pending rows.
- **Fix**: Atomically claim rows with `UPDATE ... SET status = 'processing' ... RETURNING` instead of `SELECT ... FOR UPDATE`.

**2. [consensus: Codex + Claude] `dispatch_event` fire-and-forget → events lost before outbox write**
- **File**: `webhooks.rs:dispatch_event_for_client` line 68
- `tokio::spawn` without tracking JoinHandle. If the server crashes between business commit and the spawned task executing, the event is permanently lost.
- **Fix**: Make `dispatch_event` async and `.await` the INSERT (sub-millisecond DB write, negligible latency impact).

**3. [claude-only] `enqueue_webhook_events` is not atomic — partial enqueue on failure**
- **File**: `db.rs:enqueue_webhook_events`
- Loop of individual INSERTs without a transaction. If the 2nd of 3 INSERTs fails, the 1st is already committed.
- **Fix**: Use a single `INSERT INTO webhook_outbox SELECT ... FROM webhooks WHERE ...` statement.

**4. [codex-only] `max_concurrent_deliveries = 0` deadlocks the worker**
- **File**: `config.rs:WebhooksConfig`, `webhooks.rs:delivery_worker` line 158
- Config accepts any `usize` with no validation. `Semaphore::new(0)` blocks `acquire_owned()` forever, stalling shutdown.
- **Fix**: Add config validation `max_concurrent_deliveries >= 1`.

### Minor

**5. [consensus: Codex + Gemini + Claude] Shutdown does not drain in-flight delivery tasks**
- Worker spawns detached tasks and exits on shutdown without joining them.
- **Fix**: Acquire all semaphore permits before returning from `delivery_worker` to ensure in-flight tasks complete.

**6. [claude-only] Inactive webhook outbox entries waste cycles**
- When a webhook is deactivated, pending entries keep retrying until max_attempts.
- **Fix**: Mark as failed immediately when webhook is inactive (not retryable).

**7. [claude-only] `body_bytes.clone()` unnecessary**
- `webhooks.rs` line 113: `body_bytes` is not used after `.body()`, clone is wasteful.
- **Fix**: Remove `.clone()`.

**8. [claude-only] Stale doc comment on `deliver_outbox_entry`**
- Comment says `Ok(true)/Ok(false)` but signature is `Result<(), String>`.
- **Fix**: Update comment.

**9. [claude-only] `webhook_delivery_recorded_on_event` timing-flaky**
- Fixed 500ms sleep assumes enqueue completed. Should use polling loop.
- **Fix**: Convert to polling loop like other tests.

**10. [gemini-only] Delivery timestamp uses `Utc::now()` instead of event creation time**
- Retries after long backoff report wrong timestamp to consumers.
- **Fix**: Use `entry.created_at` for event timestamp.

**11. [claude-only] `record_outbox_attempt`/`mark_outbox_*` don't check affected rows**
- If entry was cascade-deleted, operations silently do nothing.
- **Fix**: Log warning when 0 rows affected.

### Notes (Observations / Tradeoffs)

**N1. SSRF on webhook URLs** [consensus: Codex + Gemini + Claude]
- Only scheme is validated. Phase 6 of v3 architecture explicitly addresses SSRF hardening. Not a Phase 2 issue — planned work.

**N2. Webhook secrets stored in plaintext** [claude-only]
- Unlike client secrets which are hashed. However, webhook secrets must be used for HMAC signing on every delivery — hashing doesn't work. Envelope encryption adds significant complexity. Accepted tradeoff given admin-only access to DB.

**N3. No idempotency key in webhook payloads** [claude-only]
- Include `entry.id` as a stable identifier for consumer deduplication. Good improvement.

**N4. No periodic outbox cleanup** [consensus: Gemini + Claude]
- `cleanup_webhook_outbox` exists but is never called. Phase 5 (Background Cleanup Task) explicitly covers this.

**N5. Webhook signing lacks replay protection** [claude-only]
- No timestamp in signed content. Industry standard includes timestamp + tolerance window.

**N6. `list_webhooks` fetches secret unnecessarily** [claude-only]
- `SELECT *` includes secret in memory. API layer redacts it, but defense-in-depth suggests explicit column list.

**N7. `deliver_outbox_entry` re-fetches webhook per entry** [claude-only]
- Per-batch webhook caching would reduce DB queries under high load.

**N8. `deliver_outbox_entry` returns `Result<(), String>` instead of crate error type** [gemini-only]
- Deviates from the `Error` pattern used elsewhere.
