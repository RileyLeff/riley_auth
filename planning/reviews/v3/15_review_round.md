# Review Round 15 — 2026-02-23 (Phase 4 Exhaustive R2)

**Models**: Claude (Gemini failed — only captured initialization messages, no review output)
**Context**: ~96k tokens
**Scope**: Full codebase review, NEW issues only (not re-flagging accepted tradeoffs)

## Findings

### Major

None.

### Minor

1. **m2 [claude-only]: Missing CHECK constraint on `webhook_outbox.status` column**
   - File: `migrations/005_webhook_outbox.sql`
   - The `status` text column accepts arbitrary strings. A CHECK constraint would prevent silent data corruption from admin errors or migration bugs.
   - **Action**: Fix — add migration with CHECK constraint.

2. **m3 [claude-only]: `generate_keypair` shells out to `openssl` via PATH**
   - File: `crates/riley-auth-core/src/jwt.rs`
   - Key generation uses `Command::new("openssl")` which resolves via system PATH. CLI-only function, not reachable via HTTP API.
   - **Action**: Accept — CLI-only setup-time operation. Documented in review_notes.

3. **m4 [claude-only]: Unnecessary `unsafe impl Sync for TestServer`**
   - File: `crates/riley-auth-api/tests/integration.rs`
   - All fields are already Send + Sync. The unsafe impl suppresses auto-trait checking.
   - **Action**: Fix — remove the unsafe impl.

4. **m5 [claude-only]: No format validation on `redirect_uris` at client registration**
   - File: `crates/riley-auth-api/src/routes/admin.rs`
   - Redirect URIs stored without scheme validation, allowing `javascript:`, `data:`, etc.
   - **Action**: Fix — validate scheme is `https://` or `http://localhost`.

5. **n3 [claude-only]: Unparseable CORS origins silently dropped**
   - File: `crates/riley-auth-api/src/server.rs`
   - Origins that fail to parse are skipped with no warning log.
   - **Action**: Fix — add `tracing::warn` for unparseable origins.

6. **n4 [claude-only]: No recovery mechanism for stuck 'processing' outbox entries**
   - File: `crates/riley-auth-core/src/db.rs`
   - If worker crashes after claiming entries, they stay in 'processing' forever.
   - **Action**: Accept — Phase 5 (Background Cleanup Task) will address this.

### Notes

1. **n5 [claude-only]: Unused `http_client` in AppState**
   - File: `crates/riley-auth-api/src/server.rs`
   - `http_client: reqwest::Client` in AppState is never used by route handlers.
   - **Action**: Note — could be removed, but harmless.

2. **n6 [claude-only]: `WebhookResponse` secret field leak risk**
   - File: `crates/riley-auth-api/src/routes/admin.rs`
   - The type design makes it possible for future endpoints to accidentally leak secrets.
   - **Action**: Note — architecture is correct today.

3. **n7 [claude-only]: Cookie `Secure` flag always true**
   - File: `crates/riley-auth-api/src/routes/auth.rs`
   - Prevents local development without HTTPS. Integration tests work because reqwest ignores Secure flag.
   - **Action**: Note — safe default, accepted.
