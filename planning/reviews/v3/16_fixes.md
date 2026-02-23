# Fixes for Review Round 15 (Phase 4 Exhaustive R2)

**Commit**: `c00526c`

## Fixed

1. **m2: Missing CHECK constraint on webhook_outbox.status** → Added migration `007_outbox_status_check.sql` with `CHECK (status IN ('pending', 'processing', 'delivered', 'failed'))`.

2. **m4: Unnecessary unsafe impl Sync for TestServer** → Removed the `unsafe impl Sync for TestServer {}` and its comment. All fields are already Sync.

3. **m5: No format validation on redirect_uris** → Added URL parsing and scheme validation at client registration. Requires `https://` or `http://localhost` / `http://127.0.0.1` for development. Added integration test `admin_rejects_invalid_redirect_uri_scheme`.

4. **n3: Unparseable CORS origins silently dropped** → Changed `filter_map(|o| o.parse().ok())` to log `tracing::warn!` for each unparseable origin.

## Accepted (added to review_notes_README.md)

5. **m3: generate_keypair shells out to openssl** → CLI-only setup-time operation. Not reachable via HTTP API. Accepted.

6. **n4: No recovery for stuck processing outbox entries** → Phase 5 (Background Cleanup Task) will address this.

## Notes (no action needed)

7. **n5: Unused http_client in AppState** → Harmless dead code.
8. **n6: WebhookResponse secret field leak risk** → Architecture is correct today.
9. **n7: Cookie Secure flag always true** → Safe default, correct for production.
