# Fixes for Review Round 13 — 2026-02-22

**Commit:** 07a327c

## Major Fixes

### 1. Webhook secrets not exposed in list endpoint
- Created `WebhookListResponse` struct (omits `secret` field)
- `list_webhooks` now returns `WebhookListResponse` instead of `WebhookResponse`
- `WebhookResponse` (with secret) only used for creation response
- Added test assertion: `hooks[0].get("secret").is_none()`

### 2. Webhook URL scheme validated
- Replaced `body.url.is_empty()` check with full URL parsing via `url::Url::parse`
- Validates scheme is `https://` or `http://` — rejects `file://`, `ftp://`, etc.
- Prevents SSRF via internal URIs

### 3. client_id-scoped webhooks properly filtered during dispatch
- Added `dispatch_event_for_client()` with explicit `event_client_id: Option<Uuid>`
- Original `dispatch_event()` preserved as convenience wrapper (passes `None`)
- `find_webhooks_for_event()` now accepts `event_client_id: Option<Uuid>`
  - `Some(cid)`: returns webhooks with matching `client_id` OR NULL `client_id` (global)
  - `None`: returns all matching webhooks (preserves existing behavior for global events)

### 4. Scope downgrade on refresh prevented
- In `refresh_token` grant, scopes from token_row are now intersected with `client.allowed_scopes`
- If admin revokes a scope from a client, refreshed tokens no longer carry it
- `effective_scopes` used for both the new access token and stored refresh token

### 5. CLI register-client validates scopes
- Added `validate_scope_name()` call for each scope
- Added existence check against `config.scopes.definitions`
- Same validation as the admin HTTP endpoint

## Minor Fixes

### Delivery pagination offset
- `list_deliveries` now passes `offset` to `db::list_webhook_deliveries()`
- DB query updated with `OFFSET $3`
