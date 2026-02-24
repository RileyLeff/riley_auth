# Fixes for Review Round 25

**Commit:** bcdb4ac

## m1: UserInfo email_verified hardcoded to true

**File:** `crates/riley-auth-api/src/routes/oauth_provider.rs` — `userinfo`

Changed from:
```rust
if let Some(email) = links.iter().find_map(|l| l.provider_email.as_deref()) {
    response.insert("email_verified".to_string(), serde_json::json!(true));
}
```

To:
```rust
if let Some(link) = links.iter().find(|l| l.provider_email.is_some()) {
    response.insert("email_verified".to_string(), serde_json::json!(link.email_verified));
}
```

Uses the actual per-link `email_verified` value from Phase 11's `oauth_links.email_verified` column.
