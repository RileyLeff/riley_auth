# Fixes for Review Round 23

**Commit:** 5cff11a

## M1: Filter auto-merge by email_verified on existing links

**File:** `crates/riley-auth-api/src/routes/auth.rs` — `auth_callback`

Changed the auto-merge path to filter `matching_links` to only verified links before collecting user IDs:

```rust
let verified_links: Vec<&db::OAuthLink> = matching_links.iter()
    .filter(|l| l.email_verified)
    .collect();

let mut user_ids: Vec<uuid::Uuid> = verified_links.iter().map(|l| l.user_id).collect();
```

This ensures auto-merge only happens when BOTH the new provider AND the existing provider have verified the email address.

**Test:** Added `account_merge_skips_unverified_existing_link` integration test.
