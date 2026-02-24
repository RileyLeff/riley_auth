# Fixes for Review Round 2 — 2026-02-24

## Phase 8-specific fixes

### 1. Added `expires_at` to ConsentResponse (MINOR-1)
- Added `expires_at: String` field to `ConsentResponse` struct
- Populated with `consent_req.expires_at.to_rfc3339()` in consent GET handler
- Added test assertion in `consent_get_returns_context`
- Commit: f1e9b7a

### 2. Added redirect_uri re-validation in consent_decision (MINOR-2 / downgraded MAJOR)
- After looking up the client in `consent_decision`, verify `consent_req.redirect_uri`
  is still in `client.redirect_uris`
- Returns `server_error` redirect if URI no longer registered
- Defense-in-depth for admin config changes during consent window
- Commit: f1e9b7a

## Pre-existing items deferred

Items 3-8 from the MINOR list and all NOTEs are pre-existing issues that
predate Phase 8. They will be tracked for future phases or documented in
review_notes_README.md.
