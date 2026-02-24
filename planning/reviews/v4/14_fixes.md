# Fixes for Review Round 3 — 2026-02-24

## 1. Atomic user ownership in consume_consent_request (MINOR-1)
- Added `user_id: Uuid` parameter to `consume_consent_request` in `db.rs`
- DELETE query now includes `AND user_id = $2` for atomic ownership check
- Updated `consent_decision` handler to pass `user_id` and removed separate check
- Commit: 3be13a3

## 2. Oracle prevention on consent GET (MINOR-2)
- Changed wrong-user response from `Error::Forbidden` (403) to `Error::NotFound` (404)
- Prevents revealing consent_id existence for other users
- Updated `consent_rejects_wrong_user` test to expect 404
- Commit: 3be13a3

## False positives

- MINOR-3 (expired consent on GET): `find_consent_request` already has `AND expires_at > now()`
- NOTE-5 (no consent tests): 8 consent integration tests exist — subagent couldn't read full prompt
