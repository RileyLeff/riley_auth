# Fixes for Review Round 1 — 2026-02-23

**Commit**: 090c864

## MAJOR Fixes

### MAJOR-01: Setup token binding removed
- Removed `binding` field from `SetupClaims` struct
- Removed `setup_token_binding()` function
- Removed binding verification in `decode_setup_token()`
- Updated integration tests to not include binding in manually-crafted setup tokens
- **Rationale**: JWT signature already prevents tampering of all claims. The binding was a tautological self-check.

### MAJOR-03: Session refresh nonce preservation
- Changed `auth_refresh` line 410: `None` -> `token_row.nonce.as_deref()`
- Now consistent with OAuth provider refresh path

## MINOR Fixes

### MINOR-09: Cookie/JWT TTL alignment
- Changed `build_temp_cookie` max_age from 10 to 15 minutes
- Now matches setup token JWT TTL of 15 minutes

## Accepted (No Code Change)

- **MAJOR-02** (setup token replay): Documented in review_notes_README.md. HttpOnly+Secure+CSRF+dual-auth mitigate sufficiently.
- **MAJOR-04** (SHA-256 for client secrets): Documented. 256-bit entropy makes hash function irrelevant.
- **MAJOR-05 / MINOR-02** (refresh cookie path): Documented. Breaking change for minimal gain.
- All other MINORs and NOTEs: Documented or no action needed.
