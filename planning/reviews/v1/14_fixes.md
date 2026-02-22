# Round 7 Fixes

## Major

### M1: Atomic link creation (0856d44)
`create_oauth_link` now uses `INSERT ... SELECT FROM users WHERE deleted_at IS NULL` to atomically prevent creating links for deleted users. The previous check-then-insert pattern had a TOCTOU race.

### M2: Cookie removal path/domain (0856d44)
Added `removal_cookie(name, path, config)` helper. All cookie removal sites now include matching `path` and `domain` attributes so browsers properly clear cookies per RFC 6265.

Affected cookies:
- Access cookie: path="/", domain=config
- Refresh cookie: path="/auth", domain=config
- Temp cookies (state, PKCE, setup): path="/", domain=config

## Minor (noted, not fixed)

- JWT audience defaults: defense-in-depth improvement, all call sites currently correct
- auth_setup unique violation mapping: edge case, pre-checked by auth_callback
