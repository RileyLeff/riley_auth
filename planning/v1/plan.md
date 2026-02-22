# riley_auth v1 Plan

## Philosophy

riley_auth is a **general-purpose OAuth-only auth service**. It is not specific to rileyleff.com. Another developer should be able to deploy it for their own ecosystem of apps. Site-specific policy (reserved usernames, character rules, etc.) lives in configuration, not code.

riley_auth is both an **OAuth consumer** (delegates authentication to Google, GitHub, etc.) and an **OAuth provider** (lets external apps offer "Sign in with Riley"). It wraps upstream identity providers into a single unified identity and re-issues it across any domain.

The same ethos as riley_cms: minimal, self-hosted, stateless-friendly, bring-your-own-Postgres, bring-your-own-S3.

---

## Crate Structure

```
riley_auth/
├── Cargo.toml                              # workspace root
├── riley_auth.example.toml                 # example config
├── migrations/                             # sqlx migrations
├── Dockerfile
└── crates/
    ├── riley-auth-core/                    # library: config, db, jwt, oauth, s3
    ├── riley-auth-api/                     # HTTP server: routes, middleware
    └── riley-auth-cli/                     # binary: serve, migrate, list-users, etc.
```

---

## Two Modes of Operation

riley_auth serves two complementary modes:

**Same-domain mode (cookie-based):** For apps on the deployer's domain and subdomains. The access token lives in an `HttpOnly` cookie on the parent domain (e.g., `.rileyleff.com`). All subdomains get SSO for free. No integration work needed beyond verifying JWTs with the public key.

**Cross-domain mode (OAuth provider):** For apps on different domains. The external app redirects users to riley_auth's `/oauth/authorize` endpoint, gets back an authorization code, exchanges it for tokens server-to-server. Standard OAuth2 authorization code flow. The external app is a registered client.

Both modes produce the same JWT format. The difference is only in delivery: cookie vs. token response.

---

## Configuration (riley_auth.toml)

Same resolution order as riley_cms: CLI flag > env var > cwd > walk up > ~/.config > /etc.

Values support `"env:VAR_NAME"` syntax for secrets.

```toml
[server]
host = "0.0.0.0"
port = 8081
cors_origins = ["https://rileyleff.com", "https://*.rileyleff.com"]
cookie_domain = ".rileyleff.com"        # domain for auth cookies (same-domain mode)
frontend_url = "https://rileyleff.com"  # redirect target after OAuth
behind_proxy = false

[database]
url = "env:DATABASE_URL"                # postgres://user:pass@host/db
max_connections = 10

[jwt]
private_key_path = "/data/keys/private.pem"   # RS256 private key (signs tokens)
public_key_path = "/data/keys/public.pem"     # RS256 public key (verifies tokens)
access_token_ttl_secs = 900                   # 15 minutes
refresh_token_ttl_secs = 2592000              # 30 days
issuer = "riley-auth"                         # JWT `iss` claim
authorization_code_ttl_secs = 300             # 5 minutes (for OAuth provider flow)

[oauth.google]
client_id = "env:GOOGLE_CLIENT_ID"
client_secret = "env:GOOGLE_CLIENT_SECRET"

[oauth.github]
client_id = "env:GITHUB_CLIENT_ID"
client_secret = "env:GITHUB_CLIENT_SECRET"

# Optional: add more providers by adding [oauth.{name}] sections.
# Each needs: client_id, client_secret.
# Provider-specific URLs (auth, token, userinfo) are built into the library.

[storage]
backend = "s3"                                # for avatar uploads
bucket = "avatars"
region = "auto"
endpoint = "https://xxx.r2.cloudflarestorage.com"
public_url_base = "https://avatars.rileyleff.com"
max_avatar_size = 2097152                     # 2MB

[usernames]
min_length = 3
max_length = 24
pattern = "^[a-zA-Z][a-zA-Z0-9_-]*$"         # must start with letter
case_sensitive = false                        # "Riley" and "riley" are the same
allow_changes = true
change_cooldown_days = 30                     # min days between changes
old_name_hold_days = 90                       # old username reserved for this long
reserved = [
  "admin", "administrator", "system", "support", "help",
  "mod", "moderator", "root", "api", "auth", "blog",
  "null", "undefined", "deleted"
]
```

---

## Database Schema (Postgres 18)

### users

```sql
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  username text UNIQUE NOT NULL,
  display_name text,
  avatar_url text,                             -- S3 URL or OAuth provider URL
  role text NOT NULL DEFAULT 'user',           -- 'user' or 'admin'
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz                       -- NULL = active
);

-- Case-insensitive uniqueness (only active users)
CREATE UNIQUE INDEX idx_users_username_lower ON users(lower(username))
  WHERE deleted_at IS NULL;
```

### oauth_links

```sql
CREATE TABLE oauth_links (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider text NOT NULL,                      -- 'google', 'github'
  provider_id text NOT NULL,                   -- provider's unique user ID
  provider_email text,                         -- email from provider (for matching)
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_id)
);

CREATE INDEX idx_oauth_links_user_id ON oauth_links(user_id);
CREATE INDEX idx_oauth_links_provider_email ON oauth_links(provider_email)
  WHERE provider_email IS NOT NULL;
```

### refresh_tokens

```sql
CREATE TABLE refresh_tokens (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id uuid REFERENCES oauth_clients(id) ON DELETE CASCADE,  -- NULL = same-domain cookie
  token_hash text NOT NULL UNIQUE,             -- SHA-256 hash (never store raw)
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
```

### username_history

```sql
CREATE TABLE username_history (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  old_username text NOT NULL,
  changed_at timestamptz NOT NULL DEFAULT now(),
  held_until timestamptz NOT NULL              -- old name reserved until this date
);

CREATE INDEX idx_username_history_old_lower ON username_history(lower(old_username))
  WHERE held_until > now();
```

### oauth_clients

```sql
CREATE TABLE oauth_clients (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  name text NOT NULL,                          -- "Riley Viewer", "Forest Royale"
  client_id text UNIQUE NOT NULL,              -- public identifier
  client_secret_hash text NOT NULL,            -- SHA-256 hash of secret
  redirect_uris text[] NOT NULL,               -- allowed callback URLs
  auto_approve boolean NOT NULL DEFAULT false,  -- skip consent for first-party apps
  created_at timestamptz NOT NULL DEFAULT now()
);
```

### authorization_codes

```sql
CREATE TABLE authorization_codes (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  code_hash text UNIQUE NOT NULL,              -- SHA-256 hash
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,                  -- must match on exchange
  scopes text[] NOT NULL DEFAULT '{}',
  code_challenge text,                         -- PKCE
  code_challenge_method text,                  -- 'S256'
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  used boolean NOT NULL DEFAULT false
);

CREATE INDEX idx_authorization_codes_expires ON authorization_codes(expires_at);
```

---

## JWT Claims

```json
{
  "sub": "uuid-of-user",
  "username": "rileyleff",
  "role": "admin",
  "aud": "client-id-or-self",
  "iss": "riley-auth",
  "iat": 1740000000,
  "exp": 1740000900
}
```

- `aud`: For same-domain cookies, this is the `issuer` value (self-referential). For cross-domain tokens, this is the `client_id` of the requesting app. Consuming apps should verify `aud` matches their own client ID.

Signed with RS256. Public key available at `/.well-known/jwks.json`. Any service can verify without calling riley-auth.

---

## API Endpoints

### OAuth Consumer (sign in with Google/GitHub)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/{provider}` | Redirect to OAuth provider (Google, GitHub) |
| GET | `/auth/{provider}/callback` | OAuth callback — exchange code, upsert user, set cookies |

### Session (same-domain, cookie-based)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/refresh` | Exchange refresh token cookie for new access token |
| POST | `/auth/logout` | Clear cookies, revoke refresh token |
| POST | `/auth/logout-all` | Revoke all refresh tokens for current user |

### User Profile

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/me` | Current user profile from JWT |
| PATCH | `/auth/me` | Update display_name |
| PATCH | `/auth/me/username` | Change username (cooldown enforced) |
| POST | `/auth/me/avatar` | Upload avatar (multipart, stored in S3) |
| DELETE | `/auth/me/avatar` | Remove avatar (revert to OAuth provider's) |
| DELETE | `/auth/me` | Delete account (anonymize) |

### OAuth Linking (requires active session)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/link/{provider}` | Start OAuth flow to link a new provider |
| GET | `/auth/link/{provider}/callback` | Complete linking |
| DELETE | `/auth/link/{provider}` | Unlink provider (must keep at least one) |
| GET | `/auth/me/links` | List linked providers |

### OAuth Provider (cross-domain "Sign in with Riley")

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oauth/authorize` | Authorization endpoint — check session, consent, redirect with code |
| POST | `/oauth/token` | Token endpoint — exchange code for access + refresh tokens |
| POST | `/oauth/revoke` | Revoke a refresh token (per RFC 7009) |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/users` | List users (paginated) |
| GET | `/admin/users/{id}` | Get user details |
| PATCH | `/admin/users/{id}/role` | Change user role |
| DELETE | `/admin/users/{id}` | Delete (anonymize) user |
| GET | `/admin/clients` | List registered OAuth clients |
| POST | `/admin/clients` | Register a new client (returns client_id + secret) |
| DELETE | `/admin/clients/{id}` | Remove a client |

### System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/.well-known/jwks.json` | Public key for JWT verification |

---

## Same-Domain Flow (cookie-based)

### First-time sign-in (no existing account)

1. User clicks "Sign in with Google" on rileyleff.com
2. Frontend redirects to `GET /auth/google`
3. riley-auth generates `state` param (random, stored in short-lived cookie), redirects to Google
4. User authenticates with Google (Google handles 2FA if enabled)
5. Google redirects to `GET /auth/google/callback?code=...&state=...`
6. riley-auth verifies `state`, exchanges code for Google tokens
7. riley-auth fetches user profile from Google (name, email, avatar)
8. No matching `oauth_links` row → check if email matches any existing link
   - **No match**: Redirect to frontend `/onboarding` with a short-lived setup token
   - **Email match found**: Redirect to frontend `/link-accounts` prompting user to sign in with existing provider to confirm link
9. User picks a username on `/onboarding` (frontend calls `POST /auth/setup` with username + setup token)
10. riley-auth creates `users` row + `oauth_links` row, issues access + refresh tokens as cookies
11. Redirect to frontend homepage — user is signed in

### Returning sign-in

1. Steps 2-7 same as above
2. Matching `oauth_links` row found → issue tokens as cookies, redirect home

### Linking a second provider

1. User is already signed in (has valid access token)
2. User clicks "Link GitHub" on profile page
3. Frontend redirects to `GET /auth/link/github`
4. Same OAuth flow, but callback creates a new `oauth_links` row pointing to the existing `user_id`

---

## Cross-Domain Flow (OAuth provider)

### External app integration ("Sign in with Riley")

1. External app (e.g., rileyviewer.com) redirects user to:
   ```
   GET auth.rileyleff.com/oauth/authorize
     ?client_id=rileyviewer
     &redirect_uri=https://rileyviewer.com/callback
     &response_type=code
     &state=random-string
     &code_challenge=sha256-hash
     &code_challenge_method=S256
   ```

2. riley-auth checks:
   - `client_id` exists in `oauth_clients` table
   - `redirect_uri` matches one of the client's registered URIs

3. **If user is already signed in** (cookie exists from same-domain):
   - `auto_approve = true` (first-party app): immediately redirect back with code
   - `auto_approve = false`: show consent screen ("rileyviewer.com wants to access your riley account")

4. **If user is NOT signed in**:
   - Show sign-in page (Google/GitHub buttons)
   - After sign-in, continue to step 3

5. riley-auth generates authorization code, stores hash in `authorization_codes` table, redirects:
   ```
   https://rileyviewer.com/callback?code=abc123&state=random-string
   ```

6. External app's backend exchanges code for tokens (server-to-server):
   ```
   POST auth.rileyleff.com/oauth/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &code=abc123
   &redirect_uri=https://rileyviewer.com/callback
   &client_id=rileyviewer
   &client_secret=the-secret
   &code_verifier=original-random-string
   ```

7. riley-auth verifies code, PKCE, client credentials, returns:
   ```json
   {
     "access_token": "eyJ...",
     "token_type": "Bearer",
     "expires_in": 900,
     "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4"
   }
   ```

8. External app stores refresh token, sets its own session. Access token is the same JWT format — verifiable with riley-auth's public key.

### Token refresh (cross-domain)

```
POST auth.rileyleff.com/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4
&client_id=rileyviewer
&client_secret=the-secret
```

Returns a new access token + rotated refresh token.

---

## Account Deletion

When a user deletes their account:

1. Set `users.deleted_at = now()`
2. Replace `users.username` with `deleted_{uuid_prefix}` (frees the username)
3. Replace `users.display_name` with `"Deleted User"`
4. Set `users.avatar_url` to NULL
5. Delete all `oauth_links` rows (CASCADE)
6. Delete all `refresh_tokens` rows (CASCADE)
7. Delete all `authorization_codes` rows (CASCADE)
8. Delete avatar from S3 if custom
9. Comments/reactions in other services retain `user_id` but display "Deleted User"

The `users` row is kept (soft delete) so foreign keys in other services don't break.

---

## Username Rules

**Library defaults** (overridable in config):

| Rule | Default | Configurable |
|------|---------|-------------|
| Min length | 3 | `usernames.min_length` |
| Max length | 24 | `usernames.max_length` |
| Pattern | `^[a-zA-Z][a-zA-Z0-9_-]*$` | `usernames.pattern` |
| Case-sensitive | false | `usernames.case_sensitive` |
| Changes allowed | true | `usernames.allow_changes` |
| Change cooldown | 30 days | `usernames.change_cooldown_days` |
| Old name hold | 90 days | `usernames.old_name_hold_days` |
| Reserved words | (empty) | `usernames.reserved` |

**Username change flow:**

1. User requests change via `PATCH /auth/me/username`
2. Check cooldown: last entry in `username_history` must be older than cooldown period
3. Check availability: new name must not be in `users` (active) or `username_history` (held)
4. Check reserved words, pattern, length
5. Insert row into `username_history` with `held_until = now() + hold_days`
6. Update `users.username`
7. Issue new access token (username is in JWT claims)

---

## CLI Commands

```
riley-auth serve                          # start HTTP server
riley-auth migrate                        # run database migrations
riley-auth generate-keys                  # generate RS256 keypair
riley-auth list-users                     # list all users
riley-auth promote <username>             # set user role to admin
riley-auth demote <username>              # set user role back to user
riley-auth revoke <username>              # revoke all refresh tokens
riley-auth delete <username>              # anonymize/delete a user
riley-auth register-client <name> <uri>   # register OAuth client, prints client_id + secret
riley-auth list-clients                   # list registered OAuth clients
riley-auth remove-client <client_id>      # remove an OAuth client
riley-auth validate                       # check config and DB connectivity
```

---

## Deployment

### Dockerfile

```dockerfile
FROM rust:1.88 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/riley-auth /usr/local/bin/
VOLUME /data
EXPOSE 8081
CMD ["riley-auth", "serve"]
```

### docker-compose (in rileyleff deploy repo)

```yaml
riley-auth:
  build:
    context: /opt/riley-auth
  environment:
    - DATABASE_URL=postgres://riley:${DB_PASSWORD}@postgres/riley
    - GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
    - GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
    - GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
    - GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}
  volumes:
    - auth-keys:/data/keys
  networks:
    - web
  depends_on:
    - postgres

postgres:
  image: postgres:18
  environment:
    - POSTGRES_USER=riley
    - POSTGRES_PASSWORD=${DB_PASSWORD}
    - POSTGRES_DB=riley
  volumes:
    - pgdata:/var/lib/postgresql/data
  networks:
    - web
```

### Caddy

```
auth.rileyleff.com {
    reverse_proxy riley-auth:8081
}
```

---

## Security Checklist

- [ ] RS256 JWT (asymmetric — public key shared, private key stays in auth service)
- [ ] Refresh tokens stored as SHA-256 hash (never store raw)
- [ ] Authorization codes stored as SHA-256 hash, single-use, short-lived
- [ ] OAuth `state` param for CSRF protection (consumer side)
- [ ] PKCE for all OAuth code exchanges (consumer and provider)
- [ ] `HttpOnly; Secure; SameSite=Lax` cookies
- [ ] Constant-time token/secret comparison
- [ ] Rate limiting on auth endpoints
- [ ] CORS restricted to configured origins
- [ ] Avatar upload size limit + type validation
- [ ] No password storage anywhere
- [ ] Soft delete preserves referential integrity
- [ ] Client `redirect_uri` strictly validated against registered URIs
- [ ] `aud` claim in JWT verified by consuming apps

---

## What's NOT in v1

- Email addresses for users (@rileyleff.com)
- MFA (OAuth providers handle this)
- Password-based auth
- Email/password recovery flows
- Social graph (following/followers)
- Notification preferences (belongs in the consuming app)
- Scoped permissions beyond `role` (no fine-grained OAuth scopes yet)
