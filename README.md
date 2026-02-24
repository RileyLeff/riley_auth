# riley_auth

OAuth 2.0 + OpenID Connect identity provider. Delegates authentication to upstream OAuth providers (Google, GitHub, or any OIDC/OAuth2 provider), then issues its own tokens so your apps authenticate against *you*, not against Google. One instance, one user database, single sign-on across all your apps.

## Features

- **Authorization Code Flow with PKCE** — full OIDC-compliant provider
- **Multi-provider OAuth** — built-in Google and GitHub presets, OIDC auto-discovery for any provider, manual OAuth2 for non-OIDC providers
- **Token rotation with reuse detection** — refresh tokens rotate on every use; reuse of a consumed token revokes the entire family
- **Multi-key JWKS with rotation** — ES256 and RS256 signing, add/remove keys with zero downtime
- **Custom scopes** — define application-specific scopes, assign per-client, propagate through consent and token issuance
- **Webhook events** — subscribe to user lifecycle events (created, deleted, role changed, etc.) with HMAC-signed delivery and retry
- **Prometheus metrics** — request counts, latencies, and error rates at `/metrics`
- **Rate limiting** — tiered (auth/standard/public), in-memory or Redis-backed
- **CLI administration** — manage users, clients, webhooks, and keys from the command line
- **OpenAPI spec** — machine-readable API documentation at `/openapi.json`

## Quick Start

### 1. Start PostgreSQL

Any PostgreSQL 14+ instance works. For local development:

```bash
docker run -d --name riley-auth-db \
  -e POSTGRES_USER=riley_auth \
  -e POSTGRES_PASSWORD=changeme \
  -e POSTGRES_DB=riley_auth \
  -p 5432:5432 postgres:17
```

### 2. Generate signing keys

```bash
cargo run -- generate-keys --algorithm es256 --output ./keys
```

This creates `private.pem` and `public.pem` in the `./keys` directory.

### 3. Write a config file

Copy `riley_auth.example.toml` to `riley_auth.toml` and fill in:

- `[jwt]` → `issuer` (required, e.g. `"https://auth.example.com"`)
- `[[jwt.keys]]` → paths to your generated keys
- `[database]` → `url` (e.g. `"postgres://riley_auth:changeme@localhost/riley_auth"`)
- `[[oauth.providers]]` → at least one OAuth provider with credentials

### 4. Run migrations

```bash
cargo run -- migrate
```

### 5. Start the server

```bash
cargo run -- serve
```

The server starts on `http://0.0.0.0:8081` by default.

### 6. First login and admin promotion

Log in through your OAuth provider, then promote yourself:

```bash
cargo run -- promote your-username
```

## Configuration

See [`riley_auth.example.toml`](riley_auth.example.toml) for a fully documented example config.

Key sections:

| Section | Purpose |
|---------|---------|
| `[server]` | Host, port, CORS, cookie domain, proxy settings |
| `[database]` | PostgreSQL connection string, pool size, optional schema |
| `[jwt]` | Token lifetimes, issuer, signing keys |
| `[[oauth.providers]]` | OAuth provider credentials (Google, GitHub, OIDC, manual) |
| `[scopes]` | Custom scope definitions |
| `[webhooks]` | Webhook delivery tuning |
| `[rate_limiting]` | Rate limit tiers (memory or Redis backend) |
| `[usernames]` | Username validation rules and reserved names |
| `[metrics]` | Prometheus metrics endpoint |
| `[maintenance]` | Background cleanup intervals |

All secret values support `"env:VAR_NAME"` syntax to read from environment variables.

## CLI Reference

```
riley-auth <command> [options]
```

| Command | Description |
|---------|-------------|
| `serve` | Start the HTTP server |
| `migrate` | Run database migrations |
| `generate-keys` | Generate a keypair for JWT signing (`--algorithm es256\|rs256`, `--output <dir>`, `--key-size <bits>`) |
| `validate` | Check config file and database connectivity |
| `list-users` | List all users |
| `promote <username>` | Promote a user to admin |
| `demote <username>` | Demote an admin to regular user |
| `revoke <username>` | Revoke all refresh tokens for a user |
| `delete <username>` | Soft-delete (anonymize) a user |
| `register-client <name> <redirect_uris...>` | Register an OAuth client (`--scopes`, `--auto-approve`) |
| `list-clients` | List registered OAuth clients |
| `remove-client <id>` | Remove an OAuth client |
| `register-webhook <url> <events...>` | Register a webhook (`--client-id`) |
| `list-webhooks` | List registered webhooks |
| `remove-webhook <id>` | Remove a webhook |

Global option: `--config <path>` to specify config file location.

## API

The full API specification is available at `/openapi.json` when the server is running. Point any OpenAPI viewer (Swagger UI, Redoc, etc.) at this endpoint for interactive documentation.

### Endpoint Groups

**Authentication** (`/auth/*`) — OAuth login flows, session management, profile updates. Cookie-based auth.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/{provider}` | Start OAuth login |
| GET | `/auth/{provider}/callback` | OAuth callback (internal) |
| POST | `/auth/setup` | Create account with username after first OAuth login |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout (revoke session) |
| POST | `/auth/logout-all` | Logout from all sessions |
| GET | `/auth/me` | Current user profile |
| PATCH | `/auth/me` | Update display name |
| PATCH | `/auth/me/username` | Update username |
| DELETE | `/auth/me` | Delete account |
| GET | `/auth/me/links` | List linked providers |
| GET | `/auth/link/{provider}` | Start provider linking flow |
| POST | `/auth/link/confirm` | Confirm linking a new provider |
| DELETE | `/auth/link/{provider}` | Unlink a provider |
| GET | `/auth/sessions` | List active sessions |
| DELETE | `/auth/sessions/{id}` | Revoke a session |

**OAuth/OIDC Provider** (`/oauth/*`) — Standard OAuth 2.0 / OIDC endpoints for downstream apps. Bearer token auth.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oauth/authorize` | Authorization endpoint |
| POST | `/oauth/token` | Token endpoint |
| GET/POST | `/oauth/userinfo` | UserInfo endpoint |
| POST | `/oauth/revoke` | Token revocation |
| POST | `/oauth/introspect` | Token introspection |
| GET | `/oauth/consent?consent_id={id}` | Get consent details |
| POST | `/oauth/consent?consent_id={id}` | Submit consent decision |

**Admin** (`/admin/*`) — User and client management. Requires admin role.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/users` | List users |
| GET | `/admin/users/{id}` | Get user details |
| PATCH | `/admin/users/{id}/role` | Change user role |
| DELETE | `/admin/users/{id}` | Soft-delete user |
| GET/POST | `/admin/clients` | List/register OAuth clients |
| DELETE | `/admin/clients/{id}` | Remove client |
| GET/POST | `/admin/webhooks` | List/register webhooks |
| DELETE | `/admin/webhooks/{id}` | Remove webhook |
| GET | `/admin/webhooks/{id}/deliveries` | Webhook delivery history |

**Discovery** — Public endpoints, no auth required.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/.well-known/openid-configuration` | OIDC discovery document |
| GET | `/.well-known/jwks.json` | JSON Web Key Set |
| GET | `/openapi.json` | OpenAPI specification |
| GET | `/metrics` | Prometheus metrics (when enabled) |

## Deployment

See [docs/deployment.md](docs/deployment.md) for Docker, Docker Compose, VPS deployment, key rotation, and backup instructions.

## License

MIT
