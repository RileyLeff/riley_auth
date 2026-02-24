# v6 Architecture: Generic Providers, Portability & Documentation

v5 hardened riley_auth's cryptographic foundation, closed OIDC spec gaps, added observability, and validated everything with conformance testing. The implementation is solid — 193 tests passing, OIDC Basic OP and Config OP conformance verified.

v6 makes riley_auth ready for anyone to deploy. The code works; now it needs to be portable, flexible, and documented. The three biggest gaps for third-party adoption are: only two hardcoded OAuth providers (Google and GitHub), a PostgreSQL 18 hard dependency (for `uuidv7()`) that most hosting providers don't support yet, and zero documentation.

## Theme

**Make riley_auth deployable by anyone: support any OAuth/OIDC provider, run on any modern Postgres, and document the whole thing.**

---

## 1. Remove Avatar Storage

### Problem

riley_auth has a half-built avatar upload feature: `StorageConfig` (S3 config) is parsed from the config file, `update_user_avatar` exists as a database function, and the example config documents a `[storage]` section — but no HTTP endpoint exists to actually upload avatars. The config implies a feature that doesn't work.

More fundamentally, avatar storage violates the soul document's "Identity, not entitlements" principle. riley_auth answers "who is this person?" — it stores the identity (username, display name, provider links) and nothing else. Avatars, preferences, billing, and other application data should be stored by downstream apps, keyed off the user ID that riley_auth provides. This is the standard OIDC pattern: the IdP returns core identity claims via UserInfo, apps store everything else.

The `avatar_url` column in the `users` table is fine to keep — it stores the URL string that Google/GitHub hand back during OAuth login, which is a legitimate identity claim (OIDC `picture`). What needs to go is the infrastructure for hosting images.

### Changes

**Remove:**
- `StorageConfig` struct and all related default functions in `config.rs`
- `pub storage: Option<StorageConfig>` from the top-level `Config` struct
- `update_user_avatar` function in `db/users.rs`
- The `[storage]` section in `riley_auth.example.toml`

**Keep:**
- `avatar_url` column in the `users` table (no migration needed)
- `avatar_url` field in `OAuthProfile` (populated from provider responses)
- `picture` field in `IdTokenClaims` (OIDC standard claim)
- Provider-sourced avatar URLs flowing into the `users.avatar_url` column during OAuth callback

**No database migration required** — the column stays, only the upload path is removed.

---

## 2. PostgreSQL 14+ Compatibility

### Problem

Every migration uses `DEFAULT uuidv7()`, which is a native function only in PostgreSQL 18. PG18 was released recently and most hosting providers, managed database services, and Linux distribution packages don't ship it yet. Someone on a typical VPS running `apt install postgresql` gets PG15 or PG16. This is the single biggest adoption barrier.

### Design

**Move UUID generation from the database to the application.** Instead of relying on `DEFAULT uuidv7()` in SQL, generate UUIDv7 in Rust using the `uuid` crate (already a dependency with the `v7` feature) and pass explicit IDs in every INSERT.

This is the gold-standard approach in the broader ecosystem — Django, Rails, and most Go/Node/Rust projects generate IDs application-side. It completely decouples the UUID strategy from the database version. The database just stores a UUID column; it doesn't need to know what version it is or how to generate one.

**Migration changes:**

Replace `DEFAULT uuidv7()` with `DEFAULT gen_random_uuid()` in all migrations. `gen_random_uuid()` is built-in since PG13 and requires no extensions. The DEFAULT is now just a safety net for manual SQL inserts — the application always provides a v7 UUID explicitly.

Example — `001_initial_schema.sql`:
```sql
-- Before (PG18 only):
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    ...
);

-- After (PG13+):
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ...
);
```

Apply the same change to every table across all 13 migrations that uses `DEFAULT uuidv7()`: `users`, `oauth_links`, `oauth_clients`, `refresh_tokens`, `username_history`, `authorization_codes`, `webhooks`, `webhook_deliveries`, `webhook_outbox`.

**Exception:** `consent_requests` already uses `DEFAULT gen_random_uuid()` (UUIDv4 for cryptographic randomness). No change needed.

**Exception:** `refresh_tokens.family_id` uses `DEFAULT uuidv7()`. Change to `DEFAULT gen_random_uuid()`. The application already generates family IDs explicitly in the token issuance code path.

**Application code changes:**

Audit every INSERT across the codebase. For each one that omits the `id` column (relying on the database DEFAULT), add an explicit `uuid::Uuid::now_v7()`:

```rust
// Before: relies on DEFAULT uuidv7() in the database
sqlx::query("INSERT INTO users (username, ...) VALUES ($1, ...)")
    .bind(username)
    ...

// After: application generates UUIDv7 explicitly
let id = uuid::Uuid::now_v7();
sqlx::query("INSERT INTO users (id, username, ...) VALUES ($1, $2, ...)")
    .bind(id)
    .bind(username)
    ...
```

Places that already generate UUIDs application-side (e.g., `family_id` in token issuance) need no changes.

**Why this is better than a polyfill:**

- **Zero PG version dependency.** Works on PG14, PG15, PG16, PG17, PG18 — any version that has `gen_random_uuid()`. No polyfill function, no extension, no conditional DDL.
- **No performance concern.** Rust's `uuid::Uuid::now_v7()` is native compiled code, faster than either a PL/pgSQL polyfill or PG18's C implementation (no SQL function call overhead at all).
- **Cleaner separation.** The database stores UUIDs. The application decides what kind. This is an application-level decision, not a schema-level one.
- **The DEFAULT fallback is safe.** If someone does a manual `INSERT` without an ID, they get a v4 UUID. It's still globally unique, just not time-ordered. For manual maintenance queries, this is fine.

**Minimum supported version: PostgreSQL 14.** PG13 is already EOL. `gen_random_uuid()` is available since PG13, but PG14 is the oldest supported release.

---

## 3. Security Defaults

### Problem

Two defaults that work against the soul document's "the library is the product" and "configuration over code" principles:

1. **CORS defaults to fully permissive** when `cors_origins` is empty. The `build_cors` function in `server.rs` logs a warning, but empty-array-means-open is a footgun — it's easy to deploy without setting CORS and be wide open without realizing it.

2. **Cookie prefix defaults to `"riley_auth"`**, so cookies are named `riley_auth_access`, `riley_auth_refresh`, etc. The soul document says: "If Bob deploys it for bob.com, his users should never encounter the word Riley." Cookie names are visible in browser dev tools.

### Design

**3a. CORS: require explicit configuration.**

Change the behavior of empty `cors_origins`:
- **Empty `[]` (default):** No CORS headers at all. This is the browser's default behavior — same-origin only. Safe by default.
- **Explicit origins `["https://app.example.com"]`:** Standard CORS with those origins. Allow credentials, the standard method/header set.
- **Wildcard `["*"]`:** Permissive CORS. Log a warning: "permissive CORS enabled — not recommended for production."

This is a behavior change but a safe one. Same-origin is the right default for an auth server. Cross-origin browser requests to the token endpoint are a specific use case that should be explicitly opted into.

**Code change in `server.rs` `build_cors()`:**
```rust
fn build_cors(config: &Config) -> Option<CorsLayer> {
    let origins = &config.server.cors_origins;
    if origins.is_empty() {
        // No CORS headers — browser default (same-origin only)
        None
    } else if origins.iter().any(|o| o == "*") {
        tracing::warn!("permissive CORS enabled — not recommended for production");
        Some(CorsLayer::permissive())
    } else {
        // Explicit origin list
        Some(CorsLayer::new()
            .allow_origin(AllowOrigin::list(...))
            .allow_methods(...)
            .allow_headers(...)
            .allow_credentials(true))
    }
}
```

Return `Option<CorsLayer>` — only apply the layer if configured. Update `serve()` to conditionally add it.

**3b. Cookie prefix: change default to `"auth"`.**

Change `default_cookie_prefix()` from `"riley_auth"` to `"auth"`:
```rust
fn default_cookie_prefix() -> String {
    "auth".to_string()
}
```

Cookies become `auth_access`, `auth_refresh`, `auth_oauth_state`, `auth_pkce`, `auth_setup`. Neutral, descriptive, no branding.

Update the example config comment to note that deployers can customize this.

**3c. Issuer default: change from `"riley-auth"` to require explicit setting.**

The JWT `issuer` defaults to `"riley-auth"`. This appears in every token and every discovery document. Change to no default — require it in the config. Config validation rejects startup without an issuer.

This is the one value that every deployer must set to something meaningful (typically their domain, e.g., `"https://auth.example.com"`). Making it required prevents silent deployment with a default that leaks the implementation.

---

## 4. Generic OAuth Provider Pipeline

### Problem

The `Provider` enum in `oauth.rs` is hardcoded to two variants: `Google` and `GitHub`. Every endpoint URL, scope string, and profile parser is a `match` arm on this enum. Adding a provider means changing Rust code. This contradicts the soul document's "configuration over code" principle — the set of OAuth providers should be a deployment decision, not a library decision.

For third-party adoption, users need to configure arbitrary OAuth/OIDC providers without forking the code. Common needs: Microsoft/Azure AD for corporate deployments, Apple Sign-In for iOS apps, Discord/Twitch for gaming, any corporate OIDC IdP, any Keycloak/Auth0/Okta instance.

### Design

**Replace the hardcoded `Provider` enum with a configuration-driven provider system that has three tiers:**

1. **Built-in presets** — `name = "google"` or `name = "github"`. Endpoints, scopes, and profile parsing are pre-configured. You just supply credentials. These preserve the current zero-config convenience.

2. **OIDC auto-discovery** — Specify an `issuer` URL. riley_auth fetches `{issuer}/.well-known/openid-configuration` at startup to discover all endpoints. Profile parsing uses standard OIDC claims (`sub`, `email`, `email_verified`, `name`, `picture`). Scopes default to `"openid email profile"`.

3. **Manual OAuth2** — Specify `auth_url`, `token_url`, `userinfo_url`, `scopes` explicitly, plus a `profile_mapping` for non-standard UserInfo responses. For providers that don't implement OIDC (GitHub-style OAuth2-only providers like Discord, Twitch, etc.).

### Config format

```toml
[oauth]
account_merge_policy = "verified_email"
login_url = "https://auth.example.com/login"
consent_url = "https://auth.example.com/consent"

# Built-in preset — just credentials, everything else is pre-configured
[[oauth.providers]]
name = "google"
client_id = "env:GOOGLE_CLIENT_ID"
client_secret = "env:GOOGLE_CLIENT_SECRET"

# Built-in preset
[[oauth.providers]]
name = "github"
client_id = "env:GITHUB_CLIENT_ID"
client_secret = "env:GITHUB_CLIENT_SECRET"

# OIDC auto-discovery — specify issuer, endpoints are discovered
[[oauth.providers]]
name = "corporate"
display_name = "Corporate SSO"
issuer = "https://login.corp.com"
client_id = "env:CORP_CLIENT_ID"
client_secret = "env:CORP_CLIENT_SECRET"
# scopes defaults to "openid email profile" for OIDC providers
# scopes = "openid email profile groups"  # override if needed

# Manual OAuth2 — specify everything explicitly
[[oauth.providers]]
name = "discord"
display_name = "Discord"
auth_url = "https://discord.com/api/oauth2/authorize"
token_url = "https://discord.com/api/oauth2/token"
userinfo_url = "https://discord.com/api/users/@me"
scopes = "identify email"
client_id = "env:DISCORD_CLIENT_ID"
client_secret = "env:DISCORD_CLIENT_SECRET"

# Profile field mapping for non-standard UserInfo responses
[oauth.providers.profile_mapping]
provider_id = "id"           # Required: unique user ID field
email = "email"              # Optional: email field
email_verified = "verified"  # Optional: email verification boolean
name = "username"            # Optional: display name field
avatar_url = ""              # Empty string = not available
```

### Tier detection logic

When parsing a provider entry:

1. If `name` matches a known preset (`"google"`, `"github"`) and no `auth_url`/`issuer` is specified → **built-in preset**. Fill in endpoints, scopes, and profile parsing from the preset definition.
2. If `issuer` is specified → **OIDC auto-discovery**. Fetch `{issuer}/.well-known/openid-configuration` at startup. Use discovered endpoints. Profile mapping uses standard OIDC claims.
3. If `auth_url`, `token_url`, `userinfo_url` are all specified → **manual OAuth2**. Use provided endpoints. Require `profile_mapping` for non-OIDC providers.
4. Otherwise → config validation error at startup.

Built-in presets can be overridden: if someone specifies `name = "google"` with a custom `issuer`, the OIDC auto-discovery path is used instead of the Google preset.

### Config structs

Replace `OAuthProvidersConfig`:

```rust
pub struct OAuthProvidersConfig {
    #[serde(default)]
    pub providers: Vec<ProviderEntry>,
    pub login_url: Option<String>,
    pub consent_url: Option<String>,
    #[serde(default)]
    pub account_merge_policy: AccountMergePolicy,
}

pub struct ProviderEntry {
    pub name: String,                          // Internal identifier, stored in oauth_links.provider
    pub display_name: Option<String>,          // Human-readable, defaults to capitalized name
    pub client_id: ConfigValue,
    pub client_secret: ConfigValue,
    // OIDC auto-discovery
    pub issuer: Option<String>,
    // Manual OAuth2 endpoints (override discovery or preset)
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scopes: Option<String>,
    // Profile field mapping for non-OIDC providers
    pub profile_mapping: Option<ProfileMapping>,
}

pub struct ProfileMapping {
    pub provider_id: String,                   // JSON field for unique user ID (required)
    pub email: Option<String>,                 // JSON field for email
    pub email_verified: Option<String>,        // JSON field for email verified boolean
    pub name: Option<String>,                  // JSON field for display name
    pub avatar_url: Option<String>,            // JSON field for avatar URL
}
```

### Resolved provider (runtime)

At startup, each `ProviderEntry` resolves to a `ResolvedProvider`:

```rust
pub struct ResolvedProvider {
    pub name: String,
    pub display_name: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: String,
    pub client_id: String,
    pub client_secret: String,
    pub profile_mapping: ProfileMapping,
    // Preset-specific behavior flags
    pub extra_auth_params: Vec<(String, String)>,   // e.g., Google: access_type=offline
    pub token_request_accept_json: bool,             // e.g., GitHub needs Accept: application/json
    pub extra_email_endpoint: Option<String>,         // e.g., GitHub: /user/emails
}
```

For built-in presets, the quirks are encoded in the preset definition:
- **Google:** `extra_auth_params = [("access_type", "offline")]`, standard OIDC profile mapping
- **GitHub:** `token_request_accept_json = true`, `extra_email_endpoint = Some("https://api.github.com/user/emails")`, custom profile mapping (`id`, `name`, `avatar_url`, email from separate endpoint)

For OIDC auto-discovery providers, endpoints come from the discovery document. Quirk flags are all off (standard OIDC behavior).

For manual OAuth2 providers, everything comes from the config.

### OIDC Discovery fetch

For providers with `issuer` set, riley_auth fetches the discovery document **at startup** (not per-request):

```rust
async fn discover_oidc_provider(issuer: &str, http: &reqwest::Client) -> Result<DiscoveredEndpoints> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let doc: serde_json::Value = http.get(&url).send().await?.json().await?;
    Ok(DiscoveredEndpoints {
        authorization_endpoint: doc["authorization_endpoint"].as_str()?.to_string(),
        token_endpoint: doc["token_endpoint"].as_str()?.to_string(),
        userinfo_endpoint: doc["userinfo_endpoint"].as_str()?.to_string(),
    })
}
```

If discovery fails at startup, riley_auth exits with a clear error. This is the right behavior — a misconfigured provider should be caught immediately, not on the first user login.

### Profile parsing

Replace the hardcoded `parse_google_profile` / `parse_github_profile` with a generic profile parser:

```rust
fn parse_profile(body: &serde_json::Value, mapping: &ProfileMapping) -> Result<OAuthProfile> {
    let provider_id = body[&mapping.provider_id]
        .as_str()
        .or_else(|| body[&mapping.provider_id].as_i64().map(|n| /* int to string */))
        .ok_or_else(|| Error::OAuth("missing provider user ID".into()))?;

    Ok(OAuthProfile {
        provider_id: provider_id.to_string(),
        email: mapping.email.as_ref().and_then(|f| body[f].as_str().map(String::from)),
        email_verified: mapping.email_verified.as_ref()
            .and_then(|f| body[f].as_bool())
            .unwrap_or(false),
        name: mapping.name.as_ref().and_then(|f| body[f].as_str().map(String::from)),
        avatar_url: mapping.avatar_url.as_deref()
            .filter(|f| !f.is_empty())
            .and_then(|f| body[f].as_str().map(String::from)),
    })
}
```

The `provider` field on `OAuthProfile` is set from `ResolvedProvider.name`, not from the profile response.

For GitHub's special email endpoint: after fetching the main profile, if `extra_email_endpoint` is set, make a second request and extract the verified primary email. This replaces the current `fetch_github_email_verified` / `fetch_github_primary_email` functions with a generic secondary-email-fetch that any preset can use.

### Auth route changes

The current routes `/auth/login/{provider}` and `/auth/callback/{provider}` already take the provider as a path parameter. The route handlers need to:

1. Look up the provider by `name` in the resolved providers list (instead of parsing a `Provider` enum)
2. Call the generic `build_auth_url` / `exchange_code` / `fetch_profile` functions with the `ResolvedProvider` config
3. Handle the optional secondary email endpoint

**`oauth.rs` changes:**
- Remove the `Provider` enum entirely
- `build_auth_url` takes `&ResolvedProvider` instead of `Provider`
- `exchange_code` takes `&ResolvedProvider`
- `fetch_profile` takes `&ResolvedProvider`, calls the generic parser, then optionally fetches from `extra_email_endpoint`

### AppState changes

Add resolved providers to `AppState`:

```rust
pub struct AppState {
    // ... existing fields ...
    pub providers: Arc<Vec<ResolvedProvider>>,
}
```

Provider resolution happens once at startup in `serve()`, before building the state.

### Database impact

No schema changes. The `oauth_links.provider` column is already `text` — it stores whatever the provider `name` is. Existing `"google"` and `"github"` values continue to work with the built-in presets.

### Backward compatibility

The old config format (`[oauth.google]` and `[oauth.github]` sections) is **not** supported. This is a breaking change. Since riley_auth has no external users yet, this is acceptable. The migration is straightforward: move credentials from `[oauth.google]` to a `[[oauth.providers]]` entry with `name = "google"`.

### Validation

At startup:
- Provider names must be unique
- Provider names must be lowercase alphanumeric + hyphens (they're stored in the database)
- At least one provider must be configured
- OIDC discovery URLs must be reachable (startup fails clearly if not)
- Manual OAuth2 providers must have all three endpoint URLs
- Manual OAuth2 providers must have a `profile_mapping` with at least `provider_id`
- Built-in presets must not specify conflicting manual endpoints (or if they do, the manual endpoints override the preset — allows customization)

---

## 5. OpenAPI Documentation (utoipa)

### Problem

riley_auth has no API documentation. A developer integrating their app against riley_auth has to read Rust source code to figure out what endpoints exist, what parameters they take, and what they return. This is the primary DX gap for third-party adoption.

### Design

**Add OpenAPI 3.1 spec generation via the `utoipa` crate, served at `/openapi.json`.**

**New dependencies:**
- `utoipa = "5"` — OpenAPI spec generation from Rust types and route annotations
- `utoipa-axum` — Axum integration for automatic path registration

**Changes per file:**

**Request/response types** — Add `#[derive(utoipa::ToSchema)]` to all types that appear in request bodies or responses:
- `ErrorBody` in `error.rs`
- User response types in `routes/auth.rs`
- Admin request/response types in `routes/admin.rs`
- Token request/response types in `routes/oauth_provider.rs`
- UserInfo response in `routes/oauth_provider.rs`
- Discovery document in `routes/mod.rs`
- JWKS response in `routes/mod.rs`
- Webhook types in `routes/admin.rs`

**Route handlers** — Add `#[utoipa::path(...)]` annotations to every route handler:

```rust
#[utoipa::path(
    get,
    path = "/oauth/userinfo",
    responses(
        (status = 200, description = "User identity claims", body = UserInfoResponse),
        (status = 401, description = "Invalid or missing bearer token", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
async fn userinfo(...) -> ... { ... }
```

**API doc struct** — Assemble the full spec:

```rust
#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "riley_auth",
        description = "OAuth 2.0 + OpenID Connect identity provider",
        version = env!("CARGO_PKG_VERSION"),
    ),
    paths(
        // All annotated handlers
    ),
    components(schemas(
        // All ToSchema types
    )),
    tags(
        (name = "auth", description = "Authentication (OAuth consumer side)"),
        (name = "oauth", description = "OAuth/OIDC provider endpoints"),
        (name = "admin", description = "Admin API"),
        (name = "discovery", description = "OIDC discovery and JWKS"),
    )
)]
struct ApiDoc;
```

**Endpoint** — Serve the spec at `GET /openapi.json`:

```rust
async fn openapi_spec() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        ApiDoc::openapi().to_json().unwrap(),
    )
}
```

This endpoint is always available (no auth required, no CSRF, public tier rate limiting). It's the machine-readable API contract.

**No Swagger UI bundled** — riley_auth is headless. If someone wants interactive docs, they point Swagger UI, Redoc, or any OpenAPI viewer at `/openapi.json`. This is one line of config in any of those tools.

### Endpoint inventory

Every endpoint that gets an OpenAPI annotation:

| Method | Path | Tag | Description |
|--------|------|-----|-------------|
| GET | `/health` | discovery | Health check |
| GET | `/openapi.json` | discovery | OpenAPI spec |
| GET | `/.well-known/openid-configuration` | discovery | OIDC discovery document |
| GET | `/.well-known/jwks.json` | discovery | JSON Web Key Set |
| GET | `/metrics` | discovery | Prometheus metrics (optional) |
| GET | `/auth/login/{provider}` | auth | Start OAuth login flow |
| GET | `/auth/callback/{provider}` | auth | OAuth callback (internal) |
| GET | `/auth/me` | auth | Current user info (cookie auth) |
| POST | `/auth/refresh` | auth | Refresh access token (cookie auth) |
| POST | `/auth/logout` | auth | Logout (cookie auth) |
| PATCH | `/auth/username` | auth | Change username |
| POST | `/auth/link/{provider}` | auth | Link additional OAuth provider |
| DELETE | `/auth/link/{provider}` | auth | Unlink OAuth provider |
| GET | `/oauth/authorize` | oauth | Authorization endpoint (OIDC) |
| POST | `/oauth/token` | oauth | Token endpoint |
| POST | `/oauth/revoke` | oauth | Token revocation |
| POST | `/oauth/introspect` | oauth | Token introspection |
| GET | `/oauth/userinfo` | oauth | UserInfo endpoint |
| POST | `/oauth/userinfo` | oauth | UserInfo endpoint (POST) |
| POST | `/oauth/consent/{consent_id}/approve` | oauth | Approve consent request |
| POST | `/oauth/consent/{consent_id}/deny` | oauth | Deny consent request |
| GET | `/admin/users` | admin | List users |
| GET | `/admin/users/{id}` | admin | Get user details |
| PATCH | `/admin/users/{id}/role` | admin | Change user role |
| DELETE | `/admin/users/{id}` | admin | Soft-delete user |
| POST | `/admin/clients` | admin | Register OAuth client |
| GET | `/admin/clients` | admin | List OAuth clients |
| DELETE | `/admin/clients/{client_id}` | admin | Remove OAuth client |
| POST | `/admin/webhooks` | admin | Register webhook |
| GET | `/admin/webhooks` | admin | List webhooks |
| DELETE | `/admin/webhooks/{id}` | admin | Remove webhook |

---

## 6. Documentation

### Problem

No README, no quickstart guide, no deployment guide, no API overview. Someone cloning the repo has no idea what riley_auth is or how to use it.

### Design

**Documentation is the last phase** — written after all code changes are locked in so it doesn't need to be updated as implementation evolves.

**6a. README.md** (repo root)

Sections:
- **What is riley_auth?** — One-paragraph description. Link to soul document for philosophy.
- **Features** — Bullet list: OIDC-certified authorization code flow, multi-provider OAuth (Google, GitHub, any OIDC/OAuth2 provider), PKCE, token rotation with reuse detection, multi-key JWKS with rotation, Prometheus metrics, webhook events, CLI administration.
- **Quick start** — 5-step setup: install Postgres, generate keys, write config, run migrations, start server.
- **Configuration** — Link to example config with brief explanation of each section.
- **CLI reference** — Table of all commands with one-line descriptions.
- **API** — Link to `/openapi.json` endpoint. Brief overview of endpoint groups (auth, OAuth/OIDC, admin, discovery).
- **Deployment** — Link to deployment guide.
- **License** — MIT.

**6b. Deployment guide** (`docs/deployment.md`)

Sections:
- **Requirements** — PostgreSQL 14+ (UUIDs generated application-side, no PG18 features needed), Rust 1.88+ (if building from source), or Docker.
- **Docker** — `docker build`, `docker run` with env vars, docker-compose example with Postgres.
- **Docker Compose** — Production-ready `docker-compose.yml` (not the test one) with Postgres, riley_auth, and a Caddy reverse proxy for TLS.
- **VPS** — Build from source, systemd service file, nginx/Caddy reverse proxy config with TLS.
- **First-time setup** — Step-by-step: create config, generate keys, start server, log in via OAuth, promote yourself to admin via CLI.
- **Key rotation** — How to rotate signing keys with zero downtime.
- **Backup** — What to back up (Postgres database, signing keys, config file).

**6c. Production docker-compose** (`docker-compose.yml`)

A docker-compose file that actually works for production:
```yaml
services:
  riley-auth:
    image: riley-auth:latest
    environment:
      RILEY_AUTH_CONFIG: /config/riley_auth.toml
      DATABASE_URL: postgres://riley_auth:${DB_PASSWORD}@db:5432/riley_auth
    volumes:
      - ./config:/config:ro
      - ./keys:/keys:ro
    ports:
      - "8081:8081"
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:17
    environment:
      POSTGRES_USER: riley_auth
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: riley_auth
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U riley_auth"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  pgdata:
```

Note: uses `postgres:17` (not 18) — riley_auth works on PG14+ since all UUIDs are generated application-side.

**6d. Dockerfile improvements**

Add `HEALTHCHECK` directive:
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8081/health || exit 1
```

This requires adding `curl` to the runtime image, or using a lighter health check mechanism (e.g., a small static binary, or just `wget` which is in busybox).

Alternatively, add a tiny healthcheck binary or use the riley-auth binary itself:
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD riley-auth validate --health-only || exit 1
```

This would require adding a `--health-only` flag to the `validate` command that just checks if the server is reachable. Simpler: just install `curl` in the slim image.

---

## Implementation Order

1. **Remove Avatar Storage** — small cleanup, simplifies the codebase
2. **PostgreSQL 14+ Compatibility** — migration shim, independent of other changes
3. **Security Defaults** — CORS, cookie prefix, issuer requirement
4. **Generic OAuth Provider Pipeline** — largest change, core feature
5. **OpenAPI Documentation** — needs routes and types finalized (after phase 4)
6. **Documentation** — README, deployment guide, docker-compose, Dockerfile improvements

**Grouping:**
- Phases 1-3: Cleanup and portability (small, independent changes)
- Phase 4: Core feature (generic providers)
- Phase 5: Machine-readable API docs (code change)
- Phase 6: Human-readable docs (writing, not code)

**Review strategy:**
- Standard review after phases 1-3 (grouped, small changes)
- Exhaustive review after phase 4 (core feature, security-sensitive)
- Standard review after phase 5 (mechanical annotations)
- Phase 6 is documentation — review for accuracy against the code

---

## Out of Scope

Still not in v6:
- **Email/password auth** — violates the soul document
- **MFA/TOTP** — delegated to upstream OAuth providers
- **Built-in frontend/UI** — riley_auth provides APIs, deployer builds UI
- **Dynamic client registration (RFC 7591)** — CLI/admin API is sufficient for the target deployment profile
- **Webhook secret encryption at rest** — plaintext in DB is a known tradeoff; the DB should be encrypted at the filesystem level
- **Horizontal scaling / distributed session store** — single-instance is sufficient for the target deployment profile
- **Apple Sign-In preset** — can be added as a preset later; Apple's OIDC-ish implementation has enough quirks to deserve its own investigation. Users can configure Apple as a manual OIDC provider in the meantime.
- **Swagger UI** — riley_auth is headless; viewers are the deployer's choice
- **CLI pagination** — `list-users` hardcoded to 100 is a minor annoyance, not a blocker
