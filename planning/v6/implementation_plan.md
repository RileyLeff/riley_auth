# v6 Implementation Plan

## Phase 1: Remove Avatar Storage

| Step | Description |
|------|-------------|
| 1.1 | Remove `StorageConfig` struct, related defaults, and `pub storage: Option<StorageConfig>` from `Config` in `config.rs` |
| 1.2 | Remove `update_user_avatar` function from `db/users.rs` |
| 1.3 | Remove `[storage]` section from `riley_auth.example.toml` |
| 1.4 | Run tests — verify nothing breaks |

## Phase 2: PostgreSQL 14+ Compatibility

| Step | Description |
|------|-------------|
| 2.1 | Replace `DEFAULT uuidv7()` with `DEFAULT gen_random_uuid()` in all migration files |
| 2.2 | Audit all INSERTs in application code (`db/` module). For each INSERT that omits `id`, add explicit `uuid::Uuid::now_v7()` |
| 2.3 | Update test infrastructure (`common/mod.rs`) — ensure test helpers also generate IDs app-side where needed |
| 2.4 | Run full test suite (unit + integration) to verify everything still passes |

## Phase 3: Security Defaults

| Step | Description |
|------|-------------|
| 3.1 | Change `build_cors()` in `server.rs`: empty origins = no CORS layer, `["*"]` = permissive with warning, explicit list = standard CORS |
| 3.2 | Change `default_cookie_prefix()` from `"riley_auth"` to `"auth"` in `config.rs` |
| 3.3 | Make `issuer` required — remove default, add config validation that rejects missing issuer |
| 3.4 | Update `riley_auth.example.toml` to reflect new defaults and document changes |
| 3.5 | Update test infrastructure — set explicit issuer and adjust for new CORS/cookie behavior |
| 3.6 | Run full test suite |

**Review: Phases 1-3** — standard review (grouped, small changes)

## Phase 4: Generic OAuth Provider Pipeline

| Step | Description |
|------|-------------|
| 4.1 | Define new config structs: `ProviderEntry`, `ProfileMapping` in `config.rs`. Replace `OAuthProvidersConfig` fields (`google`, `github`) with `providers: Vec<ProviderEntry>` |
| 4.2 | Define `ResolvedProvider` struct in `oauth.rs`. Implement built-in presets for Google and GitHub with their quirks |
| 4.3 | Implement provider resolution logic: preset detection, OIDC auto-discovery fetch, manual OAuth2 validation |
| 4.4 | Implement generic profile parsing (`parse_profile` using `ProfileMapping`) and generic secondary email endpoint fetch |
| 4.5 | Refactor `oauth.rs` — remove `Provider` enum, refactor `build_auth_url`, `exchange_code`, `fetch_profile` to take `&ResolvedProvider` |
| 4.6 | Refactor auth routes (`routes/auth.rs`) — look up provider from `AppState.providers` instead of parsing `Provider` enum |
| 4.7 | Update `AppState` with `providers: Arc<Vec<ResolvedProvider>>`. Add provider resolution to server startup in `serve()` |
| 4.8 | Update `riley_auth.example.toml` with new `[[oauth.providers]]` format |
| 4.9 | Write unit tests for provider resolution, preset defaults, profile parsing, config validation |
| 4.10 | Update integration tests — adjust test config to new provider format. Run full test suite |

**Review: Phase 4** — exhaustive review (core feature, security-sensitive)

## Phase 5: OpenAPI Documentation (utoipa)

| Step | Description |
|------|-------------|
| 5.1 | Add `utoipa` and `utoipa-axum` dependencies to `riley-auth-api` Cargo.toml |
| 5.2 | Add `#[derive(utoipa::ToSchema)]` to all request/response types across `error.rs`, `routes/auth.rs`, `routes/admin.rs`, `routes/oauth_provider.rs`, `routes/mod.rs` |
| 5.3 | Add `#[utoipa::path(...)]` annotations to all route handlers |
| 5.4 | Assemble `ApiDoc` struct, add `GET /openapi.json` endpoint to router |
| 5.5 | Build and verify the spec is valid JSON, all endpoints documented, all types resolve |

**Review: Phase 5** — standard review (mechanical annotations)

## Phase 6: Documentation

| Step | Description |
|------|-------------|
| 6.1 | Write `README.md` — what/why/features/quickstart/config/CLI/API/deployment/license |
| 6.2 | Write `docs/deployment.md` — requirements, Docker, docker-compose, VPS, first-time setup, key rotation, backup |
| 6.3 | Create production `docker-compose.yml` with Postgres 17 + riley_auth |
| 6.4 | Improve `Dockerfile` — add HEALTHCHECK, install curl in runtime image |
| 6.5 | Final pass on `riley_auth.example.toml` — ensure every section is fully documented |

**Review: Phase 6** — review for accuracy against code
