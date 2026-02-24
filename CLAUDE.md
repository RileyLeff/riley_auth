## Slack

When using slack_notify or slack_ask, use channel `C0AG97SATGB`.

## Project Structure

Cargo workspace with three crates:
- `riley-auth-core` — config, db (sqlx/postgres), JWT (ES256/RS256), OAuth flows, error types
- `riley-auth-api` — Axum HTTP server, route handlers, middleware
- `riley-auth-cli` — CLI binary (clap), serves API and manages setup

## Conventions

- Rust edition 2024, MSRV 1.88
- PostgreSQL 14+ (`gen_random_uuid()` for DB defaults, app-side `Uuid::now_v7()` for new rows), `timestamptz` for all timestamps
- ES256 (default) and RS256 asymmetric JWTs — private key signs, public key verifies via `/.well-known/jwks.json`
- All config is TOML, loaded with the same resolution pattern as riley_cms
- This is a general-purpose library, not "Riley's auth" — APIs and config should make sense to anyone

## Architecture

See `planning/soul.md` for project philosophy.
See `planning/v6/architecture.md` for the current implementation plan.
