use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, FromRow, PgPool};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::config::DatabaseConfig;

mod auth_codes;
mod clients;
mod oauth_links;
mod tokens;
mod users;
mod webhooks;

pub use auth_codes::*;
pub use clients::*;
pub use oauth_links::*;
pub use tokens::*;
pub use users::*;
pub use webhooks::*;

// --- Connection ---

pub async fn connect(config: &DatabaseConfig) -> Result<PgPool> {
    let url = config.url.resolve()?;
    let mut opts = PgPoolOptions::new().max_connections(config.max_connections);

    if let Some(schema) = &config.schema {
        // Validate schema name to prevent SQL injection — only allow safe identifiers.
        if schema.is_empty()
            || schema.starts_with(|c: char| c.is_ascii_digit())
            || !schema.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(Error::Config(format!(
                "invalid schema name '{}': must match [a-zA-Z_][a-zA-Z0-9_]*",
                schema
            )));
        }
        let schema = schema.clone();
        opts = opts.after_connect(move |conn, _meta| {
            let schema = schema.clone();
            Box::pin(async move {
                conn.execute(format!("SET search_path TO \"{}\"", schema).as_str())
                    .await?;
                Ok(())
            })
        });
    }

    let pool = opts.connect(&url).await?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("../../migrations").run(pool).await?;
    Ok(())
}

// --- Models ---

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct OAuthLink {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_id: String,
    pub provider_email: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct RefreshTokenRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: Option<Uuid>,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub family_id: Uuid,
    pub nonce: Option<String>,
    pub auth_time: Option<i64>,
}

// --- Cleanup ---

/// Delete expired refresh tokens in batches of 1000 to avoid long locks.
pub async fn cleanup_expired_tokens(pool: &PgPool) -> Result<u64> {
    let mut total = 0u64;
    loop {
        let result = sqlx::query(
            "DELETE FROM refresh_tokens WHERE id IN (
                SELECT id FROM refresh_tokens WHERE expires_at <= now() LIMIT 1000
            )"
        )
        .execute(pool)
        .await?;
        let affected = result.rows_affected();
        total += affected;
        if affected < 1000 { break; }
    }
    Ok(total)
}

/// Delete expired authorization codes in batches of 1000.
pub async fn cleanup_expired_auth_codes(pool: &PgPool) -> Result<u64> {
    let mut total = 0u64;
    loop {
        let result = sqlx::query(
            "DELETE FROM authorization_codes WHERE id IN (
                SELECT id FROM authorization_codes WHERE expires_at <= now() LIMIT 1000
            )"
        )
        .execute(pool)
        .await?;
        let affected = result.rows_affected();
        total += affected;
        if affected < 1000 { break; }
    }
    Ok(total)
}

/// Clean up consumed refresh token records older than the given cutoff.
/// The cutoff should be ~2x the refresh token TTL — if the attacker hasn't
/// replayed the stolen token within that window, the family has naturally expired.
/// Batched to 1000 per iteration.
pub async fn cleanup_consumed_refresh_tokens(
    pool: &PgPool,
    older_than: DateTime<Utc>,
) -> Result<u64> {
    let mut total = 0u64;
    loop {
        let result = sqlx::query(
            "DELETE FROM consumed_refresh_tokens WHERE token_hash IN (
                SELECT token_hash FROM consumed_refresh_tokens WHERE consumed_at < $1 LIMIT 1000
            )"
        )
        .bind(older_than)
        .execute(pool)
        .await?;
        let affected = result.rows_affected();
        total += affected;
        if affected < 1000 { break; }
    }
    Ok(total)
}

/// Clean up old webhook delivery records beyond the retention period.
/// Batched to 1000 per iteration.
pub async fn cleanup_webhook_deliveries(pool: &PgPool, retention_days: i64) -> Result<u64> {
    let mut total = 0u64;
    loop {
        let result = sqlx::query(
            "DELETE FROM webhook_deliveries WHERE id IN (
                SELECT id FROM webhook_deliveries
                WHERE attempted_at < now() - make_interval(days => $1::int)
                LIMIT 1000
            )"
        )
        .bind(retention_days as i32)
        .execute(pool)
        .await?;
        let affected = result.rows_affected();
        total += affected;
        if affected < 1000 { break; }
    }
    Ok(total)
}

/// Clean up expired consent requests in batches of 1000.
pub async fn cleanup_expired_consent_requests(pool: &PgPool) -> Result<u64> {
    let mut total = 0u64;
    loop {
        let result = sqlx::query(
            "DELETE FROM consent_requests WHERE id IN (
                SELECT id FROM consent_requests WHERE expires_at <= now() LIMIT 1000
            )"
        )
        .execute(pool)
        .await?;
        let affected = result.rows_affected();
        total += affected;
        if affected < 1000 { break; }
    }
    Ok(total)
}
