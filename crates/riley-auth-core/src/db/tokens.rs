use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::Result;
use super::RefreshTokenRow;

// --- Refresh token queries ---

pub async fn store_refresh_token(
    pool: &PgPool,
    user_id: Uuid,
    client_id: Option<Uuid>,
    token_hash: &str,
    expires_at: DateTime<Utc>,
    scopes: &[String],
    user_agent: Option<&str>,
    ip_address: Option<&str>,
    family_id: Uuid,
    nonce: Option<&str>,
    auth_time: Option<i64>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO refresh_tokens (user_id, client_id, token_hash, expires_at, scopes, user_agent, ip_address, family_id, nonce, auth_time)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
    )
    .bind(user_id)
    .bind(client_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(scopes)
    .bind(user_agent)
    .bind(ip_address)
    .bind(family_id)
    .bind(nonce)
    .bind(auth_time)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn find_refresh_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>> {
    let row = sqlx::query_as::<_, RefreshTokenRow>(
        "SELECT * FROM refresh_tokens WHERE token_hash = $1 AND expires_at > now()"
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Atomically consume a client-bound refresh token for rotation.
/// Only consumes tokens that belong to the specified client, preventing
/// session tokens or other clients' tokens from being destroyed when
/// mistakenly sent to the OAuth token endpoint.
pub async fn consume_client_refresh_token(
    pool: &PgPool,
    token_hash: &str,
    client_id: Uuid,
) -> Result<Option<RefreshTokenRow>> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query_as::<_, RefreshTokenRow>(
        "DELETE FROM refresh_tokens
         WHERE token_hash = $1 AND expires_at > now() AND client_id = $2
         RETURNING *"
    )
    .bind(token_hash)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(ref token) = row {
        sqlx::query(
            "INSERT INTO consumed_refresh_tokens (token_hash, family_id)
             VALUES ($1, $2)
             ON CONFLICT (token_hash) DO NOTHING"
        )
        .bind(&token.token_hash)
        .bind(token.family_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(row)
}

/// Atomically consume a session-only refresh token (client_id IS NULL).
/// Rejects client-bound tokens without consuming them, preventing accidental
/// destruction of OAuth client tokens at the session refresh endpoint.
pub async fn consume_session_refresh_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query_as::<_, RefreshTokenRow>(
        "DELETE FROM refresh_tokens
         WHERE token_hash = $1 AND expires_at > now() AND client_id IS NULL
         RETURNING *"
    )
    .bind(token_hash)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(ref token) = row {
        sqlx::query(
            "INSERT INTO consumed_refresh_tokens (token_hash, family_id)
             VALUES ($1, $2)
             ON CONFLICT (token_hash) DO NOTHING"
        )
        .bind(&token.token_hash)
        .bind(token.family_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(row)
}

/// Check if a token hash was already consumed (reuse detection).
/// If found, returns the family_id so the caller can revoke the entire family.
pub async fn check_token_reuse(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<Uuid>> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT family_id FROM consumed_refresh_tokens WHERE token_hash = $1"
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id,)| id))
}

/// Revoke all refresh tokens in a family (used when reuse is detected).
/// Also cleans up consumed token records for the family.
pub async fn revoke_token_family(pool: &PgPool, family_id: Uuid) -> Result<u64> {
    let mut tx = pool.begin().await?;

    let result = sqlx::query("DELETE FROM refresh_tokens WHERE family_id = $1")
        .bind(family_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM consumed_refresh_tokens WHERE family_id = $1")
        .bind(family_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(result.rows_affected())
}

pub async fn delete_refresh_token(pool: &PgPool, token_hash: &str) -> Result<()> {
    sqlx::query("DELETE FROM refresh_tokens WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete a refresh token only if it belongs to the specified client.
pub async fn delete_refresh_token_for_client(
    pool: &PgPool,
    token_hash: &str,
    client_id: Uuid,
) -> Result<()> {
    sqlx::query("DELETE FROM refresh_tokens WHERE token_hash = $1 AND client_id = $2")
        .bind(token_hash)
        .bind(client_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_all_refresh_tokens(pool: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn touch_refresh_token(pool: &PgPool, token_hash: &str) -> Result<()> {
    sqlx::query("UPDATE refresh_tokens SET last_used_at = now() WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

// --- Session queries ---

/// A session is a session-scoped refresh token (client_id IS NULL).
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SessionRow {
    pub id: Uuid,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// List active sessions for a user (non-expired, session-scoped refresh tokens).
pub async fn list_sessions(pool: &PgPool, user_id: Uuid) -> Result<Vec<SessionRow>> {
    let rows = sqlx::query_as::<_, SessionRow>(
        "SELECT id, user_agent, ip_address, created_at, last_used_at
         FROM refresh_tokens
         WHERE user_id = $1 AND client_id IS NULL AND expires_at > now()
         ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Revoke a specific session. Returns true if a row was deleted.
pub async fn revoke_session(pool: &PgPool, session_id: Uuid, user_id: Uuid) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM refresh_tokens WHERE id = $1 AND user_id = $2 AND client_id IS NULL"
    )
    .bind(session_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
