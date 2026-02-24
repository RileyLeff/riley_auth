use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::Result;

// --- Authorization code queries ---

#[derive(Debug, Clone, FromRow)]
pub struct AuthorizationCodeRow {
    pub id: Uuid,
    pub code_hash: String,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used: bool,
}

pub async fn store_authorization_code(
    pool: &PgPool,
    code_hash: &str,
    user_id: Uuid,
    client_id: Uuid,
    redirect_uri: &str,
    scopes: &[String],
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
    nonce: Option<&str>,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO authorization_codes (code_hash, user_id, client_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    )
    .bind(code_hash)
    .bind(user_id)
    .bind(client_id)
    .bind(redirect_uri)
    .bind(scopes)
    .bind(code_challenge)
    .bind(code_challenge_method)
    .bind(nonce)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Atomically find and consume an authorization code.
/// Returns None if the code doesn't exist, is expired, or was already used.
pub async fn consume_authorization_code(
    pool: &PgPool,
    code_hash: &str,
) -> Result<Option<AuthorizationCodeRow>> {
    let row = sqlx::query_as::<_, AuthorizationCodeRow>(
        "UPDATE authorization_codes SET used = true
         WHERE code_hash = $1 AND expires_at > now() AND used = false
         RETURNING *"
    )
    .bind(code_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

// --- Consent request queries ---

#[derive(Debug, Clone, FromRow)]
pub struct ConsentRequestRow {
    pub id: Uuid,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub async fn store_consent_request(
    pool: &PgPool,
    client_id: Uuid,
    user_id: Uuid,
    scopes: &[String],
    redirect_uri: &str,
    state: Option<&str>,
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
    nonce: Option<&str>,
    expires_at: DateTime<Utc>,
) -> Result<Uuid> {
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO consent_requests (client_id, user_id, scopes, redirect_uri, state, code_challenge, code_challenge_method, nonce, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id"
    )
    .bind(client_id)
    .bind(user_id)
    .bind(scopes)
    .bind(redirect_uri)
    .bind(state)
    .bind(code_challenge)
    .bind(code_challenge_method)
    .bind(nonce)
    .bind(expires_at)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Find a consent request by ID, only if not expired (read-only, for GET).
pub async fn find_consent_request(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<ConsentRequestRow>> {
    let row = sqlx::query_as::<_, ConsentRequestRow>(
        "SELECT * FROM consent_requests WHERE id = $1 AND expires_at > now()"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Atomically consume a consent request by deleting it and returning the row.
/// Returns None if the consent request does not exist, is expired, belongs to
/// a different user, or was already consumed by a concurrent request.
/// The user_id check is part of the atomic DELETE to prevent a wrong user from
/// destroying another user's consent request.
pub async fn consume_consent_request(
    pool: &PgPool,
    id: Uuid,
    user_id: Uuid,
) -> Result<Option<ConsentRequestRow>> {
    let row = sqlx::query_as::<_, ConsentRequestRow>(
        "DELETE FROM consent_requests WHERE id = $1 AND user_id = $2 AND expires_at > now() RETURNING *"
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Delete a consent request (for cleanup / soft-delete).
pub async fn delete_consent_request(pool: &PgPool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM consent_requests WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
