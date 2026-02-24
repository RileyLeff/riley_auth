use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::Result;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct OAuthClient {
    pub id: Uuid,
    pub name: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret_hash: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub auto_approve: bool,
    pub created_at: DateTime<Utc>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
}

pub async fn find_client_by_client_id(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<OAuthClient>> {
    let client = sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE client_id = $1"
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?;
    Ok(client)
}

pub async fn find_client_by_id(pool: &PgPool, id: Uuid) -> Result<Option<OAuthClient>> {
    let client = sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(client)
}

pub async fn list_clients(pool: &PgPool) -> Result<Vec<OAuthClient>> {
    let clients = sqlx::query_as::<_, OAuthClient>(
        "SELECT * FROM oauth_clients ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?;
    Ok(clients)
}

pub async fn create_client(
    pool: &PgPool,
    name: &str,
    client_id: &str,
    client_secret_hash: &str,
    redirect_uris: &[String],
    allowed_scopes: &[String],
    auto_approve: bool,
) -> Result<OAuthClient> {
    create_client_full(pool, name, client_id, client_secret_hash, redirect_uris, allowed_scopes, auto_approve, None, false).await
}

pub async fn create_client_full(
    pool: &PgPool,
    name: &str,
    client_id: &str,
    client_secret_hash: &str,
    redirect_uris: &[String],
    allowed_scopes: &[String],
    auto_approve: bool,
    backchannel_logout_uri: Option<&str>,
    backchannel_logout_session_required: bool,
) -> Result<OAuthClient> {
    let client = sqlx::query_as::<_, OAuthClient>(
        "INSERT INTO oauth_clients (name, client_id, client_secret_hash, redirect_uris, allowed_scopes, auto_approve, backchannel_logout_uri, backchannel_logout_session_required)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *"
    )
    .bind(name)
    .bind(client_id)
    .bind(client_secret_hash)
    .bind(redirect_uris)
    .bind(allowed_scopes)
    .bind(auto_approve)
    .bind(backchannel_logout_uri)
    .bind(backchannel_logout_session_required)
    .fetch_one(pool)
    .await?;
    Ok(client)
}

pub async fn update_client_backchannel_logout(
    pool: &PgPool,
    id: Uuid,
    backchannel_logout_uri: Option<&str>,
    backchannel_logout_session_required: bool,
) -> Result<Option<OAuthClient>> {
    let client = sqlx::query_as::<_, OAuthClient>(
        "UPDATE oauth_clients
         SET backchannel_logout_uri = $2, backchannel_logout_session_required = $3
         WHERE id = $1
         RETURNING *"
    )
    .bind(id)
    .bind(backchannel_logout_uri)
    .bind(backchannel_logout_session_required)
    .fetch_optional(pool)
    .await?;
    Ok(client)
}

/// Find all clients with a backchannel_logout_uri that have active refresh tokens
/// for the given user. Used to dispatch back-channel logout notifications.
pub async fn find_backchannel_logout_clients_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<OAuthClient>> {
    let clients = sqlx::query_as::<_, OAuthClient>(
        "SELECT DISTINCT ON (c.id) c.*
         FROM oauth_clients c
         INNER JOIN refresh_tokens rt ON rt.client_id = c.id
         WHERE rt.user_id = $1
           AND c.backchannel_logout_uri IS NOT NULL
           AND rt.expires_at > now()"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(clients)
}

pub async fn delete_client(pool: &PgPool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
