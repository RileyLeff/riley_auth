use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::config::DatabaseConfig;

// --- Connection ---

pub async fn connect(config: &DatabaseConfig) -> Result<PgPool> {
    let url = config.url.resolve()?;
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .connect(&url)
        .await?;
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
}

// --- User queries ---

pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn find_user_by_username(pool: &PgPool, username: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE lower(username) = lower($1) AND deleted_at IS NULL"
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn create_user(
    pool: &PgPool,
    username: &str,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (username, display_name, avatar_url)
         VALUES ($1, $2, $3)
         RETURNING *"
    )
    .bind(username)
    .bind(display_name)
    .bind(avatar_url)
    .fetch_one(pool)
    .await?;
    Ok(user)
}

pub async fn update_user_display_name(
    pool: &PgPool,
    user_id: Uuid,
    display_name: &str,
) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET display_name = $2, updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING *"
    )
    .bind(user_id)
    .bind(display_name)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::UserNotFound)?;
    Ok(user)
}

pub async fn update_username(
    pool: &PgPool,
    user_id: Uuid,
    new_username: &str,
) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET username = $2, updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING *"
    )
    .bind(user_id)
    .bind(new_username)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::UserNotFound)?;
    Ok(user)
}

pub async fn update_user_avatar(
    pool: &PgPool,
    user_id: Uuid,
    avatar_url: Option<&str>,
) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET avatar_url = $2, updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING *"
    )
    .bind(user_id)
    .bind(avatar_url)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::UserNotFound)?;
    Ok(user)
}

pub async fn soft_delete_user(pool: &PgPool, user_id: Uuid) -> Result<()> {
    // Anonymize: replace username, clear PII, set deleted_at
    let uuid_prefix = &user_id.to_string()[..8];
    sqlx::query(
        "UPDATE users SET
            username = $2,
            display_name = 'Deleted User',
            avatar_url = NULL,
            deleted_at = now(),
            updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL"
    )
    .bind(user_id)
    .bind(format!("deleted_{uuid_prefix}"))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_user_role(
    pool: &PgPool,
    user_id: Uuid,
    role: &str,
) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET role = $2, updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING *"
    )
    .bind(user_id)
    .bind(role)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::UserNotFound)?;
    Ok(user)
}

pub async fn list_users(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<User>> {
    let users = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE deleted_at IS NULL
         ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(users)
}

// --- OAuth link queries ---

pub async fn find_oauth_link(
    pool: &PgPool,
    provider: &str,
    provider_id: &str,
) -> Result<Option<OAuthLink>> {
    let link = sqlx::query_as::<_, OAuthLink>(
        "SELECT * FROM oauth_links WHERE provider = $1 AND provider_id = $2"
    )
    .bind(provider)
    .bind(provider_id)
    .fetch_optional(pool)
    .await?;
    Ok(link)
}

pub async fn find_oauth_links_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Vec<OAuthLink>> {
    let links = sqlx::query_as::<_, OAuthLink>(
        "SELECT * FROM oauth_links WHERE lower(provider_email) = lower($1)"
    )
    .bind(email)
    .fetch_all(pool)
    .await?;
    Ok(links)
}

pub async fn find_oauth_links_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<OAuthLink>> {
    let links = sqlx::query_as::<_, OAuthLink>(
        "SELECT * FROM oauth_links WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(links)
}

pub async fn create_oauth_link(
    pool: &PgPool,
    user_id: Uuid,
    provider: &str,
    provider_id: &str,
    email: Option<&str>,
) -> Result<OAuthLink> {
    let link = sqlx::query_as::<_, OAuthLink>(
        "INSERT INTO oauth_links (user_id, provider, provider_id, provider_email)
         VALUES ($1, $2, $3, $4)
         RETURNING *"
    )
    .bind(user_id)
    .bind(provider)
    .bind(provider_id)
    .bind(email)
    .fetch_one(pool)
    .await?;
    Ok(link)
}

pub async fn delete_oauth_link(
    pool: &PgPool,
    user_id: Uuid,
    provider: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM oauth_links WHERE user_id = $1 AND provider = $2"
    )
    .bind(user_id)
    .bind(provider)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn count_oauth_links(pool: &PgPool, user_id: Uuid) -> Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_links WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

// --- Refresh token queries ---

pub async fn store_refresh_token(
    pool: &PgPool,
    user_id: Uuid,
    client_id: Option<Uuid>,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO refresh_tokens (user_id, client_id, token_hash, expires_at)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(user_id)
    .bind(client_id)
    .bind(token_hash)
    .bind(expires_at)
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

pub async fn delete_refresh_token(pool: &PgPool, token_hash: &str) -> Result<()> {
    sqlx::query("DELETE FROM refresh_tokens WHERE token_hash = $1")
        .bind(token_hash)
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

// --- Username history queries ---

pub async fn record_username_change(
    pool: &PgPool,
    user_id: Uuid,
    old_username: &str,
    held_until: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO username_history (user_id, old_username, held_until)
         VALUES ($1, $2, $3)"
    )
    .bind(user_id)
    .bind(old_username)
    .bind(held_until)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn last_username_change(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<DateTime<Utc>>> {
    let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
        "SELECT changed_at FROM username_history
         WHERE user_id = $1
         ORDER BY changed_at DESC LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}

pub async fn is_username_held(pool: &PgPool, username: &str) -> Result<bool> {
    let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
        "SELECT held_until FROM username_history
         WHERE lower(old_username) = lower($1) AND held_until > now()
         LIMIT 1"
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

// --- Cleanup ---

pub async fn cleanup_expired_tokens(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn cleanup_expired_auth_codes(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM authorization_codes WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
