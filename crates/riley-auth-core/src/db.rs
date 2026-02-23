use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, FromRow, PgPool};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::config::DatabaseConfig;

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
                conn.execute(format!("SET search_path TO {}", schema).as_str())
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

/// Result of attempting to soft-delete a user.
pub enum DeleteUserResult {
    /// Successfully deleted.
    Deleted,
    /// Cannot delete the last admin.
    LastAdmin,
    /// User not found (or already deleted).
    NotFound,
}

/// Soft-delete a user: revoke all tokens, delete linked data, anonymize.
/// Prevents deleting the last admin. All operations are atomic within a single transaction.
/// Uses a single lock query with consistent ORDER BY to prevent deadlocks.
pub async fn soft_delete_user(pool: &PgPool, user_id: Uuid) -> Result<DeleteUserResult> {
    let mut tx = pool.begin().await?;

    // Lock the target user AND all admin rows in a single query with consistent
    // id ordering to prevent deadlocks between concurrent delete/demote operations.
    let locked_rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, role FROM users
         WHERE (id = $1 OR role = 'admin') AND deleted_at IS NULL
         ORDER BY id FOR UPDATE"
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;

    // Find the target user in the result set
    let target = locked_rows.iter().find(|(id, _)| *id == user_id);
    let Some((_, role)) = target else {
        return Ok(DeleteUserResult::NotFound);
    };

    if role == "admin" {
        let admin_count = locked_rows.iter().filter(|(_, r)| r == "admin").count();
        if admin_count <= 1 {
            return Ok(DeleteUserResult::LastAdmin);
        }
    }

    // Revoke all refresh tokens
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // Revoke any outstanding authorization codes
    sqlx::query("DELETE FROM authorization_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // Delete OAuth links so the provider identity can be re-used
    sqlx::query("DELETE FROM oauth_links WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // Clean up username history (PII)
    sqlx::query("DELETE FROM username_history WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // Anonymize: replace username with a compact, unregisterable placeholder.
    // Format: "_" + base64url(uuid_bytes) = 23 chars, fits within default max_length (24).
    // The "_" prefix is blocked by the default username regex (first char must be a letter),
    // preventing anyone from registering a collision.
    let deleted_name = format!("_{}", URL_SAFE_NO_PAD.encode(user_id.as_bytes()));
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
    .bind(deleted_name)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(DeleteUserResult::Deleted)
}

/// Result of attempting to update a user's role.
pub enum RoleUpdateResult {
    /// Successfully updated.
    Updated(User),
    /// Would leave zero admins — rejected.
    LastAdmin,
    /// Target user not found.
    NotFound,
}

/// Update a user's role, preventing last-admin lockout.
/// Uses a single `SELECT FOR UPDATE` with consistent `ORDER BY id` to prevent
/// deadlocks with concurrent role changes and soft-deletes.
pub async fn update_user_role(
    pool: &PgPool,
    user_id: Uuid,
    new_role: &str,
) -> Result<RoleUpdateResult> {
    let mut tx = pool.begin().await?;

    if new_role != "admin" {
        // Lock the target user AND all admin rows in a single query with
        // consistent id ordering to prevent deadlocks between concurrent
        // demote/delete operations.
        let locked_rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, role FROM users
             WHERE (id = $1 OR role = 'admin') AND deleted_at IS NULL
             ORDER BY id FOR UPDATE"
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;

        let target = locked_rows.iter().find(|(id, _)| *id == user_id);
        let Some((_, current_role)) = target else {
            return Ok(RoleUpdateResult::NotFound);
        };

        if current_role == "admin" {
            let admin_count = locked_rows.iter().filter(|(_, r)| r == "admin").count();
            if admin_count <= 1 {
                return Ok(RoleUpdateResult::LastAdmin);
            }
        }
    }

    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET role = $2, updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING *"
    )
    .bind(user_id)
    .bind(new_role)
    .fetch_optional(&mut *tx)
    .await?;

    tx.commit().await?;

    match user {
        Some(u) => Ok(RoleUpdateResult::Updated(u)),
        None => Ok(RoleUpdateResult::NotFound),
    }
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

/// Find an OAuth link, only for active (non-deleted) users.
pub async fn find_oauth_link(
    pool: &PgPool,
    provider: &str,
    provider_id: &str,
) -> Result<Option<OAuthLink>> {
    let link = sqlx::query_as::<_, OAuthLink>(
        "SELECT ol.* FROM oauth_links ol
         JOIN users u ON u.id = ol.user_id
         WHERE ol.provider = $1 AND ol.provider_id = $2 AND u.deleted_at IS NULL"
    )
    .bind(provider)
    .bind(provider_id)
    .fetch_optional(pool)
    .await?;
    Ok(link)
}

/// Find OAuth links by email, filtering to active (non-deleted) users only.
pub async fn find_oauth_links_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Vec<OAuthLink>> {
    let links = sqlx::query_as::<_, OAuthLink>(
        "SELECT ol.* FROM oauth_links ol
         JOIN users u ON u.id = ol.user_id
         WHERE lower(ol.provider_email) = lower($1) AND u.deleted_at IS NULL"
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

/// Create an OAuth link, atomically verifying the user is active (not soft-deleted).
/// Uses `SELECT ... FOR SHARE` to lock the user row, serializing against
/// `soft_delete_user`'s `FOR UPDATE` lock. This prevents the READ COMMITTED
/// snapshot race where an INSERT could succeed against a concurrently-deleted user.
/// `FOR SHARE` (not `FOR UPDATE`) allows concurrent link creations to proceed in parallel.
pub async fn create_oauth_link(
    pool: &PgPool,
    user_id: Uuid,
    provider: &str,
    provider_id: &str,
    email: Option<&str>,
) -> Result<OAuthLink> {
    let mut tx = pool.begin().await?;

    // Lock the user row with FOR SHARE — blocks if soft_delete_user holds FOR UPDATE,
    // and prevents soft_delete_user from acquiring FOR UPDATE while we hold this lock.
    let user_exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL FOR SHARE"
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;

    if user_exists.is_none() {
        return Err(Error::UserNotFound);
    }

    let link = sqlx::query_as::<_, OAuthLink>(
        "INSERT INTO oauth_links (user_id, provider, provider_id, provider_email)
         VALUES ($1, $2, $3, $4)
         RETURNING *"
    )
    .bind(user_id)
    .bind(provider)
    .bind(provider_id)
    .bind(email)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(link)
}

/// Result of attempting to unlink a provider.
pub enum UnlinkResult {
    /// Successfully deleted the link.
    Deleted,
    /// Cannot delete — this is the user's only provider.
    LastProvider,
    /// No link found for this provider.
    NotFound,
}

/// Delete an OAuth link only if the user has more than one.
/// Uses `SELECT FOR UPDATE` to serialize concurrent unlink attempts.
pub async fn delete_oauth_link_if_not_last(
    pool: &PgPool,
    user_id: Uuid,
    provider: &str,
) -> Result<UnlinkResult> {
    let mut tx = pool.begin().await?;

    // Lock all links for this user to prevent concurrent unlinks
    let links: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, provider FROM oauth_links WHERE user_id = $1 FOR UPDATE"
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;

    // Check if the target provider link exists
    let same_provider_count = links.iter().filter(|(_, p)| p == provider).count();
    if same_provider_count == 0 {
        return Ok(UnlinkResult::NotFound);
    }

    // Ensure at least one link remains after removing all links for this provider
    if links.len() - same_provider_count < 1 {
        return Ok(UnlinkResult::LastProvider);
    }

    // Safe to delete
    sqlx::query("DELETE FROM oauth_links WHERE user_id = $1 AND provider = $2")
        .bind(user_id)
        .bind(provider)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(UnlinkResult::Deleted)
}

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
) -> Result<()> {
    sqlx::query(
        "INSERT INTO refresh_tokens (user_id, client_id, token_hash, expires_at, scopes, user_agent, ip_address)
         VALUES ($1, $2, $3, $4, $5, $6, $7)"
    )
    .bind(user_id)
    .bind(client_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(scopes)
    .bind(user_agent)
    .bind(ip_address)
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

/// Atomically find and delete a refresh token (for rotation).
/// Returns None if the token doesn't exist or is expired.
pub async fn consume_refresh_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>> {
    let row = sqlx::query_as::<_, RefreshTokenRow>(
        "DELETE FROM refresh_tokens
         WHERE token_hash = $1 AND expires_at > now()
         RETURNING *"
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

// --- OAuth client queries ---

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct OAuthClient {
    pub id: Uuid,
    pub name: String,
    pub client_id: String,
    pub client_secret_hash: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub auto_approve: bool,
    pub created_at: DateTime<Utc>,
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
    let client = sqlx::query_as::<_, OAuthClient>(
        "INSERT INTO oauth_clients (name, client_id, client_secret_hash, redirect_uris, allowed_scopes, auto_approve)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *"
    )
    .bind(name)
    .bind(client_id)
    .bind(client_secret_hash)
    .bind(redirect_uris)
    .bind(allowed_scopes)
    .bind(auto_approve)
    .fetch_one(pool)
    .await?;
    Ok(client)
}

pub async fn delete_client(pool: &PgPool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

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
    expires_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO authorization_codes (code_hash, user_id, client_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(code_hash)
    .bind(user_id)
    .bind(client_id)
    .bind(redirect_uri)
    .bind(scopes)
    .bind(code_challenge)
    .bind(code_challenge_method)
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

// --- Transactional operations ---

/// Create a user and OAuth link atomically.
pub async fn create_user_with_link(
    pool: &PgPool,
    username: &str,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
    provider: &str,
    provider_id: &str,
    email: Option<&str>,
) -> Result<User> {
    let mut tx = pool.begin().await?;

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (username, display_name, avatar_url)
         VALUES ($1, $2, $3)
         RETURNING *"
    )
    .bind(username)
    .bind(display_name)
    .bind(avatar_url)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO oauth_links (user_id, provider, provider_id, provider_email)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(user.id)
    .bind(provider)
    .bind(provider_id)
    .bind(email)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(user)
}

/// Change username with history tracking, atomically.
pub async fn change_username(
    pool: &PgPool,
    user_id: Uuid,
    old_username: &str,
    new_username: &str,
    held_until: DateTime<Utc>,
) -> Result<User> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT INTO username_history (user_id, old_username, held_until)
         VALUES ($1, $2, $3)"
    )
    .bind(user_id)
    .bind(old_username)
    .bind(held_until)
    .execute(&mut *tx)
    .await?;

    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET username = $2, updated_at = now()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING *"
    )
    .bind(user_id)
    .bind(new_username)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::UserNotFound)?;

    tx.commit().await?;
    Ok(user)
}

/// Find the current role for a user (fresh from DB, not from JWT claims).
pub async fn get_user_role(pool: &PgPool, user_id: Uuid) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM users WHERE id = $1 AND deleted_at IS NULL"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
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
