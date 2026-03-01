use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::RngCore;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{Error, Result};
use super::User;

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
    let id = Uuid::now_v7();
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (id, username, display_name, avatar_url)
         VALUES ($1, $2, $3, $4)
         RETURNING *"
    )
    .bind(id)
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
    display_name: Option<&str>,
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

    // Delete any pending consent requests
    sqlx::query("DELETE FROM consent_requests WHERE user_id = $1")
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

    // Scrub PII from webhook delivery payloads referencing this user.
    // Delivery records store enveloped payloads: {"id":..., "event":..., "data": {flat payload}}.
    // The user_id lives under the "data" key.
    sqlx::query(
        "UPDATE webhook_deliveries SET payload = jsonb_set(payload, '{data}', '{\"scrubbed\": true}')
         WHERE payload->'data'->>'user_id' = $1::text"
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    // Also scrub pending outbox entries (flat payloads: {"user_id": ...})
    sqlx::query(
        "UPDATE webhook_outbox SET payload = '{\"scrubbed\": true}'::jsonb
         WHERE payload->>'user_id' = $1::text"
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    // Anonymize: replace username with a random, unregisterable placeholder.
    // Uses 12 random bytes (16 base64 chars) → "_" + 16 chars = 17 chars total.
    // The "_" prefix is blocked by the default username regex (first char must be a letter),
    // preventing anyone from registering a collision. Random bytes (not user_id-derived)
    // prevent confirming whether a known UUID was deleted by predicting the placeholder.
    let mut random_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut random_bytes);
    let deleted_name = format!("_{}", URL_SAFE_NO_PAD.encode(&random_bytes));
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

// --- Username history queries ---

pub async fn record_username_change(
    pool: &PgPool,
    user_id: Uuid,
    old_username: &str,
    held_until: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO username_history (id, user_id, old_username, held_until)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(Uuid::now_v7())
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

pub async fn is_username_held(pool: &PgPool, username: &str, requesting_user_id: Uuid) -> Result<bool> {
    let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
        "SELECT held_until FROM username_history
         WHERE lower(old_username) = lower($1) AND held_until > now()
           AND user_id != $2
         LIMIT 1"
    )
    .bind(username)
    .bind(requesting_user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

// --- Transactional user operations ---

/// Create a user and OAuth link atomically.
pub async fn create_user_with_link(
    pool: &PgPool,
    username: &str,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
    provider: &str,
    provider_id: &str,
    email: Option<&str>,
    email_verified: bool,
) -> Result<User> {
    let mut tx = pool.begin().await?;

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (id, username, display_name, avatar_url)
         VALUES ($1, $2, $3, $4)
         RETURNING *"
    )
    .bind(Uuid::now_v7())
    .bind(username)
    .bind(display_name)
    .bind(avatar_url)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO oauth_links (id, user_id, provider, provider_id, provider_email, email_verified)
         VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(Uuid::now_v7())
    .bind(user.id)
    .bind(provider)
    .bind(provider_id)
    .bind(email)
    .bind(email_verified)
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
        "INSERT INTO username_history (id, user_id, old_username, held_until)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(Uuid::now_v7())
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

// --- Reserved usernames (admin-managed via DB) ---

pub async fn list_reserved_usernames(pool: &PgPool) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT name FROM reserved_usernames ORDER BY name"
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn add_reserved_username(pool: &PgPool, name: &str) -> Result<bool> {
    let result = sqlx::query(
        "INSERT INTO reserved_usernames (name) VALUES (lower($1)) ON CONFLICT DO NOTHING"
    )
    .bind(name)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn remove_reserved_username(pool: &PgPool, name: &str) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM reserved_usernames WHERE name = lower($1)"
    )
    .bind(name)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn is_username_reserved_in_db(pool: &PgPool, username: &str) -> Result<bool> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT name FROM reserved_usernames WHERE name = lower($1)"
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}
