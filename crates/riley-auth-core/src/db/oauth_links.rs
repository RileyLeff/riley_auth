use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{Error, Result};
use super::OAuthLink;

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
        "SELECT * FROM oauth_links WHERE user_id = $1 ORDER BY created_at"
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
    email_verified: bool,
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
        "INSERT INTO oauth_links (id, user_id, provider, provider_id, provider_email, email_verified)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *"
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(provider)
    .bind(provider_id)
    .bind(email)
    .bind(email_verified)
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
