use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::Result;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Webhook {
    pub id: Uuid,
    pub client_id: Option<Uuid>,
    pub url: String,
    pub events: Vec<String>,
    #[serde(skip_serializing)]
    pub secret: String,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status_code: Option<i16>,
    pub error: Option<String>,
    pub attempted_at: DateTime<Utc>,
}

pub async fn create_webhook(
    pool: &PgPool,
    client_id: Option<Uuid>,
    url: &str,
    events: &[String],
    secret: &str,
) -> Result<Webhook> {
    let row = sqlx::query_as::<_, Webhook>(
        "INSERT INTO webhooks (id, client_id, url, events, secret)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *"
    )
    .bind(Uuid::now_v7())
    .bind(client_id)
    .bind(url)
    .bind(events)
    .bind(secret)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

pub async fn list_webhooks(pool: &PgPool) -> Result<Vec<Webhook>> {
    let rows = sqlx::query_as::<_, Webhook>(
        "SELECT * FROM webhooks ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn find_webhook(pool: &PgPool, id: Uuid) -> Result<Option<Webhook>> {
    let row = sqlx::query_as::<_, Webhook>(
        "SELECT * FROM webhooks WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn delete_webhook(pool: &PgPool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM webhooks WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Find all active webhooks subscribed to a given event type.
///
/// When `event_client_id` is `Some`, only returns webhooks with a matching
/// `client_id` or with NULL `client_id` (global webhooks). When `None`, returns
/// all matching webhooks regardless of their `client_id`.
pub async fn find_webhooks_for_event(
    pool: &PgPool,
    event_type: &str,
    event_client_id: Option<Uuid>,
) -> Result<Vec<Webhook>> {
    let rows = match event_client_id {
        Some(cid) => {
            sqlx::query_as::<_, Webhook>(
                "SELECT * FROM webhooks WHERE active = true AND $1 = ANY(events) AND (client_id IS NULL OR client_id = $2)"
            )
            .bind(event_type)
            .bind(cid)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, Webhook>(
                "SELECT * FROM webhooks WHERE active = true AND $1 = ANY(events)"
            )
            .bind(event_type)
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows)
}

pub async fn record_webhook_delivery(
    pool: &PgPool,
    webhook_id: Uuid,
    event_type: &str,
    payload: &serde_json::Value,
    status_code: Option<i16>,
    error: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status_code, error)
         VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(Uuid::now_v7())
    .bind(webhook_id)
    .bind(event_type)
    .bind(payload)
    .bind(status_code)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_webhook_deliveries(
    pool: &PgPool,
    webhook_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<WebhookDelivery>> {
    let rows = sqlx::query_as::<_, WebhookDelivery>(
        "SELECT * FROM webhook_deliveries
         WHERE webhook_id = $1
         ORDER BY attempted_at DESC
         LIMIT $2 OFFSET $3"
    )
    .bind(webhook_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// --- Webhook Outbox ---

#[derive(Debug, FromRow)]
pub struct OutboxEntry {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub attempts: i32,
    pub max_attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Enqueue webhook events into the outbox for all matching webhooks.
/// Uses a single atomic INSERT ... SELECT to ensure all-or-nothing enqueue.
/// Returns the number of outbox entries created.
pub async fn enqueue_webhook_events(
    pool: &PgPool,
    event_type: &str,
    payload: &serde_json::Value,
    max_attempts: u32,
    event_client_id: Option<Uuid>,
) -> Result<u64> {
    let result = match event_client_id {
        Some(cid) => {
            sqlx::query(
                "INSERT INTO webhook_outbox (webhook_id, event_type, payload, max_attempts)
                 SELECT id, $1, $2, $3
                 FROM webhooks
                 WHERE active = true AND $1 = ANY(events) AND (client_id IS NULL OR client_id = $4)"
            )
            .bind(event_type)
            .bind(payload)
            .bind(max_attempts as i32)
            .bind(cid)
            .execute(pool)
            .await?
        }
        None => {
            sqlx::query(
                "INSERT INTO webhook_outbox (webhook_id, event_type, payload, max_attempts)
                 SELECT id, $1, $2, $3
                 FROM webhooks
                 WHERE active = true AND $1 = ANY(events)"
            )
            .bind(event_type)
            .bind(payload)
            .bind(max_attempts as i32)
            .execute(pool)
            .await?
        }
    };

    Ok(result.rows_affected())
}

/// Atomically claim pending outbox entries for delivery by transitioning them
/// to 'processing' status. Uses a CTE with FOR UPDATE SKIP LOCKED to prevent
/// duplicate delivery across concurrent workers.
pub async fn claim_pending_outbox_entries(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<OutboxEntry>> {
    let rows = sqlx::query_as::<_, OutboxEntry>(
        "WITH claimed AS (
             SELECT id FROM webhook_outbox
             WHERE status = 'pending' AND next_attempt_at <= now()
             ORDER BY next_attempt_at
             LIMIT $1
             FOR UPDATE SKIP LOCKED
         )
         UPDATE webhook_outbox
         SET status = 'processing'
         FROM claimed
         WHERE webhook_outbox.id = claimed.id
         RETURNING webhook_outbox.*"
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Mark an outbox entry as delivered (only if currently processing).
pub async fn mark_outbox_delivered(pool: &PgPool, id: Uuid) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE webhook_outbox SET status = 'delivered' WHERE id = $1 AND status = 'processing'"
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Mark an outbox entry as failed (only if currently processing).
pub async fn mark_outbox_failed(pool: &PgPool, id: Uuid, error: &str) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE webhook_outbox SET status = 'failed', last_error = $2 WHERE id = $1 AND status = 'processing'"
    )
    .bind(id)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Record a failed delivery attempt: increment attempts, set next retry time
/// with exponential backoff (10s, 30s, 90s, 270s, 810s), and return to pending.
pub async fn record_outbox_attempt(
    pool: &PgPool,
    id: Uuid,
    error: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE webhook_outbox
         SET status = 'pending',
             attempts = attempts + 1,
             last_error = $2,
             next_attempt_at = now() + (10 * pow(3, attempts)) * interval '1 second'
         WHERE id = $1 AND status = 'processing'"
    )
    .bind(id)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Cleanup delivered and failed outbox entries older than the given retention.
/// Batched to 1000 per iteration.
pub async fn cleanup_webhook_outbox(pool: &PgPool, retention_days: i64) -> Result<u64> {
    let mut total = 0u64;
    loop {
        let result = sqlx::query(
            "DELETE FROM webhook_outbox WHERE id IN (
                SELECT id FROM webhook_outbox
                WHERE status IN ('delivered', 'failed')
                AND created_at < now() - make_interval(days => $1::int)
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

/// Reset outbox entries stuck in "processing" status back to "pending".
/// Entries are considered stuck if they've been in "processing" longer than
/// `timeout_secs`. This handles ungraceful server crashes during delivery.
pub async fn reset_stuck_outbox_entries(pool: &PgPool, timeout_secs: u64) -> Result<u64> {
    let result = sqlx::query(
        "UPDATE webhook_outbox
         SET status = 'pending', next_attempt_at = now()
         WHERE status = 'processing'
           AND next_attempt_at < now() - make_interval(secs => $1::double precision)"
    )
    .bind(timeout_secs as f64)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
