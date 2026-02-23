use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use tracing::{info, warn};

use crate::db;

// --- Event type constants ---

pub const USER_CREATED: &str = "user.created";
pub const USER_DELETED: &str = "user.deleted";
pub const USER_UPDATED: &str = "user.updated";
pub const USER_USERNAME_CHANGED: &str = "user.username_changed";
pub const USER_ROLE_CHANGED: &str = "user.role_changed";
pub const SESSION_CREATED: &str = "session.created";
pub const LINK_CREATED: &str = "link.created";
pub const LINK_DELETED: &str = "link.deleted";

pub const ALL_EVENT_TYPES: &[&str] = &[
    USER_CREATED,
    USER_DELETED,
    USER_UPDATED,
    USER_USERNAME_CHANGED,
    USER_ROLE_CHANGED,
    SESSION_CREATED,
    LINK_CREATED,
    LINK_DELETED,
];

/// Returns true if the given string is a valid webhook event type.
pub fn is_valid_event_type(event_type: &str) -> bool {
    ALL_EVENT_TYPES.contains(&event_type)
}

// --- HMAC signing ---

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 of `payload` using `secret`, returned as a hex string.
pub fn sign_payload(secret: &str, payload: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

// --- Dispatch (outbox-based) ---

/// Enqueue a webhook event for all matching subscribers via the outbox.
///
/// Events are written to the database; a background worker delivers them.
/// This replaces the old fire-and-forget dispatch with durable delivery.
pub fn dispatch_event(pool: PgPool, event_type: &str, payload: serde_json::Value, max_retry_attempts: u32) {
    dispatch_event_for_client(pool, event_type, payload, max_retry_attempts, None);
}

/// Like `dispatch_event`, but scoped to a specific client.
pub fn dispatch_event_for_client(
    pool: PgPool,
    event_type: &str,
    payload: serde_json::Value,
    max_retry_attempts: u32,
    event_client_id: Option<uuid::Uuid>,
) {
    let event_type = event_type.to_owned();

    tokio::spawn(async move {
        match db::enqueue_webhook_events(&pool, &event_type, &payload, max_retry_attempts, event_client_id).await {
            Ok(0) => {}
            Ok(count) => {
                info!(event = %event_type, count, "enqueued webhook events");
            }
            Err(e) => {
                warn!(event = %event_type, error = %e, "failed to enqueue webhook events");
            }
        }
    });
}

/// Deliver a single outbox entry. Called by the background worker.
///
/// Returns Ok(true) if delivered successfully, Ok(false) if delivery failed
/// (caller should handle retry/failure logic).
pub async fn deliver_outbox_entry(
    pool: &PgPool,
    client: &reqwest::Client,
    entry: &db::OutboxEntry,
) -> std::result::Result<(), String> {
    // Look up the webhook to get URL and secret
    let webhook = db::find_webhook(pool, entry.webhook_id)
        .await
        .map_err(|e| format!("db error: {e}"))?
        .ok_or_else(|| "webhook not found (deleted?)".to_string())?;

    if !webhook.active {
        return Err("webhook is inactive".to_string());
    }

    let body = serde_json::json!({
        "event": entry.event_type,
        "timestamp": Utc::now().to_rfc3339(),
        "data": entry.payload,
    });
    let body_bytes = serde_json::to_vec(&body).expect("JSON serialization cannot fail");
    let signature = sign_payload(&webhook.secret, &body_bytes);

    let result = client
        .post(&webhook.url)
        .header("Content-Type", "application/json")
        .header("X-Webhook-Signature", &signature)
        .header("X-Webhook-Event", &entry.event_type)
        .body(body_bytes.clone())
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status();
            let error_msg = if status.is_success() { None } else { Some(format!("HTTP {}", status.as_u16())) };
            let _ = db::record_webhook_delivery(
                pool, webhook.id, &entry.event_type, &body,
                Some(status.as_u16() as i16), error_msg.as_deref(),
            ).await;

            if status.is_success() { Ok(()) } else { Err(format!("HTTP {}", status.as_u16())) }
        }
        Err(e) => {
            let error_msg = e.to_string();
            let _ = db::record_webhook_delivery(
                pool, webhook.id, &entry.event_type, &body,
                None, Some(&error_msg),
            ).await;
            Err(error_msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_payload() {
        let sig = sign_payload("test-secret", b"hello world");
        // Deterministic — same input always produces same output
        assert_eq!(sig, sign_payload("test-secret", b"hello world"));
        // Different secret → different signature
        assert_ne!(sig, sign_payload("other-secret", b"hello world"));
        // Different payload → different signature
        assert_ne!(sig, sign_payload("test-secret", b"goodbye"));
        // Output is hex-encoded
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_is_valid_event_type() {
        assert!(is_valid_event_type("user.created"));
        assert!(is_valid_event_type("link.deleted"));
        assert!(!is_valid_event_type("user.nonexistent"));
        assert!(!is_valid_event_type(""));
    }
}
