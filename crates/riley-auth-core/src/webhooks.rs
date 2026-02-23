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

// --- Dispatch ---

const MAX_DELIVERY_ATTEMPTS: u32 = 3;

/// Dispatch a webhook event to all matching subscribers.
///
/// When `event_client_id` is `Some`, only webhooks with a matching `client_id`
/// or a NULL `client_id` (global) are notified. When `None`, all matching
/// webhooks receive the event.
///
/// Spawns a background task per webhook — delivery failures are recorded but
/// never bubble up to the caller.
pub fn dispatch_event(pool: PgPool, client: reqwest::Client, event_type: &str, payload: serde_json::Value) {
    dispatch_event_for_client(pool, client, event_type, payload, None);
}

/// Like `dispatch_event`, but scoped to a specific client.
pub fn dispatch_event_for_client(
    pool: PgPool,
    client: reqwest::Client,
    event_type: &str,
    payload: serde_json::Value,
    event_client_id: Option<uuid::Uuid>,
) {
    let event_type = event_type.to_owned();
    let pool = pool.clone();

    tokio::spawn(async move {
        let webhooks = match db::find_webhooks_for_event(&pool, &event_type, event_client_id).await {
            Ok(hooks) => hooks,
            Err(e) => {
                warn!(event = %event_type, error = %e, "failed to query webhooks");
                return;
            }
        };

        if webhooks.is_empty() {
            return;
        }

        info!(event = %event_type, count = webhooks.len(), "dispatching webhook event");

        for webhook in webhooks {
            let pool = pool.clone();
            let client = client.clone();
            let event_type = event_type.clone();
            let payload = payload.clone();

            tokio::spawn(async move {
                deliver_webhook(&pool, &client, &webhook, &event_type, &payload).await;
            });
        }
    });
}

/// Attempt delivery to a single webhook with retries and exponential backoff.
async fn deliver_webhook(
    pool: &PgPool,
    client: &reqwest::Client,
    webhook: &db::Webhook,
    event_type: &str,
    payload: &serde_json::Value,
) {
    let body = serde_json::json!({
        "event": event_type,
        "timestamp": Utc::now().to_rfc3339(),
        "data": payload,
    });
    let body_bytes = serde_json::to_vec(&body).expect("JSON serialization cannot fail");
    let signature = sign_payload(&webhook.secret, &body_bytes);

    let mut last_status: Option<i16> = None;
    let mut last_error: Option<String> = None;

    for attempt in 0..MAX_DELIVERY_ATTEMPTS {
        if attempt > 0 {
            let delay = std::time::Duration::from_millis(500 * 2u64.pow(attempt - 1));
            tokio::time::sleep(delay).await;
        }

        match client
            .post(&webhook.url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Signature", &signature)
            .header("X-Webhook-Event", event_type)
            .body(body_bytes.clone())
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16() as i16;
                last_status = Some(status);
                if resp.status().is_success() {
                    last_error = None;
                    break;
                }
                last_error = Some(format!("HTTP {status}"));
            }
            Err(e) => {
                last_status = None;
                last_error = Some(e.to_string());
            }
        }
    }

    if let Err(e) = db::record_webhook_delivery(
        pool,
        webhook.id,
        event_type,
        &body,
        last_status,
        last_error.as_deref(),
    )
    .await
    {
        warn!(
            webhook_id = %webhook.id,
            event = %event_type,
            error = %e,
            "failed to record webhook delivery"
        );
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
