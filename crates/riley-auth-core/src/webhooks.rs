use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use tokio::sync::{watch, Semaphore};
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
/// Awaits the database INSERT to guarantee durability. A background worker
/// delivers the enqueued events asynchronously.
pub async fn dispatch_event(pool: &PgPool, event_type: &str, payload: serde_json::Value, max_retry_attempts: u32) {
    dispatch_event_for_client(pool, event_type, payload, max_retry_attempts, None).await;
}

/// Like `dispatch_event`, but scoped to a specific client.
pub async fn dispatch_event_for_client(
    pool: &PgPool,
    event_type: &str,
    payload: serde_json::Value,
    max_retry_attempts: u32,
    event_client_id: Option<uuid::Uuid>,
) {
    match db::enqueue_webhook_events(pool, event_type, &payload, max_retry_attempts, event_client_id).await {
        Ok(0) => {}
        Ok(count) => {
            info!(event = %event_type, count, "enqueued webhook events");
        }
        Err(e) => {
            warn!(event = %event_type, error = %e, "failed to enqueue webhook events");
        }
    }
}

/// Check whether a webhook URL's host is a private IP literal.
///
/// This complements the `SsrfSafeResolver` (which blocks hostnames that resolve
/// to private IPs) by catching direct IP literal URLs like `http://127.0.0.1/`.
fn check_url_ip_literal(url: &str) -> std::result::Result<(), String> {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            if let Ok(ip) = host.parse::<IpAddr>() {
                if is_private_ip(&ip) {
                    return Err(format!(
                        "webhook URL resolved to private/reserved IP: {ip}"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Deliver a single outbox entry. Called by the background worker.
///
/// Returns `Ok(())` on successful delivery, `Err(message)` on failure.
/// Returns `Err("permanent:...")` for non-retryable errors (deleted/inactive webhook).
///
/// When `block_private_ips` is true, URLs with private IP literals are rejected
/// before any network request is made. Hostname-based URLs are protected by the
/// `SsrfSafeResolver` on the client instead.
pub async fn deliver_outbox_entry(
    pool: &PgPool,
    client: &reqwest::Client,
    entry: &db::OutboxEntry,
    block_private_ips: bool,
) -> std::result::Result<(), String> {
    // Look up the webhook to get URL and secret
    let webhook = db::find_webhook(pool, entry.webhook_id)
        .await
        .map_err(|e| format!("db error: {e}"))?
        .ok_or_else(|| "permanent: webhook not found (deleted?)".to_string())?;

    if !webhook.active {
        return Err("permanent: webhook is inactive".to_string());
    }

    // SSRF check: block private IP literals in the URL
    if block_private_ips {
        check_url_ip_literal(&webhook.url)
            .map_err(|e| format!("permanent: {e}"))?;
    }

    let body = serde_json::json!({
        "id": entry.id.to_string(),
        "event": entry.event_type,
        "timestamp": entry.created_at.to_rfc3339(),
        "data": entry.payload,
    });
    let body_bytes = serde_json::to_vec(&body).expect("JSON serialization cannot fail");
    let signature = sign_payload(&webhook.secret, &body_bytes);

    let result = client
        .post(&webhook.url)
        .header("Content-Type", "application/json")
        .header("X-Webhook-Signature", &signature)
        .header("X-Webhook-Event", &entry.event_type)
        .body(body_bytes)
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

// --- Delivery worker ---

/// Background worker that polls the outbox and delivers pending webhook events.
///
/// Uses a semaphore to bound concurrent outbound HTTP requests. Entries that
/// fail delivery are retried with exponential backoff (handled by
/// `record_outbox_attempt`). Entries that exceed max_attempts are marked failed.
/// Non-retryable errors (deleted/inactive webhook) immediately mark as failed.
///
/// Runs until the shutdown receiver signals `true`, then drains in-flight tasks.
pub async fn delivery_worker(
    pool: PgPool,
    client: reqwest::Client,
    max_concurrent: usize,
    block_private_ips: bool,
    mut shutdown: watch::Receiver<bool>,
) {
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let poll_interval = std::time::Duration::from_secs(1);

    info!(max_concurrent, "webhook delivery worker started");

    loop {
        // Check shutdown before polling
        if *shutdown.borrow() {
            break;
        }

        // Atomically claim a batch of pending entries (transitions to 'processing')
        let batch_size = semaphore.available_permits().max(1) as i64;
        let entries = match db::claim_pending_outbox_entries(&pool, batch_size).await {
            Ok(entries) => entries,
            Err(e) => {
                warn!(error = %e, "failed to claim outbox entries");
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => continue,
                    _ = shutdown.changed() => break,
                }
            }
        };

        if entries.is_empty() {
            // Nothing to deliver — wait before polling again
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => continue,
                _ = shutdown.changed() => break,
            }
        }

        // Deliver each entry concurrently, bounded by the semaphore
        for entry in entries {
            let permit = semaphore.clone().acquire_owned().await.expect("semaphore closed");
            let pool = pool.clone();
            let client = client.clone();

            tokio::spawn(async move {
                let entry_id = entry.id;
                let result = deliver_outbox_entry(&pool, &client, &entry, block_private_ips).await;

                match result {
                    Ok(()) => {
                        let _ = db::mark_outbox_delivered(&pool, entry_id).await;
                    }
                    Err(ref error) if error.starts_with("permanent:") => {
                        // Non-retryable: immediately mark as failed
                        let _ = db::mark_outbox_failed(&pool, entry_id, error).await;
                    }
                    Err(error) => {
                        let next_attempt = entry.attempts + 1;
                        if next_attempt >= entry.max_attempts {
                            let _ = db::mark_outbox_failed(&pool, entry_id, &error).await;
                        } else {
                            let _ = db::record_outbox_attempt(&pool, entry_id, &error).await;
                        }
                    }
                }

                drop(permit); // Release semaphore slot
            });
        }
    }

    // Drain in-flight tasks by waiting for all semaphore permits to be returned
    let _ = semaphore.acquire_many(max_concurrent as u32).await;

    info!("webhook delivery worker stopped");
}

// --- SSRF protection ---

/// Check whether an IP address is in a private/reserved range that should be
/// blocked for SSRF protection.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()       // 127.0.0.0/8
            || v4.is_private()     // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_link_local()  // 169.254.0.0/16
            || v4.is_broadcast()   // 255.255.255.255
            || v4.is_unspecified() // 0.0.0.0
            || v4.is_multicast()   // 224.0.0.0/4
            || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(v6) => {
            // Check IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return is_private_ip(&IpAddr::V4(mapped_v4));
            }
            v6.is_loopback()       // ::1
            || v6.is_unspecified() // ::
            || v6.is_multicast()   // ff00::/8
            || (v6.segments()[0] & 0xFE00) == 0xFC00  // fc00::/7 (unique local)
            || (v6.segments()[0] & 0xFFC0) == 0xFE80  // fe80::/10 (link-local)
        }
    }
}

/// DNS resolver that blocks private/reserved IPs (SSRF protection).
///
/// Used as a `reqwest::dns::Resolve` implementation to prevent webhook
/// delivery to internal network addresses.
pub struct SsrfSafeResolver;

impl reqwest::dns::Resolve for SsrfSafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();

            for addr in &addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "webhook URL resolved to private/reserved IP: {}",
                            addr.ip()
                        ),
                    ))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
            }

            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Build a `reqwest::Client` for webhook delivery.
///
/// When `allow_private_ips` is false, uses `SsrfSafeResolver` to block
/// delivery to private/loopback addresses.
pub fn build_webhook_client(allow_private_ips: bool) -> reqwest::Client {
    let builder = reqwest::Client::builder()
        // Disable redirect following — prevents open-redirect SSRF bypass
        // where a public server 302s to a private IP literal
        .redirect(reqwest::redirect::Policy::none());

    if allow_private_ips {
        builder.build().expect("failed to build HTTP client")
    } else {
        builder
            .dns_resolver(Arc::new(SsrfSafeResolver))
            .build()
            .expect("failed to build SSRF-safe HTTP client")
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

    #[test]
    fn is_private_ip_blocks_private_ranges() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        // IPv4 private ranges
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));   // loopback
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));    // 10.0.0.0/8
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));  // 172.16.0.0/12
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))); // 192.168.0.0/16
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)))); // link-local
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));     // unspecified
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)))); // broadcast
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));  // CGNAT
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));  // multicast
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(239, 255, 255, 255)))); // multicast

        // IPv6 private ranges
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));           // ::1
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));         // ::
        assert!(is_private_ip(&IpAddr::V6("fc00::1".parse().unwrap())));    // unique local
        assert!(is_private_ip(&IpAddr::V6("fd12::1".parse().unwrap())));    // unique local
        assert!(is_private_ip(&IpAddr::V6("fe80::1".parse().unwrap())));    // link-local
        assert!(is_private_ip(&IpAddr::V6("ff02::1".parse().unwrap())));    // multicast

        // IPv4-mapped IPv6 addresses
        assert!(is_private_ip(&IpAddr::V6("::ffff:127.0.0.1".parse().unwrap())));   // mapped loopback
        assert!(is_private_ip(&IpAddr::V6("::ffff:10.0.0.1".parse().unwrap())));    // mapped private
        assert!(is_private_ip(&IpAddr::V6("::ffff:192.168.1.1".parse().unwrap()))); // mapped private
        assert!(is_private_ip(&IpAddr::V6("::ffff:172.16.0.1".parse().unwrap())));  // mapped private
    }

    #[test]
    fn is_private_ip_allows_public_ips() {
        use std::net::Ipv4Addr;

        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));     // Google DNS
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));     // Cloudflare
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))); // example.com
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 15, 255, 255)))); // just outside 172.16/12
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 32, 0, 0))));   // just outside 172.16/12
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255)))); // just outside CGNAT

        assert!(!is_private_ip(&IpAddr::V6("2001:db8::1".parse().unwrap())));
        assert!(!is_private_ip(&IpAddr::V6("2607:f8b0:4004:800::200e".parse().unwrap()))); // Google

        // IPv4-mapped public IPs should be allowed
        assert!(!is_private_ip(&IpAddr::V6("::ffff:8.8.8.8".parse().unwrap())));     // mapped Google DNS
        assert!(!is_private_ip(&IpAddr::V6("::ffff:93.184.216.34".parse().unwrap()))); // mapped example.com
    }
}
