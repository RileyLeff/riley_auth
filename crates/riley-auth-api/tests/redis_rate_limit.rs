//! Integration tests for Redis-backed rate limiting.
//!
//! Requires a running Redis instance on localhost:16379
//! (started by docker-compose.test.yml).
//!
//! Run with:
//!   cargo test --test redis_rate_limit --features redis -- --include-ignored --test-threads=1

#![cfg(feature = "redis")]

use riley_auth_api::rate_limit::{RedisRateLimiter, TieredRedisRateLimiter};
use riley_auth_core::config::{RateLimitTierConfig, RateLimitTiersConfig};
use std::net::IpAddr;

const REDIS_URL: &str = "redis://localhost:16379";

async fn flush_redis() {
    let mut conn = redis::Client::open(REDIS_URL)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut conn)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn redis_rate_limiter_allows_within_burst() {
    let limiter = RedisRateLimiter::new(REDIS_URL, 5, 60)
        .await
        .expect("failed to connect to Redis");
    flush_redis().await;

    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // First 5 requests should be allowed (burst_size = 5)
    for i in 1..=5 {
        assert!(
            limiter.is_allowed(&ip).await,
            "request {i} should be allowed"
        );
    }

    // 6th request should be denied
    assert!(
        !limiter.is_allowed(&ip).await,
        "request 6 should be rate-limited"
    );
}

#[tokio::test]
#[ignore]
async fn redis_rate_limiter_different_ips_independent() {
    let limiter = RedisRateLimiter::new(REDIS_URL, 2, 60)
        .await
        .expect("failed to connect to Redis");
    flush_redis().await;

    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    // Exhaust ip1's limit
    assert!(limiter.is_allowed(&ip1).await);
    assert!(limiter.is_allowed(&ip1).await);
    assert!(!limiter.is_allowed(&ip1).await);

    // ip2 should still have its own limit
    assert!(limiter.is_allowed(&ip2).await);
    assert!(limiter.is_allowed(&ip2).await);
    assert!(!limiter.is_allowed(&ip2).await);
}

#[tokio::test]
#[ignore]
async fn redis_rate_limiter_window_expires() {
    // Use a very short window (1 second) to test expiry
    let limiter = RedisRateLimiter::new(REDIS_URL, 1, 1)
        .await
        .expect("failed to connect to Redis");
    flush_redis().await;

    let ip: IpAddr = "10.0.0.3".parse().unwrap();

    // Use up the limit
    assert!(limiter.is_allowed(&ip).await);
    assert!(!limiter.is_allowed(&ip).await);

    // Wait for the window to expire
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Should be allowed again
    assert!(limiter.is_allowed(&ip).await);
}

#[tokio::test]
#[ignore]
async fn redis_rate_limiter_check_returns_count_and_ttl() {
    let limiter = RedisRateLimiter::new(REDIS_URL, 10, 60)
        .await
        .expect("failed to connect to Redis");
    flush_redis().await;

    let ip: IpAddr = "10.0.0.4".parse().unwrap();

    let (count, ttl) = limiter.check(&ip).await.unwrap();
    assert_eq!(count, 1);
    assert!(ttl > 0 && ttl <= 60, "ttl should be between 1 and 60, got {ttl}");

    let (count, _) = limiter.check(&ip).await.unwrap();
    assert_eq!(count, 2);

    let (count, _) = limiter.check(&ip).await.unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
#[ignore]
async fn redis_rate_limiter_headers_info() {
    let limiter = RedisRateLimiter::new(REDIS_URL, 3, 60)
        .await
        .expect("failed to connect to Redis");
    flush_redis().await;

    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    // First request: 2 remaining
    let (allowed, remaining, retry_after) = limiter.check_with_headers(&ip).await;
    assert!(allowed);
    assert_eq!(remaining, Some(2));
    assert_eq!(retry_after, None);

    // Second request: 1 remaining
    let (allowed, remaining, _) = limiter.check_with_headers(&ip).await;
    assert!(allowed);
    assert_eq!(remaining, Some(1));

    // Third request: 0 remaining
    let (allowed, remaining, _) = limiter.check_with_headers(&ip).await;
    assert!(allowed);
    assert_eq!(remaining, Some(0));

    // Fourth request: rate limited with TTL-based retry_after
    let (allowed, remaining, retry_after) = limiter.check_with_headers(&ip).await;
    assert!(!allowed);
    assert_eq!(remaining, Some(0));
    // retry_after is now the TTL from Redis, not the full window_secs
    assert!(retry_after.is_some());
    let wait = retry_after.unwrap();
    assert!(wait >= 1 && wait <= 60, "retry_after should be between 1 and 60, got {wait}");
}

// --- Tiered rate limiter tests ---

fn test_tiers() -> RateLimitTiersConfig {
    RateLimitTiersConfig {
        auth: RateLimitTierConfig { requests: 3, window_secs: 60 },
        standard: RateLimitTierConfig { requests: 10, window_secs: 60 },
        public: RateLimitTierConfig { requests: 50, window_secs: 60 },
    }
}

#[tokio::test]
#[ignore]
async fn tiered_redis_auth_limited_at_lower_threshold() {
    flush_redis().await;
    let limiter = TieredRedisRateLimiter::new(REDIS_URL, &test_tiers())
        .await
        .expect("failed to connect to Redis");

    let ip: IpAddr = "10.0.0.10".parse().unwrap();

    // Auth tier allows only 3 requests
    for i in 1..=3 {
        assert!(
            limiter.auth().is_allowed(&ip).await,
            "auth request {i} should be allowed"
        );
    }
    assert!(
        !limiter.auth().is_allowed(&ip).await,
        "auth request 4 should be rate-limited"
    );
}

#[tokio::test]
#[ignore]
async fn tiered_redis_public_allows_higher_traffic() {
    flush_redis().await;
    let limiter = TieredRedisRateLimiter::new(REDIS_URL, &test_tiers())
        .await
        .expect("failed to connect to Redis");

    let ip: IpAddr = "10.0.0.11".parse().unwrap();

    // Public tier allows 50 requests
    for i in 1..=50 {
        assert!(
            limiter.public().is_allowed(&ip).await,
            "public request {i} should be allowed"
        );
    }
    assert!(
        !limiter.public().is_allowed(&ip).await,
        "public request 51 should be rate-limited"
    );
}

#[tokio::test]
#[ignore]
async fn tiered_redis_tiers_are_independent() {
    flush_redis().await;
    let limiter = TieredRedisRateLimiter::new(REDIS_URL, &test_tiers())
        .await
        .expect("failed to connect to Redis");

    let ip: IpAddr = "10.0.0.12".parse().unwrap();

    // Exhaust auth tier
    for _ in 0..3 {
        limiter.auth().check(&ip).await.unwrap();
    }
    assert!(!limiter.auth().is_allowed(&ip).await, "auth should be exhausted");

    // Standard and public tiers should still work
    assert!(limiter.standard().is_allowed(&ip).await, "standard should be available");
    assert!(limiter.public().is_allowed(&ip).await, "public should be available");
}
