//! Integration tests for Redis-backed rate limiting.
//!
//! Requires a running Redis instance on localhost:16379
//! (started by docker-compose.test.yml).
//!
//! Run with:
//!   cargo test --test redis_rate_limit --features redis -- --include-ignored --test-threads=1

#![cfg(feature = "redis")]

use riley_auth_api::rate_limit::RedisRateLimiter;
use std::net::IpAddr;

const REDIS_URL: &str = "redis://localhost:16379";

#[tokio::test]
#[ignore]
async fn redis_rate_limiter_allows_within_burst() {
    let limiter = RedisRateLimiter::new(REDIS_URL, 5, 60)
        .await
        .expect("failed to connect to Redis");

    // Flush any existing state
    let mut conn = redis::Client::open(REDIS_URL)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut conn)
        .await
        .unwrap();

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

    let mut conn = redis::Client::open(REDIS_URL)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut conn)
        .await
        .unwrap();

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

    let mut conn = redis::Client::open(REDIS_URL)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut conn)
        .await
        .unwrap();

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
async fn redis_rate_limiter_check_returns_count() {
    let limiter = RedisRateLimiter::new(REDIS_URL, 10, 60)
        .await
        .expect("failed to connect to Redis");

    let mut conn = redis::Client::open(REDIS_URL)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut conn)
        .await
        .unwrap();

    let ip: IpAddr = "10.0.0.4".parse().unwrap();

    let count = limiter.check(&ip).await.unwrap();
    assert_eq!(count, 1);

    let count = limiter.check(&ip).await.unwrap();
    assert_eq!(count, 2);

    let count = limiter.check(&ip).await.unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
#[ignore]
async fn redis_rate_limiter_headers_info() {
    let limiter = RedisRateLimiter::new(REDIS_URL, 3, 60)
        .await
        .expect("failed to connect to Redis");

    let mut conn = redis::Client::open(REDIS_URL)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut conn)
        .await
        .unwrap();

    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    // First request: 2 remaining
    let (allowed, remaining, wait_time) = limiter.check_with_headers(&ip).await;
    assert!(allowed);
    assert_eq!(remaining, Some(2));
    assert_eq!(wait_time, None);

    // Second request: 1 remaining
    let (allowed, remaining, _) = limiter.check_with_headers(&ip).await;
    assert!(allowed);
    assert_eq!(remaining, Some(1));

    // Third request: 0 remaining
    let (allowed, remaining, _) = limiter.check_with_headers(&ip).await;
    assert!(allowed);
    assert_eq!(remaining, Some(0));

    // Fourth request: rate limited
    let (allowed, remaining, wait_time) = limiter.check_with_headers(&ip).await;
    assert!(!allowed);
    assert_eq!(remaining, Some(0));
    assert_eq!(wait_time, Some(60));
}
