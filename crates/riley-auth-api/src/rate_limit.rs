//! Redis-backed rate limiting middleware.
//!
//! When the `redis` feature is enabled, this module provides a fixed-window
//! rate limiter backed by Redis. Each client IP gets a key with a TTL matching
//! the rate window; the counter is atomically incremented via a Lua script.
//!
//! When Redis is unavailable, the middleware falls back to allowing the request
//! through (fail-open), logging a warning.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use redis::aio::ConnectionManager;
use redis::Script;

/// Redis-backed rate limiter.
#[derive(Clone)]
pub struct RedisRateLimiter {
    conn: ConnectionManager,
    /// Maximum requests allowed per window.
    burst_size: u32,
    /// Window duration in seconds.
    window_secs: u64,
    /// Key prefix in Redis.
    key_prefix: String,
}

impl RedisRateLimiter {
    /// Connect to Redis and create a rate limiter.
    pub async fn new(
        redis_url: &str,
        burst_size: u32,
        window_secs: u64,
    ) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self {
            conn,
            burst_size,
            window_secs,
            key_prefix: "rate_limit".to_string(),
        })
    }

    /// Check if a request from the given IP is allowed.
    ///
    /// Returns `Ok(count)` with the current request count in the window,
    /// or `Err` if Redis is unavailable.
    pub async fn check(&self, ip: &IpAddr) -> Result<u64, redis::RedisError> {
        // Lua script: atomically INCR and set EXPIRE on first access.
        // This ensures the window starts when the first request arrives.
        let script = Script::new(
            r"
            local current = redis.call('INCR', KEYS[1])
            if current == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return current
            ",
        );

        let key = format!("{}:{}", self.key_prefix, ip);
        let mut conn = self.conn.clone();
        let count: u64 = script
            .key(&key)
            .arg(self.window_secs)
            .invoke_async(&mut conn)
            .await?;
        Ok(count)
    }

    /// Returns true if the request count is within the burst limit.
    pub async fn is_allowed(&self, ip: &IpAddr) -> bool {
        match self.check(ip).await {
            Ok(count) => count <= self.burst_size as u64,
            Err(e) => {
                // Fail-open: if Redis is down, allow the request
                tracing::warn!(error = %e, "Redis rate limiter unavailable, allowing request");
                true
            }
        }
    }

    /// Returns the remaining count and wait time for rate limit headers.
    pub async fn check_with_headers(
        &self,
        ip: &IpAddr,
    ) -> (bool, Option<u64>, Option<u64>) {
        match self.check(ip).await {
            Ok(count) => {
                let allowed = count <= self.burst_size as u64;
                let remaining = if allowed {
                    Some(self.burst_size as u64 - count)
                } else {
                    Some(0)
                };
                let wait_time = if allowed { None } else { Some(self.window_secs) };
                (allowed, remaining, wait_time)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Redis rate limiter unavailable, allowing request");
                (true, None, None)
            }
        }
    }
}

/// Extract client IP from the request, with proxy header support.
pub fn extract_ip<B>(req: &Request<B>, behind_proxy: bool) -> Option<IpAddr> {
    if behind_proxy {
        // Try X-Forwarded-For first, then X-Real-IP, then Forwarded header
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(val) = xff.to_str() {
                // Take the first (leftmost) IP — the one the proxy saw
                if let Some(ip_str) = val.split(',').next() {
                    if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
        if let Some(real_ip) = req.headers().get("x-real-ip") {
            if let Ok(val) = real_ip.to_str() {
                if let Ok(ip) = val.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Fall back to peer IP from ConnectInfo
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Axum middleware that enforces rate limiting via Redis.
pub async fn redis_rate_limit_middleware(
    limiter: Arc<RedisRateLimiter>,
    behind_proxy: bool,
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let ip = match extract_ip(&req, behind_proxy) {
        Some(ip) => ip,
        None => {
            // Can't determine client IP — allow through
            return next.run(req).await;
        }
    };

    let (allowed, remaining, wait_time) = limiter.check_with_headers(&ip).await;

    if allowed {
        let mut response = next.run(req).await;
        if let Some(remaining) = remaining {
            let headers = response.headers_mut();
            headers.insert(
                "x-ratelimit-remaining",
                HeaderValue::from(remaining as u64),
            );
            headers.insert(
                "x-ratelimit-limit",
                HeaderValue::from(limiter.burst_size),
            );
        }
        response
    } else {
        let mut headers = HeaderMap::new();
        if let Some(wait) = wait_time {
            let val = HeaderValue::from(wait);
            headers.insert("x-ratelimit-after", val.clone());
            headers.insert("retry-after", val);
        }
        let mut response = (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
        response.headers_mut().extend(headers);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ip_direct() {
        let req = Request::builder()
            .uri("/test")
            .body(())
            .unwrap();
        // No ConnectInfo extension — returns None
        assert!(extract_ip(&req, false).is_none());
    }

    #[test]
    fn extract_ip_from_xff_header() {
        let req = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "203.0.113.50, 70.41.3.18, 150.172.238.178")
            .body(())
            .unwrap();
        // When behind proxy, extract first IP from X-Forwarded-For
        let ip = extract_ip(&req, true).unwrap();
        assert_eq!(ip, "203.0.113.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn extract_ip_from_real_ip_header() {
        let req = Request::builder()
            .uri("/test")
            .header("x-real-ip", "10.0.0.1")
            .body(())
            .unwrap();
        let ip = extract_ip(&req, true).unwrap();
        assert_eq!(ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn extract_ip_ignores_proxy_headers_when_not_behind_proxy() {
        let req = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "203.0.113.50")
            .body(())
            .unwrap();
        // Not behind proxy — ignore proxy headers
        assert!(extract_ip(&req, false).is_none());
    }
}
