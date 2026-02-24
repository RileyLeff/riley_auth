//! Tiered rate limiting middleware.
//!
//! Classifies request paths into three tiers (auth, standard, public) and
//! applies per-tier rate limits. Supports in-memory and Redis backends.
//!
//! OPTIONS requests bypass rate limiting entirely to avoid breaking CORS
//! preflights (browsers treat 429 on preflight as a network error regardless
//! of CORS headers).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Method, Request};
use axum::response::{IntoResponse, Response};

use riley_auth_core::config::RateLimitTiersConfig;
use riley_auth_core::error::Error;

// --- Tier classification ---

/// Rate limit tier for a request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitTier {
    /// Sensitive auth endpoints: login, token exchange, callbacks.
    Auth,
    /// General API endpoints: admin, user profile, OAuth management.
    Standard,
    /// High-traffic read-only endpoints: health, JWKS, discovery.
    Public,
}

impl RateLimitTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Standard => "standard",
            Self::Public => "public",
        }
    }
}

/// Classify a request path into a rate limit tier.
///
/// Routes are matched against the actual Axum route patterns in `routes/auth.rs`
/// and `routes/oauth_provider.rs`. Trailing slashes are normalized before matching.
pub fn classify_path(path: &str) -> RateLimitTier {
    // Normalize: strip trailing slash (keep root "/")
    let path = if path.len() > 1 && path.ends_with('/') {
        &path[..path.len() - 1]
    } else {
        path
    };

    // Auth tier: exact matches for sensitive endpoints
    if matches!(
        path,
        "/oauth/token"
            | "/oauth/authorize"
            | "/oauth/revoke"
            | "/oauth/introspect"
            | "/auth/setup"
            | "/auth/refresh"
    ) {
        return RateLimitTier::Auth;
    }

    // Auth tier: /auth/link/{provider} and /auth/link/{provider}/callback
    if let Some(rest) = path.strip_prefix("/auth/link/") {
        if !rest.is_empty() {
            return RateLimitTier::Auth;
        }
    }

    // Auth tier: /auth/{provider} and /auth/{provider}/callback
    // Exclude known non-provider path segments
    if let Some(rest) = path.strip_prefix("/auth/") {
        let segment = rest.split('/').next().unwrap_or("");
        if !matches!(
            segment,
            "me" | "logout" | "logout-all" | "sessions" | "link"
                | "setup" | "refresh" | ""
        ) {
            return RateLimitTier::Auth;
        }
    }

    // Public tier: high-traffic read-only endpoints
    if path == "/health" || path.starts_with("/.well-known/") || path == "/.well-known" {
        return RateLimitTier::Public;
    }

    // Everything else: standard tier
    RateLimitTier::Standard
}

// --- IP extraction ---

/// Extract client IP from the request, with proxy header support.
///
/// Delegates to the shared `routes::extract_client_ip` function.
pub fn extract_ip<B>(req: &Request<B>, behind_proxy: bool) -> Option<IpAddr> {
    let peer_ip = req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    crate::routes::extract_client_ip(req.headers(), peer_ip, behind_proxy)
}

// --- In-memory rate limiter ---

/// Fixed-window rate limiter entry.
struct WindowEntry {
    count: u64,
    window_start: Instant,
}

/// State behind the tier lock, including eviction tracking.
struct TierState {
    windows: HashMap<IpAddr, WindowEntry>,
    last_prune: Instant,
}

/// In-memory fixed-window rate limiter for a single tier.
struct InMemoryTierLimiter {
    state: Mutex<TierState>,
    burst_size: u32,
    window_secs: u64,
}

impl InMemoryTierLimiter {
    fn new(burst_size: u32, window_secs: u64) -> Self {
        Self {
            state: Mutex::new(TierState {
                windows: HashMap::new(),
                last_prune: Instant::now(),
            }),
            burst_size,
            window_secs,
        }
    }

    /// Check a request. Returns (allowed, remaining, retry_after_secs).
    fn check(&self, ip: &IpAddr) -> (bool, u64, u64) {
        let mut state = self.state.lock().expect("rate limit lock poisoned");
        let now = Instant::now();

        // Evict expired entries periodically (every window_secs)
        if now.duration_since(state.last_prune).as_secs() >= self.window_secs {
            let window_secs = self.window_secs;
            state.windows.retain(|_, entry| {
                now.duration_since(entry.window_start).as_secs() < window_secs
            });
            state.last_prune = now;
        }

        let entry = state.windows.entry(*ip).or_insert(WindowEntry {
            count: 0,
            window_start: now,
        });

        // Reset if window expired
        if now.duration_since(entry.window_start).as_secs() >= self.window_secs {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;
        let allowed = entry.count <= self.burst_size as u64;
        let remaining = if allowed {
            self.burst_size as u64 - entry.count
        } else {
            0
        };

        // Retry-After = time remaining in the current window (at least 1 second)
        let elapsed = now.duration_since(entry.window_start).as_secs();
        let retry_after = self.window_secs.saturating_sub(elapsed).max(1);

        (allowed, remaining, retry_after)
    }
}

/// Tiered in-memory rate limiter.
pub struct InMemoryRateLimiter {
    auth: InMemoryTierLimiter,
    standard: InMemoryTierLimiter,
    public: InMemoryTierLimiter,
}

impl InMemoryRateLimiter {
    pub fn new(tiers: &RateLimitTiersConfig) -> Self {
        Self {
            auth: InMemoryTierLimiter::new(tiers.auth.requests, tiers.auth.window_secs),
            standard: InMemoryTierLimiter::new(tiers.standard.requests, tiers.standard.window_secs),
            public: InMemoryTierLimiter::new(tiers.public.requests, tiers.public.window_secs),
        }
    }

    fn tier_limiter(&self, tier: RateLimitTier) -> &InMemoryTierLimiter {
        match tier {
            RateLimitTier::Auth => &self.auth,
            RateLimitTier::Standard => &self.standard,
            RateLimitTier::Public => &self.public,
        }
    }

    fn burst_size(&self, tier: RateLimitTier) -> u32 {
        self.tier_limiter(tier).burst_size
    }

    fn check(&self, tier: RateLimitTier, ip: &IpAddr) -> (bool, u64, u64) {
        self.tier_limiter(tier).check(ip)
    }
}

/// Axum middleware for in-memory tiered rate limiting.
pub async fn memory_rate_limit_middleware(
    limiter: Arc<InMemoryRateLimiter>,
    behind_proxy: bool,
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    // CORS preflight exemption: OPTIONS bypass rate limiting
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }

    let ip = match extract_ip(&req, behind_proxy) {
        Some(ip) => ip,
        None => {
            tracing::warn!("rate limiter: could not extract client IP, bypassing rate limit");
            return next.run(req).await;
        }
    };

    let tier = classify_path(req.uri().path());
    let (allowed, remaining, retry_after) = limiter.check(tier, &ip);

    if allowed {
        let mut response = next.run(req).await;
        let headers = response.headers_mut();
        headers.insert("x-ratelimit-remaining", HeaderValue::from(remaining));
        headers.insert("x-ratelimit-limit", HeaderValue::from(limiter.burst_size(tier)));
        headers_insert_reset(headers, retry_after);
        response
    } else {
        metrics::counter!("riley_auth_rate_limit_hits_total", "tier" => tier.as_str()).increment(1);
        let mut response = Error::RateLimited.into_response();
        let headers = response.headers_mut();
        headers_insert_retry_after(headers, retry_after);
        headers.insert("x-ratelimit-remaining", HeaderValue::from(0u64));
        headers.insert("x-ratelimit-limit", HeaderValue::from(limiter.burst_size(tier)));
        headers_insert_reset(headers, retry_after);
        response
    }
}

/// Insert retry-after header on a rate-limited response.
fn headers_insert_retry_after(headers: &mut axum::http::HeaderMap, retry_after: u64) {
    headers.insert("retry-after", HeaderValue::from(retry_after));
}

/// Insert x-ratelimit-reset header (epoch seconds when the window resets).
fn headers_insert_reset(headers: &mut axum::http::HeaderMap, retry_after: u64) {
    let reset = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + retry_after;
    headers.insert("x-ratelimit-reset", HeaderValue::from(reset));
}

// --- Redis rate limiter ---

#[cfg(feature = "redis")]
mod redis_impl {
    use super::*;
    use redis::aio::ConnectionManager;
    use redis::Script;

    /// Redis-backed rate limiter for a single tier.
    #[derive(Clone)]
    pub struct RedisRateLimiter {
        conn: ConnectionManager,
        burst_size: u32,
        window_secs: u64,
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

        /// Create a rate limiter with a specific key prefix.
        pub fn with_prefix(
            conn: ConnectionManager,
            burst_size: u32,
            window_secs: u64,
            key_prefix: String,
        ) -> Self {
            Self {
                conn,
                burst_size,
                window_secs,
                key_prefix,
            }
        }

        /// Check if a request from the given IP is allowed.
        ///
        /// Returns `Ok((count, ttl))` with the current request count and the
        /// remaining TTL (seconds) on the window key, or `Err` if Redis is
        /// unavailable.
        pub async fn check(&self, ip: &IpAddr) -> Result<(u64, u64), redis::RedisError> {
            let script = Script::new(
                r"
                local current = redis.call('INCR', KEYS[1])
                if current == 1 then
                    redis.call('EXPIRE', KEYS[1], ARGV[1])
                end
                local ttl = redis.call('TTL', KEYS[1])
                if ttl < 0 then ttl = tonumber(ARGV[1]) end
                return {current, ttl}
                ",
            );

            let key = format!("{}:{}", self.key_prefix, ip);
            let mut conn = self.conn.clone();
            let (count, ttl): (u64, u64) = script
                .key(&key)
                .arg(self.window_secs)
                .invoke_async(&mut conn)
                .await?;
            Ok((count, ttl))
        }

        /// Returns true if the request count is within the burst limit.
        pub async fn is_allowed(&self, ip: &IpAddr) -> bool {
            match self.check(ip).await {
                Ok((count, _)) => count <= self.burst_size as u64,
                Err(e) => {
                    tracing::warn!(error = %e, "Redis rate limiter unavailable, allowing request");
                    true
                }
            }
        }

        /// Returns (allowed, remaining, retry_after) for rate limit headers.
        pub async fn check_with_headers(
            &self,
            ip: &IpAddr,
        ) -> (bool, Option<u64>, Option<u64>) {
            match self.check(ip).await {
                Ok((count, ttl)) => {
                    let allowed = count <= self.burst_size as u64;
                    let remaining = if allowed {
                        Some(self.burst_size as u64 - count)
                    } else {
                        Some(0)
                    };
                    let retry_after = if allowed { None } else { Some(ttl.max(1)) };
                    (allowed, remaining, retry_after)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Redis rate limiter unavailable, allowing request");
                    (true, None, None)
                }
            }
        }
    }

    /// Tiered Redis-backed rate limiter.
    #[derive(Clone)]
    pub struct TieredRedisRateLimiter {
        auth: RedisRateLimiter,
        standard: RedisRateLimiter,
        public: RedisRateLimiter,
    }

    impl TieredRedisRateLimiter {
        /// Connect to Redis and create tiered rate limiters.
        pub async fn new(
            redis_url: &str,
            tiers: &RateLimitTiersConfig,
        ) -> Result<Self, redis::RedisError> {
            let client = redis::Client::open(redis_url)?;
            let conn = ConnectionManager::new(client).await?;
            Ok(Self {
                auth: RedisRateLimiter::with_prefix(
                    conn.clone(),
                    tiers.auth.requests,
                    tiers.auth.window_secs,
                    "rate:auth".to_string(),
                ),
                standard: RedisRateLimiter::with_prefix(
                    conn.clone(),
                    tiers.standard.requests,
                    tiers.standard.window_secs,
                    "rate:standard".to_string(),
                ),
                public: RedisRateLimiter::with_prefix(
                    conn,
                    tiers.public.requests,
                    tiers.public.window_secs,
                    "rate:public".to_string(),
                ),
            })
        }

        fn tier_limiter(&self, tier: RateLimitTier) -> &RedisRateLimiter {
            match tier {
                RateLimitTier::Auth => &self.auth,
                RateLimitTier::Standard => &self.standard,
                RateLimitTier::Public => &self.public,
            }
        }

        pub fn auth(&self) -> &RedisRateLimiter { &self.auth }
        pub fn standard(&self) -> &RedisRateLimiter { &self.standard }
        pub fn public(&self) -> &RedisRateLimiter { &self.public }
    }

    /// Axum middleware for Redis-backed tiered rate limiting.
    pub async fn redis_rate_limit_middleware(
        limiter: Arc<TieredRedisRateLimiter>,
        behind_proxy: bool,
        req: Request<Body>,
        next: axum::middleware::Next,
    ) -> Response {
        // CORS preflight exemption: OPTIONS bypass rate limiting
        if req.method() == Method::OPTIONS {
            return next.run(req).await;
        }

        let ip = match extract_ip(&req, behind_proxy) {
            Some(ip) => ip,
            None => {
                tracing::warn!("rate limiter: could not extract client IP, bypassing rate limit");
                return next.run(req).await;
            }
        };

        let tier = classify_path(req.uri().path());
        let tier_limiter = limiter.tier_limiter(tier);
        let (allowed, remaining, retry_after) = tier_limiter.check_with_headers(&ip).await;

        if allowed {
            let mut response = next.run(req).await;
            if let Some(remaining) = remaining {
                let headers = response.headers_mut();
                headers.insert("x-ratelimit-remaining", HeaderValue::from(remaining));
                headers.insert("x-ratelimit-limit", HeaderValue::from(tier_limiter.burst_size));
                if let Some(wait) = retry_after {
                    headers_insert_reset(headers, wait);
                }
            }
            response
        } else {
            metrics::counter!("riley_auth_rate_limit_hits_total", "tier" => tier.as_str()).increment(1);
            let mut response = Error::RateLimited.into_response();
            let headers = response.headers_mut();
            if let Some(wait) = retry_after {
                headers_insert_retry_after(headers, wait);
                headers_insert_reset(headers, wait);
            }
            headers.insert("x-ratelimit-remaining", HeaderValue::from(0u32));
            headers.insert("x-ratelimit-limit", HeaderValue::from(tier_limiter.burst_size));
            response
        }
    }
}

#[cfg(feature = "redis")]
pub use redis_impl::{RedisRateLimiter, TieredRedisRateLimiter, redis_rate_limit_middleware};

#[cfg(test)]
mod tests {
    use super::*;

    // --- Path classification tests ---

    #[test]
    fn classify_auth_exact_matches() {
        assert_eq!(classify_path("/oauth/token"), RateLimitTier::Auth);
        assert_eq!(classify_path("/oauth/authorize"), RateLimitTier::Auth);
        assert_eq!(classify_path("/oauth/revoke"), RateLimitTier::Auth);
        assert_eq!(classify_path("/oauth/introspect"), RateLimitTier::Auth);
        assert_eq!(classify_path("/auth/setup"), RateLimitTier::Auth);
        assert_eq!(classify_path("/auth/refresh"), RateLimitTier::Auth);
    }

    #[test]
    fn classify_auth_provider_routes() {
        // /auth/{provider} — OAuth redirect
        assert_eq!(classify_path("/auth/google"), RateLimitTier::Auth);
        assert_eq!(classify_path("/auth/github"), RateLimitTier::Auth);

        // /auth/{provider}/callback — OAuth callback
        assert_eq!(classify_path("/auth/google/callback"), RateLimitTier::Auth);
        assert_eq!(classify_path("/auth/github/callback"), RateLimitTier::Auth);
    }

    #[test]
    fn classify_auth_link_routes() {
        // /auth/link/{provider}
        assert_eq!(classify_path("/auth/link/google"), RateLimitTier::Auth);
        assert_eq!(classify_path("/auth/link/github"), RateLimitTier::Auth);

        // /auth/link/{provider}/callback
        assert_eq!(classify_path("/auth/link/google/callback"), RateLimitTier::Auth);
        assert_eq!(classify_path("/auth/link/github/callback"), RateLimitTier::Auth);
    }

    #[test]
    fn classify_auth_trailing_slash() {
        assert_eq!(classify_path("/oauth/token/"), RateLimitTier::Auth);
        assert_eq!(classify_path("/oauth/introspect/"), RateLimitTier::Auth);
        assert_eq!(classify_path("/auth/setup/"), RateLimitTier::Auth);
        assert_eq!(classify_path("/auth/google/"), RateLimitTier::Auth);
        assert_eq!(classify_path("/auth/link/google/"), RateLimitTier::Auth);
    }

    #[test]
    fn classify_public_endpoints() {
        assert_eq!(classify_path("/health"), RateLimitTier::Public);
        assert_eq!(classify_path("/.well-known/jwks.json"), RateLimitTier::Public);
        assert_eq!(classify_path("/.well-known/openid-configuration"), RateLimitTier::Public);
    }

    #[test]
    fn classify_standard_endpoints() {
        assert_eq!(classify_path("/auth/me"), RateLimitTier::Standard);
        assert_eq!(classify_path("/auth/logout"), RateLimitTier::Standard);
        assert_eq!(classify_path("/auth/logout-all"), RateLimitTier::Standard);
        assert_eq!(classify_path("/auth/sessions"), RateLimitTier::Standard);
        assert_eq!(classify_path("/auth/sessions/some-id"), RateLimitTier::Standard);
        assert_eq!(classify_path("/auth/me/links"), RateLimitTier::Standard);
        assert_eq!(classify_path("/auth/me/username"), RateLimitTier::Standard);
        assert_eq!(classify_path("/admin/users"), RateLimitTier::Standard);
        assert_eq!(classify_path("/admin/webhooks"), RateLimitTier::Standard);
        assert_eq!(classify_path("/oauth/consent"), RateLimitTier::Standard);
    }

    // --- IP extraction tests ---

    #[test]
    fn extract_ip_direct() {
        let req = Request::builder()
            .uri("/test")
            .body(())
            .unwrap();
        assert!(extract_ip(&req, false).is_none());
    }

    #[test]
    fn extract_ip_from_xff_header() {
        let req = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "203.0.113.50, 70.41.3.18, 150.172.238.178")
            .body(())
            .unwrap();
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
        assert!(extract_ip(&req, false).is_none());
    }

    // --- In-memory rate limiter tests ---

    #[test]
    fn in_memory_limiter_allows_within_burst() {
        let tiers = RateLimitTiersConfig::default();
        let limiter = InMemoryRateLimiter::new(&tiers);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Auth tier has 15 requests/60s
        for i in 1..=15 {
            let (allowed, _, _) = limiter.check(RateLimitTier::Auth, &ip);
            assert!(allowed, "request {i} should be allowed");
        }
        let (allowed, remaining, _) = limiter.check(RateLimitTier::Auth, &ip);
        assert!(!allowed, "request 16 should be rate-limited");
        assert_eq!(remaining, 0);
    }

    #[test]
    fn in_memory_limiter_tiers_are_independent() {
        let tiers = RateLimitTiersConfig::default();
        let limiter = InMemoryRateLimiter::new(&tiers);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Exhaust auth tier
        for _ in 0..15 {
            limiter.check(RateLimitTier::Auth, &ip);
        }
        let (allowed, _, _) = limiter.check(RateLimitTier::Auth, &ip);
        assert!(!allowed, "auth should be exhausted");

        // Standard tier should still work
        let (allowed, _, _) = limiter.check(RateLimitTier::Standard, &ip);
        assert!(allowed, "standard should still be available");
    }

    #[test]
    fn in_memory_limiter_different_ips_independent() {
        let tiers = RateLimitTiersConfig::default();
        let limiter = InMemoryRateLimiter::new(&tiers);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust ip1's auth limit
        for _ in 0..15 {
            limiter.check(RateLimitTier::Auth, &ip1);
        }
        let (allowed, _, _) = limiter.check(RateLimitTier::Auth, &ip1);
        assert!(!allowed);

        // ip2 should still have its own limit
        let (allowed, _, _) = limiter.check(RateLimitTier::Auth, &ip2);
        assert!(allowed);
    }

    #[test]
    fn in_memory_retry_after_less_than_window() {
        let tiers = RateLimitTiersConfig::default();
        let limiter = InMemoryRateLimiter::new(&tiers);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Exhaust auth tier (15 requests)
        for _ in 0..15 {
            limiter.check(RateLimitTier::Auth, &ip);
        }
        let (allowed, _, retry_after) = limiter.check(RateLimitTier::Auth, &ip);
        assert!(!allowed);
        // retry_after should be <= window_secs (60), not more
        assert!(retry_after <= 60, "retry_after {retry_after} should be <= 60");
        assert!(retry_after >= 1, "retry_after should be at least 1");
    }
}
