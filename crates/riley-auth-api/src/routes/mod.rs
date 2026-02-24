use std::net::IpAddr;
use std::sync::Arc;

use axum::http::{HeaderMap, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use riley_auth_core::config::RateLimitTiersConfig;
use riley_auth_core::error::Error;

pub mod admin;
pub mod auth;
pub mod oauth_provider;

use crate::metrics::{http_metrics_middleware, metrics_endpoint};
use crate::rate_limit::{InMemoryRateLimiter, memory_rate_limit_middleware};
use crate::server::AppState;

/// Extract client IP from request headers with proxy support.
///
/// When `behind_proxy` is true, checks `X-Forwarded-For` (first entry) and
/// `X-Real-IP` before falling back to `peer_ip`. The proxy **must** overwrite
/// (not append to) these headers with the real client IP.
pub fn extract_client_ip(headers: &HeaderMap, peer_ip: Option<IpAddr>, behind_proxy: bool) -> Option<IpAddr> {
    if behind_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    peer_ip
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

async fn health(axum::extract::State(_state): axum::extract::State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn jwks(axum::extract::State(state): axum::extract::State<AppState>) -> (HeaderMap, Json<serde_json::Value>) {
    let mut headers = HeaderMap::new();
    let max_age = state.config.jwt.jwks_cache_max_age_secs;
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        format!("public, max-age={max_age}").parse().unwrap(),
    );
    (headers, Json(state.keys.jwks()))
}

/// OpenID Connect Discovery document (per OpenID Connect Discovery 1.0).
async fn openid_configuration(axum::extract::State(state): axum::extract::State<AppState>) -> Json<serde_json::Value> {
    let base = state.config.server.public_url.trim_end_matches('/');
    let mut scope_names: Vec<&str> = vec!["openid", "profile", "email"];
    scope_names.extend(state.config.scopes.definitions.iter().map(|d| d.name.as_str()));

    let signing_algs: Vec<String> = state.keys.algorithms().into_iter().map(|a| a.to_string()).collect();

    Json(serde_json::json!({
        "issuer": state.config.jwt.issuer,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "userinfo_endpoint": format!("{base}/oauth/userinfo"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "revocation_endpoint": format!("{base}/oauth/revoke"),
        "introspection_endpoint": format!("{base}/oauth/introspect"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": signing_algs,
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": false,
        "scopes_supported": scope_names,
        "claims_supported": ["sub", "name", "preferred_username", "picture", "email", "email_verified", "updated_at", "auth_time"],
        "code_challenge_methods_supported": ["S256"],
        "prompt_values_supported": ["none", "login", "consent"],
    }))
}

/// CSRF protection: require `X-Requested-With` header on non-safe HTTP methods.
/// Simple form submissions and cross-origin requests cannot set custom headers
/// without a CORS preflight, so this blocks CSRF from subdomains or foreign origins.
async fn require_csrf_header(
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, Error> {
    let dominated_by_method = matches!(
        *request.method(),
        axum::http::Method::POST
            | axum::http::Method::PATCH
            | axum::http::Method::PUT
            | axum::http::Method::DELETE
    );
    if dominated_by_method && !request.headers().contains_key("x-requested-with") {
        return Err(Error::Forbidden);
    }
    Ok(next.run(request).await)
}

/// Build the base router without rate limiting (shared by all backends).
fn base_router() -> Router<AppState> {
    let csrf_protected = Router::new()
        .merge(auth::router())
        .merge(admin::router())
        .merge(oauth_provider::consent_router())
        .layer(middleware::from_fn(require_csrf_header));

    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_endpoint))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/.well-known/openid-configuration", get(openid_configuration))
        .merge(csrf_protected)
        .merge(oauth_provider::router())
        .layer(middleware::from_fn(http_metrics_middleware))
}

/// Build the application router with in-memory tiered rate limiting.
///
/// When `behind_proxy` is true, rate limiting extracts client IP from
/// `X-Forwarded-For` / `X-Real-IP` headers (falling back to peer IP).
///
/// # Security: proxy header spoofing
///
/// When `behind_proxy` is true, the reverse proxy **must** overwrite (not
/// append to) the `X-Forwarded-For` header with the actual peer IP.
/// Otherwise, malicious clients can bypass rate limiting by sending a
/// spoofed `X-Forwarded-For` header with a random IP.
pub fn router(behind_proxy: bool, tiers: &RateLimitTiersConfig) -> Router<AppState> {
    let limiter = Arc::new(InMemoryRateLimiter::new(tiers));
    base_router().layer(middleware::from_fn(move |req, next| {
        let limiter = limiter.clone();
        memory_rate_limit_middleware(limiter, behind_proxy, req, next)
    }))
}

/// Build the application router without rate limiting (for tests).
pub fn router_without_rate_limit() -> Router<AppState> {
    base_router()
}

/// Build the application router with Redis-backed tiered rate limiting.
#[cfg(feature = "redis")]
pub fn router_with_redis_rate_limit(
    behind_proxy: bool,
    limiter: Arc<crate::rate_limit::TieredRedisRateLimiter>,
) -> Router<AppState> {
    base_router().layer(middleware::from_fn(move |req, next| {
        let limiter = limiter.clone();
        crate::rate_limit::redis_rate_limit_middleware(limiter, behind_proxy, req, next)
    }))
}
