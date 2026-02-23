use std::sync::Arc;

use axum::http::Request;
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

use crate::rate_limit::{InMemoryRateLimiter, memory_rate_limit_middleware};
use crate::server::AppState;

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

async fn jwks(axum::extract::State(state): axum::extract::State<AppState>) -> Json<serde_json::Value> {
    Json(state.keys.jwks())
}

/// OpenID Connect Discovery document (per OpenID Connect Discovery 1.0).
async fn openid_configuration(axum::extract::State(state): axum::extract::State<AppState>) -> Json<serde_json::Value> {
    let base = state.config.server.public_url.trim_end_matches('/');
    let mut scope_names: Vec<&str> = vec!["openid"];
    scope_names.extend(state.config.scopes.definitions.iter().map(|d| d.name.as_str()));

    Json(serde_json::json!({
        "issuer": state.config.jwt.issuer,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "userinfo_endpoint": format!("{base}/auth/me"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "revocation_endpoint": format!("{base}/oauth/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "scopes_supported": scope_names,
        "claims_supported": ["sub", "name", "preferred_username", "picture"],
        "code_challenge_methods_supported": ["S256"],
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
        .layer(middleware::from_fn(require_csrf_header));

    Router::new()
        .route("/health", get(health))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/.well-known/openid-configuration", get(openid_configuration))
        .merge(csrf_protected)
        .merge(oauth_provider::router())
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
