use std::sync::Arc;

use axum::extract::State;
use axum::http::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;

use riley_auth_core::error::Error;

pub mod admin;
pub mod auth;
pub mod oauth_provider;

use crate::server::AppState;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

async fn health(State(_state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn jwks(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(state.keys.jwks())
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

/// Build the application router.
pub fn router() -> Router<AppState> {
    // Rate limiting: 30 requests per 60 seconds per IP on auth endpoints.
    // Prevents brute-force attacks on login, token exchange, and setup flows.
    let rate_limit_config = GovernorConfigBuilder::default()
        .per_second(2)
        .burst_size(30)
        .finish()
        .expect("invalid rate limit config");

    // Cookie-authenticated routes get CSRF protection + rate limiting.
    // The OAuth provider router (client-credential authenticated) is CSRF-exempt
    // but still rate-limited.
    let csrf_protected = Router::new()
        .merge(auth::router())
        .merge(admin::router())
        .layer(middleware::from_fn(require_csrf_header));

    Router::new()
        .route("/health", get(health))
        .route("/.well-known/jwks.json", get(jwks))
        .merge(csrf_protected)
        .merge(oauth_provider::router())
        .layer(GovernorLayer::new(Arc::new(rate_limit_config)))
}
