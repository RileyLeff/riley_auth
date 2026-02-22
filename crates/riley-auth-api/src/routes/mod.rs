use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

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

/// Build the application router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/.well-known/jwks.json", get(jwks))
        .merge(auth::router())
        .merge(oauth_provider::router())
        .merge(admin::router())
}
