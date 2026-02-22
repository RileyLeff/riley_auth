use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use riley_auth_core::config::Config;

use crate::routes;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
}

pub async fn serve(config: Config, db: PgPool) -> anyhow::Result<()> {
    let addr = SocketAddr::new(config.server.host.parse()?, config.server.port);

    let cors = build_cors(&config);

    let state = AppState {
        config: Arc::new(config),
        db,
    };

    let app = Router::new()
        .merge(routes::router())
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    tracing::info!(%addr, "starting server");
    let listener = TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn build_cors(config: &Config) -> CorsLayer {
    let origins = &config.server.cors_origins;
    if origins.is_empty() {
        CorsLayer::permissive()
    } else {
        let origins: Vec<_> = origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PATCH,
                axum::http::Method::DELETE,
            ])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
            ])
            .allow_credentials(true)
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => tracing::info!("received CTRL+C"),
        _ = sigterm.recv() => tracing::info!("received SIGTERM"),
    }
}
