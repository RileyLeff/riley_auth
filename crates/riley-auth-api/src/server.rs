use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use riley_auth_core::config::Config;
use riley_auth_core::jwt::Keys;

use crate::routes;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub keys: Arc<Keys>,
    pub http_client: reqwest::Client,
}

pub async fn serve(config: Config, db: PgPool, keys: Keys) -> anyhow::Result<()> {
    let addr = SocketAddr::new(config.server.host.parse()?, config.server.port);

    let cors = build_cors(&config);

    let state = AppState {
        config: Arc::new(config),
        db,
        keys: Arc::new(keys),
        http_client: reqwest::Client::new(),
    };

    let behind_proxy = state.config.server.behind_proxy;
    let app = Router::new()
        .merge(routes::router(behind_proxy))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    tracing::info!(%addr, "starting server");
    let listener = TcpListener::bind(addr).await?;

    // Use into_make_service_with_connect_info so tower_governor can extract peer IP
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

fn build_cors(config: &Config) -> CorsLayer {
    let origins = &config.server.cors_origins;
    if origins.is_empty() {
        tracing::warn!("no cors_origins configured — using permissive CORS (not safe for production)");
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
                axum::http::HeaderName::from_static("x-requested-with"),
            ])
            .allow_credentials(true)
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");

        tokio::select! {
            _ = ctrl_c => tracing::info!("received CTRL+C"),
            _ = sigterm.recv() => tracing::info!("received SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        tracing::info!("received CTRL+C");
    }
}
