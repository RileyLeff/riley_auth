use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use riley_auth_core::config::Config;
use riley_auth_core::jwt::Keys;
use riley_auth_core::webhooks;

use crate::routes;

/// Cookie names derived from the configurable prefix.
#[derive(Clone, Debug)]
pub struct CookieNames {
    pub access: String,
    pub refresh: String,
    pub oauth_state: String,
    pub pkce: String,
    pub setup: String,
}

impl CookieNames {
    pub fn from_prefix(prefix: &str) -> Self {
        Self {
            access: format!("{prefix}_access"),
            refresh: format!("{prefix}_refresh"),
            oauth_state: format!("{prefix}_oauth_state"),
            pkce: format!("{prefix}_pkce"),
            setup: format!("{prefix}_setup"),
        }
    }
}

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub keys: Arc<Keys>,
    pub http_client: reqwest::Client,
    pub cookie_names: CookieNames,
    pub username_regex: regex::Regex,
}

pub async fn serve(config: Config, db: PgPool, keys: Keys) -> anyhow::Result<()> {
    let addr = SocketAddr::new(config.server.host.parse()?, config.server.port);

    let cors = build_cors(&config);

    let behind_proxy = config.server.behind_proxy;
    let rate_limit_backend = config.rate_limiting.backend.as_str();

    // Build router with appropriate rate limiting backend
    let base_router = match rate_limit_backend {
        #[cfg(feature = "redis")]
        "redis" => {
            let redis_url = config
                .rate_limiting
                .redis_url
                .as_ref()
                .expect("redis_url validated at config load")
                .resolve()?;
            let limiter =
                crate::rate_limit::TieredRedisRateLimiter::new(&redis_url, &config.rate_limiting.tiers)
                    .await?;
            let limiter = Arc::new(limiter);
            tracing::info!("rate limiting backend: redis (tiered)");
            routes::router_with_redis_rate_limit(behind_proxy, limiter)
        }
        #[cfg(not(feature = "redis"))]
        "redis" => {
            anyhow::bail!(
                "rate_limiting.backend is \"redis\" but riley-auth was compiled without \
                 the `redis` feature. Rebuild with `--features redis`."
            );
        }
        _ => {
            tracing::info!("rate limiting backend: in-memory (tiered)");
            routes::router(behind_proxy, &config.rate_limiting.tiers)
        }
    };

    let cookie_names = CookieNames::from_prefix(&config.server.cookie_prefix);
    let http_client = webhooks::build_webhook_client(config.webhooks.allow_private_ips);
    if !config.webhooks.allow_private_ips {
        tracing::info!("SSRF protection enabled for webhook delivery");
    }
    let username_regex = regex::Regex::new(&config.usernames.pattern)
        .map_err(|e| anyhow::anyhow!("invalid username pattern: {e}"))?;
    let config = Arc::new(config);
    let state = AppState {
        config: Arc::clone(&config),
        db: db.clone(),
        keys: Arc::new(keys),
        http_client: http_client.clone(),
        cookie_names,
        username_regex,
    };

    let app = Router::new()
        .merge(base_router)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Shutdown coordination: signal both the HTTP server and background workers
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start the webhook delivery worker
    let delivery_shutdown = shutdown_rx.clone();
    let block_private_ips = !config.webhooks.allow_private_ips;
    let worker_handle = tokio::spawn(webhooks::delivery_worker(
        db.clone(),
        http_client,
        config.webhooks.max_concurrent_deliveries,
        block_private_ips,
        delivery_shutdown,
    ));

    // Start the maintenance cleanup worker
    let cleanup_handle = tokio::spawn(maintenance_worker(
        db,
        Arc::clone(&config),
        shutdown_rx,
    ));

    tracing::info!(%addr, "starting server");
    let listener = TcpListener::bind(addr).await?;

    // Use into_make_service_with_connect_info so rate limit middleware
    // can extract peer IP
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    })
    .await?;

    // Wait for workers to finish draining
    let _ = worker_handle.await;
    let _ = cleanup_handle.await;

    Ok(())
}

/// Background maintenance worker that periodically cleans up expired data.
async fn maintenance_worker(
    pool: PgPool,
    config: Arc<Config>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let interval = std::time::Duration::from_secs(config.maintenance.cleanup_interval_secs);
    let retention_days = config.maintenance.webhook_delivery_retention_days as i64;
    let consumed_token_cutoff_secs = config.jwt.refresh_token_ttl_secs * 2;

    tracing::info!(
        interval_secs = config.maintenance.cleanup_interval_secs,
        "maintenance worker started"
    );

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                tracing::info!("maintenance worker shutting down");
                return;
            }
        }

        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(consumed_token_cutoff_secs as i64);

        match riley_auth_core::db::cleanup_expired_tokens(&pool).await {
            Ok(n) if n > 0 => tracing::info!(count = n, "cleaned up expired refresh tokens"),
            Err(e) => tracing::warn!("cleanup_expired_tokens failed: {e}"),
            _ => {}
        }

        match riley_auth_core::db::cleanup_expired_auth_codes(&pool).await {
            Ok(n) if n > 0 => tracing::info!(count = n, "cleaned up expired auth codes"),
            Err(e) => tracing::warn!("cleanup_expired_auth_codes failed: {e}"),
            _ => {}
        }

        match riley_auth_core::db::cleanup_expired_consent_requests(&pool).await {
            Ok(n) if n > 0 => tracing::info!(count = n, "cleaned up expired consent requests"),
            Err(e) => tracing::warn!("cleanup_expired_consent_requests failed: {e}"),
            _ => {}
        }

        match riley_auth_core::db::cleanup_consumed_refresh_tokens(&pool, cutoff).await {
            Ok(n) if n > 0 => tracing::info!(count = n, "cleaned up consumed refresh tokens"),
            Err(e) => tracing::warn!("cleanup_consumed_refresh_tokens failed: {e}"),
            _ => {}
        }

        match riley_auth_core::db::cleanup_webhook_deliveries(&pool, retention_days).await {
            Ok(n) if n > 0 => tracing::info!(count = n, "cleaned up old webhook deliveries"),
            Err(e) => tracing::warn!("cleanup_webhook_deliveries failed: {e}"),
            _ => {}
        }

        match riley_auth_core::db::cleanup_webhook_outbox(&pool, retention_days).await {
            Ok(n) if n > 0 => tracing::info!(count = n, "cleaned up old outbox entries"),
            Err(e) => tracing::warn!("cleanup_webhook_outbox failed: {e}"),
            _ => {}
        }

        match riley_auth_core::db::reset_stuck_outbox_entries(
            &pool,
            config.webhooks.stuck_processing_timeout_secs,
        ).await {
            Ok(n) if n > 0 => tracing::info!(count = n, "reset stuck processing outbox entries"),
            Err(e) => tracing::warn!("reset_stuck_outbox_entries failed: {e}"),
            _ => {}
        }
    }
}

fn build_cors(config: &Config) -> CorsLayer {
    let origins = &config.server.cors_origins;
    if origins.is_empty() {
        tracing::warn!("no cors_origins configured — using permissive CORS (not safe for production)");
        CorsLayer::permissive()
    } else {
        let origins: Vec<_> = origins
            .iter()
            .filter_map(|o| match o.parse() {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!("ignoring unparseable CORS origin {o:?}: {e}");
                    None
                }
            })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_names_default_prefix() {
        let names = CookieNames::from_prefix("riley_auth");
        assert_eq!(names.access, "riley_auth_access");
        assert_eq!(names.refresh, "riley_auth_refresh");
        assert_eq!(names.oauth_state, "riley_auth_oauth_state");
        assert_eq!(names.pkce, "riley_auth_pkce");
        assert_eq!(names.setup, "riley_auth_setup");
    }

    #[test]
    fn cookie_names_custom_prefix() {
        let names = CookieNames::from_prefix("myapp");
        assert_eq!(names.access, "myapp_access");
        assert_eq!(names.refresh, "myapp_refresh");
        assert_eq!(names.oauth_state, "myapp_oauth_state");
        assert_eq!(names.pkce, "myapp_pkce");
        assert_eq!(names.setup, "myapp_setup");
    }
}
