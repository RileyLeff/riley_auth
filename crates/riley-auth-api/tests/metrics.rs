mod common;
use common::*;

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use metrics_exporter_prometheus::PrometheusHandle;
use riley_auth_api::routes;
use riley_auth_api::server::{AppState, CookieNames};
use riley_auth_core::config::{
    Config, ConfigValue, DatabaseConfig, JwtConfig, KeyConfig, MaintenanceConfig, MetricsConfig,
    OAuthProvidersConfig, RateLimitingConfig, ScopeDefinition, ScopesConfig, ServerConfig,
    SigningAlgorithm, UsernameConfig, WebhooksConfig,
};
use riley_auth_core::jwt::KeySet;
use tokio::net::TcpListener;

/// Shared PrometheusHandle — global recorder can only be installed once per process.
static METRICS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

fn metrics_handle() -> &'static PrometheusHandle {
    METRICS_HANDLE.get_or_init(|| {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .expect("failed to install metrics recorder")
    })
}

/// Build a minimal Config for metrics tests, optionally with bearer token protection.
fn metrics_test_config(
    key_config: KeyConfig,
    bearer_token: Option<ConfigValue>,
) -> Config {
    Config {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            cors_origins: vec![],
            cookie_domain: None,
            public_url: "http://localhost:3000".to_string(),
            behind_proxy: false,
            cookie_prefix: "riley_auth".to_string(),
        },
        database: DatabaseConfig {
            url: ConfigValue::Literal("unused".to_string()),
            max_connections: 10,
            schema: None,
        },
        jwt: JwtConfig {
            keys: vec![key_config],
            private_key_path: None,
            public_key_path: None,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 2_592_000,
            issuer: "riley-auth-test-metrics".to_string(),
            authorization_code_ttl_secs: 300,
            jwks_cache_max_age_secs: 3600,
        },
        oauth: OAuthProvidersConfig::default(),
        storage: None,
        usernames: UsernameConfig::default(),
        scopes: ScopesConfig {
            definitions: vec![ScopeDefinition {
                name: "read:profile".to_string(),
                description: "Read profile".to_string(),
            }],
        },
        rate_limiting: RateLimitingConfig::default(),
        webhooks: WebhooksConfig::default(),
        maintenance: MaintenanceConfig::default(),
        metrics: MetricsConfig {
            enabled: true,
            bearer_token,
        },
    }
}

/// Spin up a test server with the given config and metrics handle.
async fn spawn_metrics_server(
    pool: sqlx::PgPool,
    config: Config,
    handle: PrometheusHandle,
) -> String {
    let key_configs = config.jwt.keys.clone();
    let keys = KeySet::from_configs(&key_configs).expect("failed to load keys");

    let cookie_names = CookieNames::from_prefix(&config.server.cookie_prefix);
    let username_regex = regex::Regex::new(&config.usernames.pattern).unwrap();
    let state = AppState {
        config: Arc::new(config),
        db: pool,
        keys: Arc::new(keys),
        http_client: reqwest::Client::new(),
        cookie_names,
        username_regex,
        metrics_handle: Some(handle),
    };

    let app = axum::Router::new()
        .merge(routes::router_without_rate_limit())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    format!("http://{}", addr)
}

#[test]
#[ignore]
fn metrics_endpoint_returns_404_when_disabled() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let resp = client.get(s.url("/metrics")).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = resp.text().await.unwrap();
        assert_eq!(body, "metrics not enabled");
    });
}

/// Verify /metrics returns Prometheus text format with HTTP request metrics.
#[test]
#[ignore]
fn metrics_endpoint_returns_prometheus_format() {
    let s = server();
    let handle = metrics_handle().clone();
    runtime().block_on(async {
        let key_dir = tempfile::tempdir().unwrap();
        riley_auth_core::jwt::generate_keypair(key_dir.path()).unwrap();
        let key_config = KeyConfig {
            algorithm: SigningAlgorithm::ES256,
            private_key_path: key_dir.path().join("private.pem"),
            public_key_path: key_dir.path().join("public.pem"),
            kid: None,
        };

        let config = metrics_test_config(key_config, None);
        let base = spawn_metrics_server(s.db.clone(), config, handle).await;

        let client = reqwest::Client::new();

        // Make a request to generate some metrics
        let _ = client.get(format!("{}/health", base)).send().await.unwrap();

        // Fetch /metrics
        let resp = client.get(format!("{}/metrics", base)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let content_type = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            content_type.contains("text/plain"),
            "expected text/plain content type, got: {}",
            content_type,
        );

        let body = resp.text().await.unwrap();
        assert!(
            body.contains("riley_auth_http_requests_total"),
            "metrics output should contain HTTP request counter, got: {}",
            &body[..body.len().min(500)],
        );
        assert!(
            body.contains("riley_auth_http_request_duration_seconds"),
            "metrics output should contain HTTP duration histogram",
        );
    });
}

/// Verify /metrics rejects unauthenticated requests when bearer_token is configured.
#[test]
#[ignore]
fn metrics_endpoint_bearer_token_auth() {
    let s = server();
    let handle = metrics_handle().clone();
    runtime().block_on(async {
        let key_dir = tempfile::tempdir().unwrap();
        riley_auth_core::jwt::generate_keypair(key_dir.path()).unwrap();
        let key_config = KeyConfig {
            algorithm: SigningAlgorithm::ES256,
            private_key_path: key_dir.path().join("private.pem"),
            public_key_path: key_dir.path().join("public.pem"),
            kid: None,
        };

        let config = metrics_test_config(
            key_config,
            Some(ConfigValue::Literal("test-metrics-secret".to_string())),
        );
        let base = spawn_metrics_server(s.db.clone(), config, handle).await;

        let client = reqwest::Client::new();

        // No token → 401
        let resp = client.get(format!("{}/metrics", base)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong token → 401
        let resp = client
            .get(format!("{}/metrics", base))
            .header("Authorization", "Bearer wrong-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Correct token → 200
        let resp = client
            .get(format!("{}/metrics", base))
            .header("Authorization", "Bearer test-metrics-secret")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    });
}
