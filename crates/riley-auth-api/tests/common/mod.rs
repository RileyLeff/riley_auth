//! Shared test infrastructure for riley-auth integration tests.
//!
//! These tests require a running PostgreSQL 18 instance.
//! Use `scripts/test-integration.sh` to start Docker Compose and run tests,
//! or set DATABASE_URL manually and run:
//!   `cargo test -p riley-auth-api -- --ignored --test-threads=1`
//!
//! Tests are #[ignore]d by default so `cargo test` doesn't require a live database.
//!
//! Tests run serially (--test-threads=1) to avoid DB state conflicts.
//! A single shared tokio runtime and Axum server are used across all tests.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

pub use reqwest::{Client, StatusCode};
pub use riley_auth_core::db;
pub use riley_auth_core::jwt::{self, Claims, KeySet};
pub use serde_json;
pub use uuid;
pub use chrono;
pub use base64;
pub use url;

use riley_auth_api::routes;
use riley_auth_api::server::AppState;
use riley_auth_core::config::{
    Config, ConfigValue, DatabaseConfig, JwtConfig, KeyConfig, MaintenanceConfig, MetricsConfig,
    OAuthProvidersConfig, RateLimitingConfig, ScopeDefinition, ScopesConfig, ServerConfig,
    SigningAlgorithm, UsernameConfig, WebhooksConfig,
};
use sqlx::PgPool;
use tokio::net::TcpListener;

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static SERVER: OnceLock<TestServer> = OnceLock::new();

pub fn runtime() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime")
    })
}

pub fn server() -> &'static TestServer {
    SERVER.get_or_init(|| runtime().block_on(TestServer::init()))
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub db: PgPool,
    pub keys: Arc<KeySet>,
    pub config: Arc<Config>,
    pub _key_dir: tempfile::TempDir,
}

impl TestServer {
    async fn init() -> Self {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set for integration tests");

        let db_config = DatabaseConfig {
            url: ConfigValue::Literal(database_url),
            max_connections: 10,
            schema: None,
        };

        let pool = db::connect(&db_config)
            .await
            .expect("failed to connect to database");
        db::migrate(&pool).await.expect("failed to run migrations");

        // Generate test keys (ES256 by default)
        let key_dir = tempfile::tempdir().expect("failed to create temp dir");
        jwt::generate_keypair(key_dir.path()).expect("failed to generate keypair");

        let private_path = key_dir.path().join("private.pem");
        let public_path = key_dir.path().join("public.pem");
        let key_config = KeyConfig {
            algorithm: SigningAlgorithm::ES256,
            private_key_path: private_path.clone(),
            public_key_path: public_path.clone(),
            kid: None,
        };
        let keys = KeySet::from_configs(&[key_config.clone()]).expect("failed to load keys");

        let config = Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
                cors_origins: vec![],
                cookie_domain: None,
                public_url: "http://localhost:3000".to_string(),
                behind_proxy: false,
                cookie_prefix: "auth".to_string(),
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
                issuer: "riley-auth-test".to_string(),
                authorization_code_ttl_secs: 300,
                jwks_cache_max_age_secs: 3600,
            },
            oauth: OAuthProvidersConfig {
                consent_url: Some("https://auth.example.com/consent".to_string()),
                ..OAuthProvidersConfig::default()
            },
            usernames: UsernameConfig::default(),
            scopes: ScopesConfig {
                definitions: vec![
                    ScopeDefinition {
                        name: "read:profile".to_string(),
                        description: "Read your profile information".to_string(),
                    },
                    ScopeDefinition {
                        name: "write:profile".to_string(),
                        description: "Update your profile information".to_string(),
                    },
                ],
            },
            rate_limiting: RateLimitingConfig::default(),
            webhooks: WebhooksConfig::default(),
            maintenance: MaintenanceConfig::default(),
            metrics: MetricsConfig::default(),
        };

        let cookie_names = riley_auth_api::server::CookieNames::from_prefix(&config.server.cookie_prefix);
        let username_regex = regex::Regex::new(&config.usernames.pattern).unwrap();
        let state = AppState {
            config: Arc::new(config.clone()),
            db: pool.clone(),
            keys: Arc::new(keys.clone()),
            http_client: reqwest::Client::new(),
            cookie_names,
            username_regex,
            metrics_handle: None,
            providers: Arc::new(vec![]),
            oauth_client: reqwest::Client::new(),
        };

        let app = axum::Router::new()
            .merge(routes::router_without_rate_limit())
            .layer(tower_http::trace::TraceLayer::new_for_http())
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

        TestServer {
            addr,
            db: pool,
            keys: Arc::new(keys),
            config: Arc::new(config),
            _key_dir: key_dir,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    /// Fresh reqwest client per test — avoids cookie bleed between tests.
    pub fn client(&self) -> Client {
        Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    /// Create a test user directly in the database and return session tokens.
    pub async fn create_user_with_session(
        &self,
        username: &str,
        role: &str,
    ) -> (db::User, String, String) {
        let user = db::create_user_with_link(
            &self.db,
            username,
            Some(&format!("{username} Display")),
            None,
            "google",
            &format!("google-id-{username}"),
            Some(&format!("{username}@example.com")),
            true,
        )
        .await
        .expect("failed to create user");

        if role == "admin" {
            db::update_user_role(&self.db, user.id, "admin")
                .await
                .expect("failed to promote user");
        }

        let effective_role = if role == "admin" { "admin" } else { &user.role };
        let access_token = self
            .keys
            .sign_access_token(
                &self.config.jwt,
                &user.id.to_string(),
                &user.username,
                effective_role,
                &self.config.jwt.issuer,
            )
            .expect("failed to sign access token");

        let (refresh_raw, refresh_hash) = jwt::generate_refresh_token();
        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(self.config.jwt.refresh_token_ttl_secs as i64);
        db::store_refresh_token(&self.db, user.id, None, &refresh_hash, expires_at, &[], None, None, uuid::Uuid::now_v7(), None, None)
            .await
            .expect("failed to store refresh token");

        (user, access_token, refresh_raw)
    }

    /// Clean test data for isolation between serial tests.
    pub async fn cleanup(&self) {
        clean_database(&self.db).await;
    }
}

pub async fn clean_database(pool: &PgPool) {
    sqlx::query("DELETE FROM webhook_deliveries")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM webhook_outbox")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM webhooks")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM authorization_codes")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM consumed_refresh_tokens")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM refresh_tokens")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM username_history")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM consent_requests")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM oauth_links")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM oauth_clients")
        .execute(pool)
        .await
        .unwrap();
}
