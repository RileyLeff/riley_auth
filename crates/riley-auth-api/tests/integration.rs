//! Integration tests for riley-auth.
//!
//! These tests require a running PostgreSQL 18 instance.
//! Use `scripts/test-integration.sh` to start Docker Compose and run tests,
//! or set DATABASE_URL manually and run:
//!   `cargo test --test integration -- --include-ignored --test-threads=1`
//!
//! Tests are #[ignore]d by default so `cargo test` doesn't require a live database.
//!
//! Tests run serially (--test-threads=1) to avoid DB state conflicts.
//! A single shared tokio runtime and Axum server are used across all tests.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use reqwest::{Client, StatusCode};
use riley_auth_api::routes;
use riley_auth_api::server::AppState;
use riley_auth_core::config::{
    Config, ConfigValue, DatabaseConfig, JwtConfig, OAuthProvidersConfig, RateLimitingConfig,
    ScopeDefinition, ScopesConfig, ServerConfig, UsernameConfig,
};
use riley_auth_core::db;
use riley_auth_core::jwt::{self, Keys};
use sqlx::PgPool;
use tokio::net::TcpListener;

// --- Shared test infrastructure ---

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static SERVER: OnceLock<TestServer> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime")
    })
}

fn server() -> &'static TestServer {
    SERVER.get_or_init(|| runtime().block_on(TestServer::init()))
}

struct TestServer {
    addr: SocketAddr,
    db: PgPool,
    keys: Arc<Keys>,
    config: Arc<Config>,
    _key_dir: tempfile::TempDir,
}

// TempDir is Send + Sync; all other fields are Send + Sync.
unsafe impl Sync for TestServer {}

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

        // Generate test keys
        let key_dir = tempfile::tempdir().expect("failed to create temp dir");
        jwt::generate_keypair(key_dir.path()).expect("failed to generate keypair");

        let private_path = key_dir.path().join("private.pem");
        let public_path = key_dir.path().join("public.pem");
        let keys = Keys::from_pem_files(&private_path, &public_path).expect("failed to load keys");

        let config = Config {
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
                private_key_path: private_path,
                public_key_path: public_path,
                access_token_ttl_secs: 900,
                refresh_token_ttl_secs: 2_592_000,
                issuer: "riley-auth-test".to_string(),
                authorization_code_ttl_secs: 300,
            },
            oauth: OAuthProvidersConfig::default(),
            storage: None,
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
        };

        let cookie_names = riley_auth_api::server::CookieNames::from_prefix(&config.server.cookie_prefix);
        let state = AppState {
            config: Arc::new(config.clone()),
            db: pool.clone(),
            keys: Arc::new(keys.clone()),
            http_client: reqwest::Client::new(),
            cookie_names,
        };

        let app = axum::Router::new()
            .merge(routes::router_with_rate_limit(false, false))
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

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    /// Fresh reqwest client per test — avoids cookie bleed between tests.
    fn client(&self) -> Client {
        Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    /// Create a test user directly in the database and return session tokens.
    async fn create_user_with_session(
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
        db::store_refresh_token(&self.db, user.id, None, &refresh_hash, expires_at, &[], None, None)
            .await
            .expect("failed to store refresh token");

        (user, access_token, refresh_raw)
    }

    /// Clean test data for isolation between serial tests.
    async fn cleanup(&self) {
        clean_database(&self.db).await;
    }
}

async fn clean_database(pool: &PgPool) {
    sqlx::query("DELETE FROM webhook_deliveries")
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
    sqlx::query("DELETE FROM refresh_tokens")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM username_history")
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

// --- Tests ---
// Run with: cargo test --test integration -- --test-threads=1

#[test]
#[ignore]
fn health_check() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let resp = client.get(s.url("/health")).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "ok");
        assert!(body["version"].as_str().is_some());
    });
}

#[test]
#[ignore]
fn jwks_endpoint() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let resp = client
            .get(s.url("/.well-known/jwks.json"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = resp.json().await.unwrap();
        let keys = body["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "RSA");
        assert_eq!(keys[0]["alg"], "RS256");
        assert!(keys[0]["n"].as_str().unwrap().len() > 100);
    });
}

#[test]
#[ignore]
fn auth_me_unauthenticated() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let resp = client.get(s.url("/auth/me")).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    });
}

#[test]
#[ignore]
fn auth_me_authenticated() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, access_token, _) = s.create_user_with_session("testuser", "user").await;

        let resp = client
            .get(s.url("/auth/me"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["username"], "testuser");
        assert_eq!(body["id"], user.id.to_string());
        assert_eq!(body["role"], "user");
    });
}

#[test]
#[ignore]
fn update_display_name() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("dispuser", "user").await;

        let resp = client
            .patch(s.url("/auth/me"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({ "display_name": "New Display Name" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["display_name"], "New Display Name");
    });
}

#[test]
#[ignore]
fn update_username() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("oldname", "user").await;

        let resp = client
            .patch(s.url("/auth/me/username"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({ "username": "newname" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["username"], "newname");

        let held = db::is_username_held(&s.db, "oldname").await.unwrap();
        assert!(held);
    });
}

#[test]
#[ignore]
fn username_validation_rejects_invalid() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("validuser", "user").await;

        // Too short — validates end-to-end that username rules are enforced
        let resp = client
            .patch(s.url("/auth/me/username"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({ "username": "ab" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    });
}

#[test]
#[ignore]
fn refresh_token_rotation() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, _, refresh_raw) = s.create_user_with_session("refresher", "user").await;

        let resp = client
            .post(s.url("/auth/refresh"))
            .header("cookie", format!("riley_auth_refresh={refresh_raw}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let cookies: Vec<_> = resp.cookies().collect();
        assert!(
            cookies.iter().any(|c| c.name() == "riley_auth_access"),
            "should set new access token cookie"
        );

        // Old refresh token should be consumed
        let resp2 = client
            .post(s.url("/auth/refresh"))
            .header("cookie", format!("riley_auth_refresh={refresh_raw}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
    });
}

#[test]
#[ignore]
fn logout() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, refresh_raw) =
            s.create_user_with_session("logoutuser", "user").await;

        let resp = client
            .post(s.url("/auth/logout"))
            .header(
                "cookie",
                format!("riley_auth_access={access_token}; riley_auth_refresh={refresh_raw}"),
            )
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let hash = jwt::hash_token(&refresh_raw);
        let token = db::find_refresh_token(&s.db, &hash).await.unwrap();
        assert!(token.is_none());
    });
}

#[test]
#[ignore]
fn logout_all() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, access_token, _) = s.create_user_with_session("logoutall", "user").await;

        let (_, hash2) = jwt::generate_refresh_token();
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(86400);
        db::store_refresh_token(&s.db, user.id, None, &hash2, expires_at, &[], None, None)
            .await
            .unwrap();

        let resp = client
            .post(s.url("/auth/logout-all"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token = db::find_refresh_token(&s.db, &hash2).await.unwrap();
        assert!(token.is_none());
    });
}

#[test]
#[ignore]
fn list_links() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("linkuser", "user").await;

        let resp = client
            .get(s.url("/auth/me/links"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(body.len(), 1);
        assert_eq!(body[0]["provider"], "google");
    });
}

#[test]
#[ignore]
fn csrf_protection() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("csrfuser", "user").await;

        // PATCH without X-Requested-With header should be rejected
        let resp = client
            .patch(s.url("/auth/me"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .json(&serde_json::json!({ "display_name": "test" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // With header should succeed
        let resp = client
            .patch(s.url("/auth/me"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({ "display_name": "test" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    });
}

#[test]
#[ignore]
fn delete_account() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("deleteuser", "user").await;

        let resp = client
            .delete(s.url("/auth/me"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let user = db::find_user_by_username(&s.db, "deleteuser")
            .await
            .unwrap();
        assert!(user.is_none(), "deleted user should not be findable");
    });
}

// --- Admin tests ---

#[test]
#[ignore]
fn admin_list_users() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("adminuser", "admin").await;
        s.create_user_with_session("regular", "user").await;

        let resp = client
            .get(s.url("/admin/users"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(body.len() >= 2);
    });
}

#[test]
#[ignore]
fn admin_requires_admin_role() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, user_token, _) = s.create_user_with_session("nonadmin", "user").await;

        let resp = client
            .get(s.url("/admin/users"))
            .header("cookie", format!("riley_auth_access={user_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    });
}

#[test]
#[ignore]
fn admin_register_and_remove_client() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("clientadmin", "admin").await;

        let resp = client
            .post(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "name": "Test App",
                "redirect_uris": ["https://testapp.example.com/callback"],
                "auto_approve": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let client_resp: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(client_resp["name"], "Test App");
        assert!(!client_resp["client_id"].as_str().unwrap().is_empty());
        assert!(!client_resp["client_secret"].as_str().unwrap().is_empty());

        let client_id = client_resp["id"].as_str().unwrap().to_string();

        // List clients
        let resp = client
            .get(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let clients: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(clients.iter().any(|c| c["name"] == "Test App"));

        // Remove client
        let resp = client
            .delete(s.url(&format!("/admin/clients/{client_id}")))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    });
}

// --- OAuth Provider flow ---

#[test]
#[ignore]
fn oauth_provider_full_flow() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("oauthowner", "user").await;

        let client_id_str = "test-client-id";
        let client_secret = "test-client-secret-value";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Integration Test Client",
            client_id_str,
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Authorize
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("state", "test-state-123"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();
        let state = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .to_string();
        assert_eq!(state, "test-state-123");

        // Exchange code for tokens
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://app.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(token_resp["token_type"], "Bearer");
        assert!(token_resp["access_token"].as_str().unwrap().len() > 100);
        let refresh_token = token_resp["refresh_token"].as_str().unwrap().to_string();

        let token_data = s
            .keys
            .verify_access_token(
                &s.config.jwt,
                token_resp["access_token"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(token_data.claims.aud, client_id_str);
        assert_eq!(token_data.claims.username, "oauthowner");

        // Refresh
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let refresh_resp: serde_json::Value = resp.json().await.unwrap();
        let new_refresh = refresh_resp["refresh_token"].as_str().unwrap().to_string();
        assert_ne!(new_refresh, refresh_token, "refresh token should be rotated");

        // Old refresh token consumed
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Revoke
        let resp = client
            .post(s.url("/oauth/revoke"))
            .form(&[
                ("token", new_refresh.as_str()),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Revoked token no longer works
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &new_refresh),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    });
}

#[test]
#[ignore]
fn oauth_provider_rejects_bad_client() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("badclient", "user").await;

        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "nonexistent"),
                ("redirect_uri", "https://evil.com/callback"),
                ("response_type", "code"),
                ("code_challenge", "test"),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    });
}

#[test]
#[ignore]
fn oauth_provider_rejects_wrong_redirect_uri() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("wrongredir", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Strict Client",
            "strict-client-id",
            &secret_hash,
            &["https://allowed.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "strict-client-id"),
                ("redirect_uri", "https://evil.com/callback"),
                ("response_type", "code"),
                ("code_challenge", "test"),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    });
}

#[test]
#[ignore]
fn last_admin_protection() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (admin, admin_token, _) = s.create_user_with_session("soleadmin", "admin").await;

        // Cannot demote last admin (DB is clean, so this is the only admin)
        let resp = client
            .patch(s.url(&format!("/admin/users/{}/role", admin.id)))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({ "role": "user" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body["detail"].as_str().unwrap().contains("last admin"));
    });
}

#[test]
#[ignore]
fn cross_audience_token_rejected() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, _, _) = s.create_user_with_session("auduser", "user").await;

        let client_token = s
            .keys
            .sign_access_token(
                &s.config.jwt,
                &user.id.to_string(),
                &user.username,
                &user.role,
                "some-client-id",
            )
            .unwrap();

        let resp = client
            .get(s.url("/auth/me"))
            .header("cookie", format!("riley_auth_access={client_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    });
}

// --- Scope tests ---

#[test]
#[ignore]
fn oauth_scopes_full_flow() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("scopeuser", "user").await;

        // Register client with allowed scopes
        let client_id_str = "scope-test-client";
        let client_secret = "scope-test-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Scope Test Client",
            client_id_str,
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string(), "write:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Authorize with scopes
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "read:profile write:profile"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();

        // Exchange code for tokens — should include scope in response
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://app.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(token_resp["scope"], "read:profile write:profile");
        let refresh_token = token_resp["refresh_token"].as_str().unwrap().to_string();

        // Verify JWT has scope claim
        let token_data = s
            .keys
            .verify_access_token(
                &s.config.jwt,
                token_resp["access_token"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(token_data.claims.scope.as_deref(), Some("read:profile write:profile"));

        // Refresh — scopes should be preserved
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let refresh_resp: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(refresh_resp["scope"], "read:profile write:profile");

        // Verify refreshed JWT also has scope claim
        let token_data = s
            .keys
            .verify_access_token(
                &s.config.jwt,
                refresh_resp["access_token"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(token_data.claims.scope.as_deref(), Some("read:profile write:profile"));
    });
}

#[test]
#[ignore]
fn oauth_rejects_unauthorized_scope() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("badscopeuser", "user").await;

        // Register client with only read:profile allowed
        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Limited Client",
            "limited-client-id",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Request write:profile which is NOT in client's allowed_scopes
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "limited-client-id"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "read:profile write:profile"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    });
}

#[test]
#[ignore]
fn oauth_rejects_unknown_scope() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("unknownscopeuser", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Unknown Scope Client",
            "unknown-scope-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Request a scope that doesn't exist in config definitions
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "unknown-scope-client"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "admin:everything"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    });
}

#[test]
#[ignore]
fn oauth_no_scopes_omits_scope_field() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("noscopeuser", "user").await;

        let client_id_str = "noscope-client";
        let client_secret = "noscope-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "No Scope Client",
            client_id_str,
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Authorize without requesting scopes
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();

        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://app.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();
        // scope field should be absent (skip_serializing_if = "Option::is_none")
        assert!(token_resp.get("scope").is_none());

        // JWT should have no scope claim
        let token_data = s
            .keys
            .verify_access_token(
                &s.config.jwt,
                token_resp["access_token"].as_str().unwrap(),
            )
            .unwrap();
        assert!(token_data.claims.scope.is_none());
    });
}

#[test]
#[ignore]
fn consent_endpoint_returns_scope_descriptions() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("consentuser", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Consent Test Client",
            "consent-test-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string(), "write:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        let resp = client
            .get(s.url("/oauth/consent"))
            .query(&[
                ("client_id", "consent-test-client"),
                ("scope", "read:profile write:profile"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["client_name"], "Consent Test Client");
        let scopes = body["scopes"].as_array().unwrap();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0]["name"], "read:profile");
        assert_eq!(scopes[0]["description"], "Read your profile information");
        assert_eq!(scopes[1]["name"], "write:profile");
        assert_eq!(scopes[1]["description"], "Update your profile information");
    });
}

#[test]
#[ignore]
fn consent_endpoint_rejects_disallowed_scope() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("consentbad", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Consent Limited Client",
            "consent-limited-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string()], // only read:profile allowed
            true,
        )
        .await
        .unwrap();

        // Request write:profile which is NOT in client's allowed_scopes
        let resp = client
            .get(s.url("/oauth/consent"))
            .query(&[
                ("client_id", "consent-limited-client"),
                ("scope", "read:profile write:profile"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    });
}

#[test]
#[ignore]
fn consent_endpoint_requires_session_token() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // No cookie — should be rejected
        let resp = client
            .get(s.url("/oauth/consent"))
            .query(&[("client_id", "anything")])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    });
}

#[test]
#[ignore]
fn oauth_deduplicates_scopes() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("dedupuser", "user").await;

        let client_id_str = "dedup-client";
        let client_secret = "dedup-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Dedup Client",
            client_id_str,
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string(), "write:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Request duplicate scopes
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "read:profile read:profile write:profile"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();

        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://app.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();
        // Scope should be deduplicated
        assert_eq!(token_resp["scope"], "read:profile write:profile");

        // JWT scope claim should also be deduplicated
        let token_data = s
            .keys
            .verify_access_token(
                &s.config.jwt,
                token_resp["access_token"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(token_data.claims.scope.as_deref(), Some("read:profile write:profile"));
    });
}

#[test]
#[ignore]
fn admin_register_client_with_scopes() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("scopeadmin", "admin").await;

        // Register client with valid scopes
        let resp = client
            .post(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "name": "Scoped App",
                "redirect_uris": ["https://app.example.com/callback"],
                "allowed_scopes": ["read:profile"],
                "auto_approve": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["allowed_scopes"], serde_json::json!(["read:profile"]));

        // List clients — verify scopes persisted
        let resp = client
            .get(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let clients: Vec<serde_json::Value> = resp.json().await.unwrap();
        let scoped_client = clients.iter().find(|c| c["name"] == "Scoped App").unwrap();
        assert_eq!(scoped_client["allowed_scopes"], serde_json::json!(["read:profile"]));
    });
}

#[test]
#[ignore]
fn admin_rejects_undefined_scope() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("badscopeadmin", "admin").await;

        // Register client with a scope that doesn't exist in config definitions
        let resp = client
            .post(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "name": "Bad Scope App",
                "redirect_uris": ["https://app.example.com/callback"],
                "allowed_scopes": ["admin:nuclear"],
                "auto_approve": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    });
}

#[test]
#[ignore]
fn admin_rejects_invalid_scope_name() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("invalidscopeadmin", "admin").await;

        // Register client with a scope name containing whitespace (injection attempt)
        let resp = client
            .post(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "name": "Whitespace Scope App",
                "redirect_uris": ["https://app.example.com/callback"],
                "allowed_scopes": ["read:profile write:profile"],
                "auto_approve": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    });
}

#[test]
#[ignore]
fn oidc_discovery_document() {
    let s = server();
    runtime().block_on(async {
        let client = s.client();

        let resp = client
            .get(s.url("/.well-known/openid-configuration"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let doc: serde_json::Value = resp.json().await.unwrap();

        // Required OIDC Discovery fields
        assert_eq!(doc["issuer"], "riley-auth-test");
        assert_eq!(
            doc["authorization_endpoint"],
            "http://localhost:3000/oauth/authorize"
        );
        assert_eq!(
            doc["token_endpoint"],
            "http://localhost:3000/oauth/token"
        );
        assert_eq!(
            doc["jwks_uri"],
            "http://localhost:3000/.well-known/jwks.json"
        );
        assert_eq!(
            doc["revocation_endpoint"],
            "http://localhost:3000/oauth/revoke"
        );

        // Supported values
        assert_eq!(doc["response_types_supported"], serde_json::json!(["code"]));
        assert_eq!(
            doc["grant_types_supported"],
            serde_json::json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(doc["subject_types_supported"], serde_json::json!(["public"]));
        assert_eq!(
            doc["id_token_signing_alg_values_supported"],
            serde_json::json!(["RS256"])
        );
        assert_eq!(
            doc["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert_eq!(
            doc["token_endpoint_auth_methods_supported"],
            serde_json::json!(["client_secret_post"])
        );

        // Scopes: "openid" always present + config-defined scopes
        let scopes = doc["scopes_supported"].as_array().unwrap();
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&serde_json::json!("openid")));
        assert!(scopes.contains(&serde_json::json!("read:profile")));
        assert!(scopes.contains(&serde_json::json!("write:profile")));
    });
}

#[test]
#[ignore]
fn oidc_token_response_includes_id_token() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("oidcuser", "user").await;

        // Register client with scopes
        let client_id_str = "oidc-test-client";
        let client_secret = "oidc-test-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "OIDC Test Client",
            client_id_str,
            &secret_hash,
            &["https://oidc.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        // Authorize
        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://oidc.example.com/callback"),
                ("response_type", "code"),
                ("scope", "read:profile"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();

        // Exchange code for tokens
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://oidc.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();

        // id_token must be present
        let id_token_str = token_resp["id_token"]
            .as_str()
            .expect("id_token missing from token response");

        // Decode id_token and check claims
        let parts: Vec<&str> = id_token_str.split('.').collect();
        assert_eq!(parts.len(), 3, "id_token must be a 3-part JWT");

        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        assert_eq!(claims["iss"], "riley-auth-test");
        assert_eq!(claims["aud"], client_id_str);
        assert_eq!(claims["preferred_username"], "oidcuser");
        assert_eq!(claims["name"], "oidcuser Display");
        assert!(claims["sub"].as_str().is_some());
        assert!(claims["exp"].as_i64().is_some());
        assert!(claims["iat"].as_i64().is_some());
        // picture should be absent (user has no avatar)
        assert!(claims.get("picture").is_none());

        // Verify scope is also in the response
        assert_eq!(token_resp["scope"], "read:profile");

        // Refresh and verify id_token is also in refresh response
        let refresh_token = token_resp["refresh_token"].as_str().unwrap();
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let refresh_resp: serde_json::Value = resp.json().await.unwrap();
        assert!(
            refresh_resp["id_token"].as_str().is_some(),
            "id_token must be present in refresh response"
        );
    });
}

// --- Session visibility tests ---

#[test]
#[ignore]
fn session_list_shows_current_session() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, refresh_token) =
            s.create_user_with_session("sess_user", "user").await;

        let resp = client
            .get(s.url("/auth/sessions"))
            .header("cookie", format!("riley_auth_access={access_token}; riley_auth_refresh={refresh_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let sessions: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["is_current"], true);
        // Session id should be a valid UUID string
        assert!(uuid::Uuid::parse_str(sessions[0]["id"].as_str().unwrap()).is_ok());
    });
}

#[test]
#[ignore]
fn session_list_multiple_sessions() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Create user with first session
        let (user, access_token, refresh_token) =
            s.create_user_with_session("multi_sess", "user").await;

        // Create a second session directly in DB (simulates login from another device)
        let (_, second_hash) = jwt::generate_refresh_token();
        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(s.config.jwt.refresh_token_ttl_secs as i64);
        db::store_refresh_token(
            &s.db,
            user.id,
            None,
            &second_hash,
            expires_at,
            &[],
            Some("Mozilla/5.0 (iPhone)"),
            Some("10.0.0.1"),
        )
        .await
        .unwrap();

        let client = s.client();
        let resp = client
            .get(s.url("/auth/sessions"))
            .header("cookie", format!("riley_auth_access={access_token}; riley_auth_refresh={refresh_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let sessions: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(sessions.len(), 2);

        // Exactly one should be current
        let current_count = sessions.iter().filter(|s| s["is_current"] == true).count();
        assert_eq!(current_count, 1);

        // The other session should have the metadata we stored
        let other = sessions.iter().find(|s| s["is_current"] == false).unwrap();
        assert_eq!(other["user_agent"], "Mozilla/5.0 (iPhone)");
        assert_eq!(other["ip_address"], "10.0.0.1");
    });
}

#[test]
#[ignore]
fn session_revoke_other_session() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        let (user, access_token, refresh_token) =
            s.create_user_with_session("revoke_sess", "user").await;

        // Create a second session
        let (_, second_hash) = jwt::generate_refresh_token();
        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(s.config.jwt.refresh_token_ttl_secs as i64);
        db::store_refresh_token(
            &s.db, user.id, None, &second_hash, expires_at, &[], None, None,
        )
        .await
        .unwrap();

        let client = s.client();

        // List sessions to find the other session's ID
        let resp = client
            .get(s.url("/auth/sessions"))
            .header("cookie", format!("riley_auth_access={access_token}; riley_auth_refresh={refresh_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        let sessions: Vec<serde_json::Value> = resp.json().await.unwrap();
        let other = sessions.iter().find(|s| s["is_current"] == false).unwrap();
        let other_id = other["id"].as_str().unwrap();

        // Revoke the other session
        let resp = client
            .delete(s.url(&format!("/auth/sessions/{other_id}")))
            .header("cookie", format!("riley_auth_access={access_token}; riley_auth_refresh={refresh_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify only one session remains
        let resp = client
            .get(s.url("/auth/sessions"))
            .header("cookie", format!("riley_auth_access={access_token}; riley_auth_refresh={refresh_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        let sessions: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["is_current"], true);
    });
}

#[test]
#[ignore]
fn session_cannot_revoke_current() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        let (_, access_token, refresh_token) =
            s.create_user_with_session("current_sess", "user").await;

        let client = s.client();

        // Get current session ID
        let resp = client
            .get(s.url("/auth/sessions"))
            .header("cookie", format!("riley_auth_access={access_token}; riley_auth_refresh={refresh_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        let sessions: Vec<serde_json::Value> = resp.json().await.unwrap();
        let current_id = sessions[0]["id"].as_str().unwrap();

        // Try to revoke current session — should fail
        let resp = client
            .delete(s.url(&format!("/auth/sessions/{current_id}")))
            .header("cookie", format!("riley_auth_access={access_token}; riley_auth_refresh={refresh_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    });
}

#[test]
#[ignore]
fn session_revoke_nonexistent_returns_404() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        let (_, access_token, refresh_token) =
            s.create_user_with_session("revoke404_user", "user").await;

        let client = s.client();

        // Try to revoke a session that doesn't exist
        let resp = client
            .delete(s.url("/auth/sessions/00000000-0000-7000-8000-000000000001"))
            .header("cookie", format!("riley_auth_access={access_token}; riley_auth_refresh={refresh_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    });
}

#[test]
#[ignore]
fn session_refresh_populates_last_used_at() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, refresh_token) =
            s.create_user_with_session("refresh_last_used", "user").await;

        // Before refresh, last_used_at should be null
        let resp = client
            .get(s.url("/auth/sessions"))
            .header("cookie", format!("riley_auth_access={access_token}; riley_auth_refresh={refresh_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        let sessions: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0]["last_used_at"].is_null(), "last_used_at should be null before refresh");

        // Refresh the session
        let resp = client
            .post(s.url("/auth/refresh"))
            .header("cookie", format!("riley_auth_access={access_token}; riley_auth_refresh={refresh_token}"))
            .header("x-requested-with", "test")
            .header("user-agent", "TestBrowser/1.0")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Extract new tokens from Set-Cookie headers
        let new_access = resp.cookies().find(|c| c.name() == "riley_auth_access")
            .map(|c| c.value().to_string())
            .expect("expected new access token cookie");
        let new_refresh = resp.cookies().find(|c| c.name() == "riley_auth_refresh")
            .map(|c| c.value().to_string())
            .expect("expected new refresh token cookie");

        // After refresh, the new session should have last_used_at set
        let resp = client
            .get(s.url("/auth/sessions"))
            .header("cookie", format!("riley_auth_access={new_access}; riley_auth_refresh={new_refresh}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        let sessions: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(
            sessions[0]["last_used_at"].as_str().is_some(),
            "last_used_at should be set after refresh"
        );
    });
}

#[test]
#[ignore]
fn session_requires_authentication() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // List sessions without auth
        let resp = client
            .get(s.url("/auth/sessions"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Revoke session without auth
        let resp = client
            .delete(s.url("/auth/sessions/00000000-0000-0000-0000-000000000000"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    });
}

// --- Webhook tests ---

#[test]
#[ignore]
fn webhook_register_list_remove() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("webhookadmin", "admin").await;

        // Register a webhook
        let resp = client
            .post(s.url("/admin/webhooks"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "url": "https://example.com/hook",
                "events": ["user.created", "user.deleted"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let webhook: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(webhook["url"], "https://example.com/hook");
        assert!(!webhook["secret"].as_str().unwrap().is_empty());
        assert_eq!(webhook["active"], true);
        let webhook_id = webhook["id"].as_str().unwrap().to_string();

        // List webhooks
        let resp = client
            .get(s.url("/admin/webhooks"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let hooks: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["url"], "https://example.com/hook");

        // Remove webhook
        let resp = client
            .delete(s.url(&format!("/admin/webhooks/{webhook_id}")))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify removed
        let resp = client
            .get(s.url("/admin/webhooks"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .send()
            .await
            .unwrap();
        let hooks: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(hooks.is_empty());
    });
}

#[test]
#[ignore]
fn webhook_rejects_unknown_event_type() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("webhookadmin2", "admin").await;

        let resp = client
            .post(s.url("/admin/webhooks"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "url": "https://example.com/hook",
                "events": ["user.nonexistent"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    });
}

#[test]
#[ignore]
fn webhook_requires_admin() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, user_token, _) = s.create_user_with_session("webhookuser", "user").await;

        // Regular user cannot register webhooks
        let resp = client
            .post(s.url("/admin/webhooks"))
            .header("cookie", format!("riley_auth_access={user_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "url": "https://example.com/hook",
                "events": ["user.created"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Regular user cannot list webhooks
        let resp = client
            .get(s.url("/admin/webhooks"))
            .header("cookie", format!("riley_auth_access={user_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    });
}

#[test]
#[ignore]
fn webhook_delivery_recorded_on_event() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Register a webhook directly in the DB pointing to a URL that won't resolve
        // (delivery will fail, but the attempt should be recorded)
        let webhook = db::create_webhook(
            &s.db,
            None,
            "http://localhost:1/nonexistent",
            &["user.created".to_string()],
            "test-secret",
        )
        .await
        .unwrap();

        // Dispatch an event
        riley_auth_core::webhooks::dispatch_event(
            s.db.clone(),
            reqwest::Client::new(),
            "user.created",
            serde_json::json!({ "user_id": "test-user-id" }),
        );

        // Give the background task time to attempt delivery and retries
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // Check delivery was recorded
        let deliveries = db::list_webhook_deliveries(&s.db, webhook.id, 10)
            .await
            .unwrap();
        assert!(!deliveries.is_empty(), "delivery should be recorded after dispatch");
        assert_eq!(deliveries[0].event_type, "user.created");
        // Should have an error since the URL is unreachable
        assert!(deliveries[0].error.is_some());
    });
}

#[test]
#[ignore]
fn webhook_deliveries_endpoint() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("webhookadmin3", "admin").await;

        // Register a webhook
        let resp = client
            .post(s.url("/admin/webhooks"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "url": "https://example.com/hook",
                "events": ["user.created"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let webhook: serde_json::Value = resp.json().await.unwrap();
        let webhook_id = webhook["id"].as_str().unwrap();

        // Deliveries should be empty initially
        let resp = client
            .get(s.url(&format!("/admin/webhooks/{webhook_id}/deliveries")))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let deliveries: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(deliveries.is_empty());

        // Deliveries for non-existent webhook returns 404
        let resp = client
            .get(s.url("/admin/webhooks/00000000-0000-0000-0000-000000000000/deliveries"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    });
}

#[test]
#[ignore]
fn webhook_remove_nonexistent_returns_404() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("webhookadmin4", "admin").await;

        let resp = client
            .delete(s.url("/admin/webhooks/00000000-0000-0000-0000-000000000000"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    });
}
