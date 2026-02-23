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
    Config, ConfigValue, DatabaseConfig, JwtConfig, OAuthProvidersConfig, ScopesConfig,
    ServerConfig, UsernameConfig,
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
            scopes: ScopesConfig::default(),
        };

        let state = AppState {
            config: Arc::new(config.clone()),
            db: pool.clone(),
            keys: Arc::new(keys.clone()),
        };

        let app = axum::Router::new()
            .merge(routes::router(false))
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
