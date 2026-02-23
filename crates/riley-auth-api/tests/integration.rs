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
    Config, ConfigValue, DatabaseConfig, JwtConfig, MaintenanceConfig, OAuthProvidersConfig,
    RateLimitingConfig, ScopeDefinition, ScopesConfig, ServerConfig, UsernameConfig, WebhooksConfig,
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
            webhooks: WebhooksConfig::default(),
            maintenance: MaintenanceConfig::default(),
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
        db::store_refresh_token(&self.db, user.id, None, &refresh_hash, expires_at, &[], None, None, uuid::Uuid::now_v7(), None)
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

// --- Token Family / Reuse Detection ---

#[test]
#[ignore]
fn session_refresh_reuse_revokes_family() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // Create user with session (token A)
        let (_, _, token_a) = s.create_user_with_session("reuse_sess", "user").await;

        // Rotate A → B (legitimate refresh)
        let resp = client
            .post(s.url("/auth/refresh"))
            .header("cookie", format!("riley_auth_refresh={token_a}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let token_b = resp
            .cookies()
            .find(|c| c.name() == "riley_auth_refresh")
            .expect("should get new refresh token")
            .value()
            .to_string();

        // Token B should work (sanity check — rotate B → C)
        let resp = client
            .post(s.url("/auth/refresh"))
            .header("cookie", format!("riley_auth_refresh={token_b}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let token_c = resp
            .cookies()
            .find(|c| c.name() == "riley_auth_refresh")
            .expect("should get new refresh token")
            .value()
            .to_string();

        // NOW: replay token A (attacker reuse). Should fail AND revoke the entire family.
        let resp = client
            .post(s.url("/auth/refresh"))
            .header("cookie", format!("riley_auth_refresh={token_a}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "reused token A should be rejected");

        // Token C (the latest legitimate token) should ALSO be revoked
        let resp = client
            .post(s.url("/auth/refresh"))
            .header("cookie", format!("riley_auth_refresh={token_c}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "token C should be revoked after family revocation"
        );
    });
}

#[test]
#[ignore]
fn oauth_refresh_reuse_revokes_family() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // Set up user + OAuth client
        let (_, access_token, _) = s.create_user_with_session("oauth_reuse", "user").await;

        let client_id_str = "reuse-test-client";
        let client_secret = "reuse-test-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Reuse Test Client",
            client_id_str,
            &secret_hash,
            &["https://reuse.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        // Full PKCE authorize + exchange flow
        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://reuse.example.com/callback"),
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
        let code = redirect_url.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();

        // Exchange code → token A
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://reuse.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let token_resp: serde_json::Value = resp.json().await.unwrap();
        let token_a = token_resp["refresh_token"].as_str().unwrap().to_string();

        // Rotate A → B
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &token_a),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_b: serde_json::Value = resp.json().await.unwrap();
        let token_b = resp_b["refresh_token"].as_str().unwrap().to_string();

        // Replay token A (reuse) — should fail and revoke family
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &token_a),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "reused token A should be rejected");

        // Token B should also be revoked
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &token_b),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "token B should be revoked after family revocation"
        );
    });
}

/// Regression: a client-bound refresh token sent to /auth/refresh must be
/// rejected without being consumed (the token should remain usable at the
/// correct endpoint).
#[test]
#[ignore]
fn cross_endpoint_client_token_at_session_endpoint() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("cross_ep1", "user").await;

        // Register OAuth client + do PKCE flow to get a client-bound refresh token
        let client_id_str = "cross-ep-client";
        let client_secret = "cross-ep-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Cross EP Client",
            client_id_str,
            &secret_hash,
            &["https://cross-ep.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://cross-ep.example.com/callback"),
                ("response_type", "code"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();

        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://cross-ep.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let token_resp: serde_json::Value = resp.json().await.unwrap();
        let oauth_refresh = token_resp["refresh_token"].as_str().unwrap().to_string();

        // Send the client-bound token to /auth/refresh — should be rejected
        let resp = client
            .post(s.url("/auth/refresh"))
            .header("cookie", format!("riley_auth_refresh={oauth_refresh}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "client-bound token must be rejected at session endpoint"
        );

        // The token should still work at the correct endpoint (not consumed/destroyed)
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &oauth_refresh),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "client-bound token must still be usable at /oauth/token after session endpoint rejection"
        );
    });
}

/// Regression: a session refresh token sent to /oauth/token must be rejected
/// without being consumed (the token should remain usable at /auth/refresh).
#[test]
#[ignore]
fn cross_endpoint_session_token_at_oauth_endpoint() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, _, session_refresh) = s.create_user_with_session("cross_ep2", "user").await;

        // Register an OAuth client to authenticate the /oauth/token request
        let client_id_str = "cross-ep-client2";
        let client_secret = "cross-ep-secret2";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Cross EP Client 2",
            client_id_str,
            &secret_hash,
            &["https://cross-ep2.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        // Send the session token to /oauth/token — should be rejected
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &session_refresh),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "session token must be rejected at OAuth endpoint"
        );

        // The session token should still work at /auth/refresh (not consumed/destroyed)
        let resp = client
            .post(s.url("/auth/refresh"))
            .header("cookie", format!("riley_auth_refresh={session_refresh}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "session token must still be usable at /auth/refresh after OAuth endpoint rejection"
        );
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
        db::store_refresh_token(&s.db, user.id, None, &hash2, expires_at, &[], None, None, uuid::Uuid::now_v7(), None)
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
        assert!(body["error_description"].as_str().unwrap().contains("last admin"));
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
fn admin_rejects_invalid_redirect_uri_scheme() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let (_, admin_token, _) = s.create_user_with_session("redirschemeadmin", "admin").await;
        let client = s.client();

        // javascript: scheme should be rejected
        let resp = client
            .post(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "name": "Evil App",
                "redirect_uris": ["javascript:alert(1)"],
                "auto_approve": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // http:// non-localhost should be rejected
        let resp = client
            .post(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "name": "HTTP App",
                "redirect_uris": ["http://example.com/callback"],
                "auto_approve": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // http://localhost should be allowed (development)
        let resp = client
            .post(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "name": "Dev App",
                "redirect_uris": ["http://localhost:3000/callback"],
                "auto_approve": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
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

        // claims_supported
        assert_eq!(
            doc["claims_supported"],
            serde_json::json!(["sub", "name", "preferred_username", "picture"])
        );
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
                ("scope", "openid read:profile"),
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

        // Verify scope is also in the response (openid + read:profile)
        assert_eq!(token_resp["scope"], "openid read:profile");

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
            uuid::Uuid::now_v7(),
            None,
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
            &s.db, user.id, None, &second_hash, expires_at, &[], None, None, uuid::Uuid::now_v7(), None,
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
        // Secret must NOT be exposed in list responses (only at creation)
        assert!(hooks[0].get("secret").is_none(), "secret should not appear in list response");

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

        // Dispatch an event (enqueues to outbox — now awaited for durability)
        riley_auth_core::webhooks::dispatch_event(
            &s.db,
            "user.created",
            serde_json::json!({ "user_id": "test-user-id" }),
            s.config.webhooks.max_retry_attempts,
        ).await;

        // Verify outbox entry was created
        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert!(!entries.is_empty(), "outbox entry should be created after dispatch");
        let entry = &entries[0];
        assert_eq!(entry.event_type, "user.created");
        assert_eq!(entry.webhook_id, webhook.id);

        // Manually process the outbox entry (simulating the delivery worker)
        let http_client = reqwest::Client::new();
        let result = riley_auth_core::webhooks::deliver_outbox_entry(
            &s.db, &http_client, entry, false,
        ).await;

        // Delivery should fail since the URL is unreachable
        assert!(result.is_err(), "delivery to unreachable URL should fail");

        // Verify the delivery record was written
        let deliveries = db::list_webhook_deliveries(&s.db, webhook.id, 10, 0)
            .await
            .unwrap();
        assert!(!deliveries.is_empty(), "delivery should be recorded after processing");
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

// --- Webhook Outbox / Reliability Tests ---

#[test]
#[ignore]
fn outbox_enqueue_creates_entries_for_matching_webhooks() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Create two webhooks: one subscribes to user.created, one to user.deleted
        let wh1 = db::create_webhook(&s.db, None, "http://localhost:1/hook1", &["user.created".to_string()], "secret1").await.unwrap();
        let wh2 = db::create_webhook(&s.db, None, "http://localhost:1/hook2", &["user.deleted".to_string()], "secret2").await.unwrap();

        // Enqueue a user.created event
        let count = db::enqueue_webhook_events(&s.db, "user.created", &serde_json::json!({"id": "u1"}), 5, None).await.unwrap();
        assert_eq!(count, 1, "only wh1 subscribes to user.created");

        // Enqueue a user.deleted event
        let count = db::enqueue_webhook_events(&s.db, "user.deleted", &serde_json::json!({"id": "u2"}), 5, None).await.unwrap();
        assert_eq!(count, 1, "only wh2 subscribes to user.deleted");

        // Fetch pending entries — should have 2
        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert_eq!(entries.len(), 2);

        let wh1_entry = entries.iter().find(|e| e.webhook_id == wh1.id).unwrap();
        assert_eq!(wh1_entry.event_type, "user.created");
        assert_eq!(wh1_entry.max_attempts, 5);

        let wh2_entry = entries.iter().find(|e| e.webhook_id == wh2.id).unwrap();
        assert_eq!(wh2_entry.event_type, "user.deleted");
    });
}

#[test]
#[ignore]
fn outbox_mark_delivered_removes_from_pending() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        let wh = db::create_webhook(&s.db, None, "http://localhost:1/hook", &["user.created".to_string()], "secret").await.unwrap();
        db::enqueue_webhook_events(&s.db, "user.created", &serde_json::json!({}), 5, None).await.unwrap();

        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert_eq!(entries.len(), 1);
        let entry_id = entries[0].id;

        // Mark as delivered
        db::mark_outbox_delivered(&s.db, entry_id).await.unwrap();

        // No longer appears in pending
        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert!(entries.is_empty(), "delivered entries should not be pending");

        let _ = wh; // keep the webhook alive
    });
}

#[test]
#[ignore]
fn outbox_retry_increments_attempts_and_delays() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        db::create_webhook(&s.db, None, "http://localhost:1/hook", &["user.created".to_string()], "secret").await.unwrap();
        db::enqueue_webhook_events(&s.db, "user.created", &serde_json::json!({}), 5, None).await.unwrap();

        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        let entry = &entries[0];
        assert_eq!(entry.attempts, 0);

        // Record a failed attempt
        db::record_outbox_attempt(&s.db, entry.id, "connection refused").await.unwrap();

        // Entry should NOT be in pending results now (next_attempt_at is in the future)
        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert!(entries.is_empty(), "retrying entry should be delayed");

        // Verify the attempt was recorded by reading the entry directly
        let row: (i32, Option<String>, String) = sqlx::query_as(
            "SELECT attempts, last_error, status FROM webhook_outbox WHERE id = $1"
        )
        .bind(entry.id)
        .fetch_one(&s.db)
        .await
        .unwrap();
        assert_eq!(row.0, 1, "attempts should be incremented");
        assert_eq!(row.1.as_deref(), Some("connection refused"));
        assert_eq!(row.2, "pending", "status should still be pending");
    });
}

#[test]
#[ignore]
fn outbox_max_attempts_marks_failed() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        db::create_webhook(&s.db, None, "http://localhost:1/hook", &["user.created".to_string()], "secret").await.unwrap();
        // max_attempts = 1, so first failure should mark as failed
        db::enqueue_webhook_events(&s.db, "user.created", &serde_json::json!({}), 1, None).await.unwrap();

        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        let entry = &entries[0];

        // Deliver to unreachable URL — will fail
        let http_client = reqwest::Client::new();
        let result = riley_auth_core::webhooks::deliver_outbox_entry(&s.db, &http_client, entry, false).await;
        assert!(result.is_err());

        // Since attempts (0) + 1 >= max_attempts (1), mark as failed
        db::mark_outbox_failed(&s.db, entry.id, &result.unwrap_err()).await.unwrap();

        // Verify it's marked failed
        let row: (String,) = sqlx::query_as(
            "SELECT status FROM webhook_outbox WHERE id = $1"
        )
        .bind(entry.id)
        .fetch_one(&s.db)
        .await
        .unwrap();
        assert_eq!(row.0, "failed");

        // Not in pending anymore
        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert!(entries.is_empty());
    });
}

#[test]
#[ignore]
fn outbox_cleanup_removes_old_entries() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        db::create_webhook(&s.db, None, "http://localhost:1/hook", &["user.created".to_string()], "secret").await.unwrap();
        db::enqueue_webhook_events(&s.db, "user.created", &serde_json::json!({}), 5, None).await.unwrap();

        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        let entry_id = entries[0].id;

        // Mark as delivered
        db::mark_outbox_delivered(&s.db, entry_id).await.unwrap();

        // Backdate the entry's created_at to make it appear old
        sqlx::query("UPDATE webhook_outbox SET created_at = now() - interval '10 days' WHERE id = $1")
            .bind(entry_id)
            .execute(&s.db)
            .await
            .unwrap();

        // Cleanup with 7-day retention — should delete the old entry
        let deleted = db::cleanup_webhook_outbox(&s.db, 7).await.unwrap();
        assert_eq!(deleted, 1);

        // Cleanup again — nothing left
        let deleted = db::cleanup_webhook_outbox(&s.db, 7).await.unwrap();
        assert_eq!(deleted, 0);
    });
}

// --- OIDC compliance tests ---

#[test]
#[ignore]
fn oidc_nonce_round_trip() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("nonceuser", "user").await;

        // Register client
        let client_id_str = "nonce-test-client";
        let client_secret = "nonce-test-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Nonce Test Client",
            client_id_str,
            &secret_hash,
            &["https://nonce.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        // Authorize with nonce
        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://nonce.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid read:profile"),
                ("nonce", "my-unique-nonce-abc123"),
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
                ("redirect_uri", "https://nonce.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();

        // id_token must be present (openid scope was requested)
        let id_token_str = token_resp["id_token"]
            .as_str()
            .expect("id_token missing when openid scope was requested");

        // Decode and verify nonce is echoed back
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let parts: Vec<&str> = id_token_str.split('.').collect();
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        assert_eq!(claims["nonce"], "my-unique-nonce-abc123");
    });
}

#[test]
#[ignore]
fn oidc_no_id_token_without_openid_scope() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("noiduser", "user").await;

        // Register client
        let client_id_str = "no-oidc-client";
        let client_secret = "no-oidc-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "No OIDC Client",
            client_id_str,
            &secret_hash,
            &["https://noidc.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        // Authorize WITHOUT openid scope
        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://noidc.example.com/callback"),
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
                ("redirect_uri", "https://noidc.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();

        // id_token must NOT be present (openid scope was not requested)
        assert!(
            token_resp.get("id_token").is_none()
                || token_resp["id_token"].is_null(),
            "id_token must be absent when openid scope is not requested"
        );

        // access_token and refresh_token should still be present
        assert!(token_resp["access_token"].as_str().is_some());
        assert!(token_resp["refresh_token"].as_str().is_some());

        // Refresh should also not include id_token
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
            refresh_resp.get("id_token").is_none()
                || refresh_resp["id_token"].is_null(),
            "id_token must be absent on refresh when openid scope was not in original grant"
        );
    });
}

#[test]
#[ignore]
fn oauth_authorization_code_replay_rejected() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("replayuser", "user").await;

        let client_id_str = "replay-client";
        let client_secret = "replay-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Replay Client",
            client_id_str,
            &secret_hash,
            &["https://replay.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://replay.example.com/callback"),
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

        // First exchange should succeed
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://replay.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Second exchange (replay) should fail
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://replay.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "invalid_authorization_code");
    });
}

#[test]
#[ignore]
fn oauth_pkce_wrong_verifier_rejected() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("pkceuser", "user").await;

        let client_id_str = "pkce-client";
        let client_secret = "pkce-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "PKCE Client",
            client_id_str,
            &secret_hash,
            &["https://pkce.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://pkce.example.com/callback"),
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

        // Exchange with wrong verifier should fail
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://pkce.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", "wrong-verifier-that-does-not-match"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "invalid_grant");
    });
}

// --- Cleanup tests ---

#[test]
#[ignore]
fn cleanup_expired_tokens_removes_old() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        let (user, _, _) = s.create_user_with_session("cleanupuser", "user").await;

        // Insert a refresh token that's already expired
        sqlx::query(
            "INSERT INTO refresh_tokens (token_hash, user_id, family_id, scopes, expires_at)
             VALUES ('expired-hash', $1, gen_random_uuid(), ARRAY[]::text[], now() - interval '1 hour')"
        )
        .bind(user.id)
        .execute(&s.db)
        .await
        .unwrap();

        // Insert a valid (non-expired) refresh token
        sqlx::query(
            "INSERT INTO refresh_tokens (token_hash, user_id, family_id, scopes, expires_at)
             VALUES ('valid-hash', $1, gen_random_uuid(), ARRAY[]::text[], now() + interval '1 hour')"
        )
        .bind(user.id)
        .execute(&s.db)
        .await
        .unwrap();

        let deleted = db::cleanup_expired_tokens(&s.db).await.unwrap();
        assert_eq!(deleted, 1);

        // Valid token should still exist
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM refresh_tokens WHERE token_hash = 'valid-hash'")
            .fetch_one(&s.db)
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    });
}

#[test]
#[ignore]
fn cleanup_expired_auth_codes_removes_old() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        let (user, _, _) = s.create_user_with_session("authcodecleanup", "user").await;

        // Register a client (needed for FK)
        let secret_hash = jwt::hash_token("cleanup-secret");
        let client = db::create_client(
            &s.db, "Cleanup Client", "cleanup-client-id", &secret_hash,
            &["https://cleanup.example.com/callback".to_string()],
            &[], false,
        ).await.unwrap();

        // Insert an expired auth code
        sqlx::query(
            "INSERT INTO authorization_codes (code_hash, user_id, client_id, redirect_uri, expires_at)
             VALUES ('expired-code', $1, $2, 'https://cleanup.example.com/callback', now() - interval '1 hour')"
        )
        .bind(user.id)
        .bind(client.id)
        .execute(&s.db)
        .await
        .unwrap();

        // Insert a valid auth code
        sqlx::query(
            "INSERT INTO authorization_codes (code_hash, user_id, client_id, redirect_uri, expires_at)
             VALUES ('valid-code', $1, $2, 'https://cleanup.example.com/callback', now() + interval '1 hour')"
        )
        .bind(user.id)
        .bind(client.id)
        .execute(&s.db)
        .await
        .unwrap();

        let deleted = db::cleanup_expired_auth_codes(&s.db).await.unwrap();
        assert_eq!(deleted, 1);

        // Valid code should still exist
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM authorization_codes WHERE code_hash = 'valid-code'")
            .fetch_one(&s.db)
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    });
}

#[test]
#[ignore]
fn cleanup_consumed_tokens_respects_cutoff() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Insert an old consumed token (60 days ago)
        sqlx::query(
            "INSERT INTO consumed_refresh_tokens (token_hash, family_id, consumed_at)
             VALUES ('old-consumed', gen_random_uuid(), now() - interval '60 days')"
        )
        .execute(&s.db)
        .await
        .unwrap();

        // Insert a recent consumed token (1 hour ago)
        sqlx::query(
            "INSERT INTO consumed_refresh_tokens (token_hash, family_id, consumed_at)
             VALUES ('recent-consumed', gen_random_uuid(), now() - interval '1 hour')"
        )
        .execute(&s.db)
        .await
        .unwrap();

        // Cutoff at 30 days ago — should only delete the old one
        let cutoff = chrono::Utc::now() - chrono::Duration::days(30);
        let deleted = db::cleanup_consumed_refresh_tokens(&s.db, cutoff).await.unwrap();
        assert_eq!(deleted, 1);

        // Recent one should still exist
        let count: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM consumed_refresh_tokens WHERE token_hash = 'recent-consumed'"
        )
        .fetch_one(&s.db)
        .await
        .unwrap();
        assert_eq!(count.0, 1);
    });
}

#[test]
#[ignore]
fn cleanup_webhook_deliveries_respects_retention() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        let webhook = db::create_webhook(
            &s.db, None, "http://localhost:1/hook",
            &["user.created".to_string()], "secret"
        ).await.unwrap();

        // Record a delivery and backdate it
        db::record_webhook_delivery(&s.db, webhook.id, "user.created", &serde_json::json!({}), Some(200), None)
            .await.unwrap();
        sqlx::query("UPDATE webhook_deliveries SET attempted_at = now() - interval '10 days' WHERE webhook_id = $1")
            .bind(webhook.id)
            .execute(&s.db)
            .await
            .unwrap();

        // Record a recent delivery
        db::record_webhook_delivery(&s.db, webhook.id, "user.created", &serde_json::json!({}), Some(200), None)
            .await.unwrap();

        // Cleanup with 7-day retention — should delete only the old one
        let deleted = db::cleanup_webhook_deliveries(&s.db, 7).await.unwrap();
        assert_eq!(deleted, 1);

        // Recent one should remain
        let count: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM webhook_deliveries WHERE webhook_id = $1"
        )
        .bind(webhook.id)
        .fetch_one(&s.db)
        .await
        .unwrap();
        assert_eq!(count.0, 1);
    });
}

// --- SSRF protection tests ---

#[test]
#[ignore]
fn ssrf_safe_client_blocks_localhost_delivery() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Register a webhook pointing to localhost
        let webhook = db::create_webhook(
            &s.db,
            None,
            "http://127.0.0.1:1/hook",
            &["user.created".to_string()],
            "test-secret",
        )
        .await
        .unwrap();

        // Enqueue an event
        riley_auth_core::webhooks::dispatch_event(
            &s.db,
            "user.created",
            serde_json::json!({ "user_id": "test" }),
            s.config.webhooks.max_retry_attempts,
        ).await;

        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert!(!entries.is_empty());

        // Build SSRF-safe client (allow_private_ips = false) + block_private_ips = true
        let ssrf_client = riley_auth_core::webhooks::build_webhook_client(false);
        let result = riley_auth_core::webhooks::deliver_outbox_entry(
            &s.db, &ssrf_client, &entries[0], true,
        ).await;

        // Should fail with permanent SSRF error
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.starts_with("permanent:"),
            "SSRF block should be a permanent error, got: {err}"
        );
        assert!(
            err.contains("private") || err.contains("reserved"),
            "error should mention private/reserved IP, got: {err}"
        );
    });
}

#[test]
#[ignore]
fn ssrf_allow_private_ips_permits_localhost() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Register a webhook pointing to localhost (unreachable port, but DNS resolves)
        let webhook = db::create_webhook(
            &s.db,
            None,
            "http://127.0.0.1:1/hook",
            &["user.created".to_string()],
            "test-secret",
        )
        .await
        .unwrap();

        riley_auth_core::webhooks::dispatch_event(
            &s.db,
            "user.created",
            serde_json::json!({ "user_id": "test" }),
            s.config.webhooks.max_retry_attempts,
        ).await;

        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert!(!entries.is_empty());

        // Build permissive client (allow_private_ips = true) + block_private_ips = false
        let permissive_client = riley_auth_core::webhooks::build_webhook_client(true);
        let result = riley_auth_core::webhooks::deliver_outbox_entry(
            &s.db, &permissive_client, &entries[0], false,
        ).await;

        // Should fail with connection error (not SSRF error) — port 1 is unreachable
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            !err.contains("private") && !err.contains("reserved"),
            "error should be a connection error, not SSRF block, got: {err}"
        );
    });
}

// --- Phase 7 QoL tests ---

#[test]
#[ignore]
fn display_name_multibyte_characters_within_limit() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("mbuser", "user").await;

        // 200 CJK characters = 600 bytes but only 200 chars → should pass
        let name = "日".repeat(200);
        let resp = client
            .patch(s.url("/auth/me"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({ "display_name": name }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 201 CJK characters → should be rejected
        let name_too_long = "日".repeat(201);
        let resp = client
            .patch(s.url("/auth/me"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({ "display_name": name_too_long }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    });
}

#[test]
#[ignore]
fn soft_delete_scrubs_webhook_delivery_payloads() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        let (user, _, _) = s.create_user_with_session("scrubme", "user").await;

        // Create a webhook and manually insert a delivery record referencing the user
        let webhook = db::create_webhook(
            &s.db,
            None,
            "https://example.com/hook",
            &["user.created".to_string()],
            "secret",
        )
        .await
        .unwrap();

        // Use envelope payload matching production deliver_outbox_entry format.
        // Delivery records wrap flat event payloads under a "data" key.
        let payload = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "event": "user.created",
            "timestamp": "2026-01-01T00:00:00Z",
            "data": { "user_id": user.id.to_string(), "username": "scrubme" }
        });
        db::record_webhook_delivery(
            &s.db,
            webhook.id,
            "user.created",
            &payload,
            Some(200),
            None,
        )
        .await
        .unwrap();

        // Verify the delivery exists with original payload
        let deliveries = db::list_webhook_deliveries(&s.db, webhook.id, 10, 0).await.unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].payload["data"]["username"].as_str(), Some("scrubme"));

        // Soft-delete the user
        let result = db::soft_delete_user(&s.db, user.id).await.unwrap();
        assert!(matches!(result, db::DeleteUserResult::Deleted));

        // Verify the delivery payload data was scrubbed but envelope preserved
        let deliveries = db::list_webhook_deliveries(&s.db, webhook.id, 10, 0).await.unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].payload["data"]["scrubbed"], true);
        // Original PII should be gone
        assert!(deliveries[0].payload["data"]["username"].as_str().is_none());
        assert!(deliveries[0].payload["data"]["user_id"].as_str().is_none());
        // Envelope metadata preserved
        assert!(deliveries[0].payload["event"].as_str().is_some());
    });
}

#[test]
#[ignore]
fn stuck_processing_outbox_entries_are_reset() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Register a webhook
        let webhook = db::create_webhook(
            &s.db,
            None,
            "https://example.com/hook",
            &["user.created".to_string()],
            "test-secret",
        )
        .await
        .unwrap();

        // Dispatch an event to create an outbox entry
        riley_auth_core::webhooks::dispatch_event(
            &s.db,
            "user.created",
            serde_json::json!({ "user_id": "stuck-test" }),
            s.config.webhooks.max_retry_attempts,
        ).await;

        // Claim the entry (sets status to 'processing')
        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert_eq!(entries.len(), 1);
        let entry_id = entries[0].id;

        // Verify it's now in 'processing' status (won't be claimed again)
        let re_claimed = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert!(re_claimed.is_empty(), "processing entry should not be re-claimed");

        // Backdating: set next_attempt_at far in the past to simulate a stuck entry
        sqlx::query("UPDATE webhook_outbox SET next_attempt_at = now() - interval '10 minutes' WHERE id = $1")
            .bind(entry_id)
            .execute(&s.db)
            .await
            .unwrap();

        // Reset stuck entries with a 5-minute timeout
        let reset_count = db::reset_stuck_outbox_entries(&s.db, 300).await.unwrap();
        assert_eq!(reset_count, 1, "should reset 1 stuck entry");

        // The entry should now be claimable again
        let re_claimed = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert_eq!(re_claimed.len(), 1, "reset entry should be claimable");
        assert_eq!(re_claimed[0].id, entry_id);
    });
}

#[test]
#[ignore]
fn nonce_preserved_across_refresh() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("nonce_refresh", "user").await;

        // Register client
        let client_id_str = "nonce-refresh-client";
        let client_secret = "nonce-refresh-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Nonce Refresh Client",
            client_id_str,
            &secret_hash,
            &["https://nonce-refresh.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        // Authorize with nonce + openid scope
        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://nonce-refresh.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid read:profile"),
                ("nonce", "preserve-me-nonce-xyz"),
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
                ("redirect_uri", "https://nonce-refresh.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();

        // Verify nonce in initial ID token
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let id_token_str = token_resp["id_token"].as_str().expect("id_token missing");
        let parts: Vec<&str> = id_token_str.split('.').collect();
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claims["nonce"], "preserve-me-nonce-xyz", "nonce should be in initial ID token");

        let refresh_token = token_resp["refresh_token"].as_str().unwrap().to_string();

        // Refresh the token
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

        // Verify nonce is preserved in refreshed ID token
        let refreshed_id_token = refresh_resp["id_token"].as_str().expect("id_token missing after refresh");
        let parts: Vec<&str> = refreshed_id_token.split('.').collect();
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claims["nonce"], "preserve-me-nonce-xyz", "nonce should be preserved after refresh");

        // Do a second refresh to verify nonce survives multiple rotations
        let refresh_token2 = refresh_resp["refresh_token"].as_str().unwrap().to_string();
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token2),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let refresh_resp2: serde_json::Value = resp.json().await.unwrap();
        let id_token3 = refresh_resp2["id_token"].as_str().expect("id_token missing after second refresh");
        let parts: Vec<&str> = id_token3.split('.').collect();
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claims["nonce"], "preserve-me-nonce-xyz", "nonce should survive multiple refresh rotations");
    });
}

#[test]
#[ignore]
fn refresh_scope_downscoping() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("downscope", "user").await;

        // Register client with both scopes allowed
        let client_id_str = "downscope-client";
        let client_secret = "downscope-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Downscope Client",
            client_id_str,
            &secret_hash,
            &["https://downscope.example.com/callback".to_string()],
            &["read:profile".to_string(), "write:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        // Authorize with both scopes
        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://downscope.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid read:profile write:profile"),
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

        // Exchange for tokens — should have all scopes
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://downscope.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();
        let scope_str = token_resp["scope"].as_str().unwrap();
        assert!(scope_str.contains("read:profile"));
        assert!(scope_str.contains("write:profile"));
        assert!(scope_str.contains("openid"));

        let refresh_token = token_resp["refresh_token"].as_str().unwrap().to_string();

        // Refresh with narrowed scope — only read:profile
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("scope", "openid read:profile"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let refresh_resp: serde_json::Value = resp.json().await.unwrap();
        let narrowed_scope = refresh_resp["scope"].as_str().unwrap();
        assert!(narrowed_scope.contains("openid"), "openid should be preserved");
        assert!(narrowed_scope.contains("read:profile"), "read:profile should be in narrowed scope");
        assert!(!narrowed_scope.contains("write:profile"), "write:profile should be dropped");

        // The new refresh token should also carry the narrowed scopes
        let refresh_token2 = refresh_resp["refresh_token"].as_str().unwrap().to_string();
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token2),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let refresh_resp2: serde_json::Value = resp.json().await.unwrap();
        let scope_after = refresh_resp2["scope"].as_str().unwrap();
        assert!(scope_after.contains("read:profile"));
        assert!(!scope_after.contains("write:profile"), "narrowed scope should persist");

        // Attempting to re-widen scope should fail with invalid_scope
        let refresh_token3 = refresh_resp2["refresh_token"].as_str().unwrap().to_string();
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token3),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("scope", "openid read:profile write:profile"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let err: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(err["error"], "invalid_scope");
    });
}
