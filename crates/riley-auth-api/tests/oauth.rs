mod common;
use common::*;

use std::sync::Arc;
use base64::Engine;
use tokio::net::TcpListener;

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
        assert_eq!(resp.status(), StatusCode::FOUND);

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
fn authorize_error_redirect_unsupported_response_type() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("errrediruser", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Error Redirect Client",
            "err-redir-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        // Valid client_id + redirect_uri, but invalid response_type
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "err-redir-client"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "token"),
                ("state", "my-state"),
                ("code_challenge", "test"),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        // Should redirect with error, not return HTTP error
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert_eq!(params["error"], "unsupported_response_type");
        assert_eq!(params["state"], "my-state");
        assert!(params.contains_key("error_description"));
    });
}

#[test]
#[ignore]
fn authorize_error_redirect_login_required() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Login Required Client",
            "login-req-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // No cookie — user is not authenticated
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "login-req-client"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("state", "login-state"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert_eq!(params["error"], "login_required");
        assert_eq!(params["state"], "login-state");
    });
}

#[test]
#[ignore]
fn authorize_redirects_to_consent_url_for_non_auto_approve() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("consentuser", "user").await;

        // Create a non-auto-approve client
        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Consent Client",
            "consent-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string()],
            false, // auto_approve = false
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "consent-client"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid read:profile"),
                ("state", "consent-state"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();

        // Should redirect to consent_url with consent_id
        assert_eq!(redirect_url.host_str(), Some("auth.example.com"));
        assert_eq!(redirect_url.path(), "/consent");
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert!(params.contains_key("consent_id"), "should have consent_id parameter");
        // Verify the consent_id is a valid UUID
        let consent_id: uuid::Uuid = params["consent_id"].parse().expect("consent_id should be a UUID");

        // Verify the consent request was stored in the DB
        let consent_req = db::find_consent_request(&s.db, consent_id).await.unwrap().unwrap();
        assert_eq!(consent_req.redirect_uri, "https://app.example.com/callback");
        assert_eq!(consent_req.state.as_deref(), Some("consent-state"));
        assert!(consent_req.scopes.contains(&"openid".to_string()));
        assert!(consent_req.scopes.contains(&"read:profile".to_string()));
    });
}

#[test]
#[ignore]
fn authorize_error_redirect_missing_pkce() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("pkceuser", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "PKCE Client",
            "pkce-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        // Missing code_challenge
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "pkce-client"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("state", "pkce-state"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert_eq!(params["error"], "invalid_request");
        assert!(params["error_description"].contains("code_challenge"));
        assert_eq!(params["state"], "pkce-state");
    });
}

#[test]
#[ignore]
fn authorize_error_redirect_unsupported_pkce_method() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("plainchallengeuser", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Plain PKCE Client",
            "plain-pkce-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        // code_challenge_method=plain is not supported (only S256)
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "plain-pkce-client"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("state", "plain-state"),
                ("code_challenge", "somechallenge"),
                ("code_challenge_method", "plain"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert_eq!(params["error"], "invalid_request");
        assert!(params["error_description"].contains("S256"));
        assert_eq!(params["state"], "plain-state");
    });
}

#[test]
#[ignore]
fn authorize_pre_redirect_errors_return_http() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("prerediruser", "user").await;

        // Invalid client_id → HTTP 401 (not redirect)
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "nonexistent"),
                ("redirect_uri", "https://evil.com/callback"),
                ("response_type", "code"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Valid client_id but wrong redirect_uri → HTTP 400 (not redirect)
        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Pre Redirect Client",
            "pre-redir-client",
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
                ("client_id", "pre-redir-client"),
                ("redirect_uri", "https://evil.com/callback"),
                ("response_type", "code"),
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
fn prompt_none_with_session_issues_code() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("promptnone", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Prompt None Client",
            "prompt-none-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true, // auto_approve
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // prompt=none with valid session + auto_approve → should issue code
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "prompt-none-client"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "silent-state"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("prompt", "none"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert!(params.contains_key("code"), "expected code in redirect, got: {location}");
        assert_eq!(params["state"], "silent-state");
    });
}

#[test]
#[ignore]
fn prompt_none_without_session_returns_login_required() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Prompt None NoSession",
            "prompt-none-nosess",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // prompt=none without session → login_required error redirect
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "prompt-none-nosess"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "no-session"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("prompt", "none"),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert_eq!(params["error"], "login_required");
        assert_eq!(params["state"], "no-session");
    });
}

#[test]
#[ignore]
fn prompt_none_with_consent_required_returns_consent_required() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("promptconsent", "user").await;

        // Non-auto-approve client requires consent
        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Prompt None Consent",
            "prompt-none-consent",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            false, // auto_approve = false
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // prompt=none with session but consent required → consent_required error redirect
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "prompt-none-consent"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "consent-state"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("prompt", "none"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert_eq!(params["error"], "consent_required");
        assert_eq!(params["state"], "consent-state");
    });
}

#[test]
#[ignore]
fn prompt_login_without_login_url_returns_login_required() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("promptlogin", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Prompt Login Client",
            "prompt-login-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // prompt=login with no login_url configured → login_required error redirect
        // (test server has no login_url configured)
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "prompt-login-client"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "login-state"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("prompt", "login"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert_eq!(params["error"], "login_required");
        assert_eq!(params["state"], "login-state");
    });
}

#[test]
#[ignore]
fn prompt_unknown_value_returns_invalid_request() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("promptunknown", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Prompt Unknown Client",
            "prompt-unknown-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Unknown prompt value → invalid_request error redirect
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "prompt-unknown-client"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "unknown-state"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("prompt", "select_account"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert_eq!(params["error"], "invalid_request");
        assert_eq!(params["state"], "unknown-state");
    });
}

#[test]
#[ignore]
fn prompt_none_combined_with_login_returns_invalid_request() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("promptcombo", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Prompt Combo Client",
            "prompt-combo-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // none + login → invalid_request (none cannot combine with others)
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "prompt-combo-client"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "combo-state"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("prompt", "none login"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert_eq!(params["error"], "invalid_request");
        assert_eq!(params["state"], "combo-state");
    });
}

#[test]
#[ignore]
fn prompt_consent_with_auto_approve_issues_code() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("promptconsentaa", "user").await;

        let secret_hash = jwt::hash_token("secret");
        db::create_client(
            &s.db,
            "Prompt Consent Auto",
            "prompt-consent-auto",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true, // auto_approve — overrides prompt=consent
        )
        .await
        .unwrap();

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // prompt=consent with auto_approve → auto_approve wins, code issued
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "prompt-consent-auto"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "consent-auto"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("prompt", "consent"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert!(params.contains_key("code"), "expected code, got: {location}");
        assert_eq!(params["state"], "consent-auto");
    });
}

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
        assert_eq!(resp.status(), StatusCode::FOUND);

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
                ("state", "scope-state-123"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        // Redirects with ?error=invalid_scope per RFC 6749 §4.1.2.1
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let error = redirect_url.query_pairs().find(|(k, _)| k == "error").unwrap().1.to_string();
        assert_eq!(error, "invalid_scope");
        let state_val = redirect_url.query_pairs().find(|(k, _)| k == "state").unwrap().1.to_string();
        assert_eq!(state_val, "scope-state-123");
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
                ("state", "unknown-scope-state"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        // Redirects with ?error=invalid_scope per RFC 6749 §4.1.2.1
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let error = redirect_url.query_pairs().find(|(k, _)| k == "error").unwrap().1.to_string();
        assert_eq!(error, "invalid_scope");
        let state_val = redirect_url.query_pairs().find(|(k, _)| k == "state").unwrap().1.to_string();
        assert_eq!(state_val, "unknown-scope-state");
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
        assert_eq!(resp.status(), StatusCode::FOUND);

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
fn consent_get_returns_context() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, access_token, _) = s.create_user_with_session("consentuser", "user").await;

        let secret_hash = jwt::hash_token("secret");
        let oauth_client = db::create_client(
            &s.db,
            "Consent Test Client",
            "consent-test-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string(), "write:profile".to_string()],
            false,
        )
        .await
        .unwrap();

        // Store a consent request directly
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(600);
        let consent_id = db::store_consent_request(
            &s.db,
            oauth_client.id,
            user.id,
            &["read:profile".to_string(), "write:profile".to_string()],
            "https://app.example.com/callback",
            Some("test-state"),
            Some("challenge123"),
            Some("S256"),
            None,
            expires_at,
        )
        .await
        .unwrap();

        let resp = client
            .get(s.url("/oauth/consent"))
            .query(&[("consent_id", consent_id.to_string())])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["client"]["name"], "Consent Test Client");
        assert_eq!(body["client"]["client_id"], "consent-test-client");
        assert_eq!(body["redirect_uri"], "https://app.example.com/callback");
        assert_eq!(body["state"], "test-state");
        let scopes = body["scopes"].as_array().unwrap();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0]["name"], "read:profile");
        assert_eq!(scopes[0]["description"], "Read your profile information");
        assert_eq!(scopes[1]["name"], "write:profile");
        assert_eq!(scopes[1]["description"], "Update your profile information");
        // expires_at should be present and parseable as RFC 3339
        let expires_at_str = body["expires_at"].as_str().unwrap();
        chrono::DateTime::parse_from_rfc3339(expires_at_str).unwrap();
    });
}

#[test]
#[ignore]
fn consent_approve_issues_auth_code() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, access_token, _) = s.create_user_with_session("consentapprove", "user").await;

        let client_secret = "consent-secret";
        let secret_hash = jwt::hash_token(client_secret);
        let oauth_client = db::create_client(
            &s.db,
            "Consent Approve Client",
            "consent-approve-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string()],
            false,
        )
        .await
        .unwrap();

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Store a consent request
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(600);
        let consent_id = db::store_consent_request(
            &s.db,
            oauth_client.id,
            user.id,
            &["openid".to_string(), "read:profile".to_string()],
            "https://app.example.com/callback",
            Some("test-state"),
            Some(&pkce_challenge),
            Some("S256"),
            Some("test-nonce"),
            expires_at,
        )
        .await
        .unwrap();

        // Approve consent
        let resp = client
            .post(s.url("/oauth/consent"))
            .query(&[("consent_id", consent_id.to_string())])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "XMLHttpRequest")
            .json(&serde_json::json!({"approved": true}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert!(params.contains_key("code"), "should have authorization code");
        assert_eq!(params["state"], "test-state");

        // Exchange the authorization code for tokens
        let code = &params["code"];
        let token_resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", "https://app.example.com/callback"),
                ("client_id", "consent-approve-client"),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(token_resp.status(), StatusCode::OK);
        let token_body: serde_json::Value = token_resp.json().await.unwrap();
        assert!(token_body["access_token"].as_str().is_some());
        assert!(token_body["id_token"].as_str().is_some()); // openid scope → ID token
        assert_eq!(token_body["scope"], "openid read:profile");

        // Consent request should be consumed (deleted)
        let stale = db::find_consent_request(&s.db, consent_id).await.unwrap();
        assert!(stale.is_none(), "consent request should be deleted after approval");
    });
}

#[test]
#[ignore]
fn consent_deny_redirects_with_access_denied() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, access_token, _) = s.create_user_with_session("consentdeny", "user").await;

        let secret_hash = jwt::hash_token("secret");
        let oauth_client = db::create_client(
            &s.db,
            "Consent Deny Client",
            "consent-deny-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            false,
        )
        .await
        .unwrap();

        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(600);
        let consent_id = db::store_consent_request(
            &s.db,
            oauth_client.id,
            user.id,
            &["openid".to_string()],
            "https://app.example.com/callback",
            Some("deny-state"),
            None,
            None,
            None,
            expires_at,
        )
        .await
        .unwrap();

        let resp = client
            .post(s.url("/oauth/consent"))
            .query(&[("consent_id", consent_id.to_string())])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "XMLHttpRequest")
            .json(&serde_json::json!({"approved": false}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert_eq!(params["error"], "access_denied");
        assert_eq!(params["state"], "deny-state");

        // Consent request should be consumed
        let stale = db::find_consent_request(&s.db, consent_id).await.unwrap();
        assert!(stale.is_none());
    });
}

#[test]
#[ignore]
fn consent_rejects_expired_request() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, access_token, _) = s.create_user_with_session("consentexpired", "user").await;

        let secret_hash = jwt::hash_token("secret");
        let oauth_client = db::create_client(
            &s.db,
            "Consent Expired Client",
            "consent-expired-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            false,
        )
        .await
        .unwrap();

        // Store an already-expired consent request
        let expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        let consent_id = db::store_consent_request(
            &s.db,
            oauth_client.id,
            user.id,
            &[],
            "https://app.example.com/callback",
            None,
            None,
            None,
            None,
            expires_at,
        )
        .await
        .unwrap();

        let resp = client
            .get(s.url("/oauth/consent"))
            .query(&[("consent_id", consent_id.to_string())])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    });
}

#[test]
#[ignore]
fn consent_rejects_wrong_user() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user_a, _, _) = s.create_user_with_session("consentusera", "user").await;
        let (_, access_token_b, _) = s.create_user_with_session("consentuserb", "user").await;

        let secret_hash = jwt::hash_token("secret");
        let oauth_client = db::create_client(
            &s.db,
            "Consent Wrong User Client",
            "consent-wrong-user-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            false,
        )
        .await
        .unwrap();

        // Store consent for user A
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(600);
        let consent_id = db::store_consent_request(
            &s.db,
            oauth_client.id,
            user_a.id,
            &[],
            "https://app.example.com/callback",
            None,
            None,
            None,
            None,
            expires_at,
        )
        .await
        .unwrap();

        // User B tries to access user A's consent request — returns 404 (not 403)
        // to prevent oracle that reveals consent_id existence for other users.
        let resp = client
            .get(s.url("/oauth/consent"))
            .query(&[("consent_id", consent_id.to_string())])
            .header("cookie", format!("riley_auth_access={access_token_b}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    });
}

#[test]
#[ignore]
fn consent_requires_session_token() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // No cookie — should be rejected
        let resp = client
            .get(s.url("/oauth/consent"))
            .query(&[("consent_id", uuid::Uuid::now_v7().to_string())])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    });
}

#[test]
#[ignore]
fn consent_full_flow_via_authorize() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("consentflow", "user").await;

        let client_secret = "flow-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Full Flow Client",
            "flow-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string()],
            false, // non-auto-approve
        )
        .await
        .unwrap();

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Step 1: Authorize → redirect to consent URL
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "flow-client"),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid read:profile"),
                ("state", "flow-state"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("nonce", "flow-nonce"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let consent_url = url::Url::parse(location).unwrap();
        assert_eq!(consent_url.host_str(), Some("auth.example.com"));
        let consent_params: std::collections::HashMap<_, _> = consent_url.query_pairs().collect();
        let consent_id = &consent_params["consent_id"];

        // Step 2: GET consent context
        let resp = client
            .get(s.url("/oauth/consent"))
            .query(&[("consent_id", consent_id.as_ref())])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["client"]["name"], "Full Flow Client");

        // Step 3: Approve
        let resp = client
            .post(s.url("/oauth/consent"))
            .query(&[("consent_id", consent_id.as_ref())])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "XMLHttpRequest")
            .json(&serde_json::json!({"approved": true}))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let params: std::collections::HashMap<_, _> = redirect_url.query_pairs().collect();
        assert!(params.contains_key("code"));
        assert_eq!(params["state"], "flow-state");

        // Step 4: Exchange code for tokens
        let code = &params["code"];
        let token_resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_ref()),
                ("redirect_uri", "https://app.example.com/callback"),
                ("client_id", "flow-client"),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(token_resp.status(), StatusCode::OK);
        let token_body: serde_json::Value = token_resp.json().await.unwrap();
        assert!(token_body["access_token"].as_str().is_some());
        assert!(token_body["id_token"].as_str().is_some());
    });
}

#[test]
#[ignore]
fn token_endpoint_basic_auth_authorization_code() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("basictoken", "user").await;

        let client_id_str = "basic-token-client";
        let client_secret = "basic-token-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Basic Token Client",
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
                ("state", "basic-state"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();

        // Exchange code using Basic auth instead of POST body credentials
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id_str}:{client_secret}"));
        let resp = client
            .post(s.url("/oauth/token"))
            .header("authorization", format!("Basic {credentials}"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", "https://app.example.com/callback"),
                ("code_verifier", pkce_verifier.as_str()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(token_resp["token_type"], "Bearer");
        assert!(token_resp["access_token"].as_str().unwrap().len() > 100);
        assert!(token_resp["refresh_token"].as_str().is_some());
    });
}

#[test]
#[ignore]
fn token_endpoint_basic_auth_refresh() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("basicrefresh", "user").await;

        let client_id_str = "basic-refresh-client";
        let client_secret = "basic-refresh-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Basic Refresh Client",
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
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let code = url::Url::parse(location)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();

        // Exchange code via POST body auth to get a refresh token
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", "https://app.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", pkce_verifier.as_str()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let token_resp: serde_json::Value = resp.json().await.unwrap();
        let refresh_token = token_resp["refresh_token"].as_str().unwrap().to_string();

        // Refresh using Basic auth
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id_str}:{client_secret}"));
        let resp = client
            .post(s.url("/oauth/token"))
            .header("authorization", format!("Basic {credentials}"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.as_str()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let refresh_resp: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(refresh_resp["token_type"], "Bearer");
        assert!(refresh_resp["access_token"].as_str().unwrap().len() > 100);
        let new_refresh = refresh_resp["refresh_token"].as_str().unwrap();
        assert_ne!(new_refresh, refresh_token, "refresh token should be rotated");
    });
}

#[test]
#[ignore]
fn revoke_endpoint_basic_auth() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("basicrevoke", "user").await;

        let client_id_str = "basic-revoke-client";
        let client_secret = "basic-revoke-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Basic Revoke Client",
            client_id_str,
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Authorize + exchange to get a refresh token
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
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let code = url::Url::parse(location)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();

        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", "https://app.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", pkce_verifier.as_str()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let token_resp: serde_json::Value = resp.json().await.unwrap();
        let refresh_token = token_resp["refresh_token"].as_str().unwrap().to_string();

        // Revoke using Basic auth
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id_str}:{client_secret}"));
        let resp = client
            .post(s.url("/oauth/revoke"))
            .header("authorization", format!("Basic {credentials}"))
            .form(&[("token", refresh_token.as_str())])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify the token is revoked by trying to use it
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.as_str()),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK, "revoked token should not work");
    });
}

#[test]
#[ignore]
fn basic_auth_takes_precedence_over_post_body() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let client_id_str = "precedence-client";
        let client_secret = "precedence-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Precedence Client",
            client_id_str,
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let (user, _, _) = s.create_user_with_session("precedenceuser", "user").await;

        let token = s.keys.sign_access_token_with_scopes(
            &s.config.jwt,
            &user.id.to_string(),
            &user.username,
            &user.role,
            client_id_str,
            Some("openid"),
        ).unwrap();

        // Send correct Basic auth but wrong POST body credentials.
        // Basic auth should take precedence, so this should succeed.
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id_str}:{client_secret}"));
        let resp = client
            .post(s.url("/oauth/introspect"))
            .header("authorization", format!("Basic {credentials}"))
            .form(&[
                ("token", token.as_str()),
                ("client_id", "wrong-client"),
                ("client_secret", "wrong-secret"),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["active"], true);

        // Now send wrong Basic auth but correct POST body.
        // Basic auth should take precedence, so this should fail.
        let bad_credentials = base64::engine::general_purpose::STANDARD
            .encode("wrong-client:wrong-secret");
        let resp = client
            .post(s.url("/oauth/introspect"))
            .header("authorization", format!("Basic {bad_credentials}"))
            .form(&[
                ("token", token.as_str()),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();

        // Should fail because Basic auth (wrong) takes precedence
        assert_ne!(resp.status(), StatusCode::OK);
    });
}

#[test]
#[ignore]
fn token_and_revoke_reject_missing_credentials() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // POST to /oauth/token with no credentials at all
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[("grant_type", "authorization_code"), ("code", "fake")])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "token endpoint should reject missing credentials");

        // POST to /oauth/revoke with no credentials at all
        let resp = client
            .post(s.url("/oauth/revoke"))
            .form(&[("token", "fake-token")])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "revoke endpoint should reject missing credentials");
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
        assert_eq!(resp.status(), StatusCode::FOUND);

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
        assert_eq!(resp.status(), StatusCode::FOUND);

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
        assert_eq!(resp.status(), StatusCode::FOUND);

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
        assert_eq!(body["error"], "invalid_grant");
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
        assert_eq!(resp.status(), StatusCode::FOUND);

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
        assert_eq!(resp.status(), StatusCode::FOUND);

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

#[test]
#[ignore]
fn authorization_code_reuse_rejected() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("codereuse", "user").await;

        let client_id_str = "code-reuse-client";
        let client_secret = "code-reuse-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Code Reuse Client",
            client_id_str,
            &secret_hash,
            &["https://reuse-test.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Authorize → get code
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://reuse-test.example.com/callback"),
                ("response_type", "code"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();

        // First exchange: should succeed
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://reuse-test.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Second exchange with the same code: must fail
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://reuse-test.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "reused authorization code must be rejected"
        );
    });
}

#[test]
#[ignore]
fn backchannel_logout_register_client_with_logout_uri() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("bcladmin", "admin").await;

        // Register client with backchannel_logout_uri (session_required=false)
        let resp = client
            .post(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "name": "BCL App",
                "redirect_uris": ["https://app.example.com/callback"],
                "backchannel_logout_uri": "https://app.example.com/logout"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["backchannel_logout_uri"], "https://app.example.com/logout");
        assert_eq!(body["backchannel_logout_session_required"], false);

        // List clients — verify backchannel fields appear
        let resp = client
            .get(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let clients: Vec<serde_json::Value> = resp.json().await.unwrap();
        let bcl_client = clients.iter().find(|c| c["name"] == "BCL App").unwrap();
        assert_eq!(bcl_client["backchannel_logout_uri"], "https://app.example.com/logout");
        assert_eq!(bcl_client["backchannel_logout_session_required"], false);
    });
}

#[test]
#[ignore]
fn backchannel_logout_rejects_non_https_uri() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("bclhttpadmin", "admin").await;

        // http:// should be rejected (no localhost exception for backchannel logout)
        let resp = client
            .post(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "name": "Bad BCL App",
                "redirect_uris": ["https://app.example.com/callback"],
                "backchannel_logout_uri": "http://app.example.com/logout"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "bad_request");
        assert!(body["error_description"].as_str().unwrap().contains("https"));
    });
}

#[test]
#[ignore]
fn backchannel_logout_client_without_uri_has_null() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("bclnulladmin", "admin").await;

        // Register client without backchannel_logout_uri
        let resp = client
            .post(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "name": "No BCL App",
                "redirect_uris": ["https://app.example.com/callback"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body["backchannel_logout_uri"].is_null());
        assert_eq!(body["backchannel_logout_session_required"], false);
    });
}

#[test]
#[ignore]
fn backchannel_logout_rejects_session_required() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, admin_token, _) = s.create_user_with_session("bclsidadmin", "admin").await;

        // backchannel_logout_session_required=true should be rejected (sid not implemented)
        let resp = client
            .post(s.url("/admin/clients"))
            .header("cookie", format!("riley_auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .json(&serde_json::json!({
                "name": "SID App",
                "redirect_uris": ["https://app.example.com/callback"],
                "backchannel_logout_uri": "https://app.example.com/logout",
                "backchannel_logout_session_required": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body["error_description"].as_str().unwrap().contains("session_required"));
    });
}

#[test]
#[ignore]
fn backchannel_logout_discovery_document() {
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
        assert_eq!(doc["backchannel_logout_supported"], true);
        assert_eq!(doc["backchannel_logout_session_supported"], false);
    });
}

#[test]
#[ignore]
fn backchannel_logout_dispatched_on_logout_all() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Start a mock HTTP server to receive the logout token
        let received = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let received_clone = received.clone();

        let mock_app = axum::Router::new().route(
            "/backchannel-logout",
            axum::routing::post(move |body: String| {
                let received = received_clone.clone();
                async move {
                    received.lock().await.push(body);
                    StatusCode::OK
                }
            }),
        );

        let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(mock_listener, mock_app).await.unwrap();
        });

        // Register client with backchannel_logout_uri pointing to mock server
        let mock_logout_url = format!("http://127.0.0.1:{}/backchannel-logout", mock_addr.port());

        let (user, _access_token, _) = s.create_user_with_session("bcluser", "user").await;

        // Create OAuth client with backchannel logout URI via DB directly
        // (bypasses https validation since tests use http://localhost)
        let client_id_str = "bcl-test-client";
        let secret_hash = jwt::hash_token("bcl-secret");
        db::create_client_full(
            &s.db,
            "BCL Test Client",
            client_id_str,
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
            Some(&mock_logout_url),
            false,
        )
        .await
        .unwrap();

        // Create a client-bound refresh token for this user+client (so dispatch finds it)
        let oauth_client = db::find_client_by_client_id(&s.db, client_id_str).await.unwrap().unwrap();
        let (_, rt_hash) = jwt::generate_refresh_token();
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(86400);
        db::store_refresh_token(
            &s.db, user.id, Some(oauth_client.id), &rt_hash, expires_at,
            &[], None, None, uuid::Uuid::now_v7(), None, None,
        ).await.unwrap();

        // Call dispatch_backchannel_logout directly with allow_private_ips=true config
        // (can't go through the test server because it defaults to blocking private IPs)
        let mut test_config = (*s.config).clone();
        test_config.webhooks.allow_private_ips = true;
        let http_client = reqwest::Client::new();

        riley_auth_core::webhooks::dispatch_backchannel_logout(
            &s.db, &s.keys, &test_config, &http_client, user.id,
        ).await;

        // Wait for async delivery (fire-and-forget task)
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Verify the mock server received a logout token POST
        let bodies = received.lock().await;
        assert_eq!(bodies.len(), 1, "expected 1 backchannel logout delivery");

        // Body should be form-encoded: logout_token=<jwt>
        let body = &bodies[0];
        assert!(body.starts_with("logout_token="), "body should start with logout_token=");

        let token = body.strip_prefix("logout_token=").unwrap();

        // Decode the JWT header to verify it uses the configured signing algorithm
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "logout token should be a JWT");

        // Verify the payload claims
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(claims["iss"], "riley-auth-test");
        assert_eq!(claims["sub"], user.id.to_string());
        assert_eq!(claims["aud"], client_id_str);
        assert!(claims["iat"].is_number());
        assert!(claims["exp"].is_number());
        assert!(claims["jti"].is_string());
        // OIDC backchannel-logout events claim
        assert!(claims["events"]["http://schemas.openid.net/event/backchannel-logout"].is_object());
    });
}
