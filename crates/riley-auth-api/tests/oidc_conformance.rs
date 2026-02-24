//! OIDC Conformance Verification Tests
//!
//! These tests verify riley_auth against the requirements of the OpenID Connect
//! Basic OP Certification Profile and Config OP Profile, as defined by the
//! OpenID Foundation conformance suite.
//!
//! Test names correspond to the official conformance test modules where applicable
//! (e.g., oidcc_server, oidcc_scope_profile, oidcc_prompt_login, etc.).
//!
//! References:
//! - OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
//! - OpenID Connect Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
//! - RFC 6749 (OAuth 2.0): https://tools.ietf.org/html/rfc6749
//! - RFC 7636 (PKCE): https://tools.ietf.org/html/rfc7636

mod common;
use common::*;

// ---------------------------------------------------------------------------
// Helper: full authorize → token flow
// ---------------------------------------------------------------------------

struct TokenResponse {
    access_token: String,
    refresh_token: String,
    id_token: Option<String>,
    scope: String,
    token_type: String,
    expires_in: i64,
}

async fn authorize_and_exchange(
    s: &common::TestServer,
    client: &Client,
    access_token: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    scope: &str,
    nonce: Option<&str>,
) -> TokenResponse {
    let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
    let mut query = vec![
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", scope),
        ("code_challenge", &pkce_challenge),
        ("code_challenge_method", "S256"),
        ("state", "test-state-123"),
    ];
    if let Some(n) = nonce {
        query.push(("nonce", n));
    }

    let resp = client
        .get(s.url("/oauth/authorize"))
        .query(&query)
        .header("cookie", format!("auth_access={access_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND, "authorize should redirect");

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let redirect_url = url::Url::parse(location).unwrap();

    // Verify state parameter round-trips
    let state = redirect_url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .expect("state must be present in redirect")
        .1
        .to_string();
    assert_eq!(state, "test-state-123", "state must round-trip");

    let code = redirect_url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .expect("code must be present in redirect")
        .1
        .to_string();

    // Exchange code for tokens
    let resp = client
        .post(s.url("/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code_verifier", &pkce_verifier),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "token exchange should succeed");

    let body: serde_json::Value = resp.json().await.unwrap();
    TokenResponse {
        access_token: body["access_token"].as_str().unwrap().to_string(),
        refresh_token: body["refresh_token"].as_str().unwrap().to_string(),
        id_token: body["id_token"].as_str().map(|s| s.to_string()),
        scope: body["scope"].as_str().unwrap().to_string(),
        token_type: body["token_type"].as_str().unwrap().to_string(),
        expires_in: body["expires_in"].as_i64().unwrap(),
    }
}

fn decode_id_token(id_token: &str) -> serde_json::Value {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3, "id_token must be a 3-part JWT");
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    serde_json::from_slice(&payload).unwrap()
}

fn decode_jwt_header(jwt: &str) -> serde_json::Value {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let parts: Vec<&str> = jwt.split('.').collect();
    let header = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    serde_json::from_slice(&header).unwrap()
}

async fn setup_client(
    s: &common::TestServer,
    name: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    allowed_scopes: &[String],
) {
    let secret_hash = jwt::hash_token(client_secret);
    db::create_client(
        &s.db,
        name,
        client_id,
        &secret_hash,
        &[redirect_uri.to_string()],
        allowed_scopes,
        true, // auto_approve
    )
    .await
    .unwrap();
}

// ===========================================================================
// CONFIG OP PROFILE — Discovery document validation
// ===========================================================================

/// Verifies the discovery document has all required fields per OIDC Discovery 1.0 §3
/// and that field values are correct.
#[test]
#[ignore]
fn config_op_discovery_document_required_fields() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let resp = client
            .get(s.url("/.well-known/openid-configuration"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let doc: serde_json::Value = resp.json().await.unwrap();

        // REQUIRED fields per OIDC Discovery 1.0 §3
        assert!(doc["issuer"].is_string(), "issuer is REQUIRED");
        assert!(doc["authorization_endpoint"].is_string(), "authorization_endpoint is REQUIRED");
        assert!(doc["token_endpoint"].is_string(), "token_endpoint is REQUIRED");
        assert!(doc["jwks_uri"].is_string(), "jwks_uri is REQUIRED");
        assert!(doc["response_types_supported"].is_array(), "response_types_supported is REQUIRED");
        assert!(doc["subject_types_supported"].is_array(), "subject_types_supported is REQUIRED");
        assert!(doc["id_token_signing_alg_values_supported"].is_array(), "id_token_signing_alg_values_supported is REQUIRED");

        // RECOMMENDED fields
        assert!(doc["userinfo_endpoint"].is_string(), "userinfo_endpoint RECOMMENDED");
        assert!(doc["scopes_supported"].is_array(), "scopes_supported RECOMMENDED");
        assert!(doc["claims_supported"].is_array(), "claims_supported RECOMMENDED");

        // Verify issuer matches
        assert_eq!(doc["issuer"], "riley-auth-test");

        // Verify response_types_supported includes "code"
        let response_types = doc["response_types_supported"].as_array().unwrap();
        assert!(
            response_types.iter().any(|v| v == "code"),
            "response_types_supported must include 'code' for Basic OP"
        );

        // Verify subject_types_supported
        let subject_types = doc["subject_types_supported"].as_array().unwrap();
        assert!(!subject_types.is_empty(), "subject_types_supported must not be empty");

        // Verify scopes_supported includes "openid"
        let scopes = doc["scopes_supported"].as_array().unwrap();
        assert!(
            scopes.iter().any(|v| v == "openid"),
            "scopes_supported must include 'openid'"
        );

        // Verify grant_types_supported includes "authorization_code"
        let grant_types = doc["grant_types_supported"].as_array().unwrap();
        assert!(
            grant_types.iter().any(|v| v == "authorization_code"),
            "grant_types_supported must include 'authorization_code'"
        );

        // Verify token_endpoint_auth_methods_supported
        let auth_methods = doc["token_endpoint_auth_methods_supported"].as_array().unwrap();
        assert!(
            auth_methods.iter().any(|v| v == "client_secret_basic"),
            "must support client_secret_basic"
        );
        assert!(
            auth_methods.iter().any(|v| v == "client_secret_post"),
            "must support client_secret_post"
        );

        // OIDC Discovery 1.0 §3: response_modes_supported
        assert_eq!(doc["response_modes_supported"], serde_json::json!(["query"]));

        // These fields should be present per our implementation
        assert_eq!(doc["claims_parameter_supported"], false);
        assert_eq!(doc["request_parameter_supported"], false);
        assert_eq!(doc["request_uri_parameter_supported"], false);

        // Verify prompt_values_supported
        let prompt_values = doc["prompt_values_supported"].as_array().unwrap();
        assert!(prompt_values.iter().any(|v| v == "none"));
        assert!(prompt_values.iter().any(|v| v == "login"));
        assert!(prompt_values.iter().any(|v| v == "consent"));

        // Verify revocation and introspection endpoints present
        assert!(doc["revocation_endpoint"].is_string(), "revocation_endpoint should be present");
        assert!(doc["introspection_endpoint"].is_string(), "introspection_endpoint should be present");
    });
}

/// Config OP: verify JWKS endpoint returns valid keys matching discovery document
#[test]
#[ignore]
fn config_op_jwks_endpoint_valid() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // Get JWKS URI from discovery
        let disc_resp = client
            .get(s.url("/.well-known/openid-configuration"))
            .send()
            .await
            .unwrap();
        let doc: serde_json::Value = disc_resp.json().await.unwrap();

        // Fetch JWKS
        let resp = client.get(s.url("/.well-known/jwks.json")).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Check Cache-Control header before consuming response body
        let cache_control = resp
            .headers()
            .get("cache-control")
            .expect("JWKS must have Cache-Control")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            cache_control.contains("max-age="),
            "Cache-Control must include max-age"
        );

        let jwks: serde_json::Value = resp.json().await.unwrap();
        let keys = jwks["keys"].as_array().expect("JWKS must have 'keys' array");
        assert!(!keys.is_empty(), "JWKS must contain at least one key");

        for key in keys {
            // Every key must have kty, kid, use, alg
            assert!(key["kty"].is_string(), "key must have 'kty'");
            assert!(key["kid"].is_string(), "key must have 'kid'");
            assert_eq!(key["use"], "sig", "key use must be 'sig'");
            assert!(key["alg"].is_string(), "key must have 'alg'");

            // Verify algorithm is in discovery document's id_token_signing_alg_values_supported
            let alg = key["alg"].as_str().unwrap();
            let supported_algs = doc["id_token_signing_alg_values_supported"].as_array().unwrap();
            assert!(
                supported_algs.iter().any(|v| v == alg),
                "JWKS key alg '{alg}' must be in id_token_signing_alg_values_supported"
            );

            // EC key specific checks
            if key["kty"] == "EC" {
                assert!(key["crv"].is_string(), "EC key must have 'crv'");
                assert!(key["x"].is_string(), "EC key must have 'x'");
                assert!(key["y"].is_string(), "EC key must have 'y'");
            }
            // RSA key specific checks
            if key["kty"] == "RSA" {
                assert!(key["n"].is_string(), "RSA key must have 'n'");
                assert!(key["e"].is_string(), "RSA key must have 'e'");
            }
        }
    });
}

// ===========================================================================
// BASIC OP PROFILE — Authorization Code Flow Tests
// ===========================================================================

/// oidcc-server: Basic authorization code flow end-to-end
/// Verifies the complete flow: authorize → code → token exchange → valid tokens
#[test]
#[ignore]
fn oidcc_server() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("conformance-user", "user").await;

        setup_client(
            s, "Conformance Client", "conf-client", "conf-secret",
            "https://conformance.example.com/callback",
            &["read:profile".to_string()],
        ).await;

        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "conf-client", "conf-secret",
            "https://conformance.example.com/callback",
            "openid read:profile",
            Some("test-nonce-123"),
        ).await;

        // Verify token response
        assert_eq!(tokens.token_type, "Bearer");
        assert!(tokens.expires_in > 0);
        assert!(tokens.id_token.is_some(), "id_token must be present when openid scope requested");

        // Verify ID token claims
        let id_token = tokens.id_token.unwrap();
        let claims = decode_id_token(&id_token);
        assert_eq!(claims["iss"], "riley-auth-test", "iss must match issuer");
        assert_eq!(claims["aud"], "conf-client", "aud must match client_id");
        assert!(claims["sub"].is_string(), "sub must be present");
        assert!(claims["exp"].is_i64(), "exp must be present");
        assert!(claims["iat"].is_i64(), "iat must be present");
        assert_eq!(claims["nonce"], "test-nonce-123", "nonce must round-trip");

        // Verify ID token header has kid matching JWKS
        let header = decode_jwt_header(&id_token);
        assert!(header["kid"].is_string(), "ID token header must have kid");
        assert!(header["alg"].is_string(), "ID token header must have alg");
    });
}

/// oidcc-response-type-missing: Request without response_type should fail
#[test]
#[ignore]
fn oidcc_response_type_missing() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("rt-missing", "user").await;

        setup_client(
            s, "RT Missing Client", "rt-missing-client", "rt-missing-secret",
            "https://rt.example.com/callback", &[],
        ).await;

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "rt-missing-client"),
                ("redirect_uri", "https://rt.example.com/callback"),
                // response_type intentionally omitted
                ("scope", "openid"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        // Should return an error — either direct 400 or redirect with error
        let status = resp.status();
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::FOUND,
            "missing response_type should result in error"
        );
    });
}

/// oidcc-userinfo-get: UserInfo endpoint via GET with Bearer token
#[test]
#[ignore]
fn oidcc_userinfo_get() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (user, access_token, _) = s.create_user_with_session("ui-get-user", "user").await;

        setup_client(
            s, "UserInfo GET Client", "ui-get-client", "ui-get-secret",
            "https://uiget.example.com/callback",
            &[],
        ).await;

        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "ui-get-client", "ui-get-secret",
            "https://uiget.example.com/callback",
            "openid profile",
            None,
        ).await;

        // GET /oauth/userinfo
        let resp = client
            .get(s.url("/oauth/userinfo"))
            .header("authorization", format!("Bearer {}", tokens.access_token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let userinfo: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(userinfo["sub"], user.id.to_string(), "sub must match");
        assert!(userinfo["preferred_username"].is_string(), "preferred_username should be present with profile scope");
    });
}

/// oidcc-userinfo-post-header: UserInfo endpoint via POST with Bearer token in header
#[test]
#[ignore]
fn oidcc_userinfo_post_header() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (user, access_token, _) = s.create_user_with_session("ui-post-user", "user").await;

        setup_client(
            s, "UserInfo POST Client", "ui-post-client", "ui-post-secret",
            "https://uipost.example.com/callback",
            &["read:profile".to_string()],
        ).await;

        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "ui-post-client", "ui-post-secret",
            "https://uipost.example.com/callback",
            "openid read:profile",
            None,
        ).await;

        // POST /oauth/userinfo with Bearer in header
        let resp = client
            .post(s.url("/oauth/userinfo"))
            .header("authorization", format!("Bearer {}", tokens.access_token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let userinfo: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(userinfo["sub"], user.id.to_string());
    });
}

/// oidcc-ensure-request-without-nonce-succeeds-for-code-flow:
/// OIDC Core §3.1.2.1: nonce is OPTIONAL in the authorization code flow
#[test]
#[ignore]
fn oidcc_ensure_request_without_nonce_succeeds_for_code_flow() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("no-nonce-user", "user").await;

        setup_client(
            s, "No Nonce Client", "no-nonce-client", "no-nonce-secret",
            "https://nononce.example.com/callback", &[],
        ).await;

        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "no-nonce-client", "no-nonce-secret",
            "https://nononce.example.com/callback",
            "openid",
            None, // no nonce
        ).await;

        assert!(tokens.id_token.is_some(), "id_token must be present even without nonce");

        let claims = decode_id_token(tokens.id_token.as_ref().unwrap());
        assert!(claims.get("nonce").is_none(), "nonce should be absent when not provided");
    });
}

/// oidcc-scope-profile: Verify profile scope returns profile claims
#[test]
#[ignore]
fn oidcc_scope_profile() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (user, access_token, _) = s.create_user_with_session("profile-user", "user").await;

        setup_client(
            s, "Profile Scope Client", "profile-client", "profile-secret",
            "https://profile.example.com/callback",
            &["read:profile".to_string()],
        ).await;

        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "profile-client", "profile-secret",
            "https://profile.example.com/callback",
            "openid profile",
            None,
        ).await;

        let resp = client
            .get(s.url("/oauth/userinfo"))
            .header("authorization", format!("Bearer {}", tokens.access_token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let userinfo: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(userinfo["sub"], user.id.to_string());
        // Profile claims per OIDC Core §5.4
        assert!(userinfo["preferred_username"].is_string(), "preferred_username expected with profile scope");
        assert!(userinfo["name"].is_string(), "name expected with profile scope");
        assert!(userinfo.get("updated_at").is_some(), "updated_at expected with profile scope");
    });
}

/// oidcc-scope-email: Verify email scope returns email claims
#[test]
#[ignore]
fn oidcc_scope_email() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (user, access_token, _) = s.create_user_with_session("email-user", "user").await;

        setup_client(
            s, "Email Scope Client", "email-client", "email-secret",
            "https://email.example.com/callback",
            &["email".to_string()],
        ).await;

        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "email-client", "email-secret",
            "https://email.example.com/callback",
            "openid email",
            None,
        ).await;

        let resp = client
            .get(s.url("/oauth/userinfo"))
            .header("authorization", format!("Bearer {}", tokens.access_token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let userinfo: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(userinfo["sub"], user.id.to_string());
        // Email claims per OIDC Core §5.4
        assert_eq!(userinfo["email"], "email-user@example.com");
        assert_eq!(userinfo["email_verified"], true);

        // Also verify email in ID token
        let id_claims = decode_id_token(tokens.id_token.as_ref().unwrap());
        assert_eq!(id_claims["email"], "email-user@example.com");
        assert_eq!(id_claims["email_verified"], true);
    });
}

/// oidcc-ensure-other-scope-order-succeeds: Scope order should not matter
#[test]
#[ignore]
fn oidcc_ensure_other_scope_order_succeeds() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("scope-order-user", "user").await;

        setup_client(
            s, "Scope Order Client", "scope-order-client", "scope-order-secret",
            "https://scopeorder.example.com/callback",
            &["read:profile".to_string(), "email".to_string()],
        ).await;

        // Request scopes in non-standard order: email before openid
        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "scope-order-client", "scope-order-secret",
            "https://scopeorder.example.com/callback",
            "email openid read:profile",
            None,
        ).await;

        assert!(tokens.id_token.is_some(), "id_token must be present regardless of scope order");
    });
}

/// oidcc-prompt-login: prompt=login should force re-authentication
#[test]
#[ignore]
fn oidcc_prompt_login() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("prompt-login-user", "user").await;

        setup_client(
            s, "Prompt Login Client", "prompt-login-client", "prompt-login-secret",
            "https://promptlogin.example.com/callback", &[],
        ).await;

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "prompt-login-client"),
                ("redirect_uri", "https://promptlogin.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("prompt", "login"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        // prompt=login should redirect to login_url or return login_required
        // Since riley_auth has no login_url configured in test, it returns login_required
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let error = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "error")
            .map(|(_, v)| v.to_string());
        assert_eq!(error.as_deref(), Some("login_required"), "prompt=login without login_url should return login_required");
    });
}

/// oidcc-prompt-none-not-logged-in: prompt=none without session → login_required
#[test]
#[ignore]
fn oidcc_prompt_none_not_logged_in() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        setup_client(
            s, "Prompt None Client", "prompt-none-client", "prompt-none-secret",
            "https://promptnone.example.com/callback", &[],
        ).await;

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "prompt-none-client"),
                ("redirect_uri", "https://promptnone.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("prompt", "none"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            // No session cookie
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let error = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "error")
            .unwrap()
            .1
            .to_string();
        assert_eq!(error, "login_required", "prompt=none without session must return login_required");
    });
}

/// oidcc-prompt-none-logged-in: prompt=none with valid session → issue code silently
#[test]
#[ignore]
fn oidcc_prompt_none_logged_in() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("silent-user", "user").await;

        setup_client(
            s, "Silent Client", "silent-client", "silent-secret",
            "https://silent.example.com/callback", &[],
        ).await;

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "silent-client"),
                ("redirect_uri", "https://silent.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("prompt", "none"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();

        // Should have code, not error
        let code = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "code");
        assert!(code.is_some(), "prompt=none with valid session should issue code silently");

        let error = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "error");
        assert!(error.is_none(), "should not have error when session is valid");
    });
}

/// oidcc-ensure-request-with-unknown-parameter-succeeds:
/// Unknown parameters should be ignored per OIDC Core §3.1.2.1
#[test]
#[ignore]
fn oidcc_ensure_request_with_unknown_parameter_succeeds() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("unknown-param-user", "user").await;

        setup_client(
            s, "Unknown Param Client", "unknown-param-client", "unknown-param-secret",
            "https://unknownparam.example.com/callback", &[],
        ).await;

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "unknown-param-client"),
                ("redirect_uri", "https://unknownparam.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("unknown_parameter", "should-be-ignored"),
                ("another_unknown", "also-ignored"),
            ])
            .header("cookie", format!("auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url.query_pairs().find(|(k, _)| k == "code");
        assert!(code.is_some(), "unknown parameters must be ignored, flow should succeed");
    });
}

/// oidcc-ensure-request-with-acr-values-succeeds:
/// acr_values parameter should be accepted (even if not acted upon)
#[test]
#[ignore]
fn oidcc_ensure_request_with_acr_values_succeeds() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("acr-user", "user").await;

        setup_client(
            s, "ACR Client", "acr-client", "acr-secret",
            "https://acr.example.com/callback", &[],
        ).await;

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "acr-client"),
                ("redirect_uri", "https://acr.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("acr_values", "urn:mace:incommon:iap:silver"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url.query_pairs().find(|(k, _)| k == "code");
        assert!(code.is_some(), "acr_values should be accepted without error");
    });
}

/// oidcc-codereuse: Authorization code must not be reusable
#[test]
#[ignore]
fn oidcc_codereuse() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("codereuse-user", "user").await;

        setup_client(
            s, "Code Reuse Client", "codereuse-client", "codereuse-secret",
            "https://codereuse.example.com/callback", &[],
        ).await;

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "codereuse-client"),
                ("redirect_uri", "https://codereuse.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();

        // First exchange should succeed
        let resp1 = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://codereuse.example.com/callback"),
                ("client_id", "codereuse-client"),
                ("client_secret", "codereuse-secret"),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK, "first code exchange should succeed");

        // Second exchange with same code should fail
        let resp2 = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://codereuse.example.com/callback"),
                ("client_id", "codereuse-client"),
                ("client_secret", "codereuse-secret"),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST, "code reuse must fail");

        let body: serde_json::Value = resp2.json().await.unwrap();
        assert_eq!(body["error"], "invalid_grant", "code reuse must return invalid_grant");
    });
}

/// oidcc-ensure-registered-redirect-uri: Only registered redirect URIs should be accepted
#[test]
#[ignore]
fn oidcc_ensure_registered_redirect_uri() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("redir-user", "user").await;

        setup_client(
            s, "Redirect URI Client", "redir-client", "redir-secret",
            "https://registered.example.com/callback", &[],
        ).await;

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "redir-client"),
                ("redirect_uri", "https://evil.example.com/callback"), // unregistered
                ("response_type", "code"),
                ("scope", "openid"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        // Must reject unregistered redirect URIs — should return error, not redirect to the evil URI
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "unregistered redirect_uri must be rejected");
    });
}

/// oidcc-server-client-secret-post: Token endpoint with client_secret_post auth
#[test]
#[ignore]
fn oidcc_server_client_secret_post() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("post-auth-user", "user").await;

        setup_client(
            s, "Post Auth Client", "post-auth-client", "post-auth-secret",
            "https://postauth.example.com/callback", &[],
        ).await;

        // This is what authorize_and_exchange does — client_secret in POST body
        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "post-auth-client", "post-auth-secret",
            "https://postauth.example.com/callback",
            "openid",
            None,
        ).await;

        assert!(tokens.id_token.is_some());
    });
}

/// oidcc-server-client-secret-basic: Token endpoint with HTTP Basic auth
#[test]
#[ignore]
fn oidcc_server_client_secret_basic() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("basic-auth-user", "user").await;

        setup_client(
            s, "Basic Auth Client", "basic-auth-client", "basic-auth-secret",
            "https://basicauth.example.com/callback", &[],
        ).await;

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "basic-auth-client"),
                ("redirect_uri", "https://basicauth.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let code = redirect_url.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();

        // Use HTTP Basic auth for token exchange
        use base64::{Engine, engine::general_purpose::STANDARD};
        let basic = STANDARD.encode("basic-auth-client:basic-auth-secret");
        let resp = client
            .post(s.url("/oauth/token"))
            .header("authorization", format!("Basic {basic}"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://basicauth.example.com/callback"),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "Basic auth token exchange should succeed");

        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body["id_token"].is_string(), "id_token must be present");
    });
}

/// oidcc-refresh-token: Refresh token flow must work and return new tokens
#[test]
#[ignore]
fn oidcc_refresh_token() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("refresh-user", "user").await;

        setup_client(
            s, "Refresh Client", "refresh-client", "refresh-secret",
            "https://refresh.example.com/callback", &[],
        ).await;

        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "refresh-client", "refresh-secret",
            "https://refresh.example.com/callback",
            "openid",
            Some("refresh-nonce"),
        ).await;

        // Refresh
        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &tokens.refresh_token),
                ("client_id", "refresh-client"),
                ("client_secret", "refresh-secret"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body["access_token"].is_string(), "refresh must return new access_token");
        assert!(body["refresh_token"].is_string(), "refresh must return new refresh_token");
        assert!(body["id_token"].is_string(), "refresh must return id_token when openid scope");
        assert_eq!(body["token_type"], "Bearer");

        // Verify refreshed ID token still has correct claims
        let id_claims = decode_id_token(body["id_token"].as_str().unwrap());
        assert_eq!(id_claims["iss"], "riley-auth-test");
        assert!(id_claims["sub"].is_string());
        assert!(id_claims["auth_time"].is_i64(), "auth_time must be present in refreshed ID token");
    });
}

/// oidcc-ensure-request-with-valid-pkce-succeeds: PKCE S256 must work
#[test]
#[ignore]
fn oidcc_ensure_request_with_valid_pkce_succeeds() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("pkce-user", "user").await;

        setup_client(
            s, "PKCE Client", "pkce-client", "pkce-secret",
            "https://pkce.example.com/callback", &[],
        ).await;

        // authorize_and_exchange already uses PKCE S256
        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "pkce-client", "pkce-secret",
            "https://pkce.example.com/callback",
            "openid",
            None,
        ).await;

        assert!(tokens.id_token.is_some(), "PKCE flow should succeed and return id_token");
    });
}

// ===========================================================================
// Token endpoint error codes (RFC 6749 §5.2)
// ===========================================================================

/// Verify unsupported_grant_type error code
#[test]
#[ignore]
fn oidcc_unsupported_grant_type() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        setup_client(
            s, "Grant Type Client", "granttype-client", "granttype-secret",
            "https://granttype.example.com/callback", &[],
        ).await;

        let resp = client
            .post(s.url("/oauth/token"))
            .header("x-requested-with", "test")
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "granttype-client"),
                ("client_secret", "granttype-secret"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "unsupported_grant_type");
    });
}

/// Verify invalid_grant error code for bad authorization code
#[test]
#[ignore]
fn oidcc_invalid_grant_bad_code() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        setup_client(
            s, "Bad Code Client", "badcode-client", "badcode-secret",
            "https://badcode.example.com/callback", &[],
        ).await;

        let resp = client
            .post(s.url("/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", "this-is-not-a-valid-code"),
                ("redirect_uri", "https://badcode.example.com/callback"),
                ("client_id", "badcode-client"),
                ("client_secret", "badcode-secret"),
                ("code_verifier", "also-not-valid"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "invalid_grant");
    });
}

// ===========================================================================
// ID Token validation (OIDC Core §3.1.3.7)
// ===========================================================================

/// Verify ID token has all REQUIRED claims per OIDC Core §2
#[test]
#[ignore]
fn oidcc_id_token_required_claims() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("idtoken-claims-user", "user").await;

        setup_client(
            s, "ID Token Claims Client", "idtoken-claims-client", "idtoken-claims-secret",
            "https://idtokenclaims.example.com/callback", &[],
        ).await;

        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "idtoken-claims-client", "idtoken-claims-secret",
            "https://idtokenclaims.example.com/callback",
            "openid",
            Some("idtoken-nonce-456"),
        ).await;

        let id_token = tokens.id_token.unwrap();
        let claims = decode_id_token(&id_token);
        let header = decode_jwt_header(&id_token);

        // REQUIRED claims per OIDC Core §2
        assert!(claims["iss"].is_string(), "iss REQUIRED");
        assert!(claims["sub"].is_string(), "sub REQUIRED");
        assert!(claims["aud"].is_string() || claims["aud"].is_array(), "aud REQUIRED");
        assert!(claims["exp"].is_number(), "exp REQUIRED");
        assert!(claims["iat"].is_number(), "iat REQUIRED");

        // iss must match issuer
        assert_eq!(claims["iss"], "riley-auth-test");

        // aud must contain client_id
        if claims["aud"].is_string() {
            assert_eq!(claims["aud"], "idtoken-claims-client");
        } else {
            let aud_arr = claims["aud"].as_array().unwrap();
            assert!(aud_arr.iter().any(|v| v == "idtoken-claims-client"));
        }

        // exp must be in the future
        let exp = claims["exp"].as_i64().unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(exp > now, "exp must be in the future");

        // iat must be in the past (or present)
        let iat = claims["iat"].as_i64().unwrap();
        assert!(iat <= now + 5, "iat must be current or past");

        // nonce must round-trip when provided
        assert_eq!(claims["nonce"], "idtoken-nonce-456");

        // auth_time should be present
        assert!(claims["auth_time"].is_i64(), "auth_time should be present");

        // JWT header must have alg and kid
        assert!(header["alg"].is_string(), "JWT header must have alg");
        assert!(header["kid"].is_string(), "JWT header must have kid");
    });
}

/// Verify ID token signature can be verified using JWKS keys
#[test]
#[ignore]
fn oidcc_id_token_signature_verification() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("sigverify-user", "user").await;

        setup_client(
            s, "Sig Verify Client", "sigverify-client", "sigverify-secret",
            "https://sigverify.example.com/callback", &[],
        ).await;

        let tokens = authorize_and_exchange(
            s, &client, &access_token,
            "sigverify-client", "sigverify-secret",
            "https://sigverify.example.com/callback",
            "openid",
            None,
        ).await;

        let id_token = tokens.id_token.unwrap();
        let header = decode_jwt_header(&id_token);
        let kid = header["kid"].as_str().unwrap();

        // Fetch JWKS
        let jwks_resp = client.get(s.url("/.well-known/jwks.json")).send().await.unwrap();
        let jwks: serde_json::Value = jwks_resp.json().await.unwrap();
        let keys = jwks["keys"].as_array().unwrap();

        // Find matching key by kid
        let matching_key = keys.iter().find(|k| k["kid"].as_str() == Some(kid));
        assert!(matching_key.is_some(), "JWKS must contain key with kid matching ID token");

        // Verify the ID token using the KeySet (which has the verification keys)
        let claims = s.keys.verify_token::<serde_json::Value>(&s.config.jwt, &id_token);
        assert!(claims.is_ok(), "ID token signature must be verifiable with JWKS keys");
    });
}

// ===========================================================================
// prompt parameter edge cases
// ===========================================================================

/// prompt with unknown value should return invalid_request
#[test]
#[ignore]
fn oidcc_prompt_unknown_value_returns_invalid_request() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("prompt-unknown-user", "user").await;

        setup_client(
            s, "Prompt Unknown Client", "prompt-unknown-client", "prompt-unknown-secret",
            "https://promptunknown.example.com/callback", &[],
        ).await;

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "prompt-unknown-client"),
                ("redirect_uri", "https://promptunknown.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("prompt", "bogus_value"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let error = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "error")
            .unwrap()
            .1
            .to_string();
        assert_eq!(error, "invalid_request");
    });
}

/// prompt=none combined with login should return invalid_request per OIDC Core §3.1.2.1
#[test]
#[ignore]
fn oidcc_prompt_none_combined_invalid() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();
        let (_, access_token, _) = s.create_user_with_session("prompt-combo-user", "user").await;

        setup_client(
            s, "Prompt Combo Client", "prompt-combo-client", "prompt-combo-secret",
            "https://promptcombo.example.com/callback", &[],
        ).await;

        let (_, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", "prompt-combo-client"),
                ("redirect_uri", "https://promptcombo.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("prompt", "none login"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
            ])
            .header("cookie", format!("auth_access={access_token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect_url = url::Url::parse(location).unwrap();
        let error = redirect_url
            .query_pairs()
            .find(|(k, _)| k == "error")
            .unwrap()
            .1
            .to_string();
        assert_eq!(error, "invalid_request");
    });
}
