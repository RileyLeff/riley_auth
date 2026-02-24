mod common;
use common::*;

use base64::Engine;

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

        // Cache-Control header should reflect jwks_cache_max_age_secs config (3600)
        let cache_control = resp
            .headers()
            .get("cache-control")
            .expect("JWKS response must have Cache-Control header")
            .to_str()
            .unwrap();
        assert_eq!(
            cache_control, "public, max-age=3600",
            "JWKS Cache-Control should be public with configured max-age"
        );

        let body: serde_json::Value = resp.json().await.unwrap();
        let keys = body["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "EC");
        assert_eq!(keys[0]["alg"], "ES256");
        assert_eq!(keys[0]["crv"], "P-256");
        assert!(keys[0]["x"].as_str().unwrap().len() > 10);
        assert!(keys[0]["y"].as_str().unwrap().len() > 10);
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
            serde_json::json!(["ES256"])
        );
        assert_eq!(
            doc["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert_eq!(
            doc["token_endpoint_auth_methods_supported"],
            serde_json::json!(["client_secret_basic", "client_secret_post"])
        );
        assert_eq!(
            doc["revocation_endpoint_auth_methods_supported"],
            serde_json::json!(["client_secret_basic", "client_secret_post"])
        );

        // Scopes: OIDC protocol-level (openid, profile, email) + config-defined scopes
        let scopes = doc["scopes_supported"].as_array().unwrap();
        assert_eq!(scopes.len(), 5);
        assert!(scopes.contains(&serde_json::json!("openid")));
        assert!(scopes.contains(&serde_json::json!("profile")));
        assert!(scopes.contains(&serde_json::json!("email")));
        assert!(scopes.contains(&serde_json::json!("read:profile")));
        assert!(scopes.contains(&serde_json::json!("write:profile")));

        // claims_supported
        assert_eq!(
            doc["claims_supported"],
            serde_json::json!(["sub", "name", "preferred_username", "picture", "email", "email_verified", "updated_at", "auth_time"])
        );

        // userinfo_endpoint
        assert_eq!(
            doc["userinfo_endpoint"],
            "http://localhost:3000/oauth/userinfo"
        );

        // prompt_values_supported
        assert_eq!(
            doc["prompt_values_supported"],
            serde_json::json!(["none", "login", "consent"])
        );

        // OIDC Discovery fields added in Phase 8 review
        assert_eq!(doc["response_modes_supported"], serde_json::json!(["query"]));
        assert_eq!(doc["claims_parameter_supported"], false);
        assert_eq!(doc["request_parameter_supported"], false);
        assert_eq!(doc["request_uri_parameter_supported"], false);
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

        // Authorize with profile scope — profile claims should be in id_token
        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://oidc.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid profile read:profile"),
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
        // Profile claims present because "profile" scope was granted
        assert_eq!(claims["preferred_username"], "oidcuser");
        assert_eq!(claims["name"], "oidcuser Display");
        assert!(claims["sub"].as_str().is_some());
        assert!(claims["exp"].as_i64().is_some());
        assert!(claims["iat"].as_i64().is_some());
        // picture should be absent (user has no avatar)
        assert!(claims.get("picture").is_none());

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

#[test]
#[ignore]
fn oidc_id_token_omits_profile_claims_without_profile_scope() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("noprofileuser", "user").await;

        let client_id_str = "noprofile-client";
        let client_secret = "noprofile-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "No Profile Client",
            client_id_str,
            &secret_hash,
            &["https://noprofile.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        // Request openid only (no profile scope)
        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://noprofile.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid read:profile"),
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
                ("redirect_uri", "https://noprofile.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();
        let id_token_str = token_resp["id_token"].as_str().expect("id_token missing");

        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let parts: Vec<&str> = id_token_str.split('.').collect();
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        // Without "profile" scope, profile claims must be absent (OIDC Core 1.0 §5.4)
        assert!(claims.get("preferred_username").is_none(), "preferred_username should be absent without profile scope");
        assert!(claims.get("name").is_none(), "name should be absent without profile scope");
        assert!(claims.get("picture").is_none(), "picture should be absent without profile scope");
        // sub is always present
        assert!(claims["sub"].as_str().is_some());
    });
}

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
            .header("cookie", format!("auth_access={access_token}"))
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
            .header("cookie", format!("auth_access={access_token}"))
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
fn introspect_active_token_via_post_body() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // Create user and OAuth client
        let (user, _, _) = s.create_user_with_session("introuser", "user").await;
        let client_secret = "introspect-secret";
        let secret_hash = jwt::hash_token(client_secret);
        let oauth_client = db::create_client(
            &s.db,
            "Introspect Client",
            "introspect-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        // Issue an access token for this client
        let access_token = s.keys.sign_access_token_with_scopes(
            &s.config.jwt,
            &user.id.to_string(),
            &user.username,
            &user.role,
            &oauth_client.client_id,
            Some("openid read:profile"),
        ).unwrap();

        // Introspect via POST body credentials
        let resp = client
            .post(s.url("/oauth/introspect"))
            .form(&[
                ("token", access_token.as_str()),
                ("client_id", "introspect-client"),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["active"], true);
        assert_eq!(body["sub"], user.id.to_string());
        assert_eq!(body["username"], "introuser");
        assert_eq!(body["aud"], "introspect-client");
        assert_eq!(body["iss"], s.config.jwt.issuer);
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["scope"], "openid read:profile");
        assert_eq!(body["client_id"], "introspect-client");
        assert!(body["exp"].as_i64().is_some());
        assert!(body["iat"].as_i64().is_some());
    });
}

#[test]
#[ignore]
fn introspect_active_token_via_basic_auth() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, _, _) = s.create_user_with_session("introbasic", "user").await;
        let client_secret = "basic-secret";
        let secret_hash = jwt::hash_token(client_secret);
        let oauth_client = db::create_client(
            &s.db,
            "Basic Auth Client",
            "basic-auth-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let access_token = s.keys.sign_access_token_with_scopes(
            &s.config.jwt,
            &user.id.to_string(),
            &user.username,
            &user.role,
            &oauth_client.client_id,
            Some("openid"),
        ).unwrap();

        // Introspect via Basic auth
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("basic-auth-client:{client_secret}"));
        let resp = client
            .post(s.url("/oauth/introspect"))
            .header("authorization", format!("Basic {credentials}"))
            .form(&[("token", access_token.as_str())])
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["active"], true);
        assert_eq!(body["sub"], user.id.to_string());
    });
}

#[test]
#[ignore]
fn introspect_invalid_token_returns_inactive() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let client_secret = "introsecret2";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Introspect Client 2",
            "introspect-client-2",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let resp = client
            .post(s.url("/oauth/introspect"))
            .form(&[
                ("token", "this-is-not-a-valid-jwt"),
                ("client_id", "introspect-client-2"),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["active"], false);
    });
}

#[test]
#[ignore]
fn introspect_deleted_user_returns_inactive() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // Create two users (need second admin so we can delete the first)
        let (user, _, _) = s.create_user_with_session("introdel", "admin").await;
        let (_admin2, _, _) = s.create_user_with_session("intoadmin2", "admin").await;

        let client_secret = "introsecret3";
        let secret_hash = jwt::hash_token(client_secret);
        let oauth_client = db::create_client(
            &s.db,
            "Introspect Client 3",
            "introspect-client-3",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        // Issue a token for the user
        let access_token = s.keys.sign_access_token_with_scopes(
            &s.config.jwt,
            &user.id.to_string(),
            &user.username,
            &user.role,
            &oauth_client.client_id,
            Some("openid"),
        ).unwrap();

        // Verify it's active
        let resp = client
            .post(s.url("/oauth/introspect"))
            .form(&[
                ("token", access_token.as_str()),
                ("client_id", "introspect-client-3"),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["active"], true);

        // Soft-delete the user
        db::soft_delete_user(&s.db, user.id).await.unwrap();

        // Now introspect should return inactive
        let resp = client
            .post(s.url("/oauth/introspect"))
            .form(&[
                ("token", access_token.as_str()),
                ("client_id", "introspect-client-3"),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["active"], false);
    });
}

#[test]
#[ignore]
fn introspect_rejects_invalid_client_credentials() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let secret_hash = jwt::hash_token("real-secret");
        db::create_client(
            &s.db,
            "Introspect Client 4",
            "introspect-client-4",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        // Wrong client secret
        let resp = client
            .post(s.url("/oauth/introspect"))
            .form(&[
                ("token", "some-token"),
                ("client_id", "introspect-client-4"),
                ("client_secret", "wrong-secret"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // No credentials at all
        let resp = client
            .post(s.url("/oauth/introspect"))
            .form(&[("token", "some-token")])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    });
}

#[test]
#[ignore]
fn introspect_discovery_document_updated() {
    let s = server();
    runtime().block_on(async {
        let client = s.client();
        let resp = client
            .get(s.url("/.well-known/openid-configuration"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        let introspection_endpoint = body["introspection_endpoint"].as_str().unwrap();
        assert!(introspection_endpoint.ends_with("/oauth/introspect"));
        let auth_methods = body["introspection_endpoint_auth_methods_supported"].as_array().unwrap();
        assert!(auth_methods.contains(&serde_json::json!("client_secret_post")));
        assert!(auth_methods.contains(&serde_json::json!("client_secret_basic")));
    });
}

#[test]
#[ignore]
fn introspect_rejects_session_token() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // Create user with a session (session tokens have aud == issuer)
        let (user, _, _) = s.create_user_with_session("introsession", "user").await;

        // Create an OAuth client for authentication
        let client_secret = "session-reject-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Session Reject Client",
            "session-reject-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        // Sign a session token (aud == issuer)
        let session_token = s.keys.sign_access_token(
            &s.config.jwt,
            &user.id.to_string(),
            &user.username,
            &user.role,
            &s.config.jwt.issuer,
        ).unwrap();

        // Introspecting a session token should return inactive
        let resp = client
            .post(s.url("/oauth/introspect"))
            .form(&[
                ("token", session_token.as_str()),
                ("client_id", "session-reject-client"),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["active"], false);
    });
}

#[test]
#[ignore]
fn introspect_returns_cache_control_headers() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, _, _) = s.create_user_with_session("introcache", "user").await;
        let client_secret = "cache-secret";
        let secret_hash = jwt::hash_token(client_secret);
        let oauth_client = db::create_client(
            &s.db,
            "Cache Client",
            "cache-client",
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        let access_token = s.keys.sign_access_token_with_scopes(
            &s.config.jwt,
            &user.id.to_string(),
            &user.username,
            &user.role,
            &oauth_client.client_id,
            Some("openid"),
        ).unwrap();

        // Active token response should have Cache-Control: no-store
        let resp = client
            .post(s.url("/oauth/introspect"))
            .form(&[
                ("token", access_token.as_str()),
                ("client_id", "cache-client"),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(resp.headers().get("pragma").unwrap(), "no-cache");

        // Inactive token response should also have Cache-Control: no-store
        let resp = client
            .post(s.url("/oauth/introspect"))
            .form(&[
                ("token", "invalid-token"),
                ("client_id", "cache-client"),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(resp.headers().get("pragma").unwrap(), "no-cache");
    });
}

#[test]
#[ignore]
fn userinfo_full_flow_with_scopes() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // Create user with an email on the oauth_link
        let (user, access_token, _) = s.create_user_with_session("userinfouser", "user").await;

        // Register an OAuth client with openid, profile, and email scopes
        let client_id_str = "userinfo-client";
        let client_secret = "userinfo-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "UserInfo Test Client",
            client_id_str,
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();

        // Authorize with openid + read:profile scopes
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://app.example.com/callback"),
                ("response_type", "code"),
                ("state", "userinfo-state"),
                ("code_challenge", &pkce_challenge),
                ("code_challenge_method", "S256"),
                ("scope", "openid read:profile"),
            ])
            .header("cookie", format!("auth_access={access_token}"))
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
        let bearer_token = token_resp["access_token"].as_str().unwrap();

        // GET /oauth/userinfo with Bearer token
        let resp = client
            .get(s.url("/oauth/userinfo"))
            .header("authorization", format!("Bearer {bearer_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let userinfo: serde_json::Value = resp.json().await.unwrap();

        // "sub" is always returned
        assert_eq!(userinfo["sub"], user.id.to_string());

        // "profile" scope was not granted (read:profile is a custom scope, not "profile")
        // so preferred_username, name, picture, updated_at should be absent
        assert!(userinfo.get("preferred_username").is_none());

        // "email" scope was not granted, so email should be absent
        assert!(userinfo.get("email").is_none());

        // POST /oauth/userinfo also works
        let resp = client
            .post(s.url("/oauth/userinfo"))
            .header("authorization", format!("Bearer {bearer_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let userinfo_post: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(userinfo_post["sub"], user.id.to_string());
    });
}

#[test]
#[ignore]
fn userinfo_with_profile_and_email_scopes() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // Create user
        let (user, access_token, _) = s.create_user_with_session("profileuser", "user").await;

        // Sign a token directly with the scopes we want (profile and email are
        // now OIDC protocol-level scopes, but direct signing is still a valid way
        // to test the UserInfo endpoint in isolation).
        let client_id_str = "profile-email-client";
        let client_secret = "profile-email-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Profile Email Client",
            client_id_str,
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        // Sign a client-scoped access token directly with profile + email scopes
        let bearer_token = s
            .keys
            .sign_access_token_with_scopes(
                &s.config.jwt,
                &user.id.to_string(),
                &user.username,
                &user.role,
                client_id_str,
                Some("openid profile email"),
            )
            .unwrap();

        // GET /oauth/userinfo
        let resp = client
            .get(s.url("/oauth/userinfo"))
            .header("authorization", format!("Bearer {bearer_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let userinfo: serde_json::Value = resp.json().await.unwrap();

        // sub is always present
        assert_eq!(userinfo["sub"], user.id.to_string());

        // profile claims
        assert_eq!(userinfo["preferred_username"], user.username);
        assert_eq!(
            userinfo["name"],
            user.display_name.as_deref().unwrap_or("")
        );
        assert!(userinfo.get("updated_at").is_some());

        // email claims — from the oauth_link created by create_user_with_session
        assert_eq!(userinfo["email"], "profileuser@example.com");
        assert_eq!(userinfo["email_verified"], true);
    });
}

#[test]
#[ignore]
fn userinfo_rejects_session_token() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("sessionuser", "user").await;

        // Session token (aud == issuer) should be rejected
        let resp = client
            .get(s.url("/oauth/userinfo"))
            .header("authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp.headers().get("www-authenticate").expect("missing WWW-Authenticate header");
        assert!(www_auth.to_str().unwrap().contains("error=\"invalid_token\""));
    });
}

#[test]
#[ignore]
fn userinfo_rejects_missing_token() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // No Authorization header
        let resp = client
            .get(s.url("/oauth/userinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp.headers().get("www-authenticate").expect("missing WWW-Authenticate header");
        let www_auth_str = www_auth.to_str().unwrap();
        assert!(www_auth_str.starts_with("Bearer realm="), "expected Bearer realm, got: {www_auth_str}");
        assert!(!www_auth_str.contains("error="), "no-token case should not include error attribute");
    });
}

#[test]
#[ignore]
fn userinfo_rejects_invalid_token() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // Invalid Bearer token
        let resp = client
            .get(s.url("/oauth/userinfo"))
            .header("authorization", "Bearer invalid-garbage-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp.headers().get("www-authenticate").expect("missing WWW-Authenticate header");
        let www_auth_str = www_auth.to_str().unwrap();
        assert!(www_auth_str.contains("error=\"invalid_token\""), "expected invalid_token error, got: {www_auth_str}");
    });
}

#[test]
#[ignore]
fn userinfo_rejects_token_without_openid_scope() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, _, _) = s.create_user_with_session("noopeniduser", "user").await;

        // Register client
        let client_id_str = "no-openid-client";
        let client_secret = "no-openid-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "No OpenID Client",
            client_id_str,
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        // Sign a client-scoped token with only "read:profile" (no "openid")
        let bearer_token = s
            .keys
            .sign_access_token_with_scopes(
                &s.config.jwt,
                &user.id.to_string(),
                &user.username,
                &user.role,
                client_id_str,
                Some("read:profile"),
            )
            .unwrap();

        // UserInfo should reject — openid scope is required per OIDC Core 1.0 §5.3
        let resp = client
            .get(s.url("/oauth/userinfo"))
            .header("authorization", format!("Bearer {bearer_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let www_auth = resp.headers().get("www-authenticate").expect("missing WWW-Authenticate on 403");
        let www_auth_str = www_auth.to_str().unwrap();
        assert!(www_auth_str.contains("error=\"insufficient_scope\""), "expected insufficient_scope, got: {www_auth_str}");
    });
}

#[test]
#[ignore]
fn userinfo_expired_token_www_authenticate() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, _, _) = s.create_user_with_session("expireduser", "user").await;

        // Register a client so we can create a client-scoped token
        let client_id_str = "expired-client";
        let client_secret = "expired-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Expired Client",
            client_id_str,
            &secret_hash,
            &["https://app.example.com/callback".to_string()],
            &[],
            true,
        )
        .await
        .unwrap();

        // Manually construct an expired access token with openid scope
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: user.id.to_string(),
            username: user.username.clone(),
            role: user.role.clone(),
            aud: client_id_str.to_string(),
            iss: s.config.jwt.issuer.clone(),
            iat: now - 1000,
            exp: now - 500, // expired 500 seconds ago
            scope: Some("openid".to_string()),
        };
        let mut header = jsonwebtoken::Header::new(s.keys.active_algorithm());
        header.kid = Some(s.keys.active_kid().to_string());
        let expired_token =
            jsonwebtoken::encode(&header, &claims, s.keys.encoding_key()).unwrap();

        let resp = client
            .get(s.url("/oauth/userinfo"))
            .header("authorization", format!("Bearer {expired_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get("www-authenticate")
            .expect("missing WWW-Authenticate header on expired token");
        let www_auth_str = www_auth.to_str().unwrap();
        assert!(
            www_auth_str.contains("error=\"invalid_token\""),
            "expected invalid_token error, got: {www_auth_str}"
        );
        assert!(
            www_auth_str.contains("error_description=\"token expired\""),
            "expected token expired description, got: {www_auth_str}"
        );
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
            .header("cookie", format!("auth_access={access_token}"))
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
fn auth_time_present_and_preserved_across_refresh() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("authtime_user", "user").await;

        // Register client
        let client_id_str = "authtime-client";
        let client_secret = "authtime-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "AuthTime Client",
            client_id_str,
            &secret_hash,
            &["https://authtime.example.com/callback".to_string()],
            &["read:profile".to_string()],
            true,
        )
        .await
        .unwrap();

        let before = chrono::Utc::now().timestamp();

        // Authorize with openid scope
        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://authtime.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid read:profile"),
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
                ("redirect_uri", "https://authtime.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();
        let after = chrono::Utc::now().timestamp();

        // Verify auth_time in initial ID token
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let id_token_str = token_resp["id_token"].as_str().expect("id_token missing");
        let parts: Vec<&str> = id_token_str.split('.').collect();
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        let auth_time = claims["auth_time"].as_i64().expect("auth_time must be present in ID token");
        assert!(auth_time >= before, "auth_time should be >= test start time");
        assert!(auth_time <= after, "auth_time should be <= test end time");

        // Refresh the token
        let refresh_token = token_resp["refresh_token"].as_str().unwrap().to_string();
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
        let refreshed_id_token = refresh_resp["id_token"].as_str().expect("id_token missing after refresh");
        let parts: Vec<&str> = refreshed_id_token.split('.').collect();
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        let refreshed_auth_time = claims["auth_time"].as_i64().expect("auth_time must survive refresh");
        assert_eq!(auth_time, refreshed_auth_time, "auth_time must be preserved through token rotation");

        // Second refresh — verify auth_time still preserved
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

        let auth_time3 = claims["auth_time"].as_i64().expect("auth_time must survive multiple refreshes");
        assert_eq!(auth_time, auth_time3, "auth_time must survive multiple refresh rotations");
    });
}

#[test]
#[ignore]
fn id_token_includes_email_claims_when_email_scope_granted() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("emailiduser", "user").await;

        // Register client with email scope
        let client_id_str = "email-idtoken-client";
        let client_secret = "email-idtoken-secret";
        let secret_hash = jwt::hash_token(client_secret);
        db::create_client(
            &s.db,
            "Email ID Token Client",
            client_id_str,
            &secret_hash,
            &["https://email.example.com/callback".to_string()],
            &["email".to_string()],
            true,
        )
        .await
        .unwrap();

        // Authorize with openid + email scope
        let (pkce_verifier, pkce_challenge) = riley_auth_core::oauth::generate_pkce();
        let resp = client
            .get(s.url("/oauth/authorize"))
            .query(&[
                ("client_id", client_id_str),
                ("redirect_uri", "https://email.example.com/callback"),
                ("response_type", "code"),
                ("scope", "openid email"),
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
                ("redirect_uri", "https://email.example.com/callback"),
                ("client_id", client_id_str),
                ("client_secret", client_secret),
                ("code_verifier", &pkce_verifier),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let token_resp: serde_json::Value = resp.json().await.unwrap();
        let id_token_str = token_resp["id_token"]
            .as_str()
            .expect("id_token missing from token response");

        // Decode id_token and verify email claims
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let parts: Vec<&str> = id_token_str.split('.').collect();
        assert_eq!(parts.len(), 3, "id_token must be a 3-part JWT");
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        assert_eq!(
            claims["email"], "emailiduser@example.com",
            "email claim must be present in id_token when email scope granted"
        );
        assert_eq!(
            claims["email_verified"], true,
            "email_verified claim must be present in id_token when email scope granted"
        );

        // Refresh and verify email claims persist
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
        let refresh_id_token = refresh_resp["id_token"]
            .as_str()
            .expect("id_token missing from refresh response");

        let parts: Vec<&str> = refresh_id_token.split('.').collect();
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        assert_eq!(
            claims["email"], "emailiduser@example.com",
            "email claim must persist through refresh"
        );
        assert_eq!(
            claims["email_verified"], true,
            "email_verified claim must persist through refresh"
        );
    });
}
