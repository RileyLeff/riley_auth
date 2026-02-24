mod common;
use common::*;

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

        let held = db::is_username_held(&s.db, "oldname", uuid::Uuid::nil()).await.unwrap();
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
        db::store_refresh_token(&s.db, user.id, None, &hash2, expires_at, &[], None, None, uuid::Uuid::now_v7(), None, None)
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
            &s.db, user.id, None, &second_hash, expires_at, &[], None, None, uuid::Uuid::now_v7(), None, None,
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
fn link_confirm_adds_provider_to_existing_account() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        // Create user with google provider
        let (user, access_token, _) = s.create_user_with_session("linkconfirm", "user").await;

        // Verify user has exactly one provider link
        let resp = client
            .get(s.url("/auth/me/links"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let links: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["provider"], "google");

        // Create a setup token simulating an email collision from github
        // (as if auth_callback detected that github user has same email)
        let setup_token = {
            let provider = "github";
            let provider_id = "gh-12345";

            let claims = serde_json::json!({
                "profile": {
                    "provider": provider,
                    "provider_id": provider_id,
                    "email": "linkconfirm@example.com",
                    "name": "Link Confirm User",
                    "avatar_url": null
                },
                "exp": (chrono::Utc::now() + chrono::Duration::minutes(15)).timestamp(),
                "iss": s.config.jwt.issuer,
                "purpose": "setup"
            });

            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
            header.kid = Some(s.keys.active_kid().to_string());
            jsonwebtoken::encode(&header, &claims, &s.keys.encoding_key()).unwrap()
        };

        // Call POST /auth/link/confirm with session + setup token cookies
        let cookie_str = format!(
            "riley_auth_access={access_token}; riley_auth_setup={setup_token}"
        );
        let resp = client
            .post(s.url("/auth/link/confirm"))
            .header("cookie", &cookie_str)
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Response should be the user profile
        let me: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(me["username"], "linkconfirm");

        // Verify user now has two provider links
        let resp = client
            .get(s.url("/auth/me/links"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let links: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(links.len(), 2, "user should now have two provider links");

        let providers: Vec<&str> = links.iter().map(|l| l["provider"].as_str().unwrap()).collect();
        assert!(providers.contains(&"google"));
        assert!(providers.contains(&"github"));
    });
}

#[test]
#[ignore]
fn link_confirm_rejects_already_linked_provider() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (user, access_token, _) = s.create_user_with_session("linkdup", "user").await;

        // Get the user's existing provider link to find the provider_id
        let links = db::find_oauth_links_by_user(&s.db, user.id).await.unwrap();
        let existing_link = &links[0];

        // Create setup token for the same provider identity that's already linked
        let setup_token = {
            let claims = serde_json::json!({
                "profile": {
                    "provider": &existing_link.provider,
                    "provider_id": &existing_link.provider_id,
                    "email": "linkdup@example.com",
                    "name": null,
                    "avatar_url": null
                },
                "exp": (chrono::Utc::now() + chrono::Duration::minutes(15)).timestamp(),
                "iss": s.config.jwt.issuer,
                "purpose": "setup"
            });

            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
            header.kid = Some(s.keys.active_kid().to_string());
            jsonwebtoken::encode(&header, &claims, &s.keys.encoding_key()).unwrap()
        };

        let cookie_str = format!(
            "riley_auth_access={access_token}; riley_auth_setup={setup_token}"
        );
        let resp = client
            .post(s.url("/auth/link/confirm"))
            .header("cookie", &cookie_str)
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let err: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(err["error"], "provider_already_linked");
    });
}

#[test]
#[ignore]
fn link_confirm_requires_both_cookies() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;
        let client = s.client();

        let (_, access_token, _) = s.create_user_with_session("linknocookie", "user").await;

        // Without setup cookie → should fail
        let resp = client
            .post(s.url("/auth/link/confirm"))
            .header("cookie", format!("riley_auth_access={access_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Without session cookie → should fail
        let resp = client
            .post(s.url("/auth/link/confirm"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    });
}

#[test]
#[ignore]
fn account_merge_email_verified_column_stored() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Create user with email_verified = true (default in test helper)
        let (user, _, _) = s.create_user_with_session("mergetest", "user").await;

        let links = db::find_oauth_links_by_user(&s.db, user.id).await.unwrap();
        assert_eq!(links.len(), 1);
        assert!(links[0].email_verified, "email_verified should be true");
        assert_eq!(links[0].provider_email.as_deref(), Some("mergetest@example.com"));
    });
}

#[test]
#[ignore]
fn account_merge_email_verified_false_stored() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Create user with email_verified = false
        let user = db::create_user_with_link(
            &s.db,
            "noverify",
            Some("No Verify"),
            None,
            "github",
            "gh-noverify",
            Some("noverify@example.com"),
            false,
        )
        .await
        .unwrap();

        let links = db::find_oauth_links_by_user(&s.db, user.id).await.unwrap();
        assert_eq!(links.len(), 1);
        assert!(!links[0].email_verified, "email_verified should be false");
    });
}

#[test]
#[ignore]
fn account_merge_auto_links_on_verified_email() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Create user with google provider + verified email
        let (user, _, _) = s.create_user_with_session("mergeuser", "user").await;
        assert_eq!(
            db::find_oauth_links_by_user(&s.db, user.id).await.unwrap().len(),
            1,
            "should have exactly one link initially"
        );

        // Simulate: a new provider (github) reports the same verified email
        // This mimics what auth_callback does when account_merge_policy = verified_email
        let matching_links = db::find_oauth_links_by_email(&s.db, "mergeuser@example.com").await.unwrap();
        assert_eq!(matching_links.len(), 1, "should find one matching link by email");
        assert_eq!(matching_links[0].user_id, user.id);

        // Auto-merge: create a new link for the same user from a different provider
        let new_link = db::create_oauth_link(
            &s.db,
            user.id,
            "github",
            "gh-merge-123",
            Some("mergeuser@example.com"),
            true,
        )
        .await
        .unwrap();
        assert_eq!(new_link.user_id, user.id);
        assert_eq!(new_link.provider, "github");
        assert!(new_link.email_verified);

        // Verify user now has two provider links
        let all_links = db::find_oauth_links_by_user(&s.db, user.id).await.unwrap();
        assert_eq!(all_links.len(), 2, "should have two links after merge");

        let providers: Vec<&str> = all_links.iter().map(|l| l.provider.as_str()).collect();
        assert!(providers.contains(&"google"));
        assert!(providers.contains(&"github"));
    });
}

#[test]
#[ignore]
fn account_merge_skips_unverified_existing_link() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Create a user whose existing link has email_verified = false
        let user = db::create_user_with_link(
            &s.db,
            "unverified_existing",
            None,
            None,
            "github",
            "gh-unverified-999",
            Some("shared@example.com"),
            false, // existing link is NOT verified
        )
        .await
        .unwrap();

        // Now simulate an auto-merge query: find matching links and filter by verified
        let matching_links = db::find_oauth_links_by_email(&s.db, "shared@example.com")
            .await
            .unwrap();
        assert_eq!(matching_links.len(), 1, "should find one matching link");

        // The auto-merge path filters to verified links only
        let verified_links: Vec<&db::OAuthLink> = matching_links
            .iter()
            .filter(|l| l.email_verified)
            .collect();
        assert!(
            verified_links.is_empty(),
            "no verified links → auto-merge should not proceed"
        );

        // Verify user still has only one link (no merge happened)
        let all_links = db::find_oauth_links_by_user(&s.db, user.id).await.unwrap();
        assert_eq!(all_links.len(), 1);
    });
}

#[test]
#[ignore]
fn account_merge_config_defaults_to_none() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Default config has account_merge_policy = None
        assert_eq!(
            s.config.oauth.account_merge_policy,
            riley_auth_core::config::AccountMergePolicy::None,
            "default merge policy should be None"
        );
    });
}
