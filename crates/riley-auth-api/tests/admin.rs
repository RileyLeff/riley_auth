mod common;
use common::*;

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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={user_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let clients: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(clients.iter().any(|c| c["name"] == "Test App"));

        // Remove client
        let resp = client
            .delete(s.url(&format!("/admin/clients/{client_id}")))
            .header("cookie", format!("auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
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
