mod common;
use common::*;

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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify removed
        let resp = client
            .get(s.url("/admin/webhooks"))
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={user_token}"))
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
            .header("cookie", format!("auth_access={user_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let deliveries: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(deliveries.is_empty());

        // Deliveries for non-existent webhook returns 404
        let resp = client
            .get(s.url("/admin/webhooks/00000000-0000-0000-0000-000000000000/deliveries"))
            .header("cookie", format!("auth_access={admin_token}"))
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
            .header("cookie", format!("auth_access={admin_token}"))
            .header("x-requested-with", "test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    });
}

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
fn webhook_signature_includes_timestamp() {
    let s = server();
    runtime().block_on(async {
        s.cleanup().await;

        // Start a local TCP listener to capture the webhook delivery
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let webhook_url = format!("http://127.0.0.1:{port}/hook");

        // Register a webhook pointing to our local listener
        let _webhook = db::create_webhook(
            &s.db,
            None,
            &webhook_url,
            &["user.created".to_string()],
            "replay-test-secret",
        )
        .await
        .unwrap();

        // Dispatch event
        riley_auth_core::webhooks::dispatch_event(
            &s.db,
            "user.created",
            serde_json::json!({ "user_id": "sig-test-user" }),
            s.config.webhooks.max_retry_attempts,
        ).await;

        // Claim and deliver the outbox entry
        let entries = db::claim_pending_outbox_entries(&s.db, 10).await.unwrap();
        assert_eq!(entries.len(), 1);

        // Accept the incoming connection in background
        let accept_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();

            // Send a 200 response
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await.unwrap();

            request
        });

        // Deliver (allow private IPs since we're using localhost)
        let http_client = reqwest::Client::new();
        let result = riley_auth_core::webhooks::deliver_outbox_entry(
            &s.db, &http_client, &entries[0], false,
        ).await;
        assert!(result.is_ok(), "delivery should succeed: {:?}", result);

        // Inspect the captured request
        let request = accept_handle.await.unwrap();

        // Find the X-Webhook-Signature header
        let sig_line = request
            .lines()
            .find(|l| l.to_lowercase().starts_with("x-webhook-signature:"))
            .expect("X-Webhook-Signature header missing");
        let sig_value = sig_line.split_once(':').unwrap().1.trim();

        // Verify format: t={digits},sha256={hex}
        assert!(sig_value.starts_with("t="), "signature should start with t=: {sig_value}");
        assert!(sig_value.contains(",sha256="), "signature should contain sha256=: {sig_value}");

        let parts: Vec<&str> = sig_value.splitn(2, ',').collect();
        let ts_str = parts[0].strip_prefix("t=").unwrap();
        let ts: i64 = ts_str.parse().expect("timestamp should be numeric");
        let now = chrono::Utc::now().timestamp();
        assert!((now - ts).abs() < 10, "timestamp should be recent (within 10s)");

        let hex_part = parts[1].strip_prefix("sha256=").unwrap();
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()), "hash should be hex");
        assert_eq!(hex_part.len(), 64, "SHA-256 hex should be 64 chars");
    });
}
