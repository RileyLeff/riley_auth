use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use riley_auth_core::config::validate_scope_name;
use riley_auth_core::db;
use riley_auth_core::error::Error;
use riley_auth_core::jwt;
use riley_auth_core::webhooks;

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/users", get(list_users))
        .route("/admin/users/{id}", get(get_user))
        .route("/admin/users/{id}/role", axum::routing::patch(update_role))
        .route("/admin/users/{id}", axum::routing::delete(delete_user))
        .route("/admin/clients", get(list_clients).post(register_client))
        .route("/admin/clients/{id}", axum::routing::delete(remove_client))
        .route("/admin/webhooks", get(list_webhooks).post(register_webhook))
        .route("/admin/webhooks/{id}", axum::routing::delete(remove_webhook))
        .route("/admin/webhooks/{id}/deliveries", get(list_deliveries))
}

// --- Types ---

#[derive(Deserialize)]
struct PaginationQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 { 50 }
const MAX_LIMIT: i64 = 500;

#[derive(Deserialize)]
struct UpdateRoleRequest {
    role: String,
}

#[derive(Deserialize)]
struct RegisterClientRequest {
    name: String,
    redirect_uris: Vec<String>,
    #[serde(default)]
    allowed_scopes: Vec<String>,
    #[serde(default)]
    auto_approve: bool,
    #[serde(default)]
    backchannel_logout_uri: Option<String>,
    #[serde(default)]
    backchannel_logout_session_required: bool,
}

#[derive(Serialize)]
struct ClientResponse {
    id: String,
    name: String,
    client_id: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    auto_approve: bool,
    created_at: String,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: bool,
}

#[derive(Serialize)]
struct RegisterClientResponse {
    id: String,
    name: String,
    client_id: String,
    client_secret: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    auto_approve: bool,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: bool,
}

// --- Admin middleware helper ---

async fn require_admin(state: &AppState, jar: &CookieJar) -> Result<jwt::Claims, Error> {
    let token = jar
        .get(&state.cookie_names.access)
        .map(|c| c.value().to_string())
        .ok_or(Error::Unauthenticated)?;

    let data = state.keys.verify_access_token(&state.config.jwt, &token)?;

    // Enforce audience: session cookies only
    if data.claims.aud != state.config.jwt.issuer {
        return Err(Error::InvalidToken);
    }

    // Check current role from DB (not just JWT claims) to handle demotion
    let user_id: uuid::Uuid = data.claims.sub.parse().map_err(|_| Error::InvalidToken)?;
    let current_role = db::get_user_role(&state.db, user_id)
        .await?
        .ok_or(Error::UserNotFound)?;

    if current_role != "admin" {
        return Err(Error::Forbidden);
    }

    Ok(data.claims)
}

// --- User admin endpoints ---

async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
    jar: CookieJar,
) -> Result<Json<Vec<serde_json::Value>>, Error> {
    require_admin(&state, &jar).await?;

    let limit = query.limit.max(0).min(MAX_LIMIT);
    let offset = query.offset.max(0);
    let users = db::list_users(&state.db, limit, offset).await?;
    let response: Vec<serde_json::Value> = users.iter().map(|u| {
        serde_json::json!({
            "id": u.id.to_string(),
            "username": u.username,
            "display_name": u.display_name,
            "avatar_url": u.avatar_url,
            "role": u.role,
            "created_at": u.created_at.to_rfc3339(),
        })
    }).collect();

    Ok(Json(response))
}

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    jar: CookieJar,
) -> Result<Json<serde_json::Value>, Error> {
    require_admin(&state, &jar).await?;

    let user = db::find_user_by_id(&state.db, id)
        .await?
        .ok_or(Error::UserNotFound)?;

    let links = db::find_oauth_links_by_user(&state.db, id).await?;

    Ok(Json(serde_json::json!({
        "id": user.id.to_string(),
        "username": user.username,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
        "role": user.role,
        "created_at": user.created_at.to_rfc3339(),
        "links": links.iter().map(|l| serde_json::json!({
            "provider": l.provider,
            "provider_email": l.provider_email,
        })).collect::<Vec<_>>(),
    })))
}

async fn update_role(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    jar: CookieJar,
    Json(body): Json<UpdateRoleRequest>,
) -> Result<StatusCode, Error> {
    let _claims = require_admin(&state, &jar).await?;

    if body.role != "user" && body.role != "admin" {
        return Err(Error::BadRequest("role must be 'user' or 'admin'".to_string()));
    }

    match db::update_user_role(&state.db, id, &body.role).await? {
        db::RoleUpdateResult::Updated(_) => {
            // Force re-authentication so the user gets fresh tokens with the
            // updated role claim. Without this, the old access token (with the
            // previous role) remains valid until TTL expiry.
            db::delete_all_refresh_tokens(&state.db, id).await?;
            webhooks::dispatch_event(
                &state.db,
                webhooks::USER_ROLE_CHANGED,
                serde_json::json!({
                    "user_id": id.to_string(),
                    "new_role": body.role,
                }),
                state.config.webhooks.max_retry_attempts,
            ).await;
            Ok(StatusCode::OK)
        }
        db::RoleUpdateResult::LastAdmin => {
            Err(Error::BadRequest("cannot demote the last admin".to_string()))
        }
        db::RoleUpdateResult::NotFound => Err(Error::UserNotFound),
    }
}

async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    jar: CookieJar,
) -> Result<StatusCode, Error> {
    require_admin(&state, &jar).await?;

    // Dispatch back-channel logout BEFORE soft delete (which deletes tokens)
    webhooks::dispatch_backchannel_logout(
        &state.db, &state.keys, &state.config, &state.http_client, id,
    ).await;

    match db::soft_delete_user(&state.db, id).await? {
        db::DeleteUserResult::Deleted => {
            webhooks::dispatch_event(
                &state.db,
                webhooks::USER_DELETED,
                serde_json::json!({ "user_id": id.to_string() }),
                state.config.webhooks.max_retry_attempts,
            ).await;
            Ok(StatusCode::OK)
        }
        db::DeleteUserResult::LastAdmin => {
            Err(Error::BadRequest("cannot delete the last admin".to_string()))
        }
        db::DeleteUserResult::NotFound => Err(Error::UserNotFound),
    }
}

// --- Client admin endpoints ---

async fn list_clients(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<ClientResponse>>, Error> {
    require_admin(&state, &jar).await?;

    let clients = db::list_clients(&state.db).await?;
    let response: Vec<ClientResponse> = clients.into_iter().map(|c| ClientResponse {
        id: c.id.to_string(),
        name: c.name,
        client_id: c.client_id,
        redirect_uris: c.redirect_uris,
        allowed_scopes: c.allowed_scopes,
        auto_approve: c.auto_approve,
        created_at: c.created_at.to_rfc3339(),
        backchannel_logout_uri: c.backchannel_logout_uri,
        backchannel_logout_session_required: c.backchannel_logout_session_required,
    }).collect();

    Ok(Json(response))
}

async fn register_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<RegisterClientRequest>,
) -> Result<(StatusCode, Json<RegisterClientResponse>), Error> {
    require_admin(&state, &jar).await?;

    if body.name.trim().is_empty() || body.name.len() > 256 {
        return Err(Error::BadRequest("client name must be 1-256 characters".to_string()));
    }
    if body.redirect_uris.is_empty() {
        return Err(Error::BadRequest("at least one redirect_uri required".to_string()));
    }

    // Validate redirect_uri schemes
    for uri in &body.redirect_uris {
        let parsed = url::Url::parse(uri).map_err(|_| {
            Error::BadRequest(format!("invalid redirect_uri: {uri}"))
        })?;
        match parsed.scheme() {
            "https" => {}
            "http" if parsed.host_str() == Some("localhost") || parsed.host_str() == Some("127.0.0.1") => {}
            scheme => {
                return Err(Error::BadRequest(format!(
                    "redirect_uri must use https (or http://localhost for development), got {scheme}://"
                )));
            }
        }
    }

    // Validate allowed_scopes: format + existence in config definitions
    let defined_names: Vec<&str> = state.config.scopes.definitions.iter()
        .map(|d| d.name.as_str())
        .collect();
    for scope in &body.allowed_scopes {
        validate_scope_name(scope).map_err(|_| {
            Error::BadRequest(format!("invalid scope name: {scope}"))
        })?;
        if !defined_names.contains(&scope.as_str()) {
            return Err(Error::BadRequest(format!("undefined scope: {scope}")));
        }
    }

    // Validate backchannel_logout_uri: must be https (no localhost exception)
    if let Some(ref uri) = body.backchannel_logout_uri {
        let parsed = url::Url::parse(uri).map_err(|_| {
            Error::BadRequest(format!("invalid backchannel_logout_uri: {uri}"))
        })?;
        if parsed.scheme() != "https" {
            return Err(Error::BadRequest(
                "backchannel_logout_uri must use https".to_string(),
            ));
        }
    }

    // Reject backchannel_logout_session_required since sid is not yet implemented
    if body.backchannel_logout_session_required {
        return Err(Error::BadRequest(
            "backchannel_logout_session_required is not supported (sid not implemented)".to_string(),
        ));
    }

    // Generate client_id and client_secret
    let mut id_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut id_bytes);
    let client_id = hex::encode(id_bytes);

    let mut secret_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret_bytes);
    let client_secret = hex::encode(secret_bytes);
    let secret_hash = jwt::hash_token(&client_secret);

    let client = db::create_client_full(
        &state.db,
        &body.name,
        &client_id,
        &secret_hash,
        &body.redirect_uris,
        &body.allowed_scopes,
        body.auto_approve,
        body.backchannel_logout_uri.as_deref(),
        body.backchannel_logout_session_required,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(RegisterClientResponse {
        id: client.id.to_string(),
        name: client.name,
        client_id,
        client_secret,
        redirect_uris: client.redirect_uris,
        allowed_scopes: client.allowed_scopes,
        auto_approve: client.auto_approve,
        backchannel_logout_uri: client.backchannel_logout_uri,
        backchannel_logout_session_required: client.backchannel_logout_session_required,
    })))
}

async fn remove_client(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    jar: CookieJar,
) -> Result<StatusCode, Error> {
    require_admin(&state, &jar).await?;

    let deleted = db::delete_client(&state.db, id).await?;
    if !deleted {
        return Err(Error::NotFound);
    }

    Ok(StatusCode::OK)
}

// --- Webhook admin endpoints ---

#[derive(Deserialize)]
struct RegisterWebhookRequest {
    url: String,
    events: Vec<String>,
    #[serde(default)]
    client_id: Option<Uuid>,
}

/// Full response including secret — returned only at creation time.
#[derive(Serialize)]
struct WebhookResponse {
    id: String,
    client_id: Option<String>,
    url: String,
    events: Vec<String>,
    secret: String,
    active: bool,
    created_at: String,
}

impl From<db::Webhook> for WebhookResponse {
    fn from(w: db::Webhook) -> Self {
        Self {
            id: w.id.to_string(),
            client_id: w.client_id.map(|id| id.to_string()),
            url: w.url,
            events: w.events,
            secret: w.secret,
            active: w.active,
            created_at: w.created_at.to_rfc3339(),
        }
    }
}

/// Redacted response for list endpoint — secret is never exposed.
#[derive(Serialize)]
struct WebhookListResponse {
    id: String,
    client_id: Option<String>,
    url: String,
    events: Vec<String>,
    active: bool,
    created_at: String,
}

impl From<db::Webhook> for WebhookListResponse {
    fn from(w: db::Webhook) -> Self {
        Self {
            id: w.id.to_string(),
            client_id: w.client_id.map(|id| id.to_string()),
            url: w.url,
            events: w.events,
            active: w.active,
            created_at: w.created_at.to_rfc3339(),
        }
    }
}

#[derive(Serialize)]
struct DeliveryResponse {
    id: String,
    webhook_id: String,
    event_type: String,
    payload: serde_json::Value,
    status_code: Option<i16>,
    error: Option<String>,
    attempted_at: String,
}

impl From<db::WebhookDelivery> for DeliveryResponse {
    fn from(d: db::WebhookDelivery) -> Self {
        Self {
            id: d.id.to_string(),
            webhook_id: d.webhook_id.to_string(),
            event_type: d.event_type,
            payload: d.payload,
            status_code: d.status_code,
            error: d.error,
            attempted_at: d.attempted_at.to_rfc3339(),
        }
    }
}

async fn register_webhook(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<RegisterWebhookRequest>,
) -> Result<(StatusCode, Json<WebhookResponse>), Error> {
    require_admin(&state, &jar).await?;

    if body.url.len() > 2048 {
        return Err(Error::BadRequest("webhook URL must be at most 2048 characters".to_string()));
    }
    // Validate URL: must be non-empty with an https:// or http:// scheme.
    // This prevents SSRF via internal URIs (e.g. file://, ftp://, internal endpoints).
    let parsed_url = url::Url::parse(&body.url)
        .map_err(|_| Error::BadRequest("invalid webhook URL".to_string()))?;
    match parsed_url.scheme() {
        "https" | "http" => {}
        _ => return Err(Error::BadRequest("webhook URL must use https:// or http://".to_string())),
    }
    if body.events.is_empty() {
        return Err(Error::BadRequest("at least one event type required".to_string()));
    }
    for event in &body.events {
        if !webhooks::is_valid_event_type(event) {
            return Err(Error::BadRequest(format!("unknown event type: {event}")));
        }
    }

    // If client_id is provided, verify the client exists
    if let Some(cid) = body.client_id {
        if db::find_client_by_id(&state.db, cid).await?.is_none() {
            return Err(Error::BadRequest("client not found".to_string()));
        }
    }

    // Generate a random HMAC signing secret
    let mut secret_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret_bytes);
    let secret = hex::encode(secret_bytes);

    let webhook = db::create_webhook(&state.db, body.client_id, &body.url, &body.events, &secret).await?;

    Ok((StatusCode::CREATED, Json(webhook.into())))
}

async fn list_webhooks(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<WebhookListResponse>>, Error> {
    require_admin(&state, &jar).await?;

    let hooks = db::list_webhooks(&state.db).await?;
    let response: Vec<WebhookListResponse> = hooks.into_iter().map(Into::into).collect();

    Ok(Json(response))
}

async fn remove_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    jar: CookieJar,
) -> Result<StatusCode, Error> {
    require_admin(&state, &jar).await?;

    let deleted = db::delete_webhook(&state.db, id).await?;
    if !deleted {
        return Err(Error::NotFound);
    }

    Ok(StatusCode::OK)
}

async fn list_deliveries(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
    jar: CookieJar,
) -> Result<Json<Vec<DeliveryResponse>>, Error> {
    require_admin(&state, &jar).await?;

    // Verify webhook exists
    if db::find_webhook(&state.db, id).await?.is_none() {
        return Err(Error::NotFound);
    }

    let limit = query.limit.max(0).min(MAX_LIMIT);
    let offset = query.offset.max(0);
    let deliveries = db::list_webhook_deliveries(&state.db, id, limit, offset).await?;
    let response: Vec<DeliveryResponse> = deliveries.into_iter().map(Into::into).collect();

    Ok(Json(response))
}
