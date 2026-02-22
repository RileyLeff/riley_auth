use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use riley_auth_core::db;
use riley_auth_core::error::Error;
use riley_auth_core::jwt;

use crate::server::AppState;

use super::auth::ACCESS_TOKEN_COOKIE;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/users", get(list_users))
        .route("/admin/users/{id}", get(get_user))
        .route("/admin/users/{id}/role", axum::routing::patch(update_role))
        .route("/admin/users/{id}", axum::routing::delete(delete_user))
        .route("/admin/clients", get(list_clients).post(register_client))
        .route("/admin/clients/{id}", axum::routing::delete(remove_client))
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

#[derive(Deserialize)]
struct UpdateRoleRequest {
    role: String,
}

#[derive(Deserialize)]
struct RegisterClientRequest {
    name: String,
    redirect_uris: Vec<String>,
    #[serde(default)]
    auto_approve: bool,
}

#[derive(Serialize)]
struct ClientResponse {
    id: String,
    name: String,
    client_id: String,
    redirect_uris: Vec<String>,
    auto_approve: bool,
    created_at: String,
}

#[derive(Serialize)]
struct RegisterClientResponse {
    id: String,
    name: String,
    client_id: String,
    client_secret: String,
    redirect_uris: Vec<String>,
    auto_approve: bool,
}

// --- Admin middleware helper ---

async fn require_admin(state: &AppState, jar: &CookieJar) -> Result<jwt::Claims, Error> {
    let token = jar
        .get(ACCESS_TOKEN_COOKIE)
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

    let users = db::list_users(&state.db, query.limit, query.offset).await?;
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
    require_admin(&state, &jar).await?;

    if body.role != "user" && body.role != "admin" {
        return Err(Error::BadRequest("role must be 'user' or 'admin'".to_string()));
    }

    db::update_user_role(&state.db, id, &body.role).await?;
    Ok(StatusCode::OK)
}

async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    jar: CookieJar,
) -> Result<StatusCode, Error> {
    require_admin(&state, &jar).await?;

    db::delete_all_refresh_tokens(&state.db, id).await?;
    db::soft_delete_user(&state.db, id).await?;
    Ok(StatusCode::OK)
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
        auto_approve: c.auto_approve,
        created_at: c.created_at.to_rfc3339(),
    }).collect();

    Ok(Json(response))
}

async fn register_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<RegisterClientRequest>,
) -> Result<(StatusCode, Json<RegisterClientResponse>), Error> {
    require_admin(&state, &jar).await?;

    if body.redirect_uris.is_empty() {
        return Err(Error::BadRequest("at least one redirect_uri required".to_string()));
    }

    // Generate client_id and client_secret
    let mut id_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut id_bytes);
    let client_id = hex::encode(id_bytes);

    let mut secret_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret_bytes);
    let client_secret = hex::encode(secret_bytes);
    let secret_hash = jwt::hash_token(&client_secret);

    let client = db::create_client(
        &state.db,
        &body.name,
        &client_id,
        &secret_hash,
        &body.redirect_uris,
        body.auto_approve,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(RegisterClientResponse {
        id: client.id.to_string(),
        name: client.name,
        client_id,
        client_secret,
        redirect_uris: client.redirect_uris,
        auto_approve: client.auto_approve,
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
