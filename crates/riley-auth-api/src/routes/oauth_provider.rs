use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Redirect;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::extract::CookieJar;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use riley_auth_core::db;
use riley_auth_core::error::Error;
use riley_auth_core::jwt;

use crate::server::AppState;

use super::auth::ACCESS_TOKEN_COOKIE;

// --- Request/Response types ---

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: String,
    client_secret: String,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    refresh_token: String,
}

#[derive(Deserialize)]
pub struct RevokeRequest {
    token: String,
    client_id: String,
    client_secret: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
}

/// GET /oauth/authorize — authorization endpoint
async fn authorize(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
    jar: CookieJar,
) -> Result<Redirect, Error> {
    if query.response_type != "code" {
        return Err(Error::BadRequest("response_type must be 'code'".to_string()));
    }

    // Validate client
    let client = db::find_client_by_client_id(&state.db, &query.client_id)
        .await?
        .ok_or(Error::InvalidClient)?;

    // Validate redirect URI
    if !client.redirect_uris.contains(&query.redirect_uri) {
        return Err(Error::InvalidRedirectUri);
    }

    // User must be authenticated (cookie-based)
    let access_token = jar
        .get(ACCESS_TOKEN_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(Error::Unauthenticated)?;

    let token_data = state.keys.verify_access_token(&state.config.jwt, &access_token)?;
    let user_id: uuid::Uuid = token_data.claims.sub.parse().map_err(|_| Error::InvalidToken)?;

    // For auto_approve clients (first-party), skip consent
    // For others, we'd show a consent page — for v1, we just proceed
    // (consent UI would be a frontend concern)

    // Generate authorization code
    let mut code_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut code_bytes);
    let code = URL_SAFE_NO_PAD.encode(code_bytes);
    let code_hash = jwt::hash_token(&code);

    let expires_at = Utc::now() + Duration::seconds(
        state.config.jwt.authorization_code_ttl_secs as i64,
    );

    db::store_authorization_code(
        &state.db,
        &code_hash,
        user_id,
        client.id,
        &query.redirect_uri,
        query.code_challenge.as_deref(),
        query.code_challenge_method.as_deref(),
        expires_at,
    )
    .await?;

    // Redirect back to client
    let mut redirect_url = url::Url::parse(&query.redirect_uri)
        .map_err(|_| Error::InvalidRedirectUri)?;

    {
        let mut params = redirect_url.query_pairs_mut();
        params.append_pair("code", &code);
        if let Some(ref state_param) = query.state {
            params.append_pair("state", state_param);
        }
    }

    Ok(Redirect::temporary(redirect_url.as_str()))
}

/// POST /oauth/token — token endpoint
async fn token(
    State(state): State<AppState>,
    Form(body): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, Error> {
    // Validate client credentials
    let client = db::find_client_by_client_id(&state.db, &body.client_id)
        .await?
        .ok_or(Error::InvalidClient)?;

    let secret_hash = jwt::hash_token(&body.client_secret);
    if !constant_time_eq(secret_hash.as_bytes(), client.client_secret_hash.as_bytes()) {
        return Err(Error::InvalidClient);
    }

    match body.grant_type.as_str() {
        "authorization_code" => {
            let code = body.code.as_deref().ok_or(Error::InvalidGrant)?;
            let redirect_uri = body.redirect_uri.as_deref().ok_or(Error::InvalidGrant)?;

            let code_hash = jwt::hash_token(code);
            let auth_code = db::find_authorization_code(&state.db, &code_hash)
                .await?
                .ok_or(Error::InvalidAuthorizationCode)?;

            // Verify redirect_uri matches
            if auth_code.redirect_uri != redirect_uri {
                return Err(Error::InvalidGrant);
            }

            // Verify client matches
            if auth_code.client_id != client.id {
                return Err(Error::InvalidGrant);
            }

            // Verify PKCE
            if let Some(ref challenge) = auth_code.code_challenge {
                let verifier = body.code_verifier.as_deref()
                    .ok_or(Error::InvalidGrant)?;

                let computed = {
                    let mut hasher = Sha256::new();
                    hasher.update(verifier.as_bytes());
                    URL_SAFE_NO_PAD.encode(hasher.finalize())
                };

                if !constant_time_eq(computed.as_bytes(), challenge.as_bytes()) {
                    return Err(Error::InvalidGrant);
                }
            }

            // Mark code as used
            db::mark_authorization_code_used(&state.db, &code_hash).await?;

            // Get user
            let user = db::find_user_by_id(&state.db, auth_code.user_id)
                .await?
                .ok_or(Error::UserNotFound)?;

            // Issue tokens with client_id as audience
            let access_token = state.keys.sign_access_token(
                &state.config.jwt,
                &user.id.to_string(),
                &user.username,
                &user.role,
                &client.client_id,
            )?;

            let (refresh_raw, refresh_hash) = jwt::generate_refresh_token();
            let expires_at = Utc::now() + Duration::seconds(
                state.config.jwt.refresh_token_ttl_secs as i64,
            );
            db::store_refresh_token(
                &state.db,
                user.id,
                Some(client.id),
                &refresh_hash,
                expires_at,
            )
            .await?;

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer",
                expires_in: state.config.jwt.access_token_ttl_secs,
                refresh_token: refresh_raw,
            }))
        }
        "refresh_token" => {
            let refresh_raw = body.refresh_token.as_deref()
                .ok_or(Error::InvalidGrant)?;

            let refresh_hash = jwt::hash_token(refresh_raw);
            let token_row = db::find_refresh_token(&state.db, &refresh_hash)
                .await?
                .ok_or(Error::InvalidGrant)?;

            // Verify this refresh token belongs to this client
            if token_row.client_id != Some(client.id) {
                return Err(Error::InvalidGrant);
            }

            let user = db::find_user_by_id(&state.db, token_row.user_id)
                .await?
                .ok_or(Error::UserNotFound)?;

            // Rotate refresh token
            db::delete_refresh_token(&state.db, &refresh_hash).await?;

            let access_token = state.keys.sign_access_token(
                &state.config.jwt,
                &user.id.to_string(),
                &user.username,
                &user.role,
                &client.client_id,
            )?;

            let (new_refresh_raw, new_refresh_hash) = jwt::generate_refresh_token();
            let expires_at = Utc::now() + Duration::seconds(
                state.config.jwt.refresh_token_ttl_secs as i64,
            );
            db::store_refresh_token(
                &state.db,
                user.id,
                Some(client.id),
                &new_refresh_hash,
                expires_at,
            )
            .await?;

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer",
                expires_in: state.config.jwt.access_token_ttl_secs,
                refresh_token: new_refresh_raw,
            }))
        }
        _ => Err(Error::BadRequest(format!("unsupported grant_type: {}", body.grant_type))),
    }
}

/// POST /oauth/revoke — revoke a refresh token (RFC 7009)
async fn revoke(
    State(state): State<AppState>,
    Form(body): Form<RevokeRequest>,
) -> Result<StatusCode, Error> {
    // Validate client
    let client = db::find_client_by_client_id(&state.db, &body.client_id)
        .await?
        .ok_or(Error::InvalidClient)?;

    let secret_hash = jwt::hash_token(&body.client_secret);
    if !constant_time_eq(secret_hash.as_bytes(), client.client_secret_hash.as_bytes()) {
        return Err(Error::InvalidClient);
    }

    // Revoke the token (RFC 7009 says always return 200 even if token doesn't exist)
    let token_hash = jwt::hash_token(&body.token);
    let _ = db::delete_refresh_token(&state.db, &token_hash).await;

    Ok(StatusCode::OK)
}

/// Constant-time string comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
