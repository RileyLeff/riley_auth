use std::collections::BTreeSet;

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
use subtle::ConstantTimeEq;

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
    scope: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

#[derive(Deserialize)]
pub struct ConsentQuery {
    client_id: String,
    scope: Option<String>,
}

#[derive(Serialize)]
pub struct ConsentResponse {
    client_name: String,
    scopes: Vec<ConsentScope>,
}

#[derive(Serialize)]
pub struct ConsentScope {
    name: String,
    description: String,
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
        .route("/oauth/consent", get(consent))
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

    // PKCE is mandatory
    let code_challenge = query.code_challenge.as_deref()
        .ok_or_else(|| Error::BadRequest("code_challenge is required".to_string()))?;
    let method = query.code_challenge_method.as_deref().unwrap_or("S256");
    if method != "S256" {
        return Err(Error::BadRequest("code_challenge_method must be 'S256'".to_string()));
    }

    // Validate client
    let client = db::find_client_by_client_id(&state.db, &query.client_id)
        .await?
        .ok_or(Error::InvalidClient)?;

    // Validate redirect URI
    if !client.redirect_uris.contains(&query.redirect_uri) {
        return Err(Error::InvalidRedirectUri);
    }

    // Validate and deduplicate requested scopes
    let granted_scopes: Vec<String> = if let Some(ref scope_str) = query.scope {
        let requested: BTreeSet<&str> = scope_str.split_whitespace().collect();
        let defined_names: Vec<&str> = state.config.scopes.definitions.iter()
            .map(|d| d.name.as_str())
            .collect();
        for s in &requested {
            if !defined_names.contains(s) {
                return Err(Error::BadRequest(format!("unknown scope: {s}")));
            }
            if !client.allowed_scopes.iter().any(|a| a == s) {
                return Err(Error::BadRequest(format!("scope not allowed for this client: {s}")));
            }
        }
        requested.into_iter().map(String::from).collect()
    } else {
        vec![]
    };

    // Enforce consent: non-auto-approve clients are not allowed (no consent UI yet)
    if !client.auto_approve {
        return Err(Error::ConsentRequired);
    }

    // User must be authenticated (cookie-based)
    let access_token = jar
        .get(ACCESS_TOKEN_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(Error::Unauthenticated)?;

    let token_data = state.keys.verify_access_token(&state.config.jwt, &access_token)?;

    // Enforce audience: only session tokens (aud == issuer) can authorize
    if token_data.claims.aud != state.config.jwt.issuer {
        return Err(Error::InvalidToken);
    }

    let user_id: uuid::Uuid = token_data.claims.sub.parse().map_err(|_| Error::InvalidToken)?;

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
        &granted_scopes,
        Some(code_challenge),
        Some(method),
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

/// GET /oauth/consent — returns client name and scope descriptions for consent UI
async fn consent(
    State(state): State<AppState>,
    Query(query): Query<ConsentQuery>,
    jar: CookieJar,
) -> Result<Json<ConsentResponse>, Error> {
    // User must be authenticated
    let access_token = jar
        .get(ACCESS_TOKEN_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(Error::Unauthenticated)?;

    let token_data = state.keys.verify_access_token(&state.config.jwt, &access_token)?;

    // Only session tokens can access consent data
    if token_data.claims.aud != state.config.jwt.issuer {
        return Err(Error::InvalidToken);
    }

    // Look up client
    let client = db::find_client_by_client_id(&state.db, &query.client_id)
        .await?
        .ok_or(Error::InvalidClient)?;

    // Resolve requested scopes to descriptions (validate like authorize endpoint)
    let scopes = if let Some(ref scope_str) = query.scope {
        let requested: BTreeSet<&str> = scope_str.split_whitespace().collect();
        let mut result = Vec::new();
        for s in &requested {
            let def = state.config.scopes.definitions.iter()
                .find(|d| d.name == *s)
                .ok_or_else(|| Error::BadRequest(format!("unknown scope: {s}")))?;
            if !client.allowed_scopes.iter().any(|a| a == s) {
                return Err(Error::BadRequest(format!("scope not allowed for this client: {s}")));
            }
            result.push(ConsentScope {
                name: s.to_string(),
                description: def.description.clone(),
            });
        }
        result
    } else {
        vec![]
    };

    Ok(Json(ConsentResponse {
        client_name: client.name,
        scopes,
    }))
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
    if secret_hash.as_bytes().ct_eq(client.client_secret_hash.as_bytes()).unwrap_u8() == 0 {
        return Err(Error::InvalidClient);
    }

    match body.grant_type.as_str() {
        "authorization_code" => {
            let code = body.code.as_deref().ok_or(Error::InvalidGrant)?;
            let redirect_uri = body.redirect_uri.as_deref().ok_or(Error::InvalidGrant)?;

            let code_hash = jwt::hash_token(code);

            // Atomically consume the authorization code (prevents TOCTOU race)
            let auth_code = db::consume_authorization_code(&state.db, &code_hash)
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

            // Verify PKCE (mandatory — code_challenge should always be present)
            let challenge = auth_code.code_challenge.as_deref()
                .ok_or(Error::InvalidGrant)?;
            let verifier = body.code_verifier.as_deref()
                .ok_or(Error::InvalidGrant)?;

            let computed = {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                URL_SAFE_NO_PAD.encode(hasher.finalize())
            };

            if computed.as_bytes().ct_eq(challenge.as_bytes()).unwrap_u8() == 0 {
                return Err(Error::InvalidGrant);
            }

            // Get user
            let user = db::find_user_by_id(&state.db, auth_code.user_id)
                .await?
                .ok_or(Error::UserNotFound)?;

            // Issue tokens with client_id as audience
            let scope_str = if auth_code.scopes.is_empty() {
                None
            } else {
                Some(auth_code.scopes.join(" "))
            };

            let access_token = state.keys.sign_access_token_with_scopes(
                &state.config.jwt,
                &user.id.to_string(),
                &user.username,
                &user.role,
                &client.client_id,
                scope_str.as_deref(),
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
                &auth_code.scopes,
                None,
                None,
            )
            .await?;

            let id_token = state.keys.sign_id_token(
                &state.config.jwt,
                &user.id.to_string(),
                &user.username,
                user.display_name.as_deref(),
                user.avatar_url.as_deref(),
                &client.client_id,
            )?;

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer",
                expires_in: state.config.jwt.access_token_ttl_secs,
                refresh_token: refresh_raw,
                id_token: Some(id_token),
                scope: scope_str,
            }))
        }
        "refresh_token" => {
            let refresh_raw = body.refresh_token.as_deref()
                .ok_or(Error::InvalidGrant)?;

            let refresh_hash = jwt::hash_token(refresh_raw);

            // Atomically consume the refresh token (prevents TOCTOU race)
            let token_row = db::consume_refresh_token(&state.db, &refresh_hash)
                .await?
                .ok_or(Error::InvalidGrant)?;

            // Verify this refresh token belongs to this client
            if token_row.client_id != Some(client.id) {
                return Err(Error::InvalidGrant);
            }

            let user = db::find_user_by_id(&state.db, token_row.user_id)
                .await?
                .ok_or(Error::UserNotFound)?;

            let scope_str = if token_row.scopes.is_empty() {
                None
            } else {
                Some(token_row.scopes.join(" "))
            };

            let access_token = state.keys.sign_access_token_with_scopes(
                &state.config.jwt,
                &user.id.to_string(),
                &user.username,
                &user.role,
                &client.client_id,
                scope_str.as_deref(),
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
                &token_row.scopes,
                None,
                None,
            )
            .await?;

            let id_token = state.keys.sign_id_token(
                &state.config.jwt,
                &user.id.to_string(),
                &user.username,
                user.display_name.as_deref(),
                user.avatar_url.as_deref(),
                &client.client_id,
            )?;

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer",
                expires_in: state.config.jwt.access_token_ttl_secs,
                refresh_token: new_refresh_raw,
                id_token: Some(id_token),
                scope: scope_str,
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
    if secret_hash.as_bytes().ct_eq(client.client_secret_hash.as_bytes()).unwrap_u8() == 0 {
        return Err(Error::InvalidClient);
    }

    // Revoke the token, scoped to this client (RFC 7009 says always return 200)
    let token_hash = jwt::hash_token(&body.token);
    if let Err(e) = db::delete_refresh_token_for_client(&state.db, &token_hash, client.id).await {
        tracing::warn!(error = %e, client_id = %body.client_id, "token revocation failed");
    }

    Ok(StatusCode::OK)
}
