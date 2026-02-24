use std::collections::BTreeSet;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
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
    nonce: Option<String>,
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
    scope: Option<String>,
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
        .route("/oauth/userinfo", get(userinfo).post(userinfo))
}

/// Build an OAuth error redirect per RFC 6749 §4.1.2.1.
///
/// Once `client_id` and `redirect_uri` are validated, all subsequent errors
/// must be communicated back to the client via redirect with query parameters.
fn redirect_error(
    redirect_uri: &str,
    error_code: &str,
    description: &str,
    state: Option<&str>,
) -> Response {
    // If the redirect_uri can't be parsed (shouldn't happen — already validated),
    // fall back to a plain HTTP error.
    let Ok(mut url) = url::Url::parse(redirect_uri) else {
        return Error::InvalidRedirectUri.into_response();
    };
    {
        let mut params = url.query_pairs_mut();
        params.append_pair("error", error_code);
        params.append_pair("error_description", description);
        if let Some(s) = state {
            params.append_pair("state", s);
        }
    }
    Redirect::temporary(url.as_str()).into_response()
}

/// GET /oauth/authorize — authorization endpoint (RFC 6749 §4.1)
///
/// Error handling follows RFC 6749 §4.1.2.1:
/// - Pre-redirect errors (invalid client_id or redirect_uri): HTTP 400
/// - Post-redirect errors (all others): redirect to redirect_uri with ?error=...
async fn authorize(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
    jar: CookieJar,
) -> Result<Response, Error> {
    // --- Phase 1: Pre-redirect validation (HTTP errors) ---
    // client_id and redirect_uri must be validated FIRST. If either is invalid,
    // we cannot safely redirect and must return an HTTP error directly.

    let client = db::find_client_by_client_id(&state.db, &query.client_id)
        .await?
        .ok_or(Error::InvalidClient)?;

    if !client.redirect_uris.contains(&query.redirect_uri) {
        return Err(Error::InvalidRedirectUri);
    }

    // --- Phase 2: Post-redirect validation (error redirects) ---
    // From here on, all errors redirect back to the client with ?error=...
    let redirect_uri = &query.redirect_uri;
    let state_param = query.state.as_deref();

    // response_type
    if query.response_type != "code" {
        return Ok(redirect_error(
            redirect_uri,
            "unsupported_response_type",
            "response_type must be 'code'",
            state_param,
        ));
    }

    // PKCE is mandatory
    let code_challenge = match query.code_challenge.as_deref() {
        Some(c) => c,
        None => {
            return Ok(redirect_error(
                redirect_uri,
                "invalid_request",
                "code_challenge is required",
                state_param,
            ));
        }
    };
    let method = query.code_challenge_method.as_deref().unwrap_or("S256");
    if method != "S256" {
        return Ok(redirect_error(
            redirect_uri,
            "invalid_request",
            "code_challenge_method must be 'S256'",
            state_param,
        ));
    }

    // Validate and deduplicate requested scopes.
    // "openid" is a protocol-level scope (triggers ID token issuance) — accepted
    // without a scope definition or allowed_scopes check, but stored so the token
    // endpoint knows whether to include an id_token.
    let granted_scopes: Vec<String> = if let Some(ref scope_str) = query.scope {
        let requested: BTreeSet<&str> = scope_str.split_whitespace().collect();
        if requested.is_empty() {
            return Ok(redirect_error(
                redirect_uri,
                "invalid_scope",
                "scope parameter must not be empty",
                state_param,
            ));
        }
        let defined_names: Vec<&str> = state.config.scopes.definitions.iter()
            .map(|d| d.name.as_str())
            .collect();
        for s in &requested {
            if *s == "openid" {
                continue; // protocol-level, always accepted
            }
            if !defined_names.contains(s) {
                return Ok(redirect_error(
                    redirect_uri,
                    "invalid_scope",
                    &format!("unknown scope: {s}"),
                    state_param,
                ));
            }
            if !client.allowed_scopes.iter().any(|a| a == s) {
                return Ok(redirect_error(
                    redirect_uri,
                    "invalid_scope",
                    &format!("scope not allowed for this client: {s}"),
                    state_param,
                ));
            }
        }
        requested.into_iter().map(String::from).collect()
    } else {
        vec![]
    };

    // Consent check
    if !client.auto_approve {
        return Ok(redirect_error(
            redirect_uri,
            "consent_required",
            "user consent is required for this client",
            state_param,
        ));
    }

    // User must be authenticated (cookie-based)
    let access_token = match jar.get(&state.cookie_names.access) {
        Some(c) => c.value().to_string(),
        None => {
            return Ok(redirect_error(
                redirect_uri,
                "login_required",
                "user is not authenticated",
                state_param,
            ));
        }
    };

    let token_data = match state.keys.verify_access_token(&state.config.jwt, &access_token) {
        Ok(data) => data,
        Err(_) => {
            return Ok(redirect_error(
                redirect_uri,
                "login_required",
                "session is invalid or expired",
                state_param,
            ));
        }
    };

    // Enforce audience: only session tokens (aud == issuer) can authorize
    if token_data.claims.aud != state.config.jwt.issuer {
        return Ok(redirect_error(
            redirect_uri,
            "login_required",
            "invalid session token",
            state_param,
        ));
    }

    let user_id: uuid::Uuid = match token_data.claims.sub.parse() {
        Ok(id) => id,
        Err(_) => {
            return Ok(redirect_error(
                redirect_uri,
                "server_error",
                "internal error",
                state_param,
            ));
        }
    };

    // --- Phase 3: Issue authorization code ---
    let mut code_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut code_bytes);
    let code = URL_SAFE_NO_PAD.encode(code_bytes);
    let code_hash = jwt::hash_token(&code);

    let expires_at = Utc::now() + Duration::seconds(
        state.config.jwt.authorization_code_ttl_secs as i64,
    );

    if let Err(e) = db::store_authorization_code(
        &state.db,
        &code_hash,
        user_id,
        client.id,
        &query.redirect_uri,
        &granted_scopes,
        Some(code_challenge),
        Some(method),
        query.nonce.as_deref(),
        expires_at,
    )
    .await
    {
        tracing::error!(error = %e, "failed to store authorization code");
        return Ok(redirect_error(
            redirect_uri,
            "server_error",
            "internal error",
            state_param,
        ));
    }

    // Redirect back to client with authorization code
    let mut redirect_url = match url::Url::parse(&query.redirect_uri) {
        Ok(url) => url,
        Err(_) => {
            return Ok(redirect_error(
                redirect_uri,
                "server_error",
                "internal error",
                state_param,
            ));
        }
    };

    {
        let mut params = redirect_url.query_pairs_mut();
        params.append_pair("code", &code);
        if let Some(s) = state_param {
            params.append_pair("state", s);
        }
    }

    Ok(Redirect::temporary(redirect_url.as_str()).into_response())
}

/// GET /oauth/consent — returns client name and scope descriptions for consent UI
async fn consent(
    State(state): State<AppState>,
    Query(query): Query<ConsentQuery>,
    jar: CookieJar,
) -> Result<Json<ConsentResponse>, Error> {
    // User must be authenticated
    let access_token = jar
        .get(&state.cookie_names.access)
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

    // Resolve requested scopes to descriptions (validate like authorize endpoint).
    // "openid" is protocol-level — accepted but not shown in consent (no description needed).
    let scopes = if let Some(ref scope_str) = query.scope {
        let requested: BTreeSet<&str> = scope_str.split_whitespace().collect();
        let mut result = Vec::new();
        for s in &requested {
            if *s == "openid" {
                continue; // protocol-level, no consent description needed
            }
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
            let family_id = uuid::Uuid::now_v7();
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
                family_id,
                auth_code.nonce.as_deref(),
            )
            .await?;

            // Only issue ID token when openid scope was granted (OIDC Core 1.0)
            let id_token = if auth_code.scopes.iter().any(|s| s == "openid") {
                Some(state.keys.sign_id_token(
                    &state.config.jwt,
                    &user.id.to_string(),
                    &user.username,
                    user.display_name.as_deref(),
                    user.avatar_url.as_deref(),
                    &client.client_id,
                    auth_code.nonce.as_deref(),
                )?)
            } else {
                None
            };

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer",
                expires_in: state.config.jwt.access_token_ttl_secs,
                refresh_token: refresh_raw,
                id_token,
                scope: scope_str,
            }))
        }
        "refresh_token" => {
            let refresh_raw = body.refresh_token.as_deref()
                .ok_or(Error::InvalidGrant)?;

            let refresh_hash = jwt::hash_token(refresh_raw);

            // Check for token reuse — if this hash was already consumed, revoke the family
            if let Some(family_id) = db::check_token_reuse(&state.db, &refresh_hash).await? {
                db::revoke_token_family(&state.db, family_id).await?;
                return Err(Error::InvalidGrant);
            }

            // Atomically consume a client-bound refresh token (client_id = verified client).
            // This rejects session tokens or other clients' tokens without consuming them,
            // preventing cross-endpoint token destruction.
            let token_row = db::consume_client_refresh_token(&state.db, &refresh_hash, client.id)
                .await?
                .ok_or(Error::InvalidGrant)?;

            let user = db::find_user_by_id(&state.db, token_row.user_id)
                .await?
                .ok_or(Error::UserNotFound)?;

            // Intersect original scopes with client's current allowed_scopes.
            // "openid" is protocol-level and passes through unconditionally.
            // If an admin revoked a resource scope from the client since the token
            // was issued, the refreshed token will no longer carry that scope.
            let mut effective_scopes: Vec<String> = token_row.scopes.iter()
                .filter(|s| s.as_str() == "openid" || client.allowed_scopes.contains(s))
                .cloned()
                .collect();

            // Scope downscoping (RFC 6749 §6): if the client requests a narrower
            // scope set, validate it's a subset of the effective scopes and narrow.
            if let Some(ref requested_scope) = body.scope {
                let requested: BTreeSet<&str> = requested_scope.split_whitespace().collect();
                let effective_set: BTreeSet<&str> = effective_scopes.iter().map(|s| s.as_str()).collect();
                for s in &requested {
                    if !effective_set.contains(s) {
                        return Err(Error::InvalidScope);
                    }
                }
                effective_scopes = requested.into_iter().map(String::from).collect();
            }

            let scope_str = if effective_scopes.is_empty() {
                None
            } else {
                Some(effective_scopes.join(" "))
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
                &effective_scopes,
                None,
                None,
                token_row.family_id,
                token_row.nonce.as_deref(),
            )
            .await?;

            // Only issue ID token when openid scope is in the effective scopes.
            // Nonce is preserved from the original authorization request across
            // refresh rotations (OIDC Core 1.0 §12.2).
            let id_token = if effective_scopes.iter().any(|s| s == "openid") {
                Some(state.keys.sign_id_token(
                    &state.config.jwt,
                    &user.id.to_string(),
                    &user.username,
                    user.display_name.as_deref(),
                    user.avatar_url.as_deref(),
                    &client.client_id,
                    token_row.nonce.as_deref(),
                )?)
            } else {
                None
            };

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer",
                expires_in: state.config.jwt.access_token_ttl_secs,
                refresh_token: new_refresh_raw,
                id_token,
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

/// GET/POST /oauth/userinfo — OIDC UserInfo endpoint (OpenID Connect Core 1.0 §5.3)
///
/// Accepts a Bearer access token via the Authorization header. The token must
/// have been issued to an OAuth client (aud != issuer). Returns profile claims
/// filtered by the scopes granted in the access token.
async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Error> {
    // Extract Bearer token from Authorization header (case-insensitive prefix per RFC 6750 §2.1)
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Unauthenticated)?;

    let bearer_token = if auth_header.len() > 7 && auth_header[..7].eq_ignore_ascii_case("bearer ") {
        &auth_header[7..]
    } else {
        return Err(Error::Unauthenticated);
    };

    // Validate the JWT
    let token_data = state
        .keys
        .verify_access_token(&state.config.jwt, bearer_token)?;

    let claims = &token_data.claims;

    // Enforce audience: must be a client token (aud != issuer).
    // Session tokens (aud == issuer) are not valid for UserInfo — use /auth/me instead.
    if claims.aud == state.config.jwt.issuer {
        return Err(Error::InvalidToken);
    }

    // Verify the audience matches a registered client
    db::find_client_by_client_id(&state.db, &claims.aud)
        .await?
        .ok_or(Error::InvalidToken)?;

    // Parse user ID
    let user_id: uuid::Uuid = claims.sub.parse().map_err(|_| Error::InvalidToken)?;

    // Fetch user profile — return 401 (not 404) if user was deleted,
    // since the token is no longer valid for any resource endpoint.
    let user = db::find_user_by_id(&state.db, user_id)
        .await?
        .ok_or(Error::InvalidToken)?;

    // Parse granted scopes from the token
    let scopes: BTreeSet<&str> = claims
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().collect())
        .unwrap_or_default();

    // UserInfo requires the "openid" scope (OIDC Core 1.0 §5.3)
    if !scopes.contains("openid") {
        return Err(Error::Forbidden);
    }

    // Build response based on granted scopes (OIDC Core 1.0 §5.4)
    let mut response = serde_json::Map::new();

    // "sub" is always returned per OIDC Core 1.0 §5.3.2
    response.insert("sub".to_string(), serde_json::json!(user.id.to_string()));

    if scopes.contains("profile") {
        response.insert(
            "preferred_username".to_string(),
            serde_json::json!(user.username),
        );
        if let Some(ref name) = user.display_name {
            response.insert("name".to_string(), serde_json::json!(name));
        }
        if let Some(ref picture) = user.avatar_url {
            response.insert("picture".to_string(), serde_json::json!(picture));
        }
        response.insert(
            "updated_at".to_string(),
            serde_json::json!(user.updated_at.timestamp()),
        );
    }

    if scopes.contains("email") {
        // Fetch email from the user's oldest oauth_link that has an email (deterministic ordering)
        let links = db::find_oauth_links_by_user(&state.db, user_id).await?;
        if let Some(email) = links.iter().find_map(|l| l.provider_email.as_deref()) {
            response.insert("email".to_string(), serde_json::json!(email));
            // All emails come from verified OAuth providers (Google, GitHub, etc.)
            response.insert("email_verified".to_string(), serde_json::json!(true));
        }
    }

    Ok(Json(serde_json::Value::Object(response)))
}
