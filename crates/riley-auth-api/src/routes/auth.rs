use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Redirect;
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use subtle::ConstantTimeEq;

use riley_auth_core::config::{AccountMergePolicy, Config};
use riley_auth_core::db;
use riley_auth_core::error::{Error, ErrorBody};
use riley_auth_core::jwt::{self, Keys};
use riley_auth_core::oauth::{self, ResolvedProvider};
use riley_auth_core::webhooks;

use crate::server::AppState;

// --- Query params ---

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct SetupRequest {
    username: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct MeResponse {
    id: String,
    username: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    role: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct LinkResponse {
    provider: String,
    provider_email: Option<String>,
    created_at: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateDisplayNameRequest {
    display_name: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateUsernameRequest {
    username: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        // OAuth consumer
        .route("/auth/{provider}", get(auth_redirect))
        .route("/auth/{provider}/callback", get(auth_callback))
        .route("/auth/setup", post(auth_setup))
        .route("/auth/link/confirm", post(link_confirm))
        // Session
        .route("/auth/refresh", post(auth_refresh))
        .route("/auth/logout", post(auth_logout))
        .route("/auth/logout-all", post(auth_logout_all))
        .route("/auth/sessions", get(list_sessions))
        .route("/auth/sessions/{id}", axum::routing::delete(revoke_session))
        // Profile
        .route("/auth/me", get(auth_me).patch(update_display_name).delete(delete_account))
        .route("/auth/me/username", patch(update_username))
        .route("/auth/me/links", get(list_links))
        // Provider linking
        .route("/auth/link/{provider}", get(link_redirect).delete(unlink_provider))
        .route("/auth/link/{provider}/callback", get(link_callback))
}

// --- OAuth Consumer Endpoints ---

/// GET /auth/{provider} — redirect to OAuth provider
#[utoipa::path(
    get,
    path = "/auth/{provider}",
    tag = "auth",
    params(("provider" = String, Path, description = "OAuth provider name")),
    responses(
        (status = 302, description = "Redirect to OAuth provider"),
        (status = 404, description = "Unknown provider", body = ErrorBody),
    )
)]
pub(crate) async fn auth_redirect(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), Error> {
    let provider = find_provider(&state.providers, &provider_name)?;
    let callback_url = format!(
        "{}/auth/{}/callback",
        state.config.server.public_url, provider_name
    );

    let oauth_state = oauth::generate_state();
    let (pkce_verifier, pkce_challenge) = oauth::generate_pkce();

    let auth_url = oauth::build_auth_url(
        provider,
        &callback_url,
        &oauth_state,
        &pkce_challenge,
    )?;

    let jar = jar
        .add(build_temp_cookie(&state.cookie_names.oauth_state, &oauth_state, &state.config))
        .add(build_temp_cookie(&state.cookie_names.pkce, &pkce_verifier, &state.config));

    Ok((jar, Redirect::temporary(&auth_url)))
}

/// GET /auth/{provider}/callback — OAuth callback
#[utoipa::path(
    get,
    path = "/auth/{provider}/callback",
    tag = "auth",
    params(("provider" = String, Path, description = "OAuth provider name")),
    responses(
        (status = 302, description = "Redirect after OAuth callback"),
        (status = 400, description = "Invalid OAuth state or code", body = ErrorBody),
    )
)]
pub(crate) async fn auth_callback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(provider_name): Path<String>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), Error> {
    let provider = find_provider(&state.providers, &provider_name)?;

    // Verify state
    let saved_state = jar
        .get(&state.cookie_names.oauth_state)
        .map(|c| c.value().to_string())
        .ok_or(Error::InvalidOAuthState)?;

    if query.state.as_bytes().ct_eq(saved_state.as_bytes()).unwrap_u8() == 0 {
        return Err(Error::InvalidOAuthState);
    }

    // Get PKCE verifier
    let pkce_verifier = jar
        .get(&state.cookie_names.pkce)
        .map(|c| c.value().to_string())
        .ok_or(Error::InvalidOAuthState)?;

    let callback_url = format!(
        "{}/auth/{}/callback",
        state.config.server.public_url, provider_name
    );

    // Exchange code for access token
    let provider_token = oauth::exchange_code(
        provider,
        &query.code,
        &callback_url,
        &pkce_verifier,
        &state.oauth_client,
    )
    .await?;

    // Fetch profile from provider
    let profile = oauth::fetch_profile(provider, &provider_token, &state.oauth_client).await?;

    // Clear temp cookies
    let jar = jar
        .remove(removal_cookie(&state.cookie_names.oauth_state, "/", &state.config))
        .remove(removal_cookie(&state.cookie_names.pkce, "/", &state.config));

    // Look up existing oauth link
    if let Some(link) = db::find_oauth_link(&state.db, &profile.provider, &profile.provider_id).await? {
        // Returning user — issue tokens
        let user = db::find_user_by_id(&state.db, link.user_id)
            .await?
            .ok_or(Error::UserNotFound)?;

        let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
        let ip = client_ip_string(&headers, addr, state.config.server.behind_proxy);
        let (jar, _) = issue_tokens(&state, jar, &user, ua, Some(&ip)).await?;
        webhooks::dispatch_event(
            &state.db,
            webhooks::SESSION_CREATED,
            serde_json::json!({ "user_id": user.id.to_string() }),
            state.config.webhooks.max_retry_attempts,
        ).await;
        return Ok((jar, Redirect::temporary(&state.config.server.public_url)));
    }

    // Check for email match (auto-merge or suggest linking)
    if let Some(ref email) = profile.email {
        let matching_links = db::find_oauth_links_by_email(&state.db, email).await?;
        if !matching_links.is_empty() {
            // Auto-merge: when policy is verified_email, BOTH the new provider and the
            // existing link(s) must have verified the email, and exactly one user matches.
            if state.config.oauth.account_merge_policy == AccountMergePolicy::VerifiedEmail
                && profile.email_verified
            {
                // Only consider links where the existing provider also verified the email
                let verified_links: Vec<&db::OAuthLink> = matching_links.iter()
                    .filter(|l| l.email_verified)
                    .collect();

                // Collect distinct user IDs from verified links only
                let mut user_ids: Vec<uuid::Uuid> = verified_links.iter().map(|l| l.user_id).collect();
                user_ids.sort();
                user_ids.dedup();

                if user_ids.len() == 1 {
                    let existing_user_id = user_ids[0];
                    let user = db::find_user_by_id(&state.db, existing_user_id)
                        .await?
                        .ok_or(Error::UserNotFound)?;

                    // Create the link (catch unique violation from concurrent requests)
                    db::create_oauth_link(
                        &state.db,
                        existing_user_id,
                        &profile.provider,
                        &profile.provider_id,
                        profile.email.as_deref(),
                        profile.email_verified,
                    )
                    .await
                    .map_err(|e| if riley_auth_core::error::is_unique_violation(&e) {
                        Error::ProviderAlreadyLinked
                    } else {
                        e
                    })?;

                    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
                    let ip = client_ip_string(&headers, addr, state.config.server.behind_proxy);
                    let (jar, _) = issue_tokens(&state, jar, &user, ua, Some(&ip)).await?;

                    webhooks::dispatch_event(
                        &state.db,
                        webhooks::LINK_CREATED,
                        serde_json::json!({
                            "user_id": user.id.to_string(),
                            "provider": profile.provider,
                        }),
                        state.config.webhooks.max_retry_attempts,
                    ).await;
                    webhooks::dispatch_event(
                        &state.db,
                        webhooks::SESSION_CREATED,
                        serde_json::json!({ "user_id": user.id.to_string() }),
                        state.config.webhooks.max_retry_attempts,
                    ).await;

                    return Ok((jar, Redirect::temporary(&state.config.server.public_url)));
                }
            }

            // Fall back to link-accounts redirect (no merge policy, email not verified,
            // or multiple matching users)
            let setup_token = create_setup_token(&state.keys, &state.config, &profile)?;
            let jar = jar.add(build_temp_cookie(&state.cookie_names.setup, &setup_token, &state.config));
            let mut redirect_url = url::Url::parse(&format!(
                "{}/link-accounts", state.config.server.public_url
            )).map_err(|_| Error::Config("invalid public_url".to_string()))?;
            redirect_url.query_pairs_mut()
                .append_pair("provider", &profile.provider)
                .append_pair("email", email);
            return Ok((jar, Redirect::temporary(redirect_url.as_str())));
        }
    }

    // New user — redirect to onboarding with setup token
    let setup_token = create_setup_token(&state.keys, &state.config, &profile)?;
    let jar = jar.add(build_temp_cookie(&state.cookie_names.setup, &setup_token, &state.config));
    let redirect_url = format!("{}/onboarding", state.config.server.public_url);
    Ok((jar, Redirect::temporary(&redirect_url)))
}

/// POST /auth/setup — create account with username after OAuth
#[utoipa::path(
    post,
    path = "/auth/setup",
    tag = "auth",
    request_body = SetupRequest,
    responses(
        (status = 200, description = "Account created", body = MeResponse),
        (status = 400, description = "Invalid username", body = ErrorBody),
        (status = 401, description = "Missing or invalid setup token", body = ErrorBody),
        (status = 409, description = "Username taken", body = ErrorBody),
    )
)]
pub(crate) async fn auth_setup(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<SetupRequest>,
) -> Result<(CookieJar, Json<MeResponse>), Error> {
    // Get setup token
    let setup_token = jar
        .get(&state.cookie_names.setup)
        .map(|c| c.value().to_string())
        .ok_or(Error::Unauthenticated)?;

    let profile = decode_setup_token(&state.keys, &state.config, &setup_token)?;

    // Validate username
    validate_username(&body.username, &state.config, &state.username_regex)?;

    // Check availability
    if db::find_user_by_username(&state.db, &body.username).await?.is_some() {
        return Err(Error::UsernameTaken);
    }
    if db::is_username_held(&state.db, &body.username, uuid::Uuid::nil()).await? {
        return Err(Error::UsernameTaken);
    }

    // Check if this provider identity is already linked to another user
    if db::find_oauth_link(&state.db, &profile.provider, &profile.provider_id)
        .await?
        .is_some()
    {
        return Err(Error::ProviderAlreadyLinked);
    }

    // Create user + OAuth link atomically
    let user = db::create_user_with_link(
        &state.db,
        &body.username,
        profile.name.as_deref(),
        profile.avatar_url.as_deref(),
        &profile.provider,
        &profile.provider_id,
        profile.email.as_deref(),
        profile.email_verified,
    )
    .await
    .map_err(|e| {
        // Race between pre-check and insert: distinguish which constraint was violated
        if let Some(constraint) = riley_auth_core::error::unique_violation_constraint(&e) {
            if constraint.contains("oauth_links") {
                Error::ProviderAlreadyLinked
            } else {
                Error::UsernameTaken
            }
        } else {
            e
        }
    })?;

    // Issue tokens, clear setup cookie
    let jar = jar.remove(removal_cookie(&state.cookie_names.setup, "/", &state.config));
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
    let ip = client_ip_string(&headers, addr, state.config.server.behind_proxy);
    let (jar, _) = issue_tokens(&state, jar, &user, ua, Some(&ip)).await?;

    webhooks::dispatch_event(
        &state.db,
        webhooks::USER_CREATED,
        serde_json::json!({ "user_id": user.id.to_string(), "username": user.username }),
        state.config.webhooks.max_retry_attempts,
    ).await;
    webhooks::dispatch_event(
        &state.db,
        webhooks::SESSION_CREATED,
        serde_json::json!({ "user_id": user.id.to_string() }),
        state.config.webhooks.max_retry_attempts,
    ).await;

    Ok((jar, Json(user_to_me(&user))))
}

/// POST /auth/link/confirm — confirm linking a new provider to an existing account
///
/// Used when auth_callback detects an email collision and redirects to /link-accounts
/// with a setup token. The frontend shows a "link this account?" prompt, and the user
/// confirms by calling this endpoint with both their session cookie and the setup token.
#[utoipa::path(
    post,
    path = "/auth/link/confirm",
    tag = "auth",
    responses(
        (status = 200, description = "Provider linked, account merged if applicable", body = MeResponse),
        (status = 401, description = "Not authenticated", body = ErrorBody),
    )
)]
pub(crate) async fn link_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<MeResponse>), Error> {
    // User must be authenticated
    let claims = extract_user(&state, &jar)?;
    let user_id = claims.sub_uuid()?;

    // Get setup token
    let setup_token = jar
        .get(&state.cookie_names.setup)
        .map(|c| c.value().to_string())
        .ok_or(Error::Unauthenticated)?;

    let profile = decode_setup_token(&state.keys, &state.config, &setup_token)?;

    // Check if this provider account is already linked
    if db::find_oauth_link(&state.db, &profile.provider, &profile.provider_id)
        .await?
        .is_some()
    {
        return Err(Error::ProviderAlreadyLinked);
    }

    // Create the link (catch unique violation from concurrent requests)
    db::create_oauth_link(
        &state.db,
        user_id,
        &profile.provider,
        &profile.provider_id,
        profile.email.as_deref(),
        profile.email_verified,
    )
    .await
    .map_err(|e| if riley_auth_core::error::is_unique_violation(&e) {
        Error::ProviderAlreadyLinked
    } else {
        e
    })?;

    // Clear setup cookie
    let jar = jar.remove(removal_cookie(&state.cookie_names.setup, "/", &state.config));

    // Dispatch webhook
    webhooks::dispatch_event(
        &state.db,
        webhooks::LINK_CREATED,
        serde_json::json!({
            "user_id": user_id.to_string(),
            "provider": profile.provider,
        }),
        state.config.webhooks.max_retry_attempts,
    ).await;

    // Return updated user profile
    let user = db::find_user_by_id(&state.db, user_id)
        .await?
        .ok_or(Error::UserNotFound)?;

    Ok((jar, Json(user_to_me(&user))))
}

// --- Session Endpoints ---

/// POST /auth/refresh — exchange refresh cookie for new access token
#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "auth",
    responses(
        (status = 200, description = "Tokens refreshed (new cookies set)"),
        (status = 401, description = "Invalid or expired refresh token", body = ErrorBody),
    )
)]
pub(crate) async fn auth_refresh(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), Error> {
    let refresh_raw = jar
        .get(&state.cookie_names.refresh)
        .map(|c| c.value().to_string())
        .ok_or(Error::Unauthenticated)?;

    let refresh_hash = jwt::hash_token(&refresh_raw);

    // Check for token reuse — if this hash was already consumed, an attacker
    // is replaying a stolen token. Revoke the entire family.
    if let Some(family_id) = db::check_token_reuse(&state.db, &refresh_hash).await? {
        db::revoke_token_family(&state.db, family_id).await?;
        return Err(Error::InvalidToken);
    }

    // Atomically consume a session-only refresh token (client_id IS NULL).
    // This rejects client-bound tokens without consuming them, preventing
    // accidental destruction of OAuth client tokens at the session endpoint.
    let token_row = db::consume_session_refresh_token(&state.db, &refresh_hash)
        .await?
        .ok_or(Error::InvalidToken)?;

    let user = db::find_user_by_id(&state.db, token_row.user_id)
        .await?
        .ok_or(Error::UserNotFound)?;

    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
    let ip = client_ip_string(&headers, addr, state.config.server.behind_proxy);

    // Issue new tokens, inheriting the family_id from the consumed token
    let access_token = state.keys.sign_access_token(
        &state.config.jwt,
        &user.id.to_string(),
        &user.username,
        &user.role,
        &state.config.jwt.issuer,
    )?;

    const MAX_USER_AGENT_BYTES: usize = 512;
    let ua_truncated = ua.map(|ua| &ua[..ua.floor_char_boundary(MAX_USER_AGENT_BYTES)]);

    let (new_refresh_raw, new_refresh_hash) = jwt::generate_refresh_token();
    let expires_at = Utc::now() + Duration::seconds(state.config.jwt.refresh_token_ttl_secs as i64);
    // Propagate auth_time for DB consistency; this session-cookie path does not
    // issue ID tokens, so auth_time is not surfaced to clients here.
    db::store_refresh_token(
        &state.db, user.id, None, &new_refresh_hash, expires_at,
        &[], ua_truncated, Some(&ip), token_row.family_id, token_row.nonce.as_deref(),
        token_row.auth_time,
    ).await?;

    // Mark the new token as just used (session was actively refreshed)
    db::touch_refresh_token(&state.db, &new_refresh_hash).await?;

    let jar = jar
        .add(build_access_cookie(&state.cookie_names.access, &access_token, &state.config))
        .add(build_refresh_cookie(&state.cookie_names.refresh, &new_refresh_raw, &state.config));

    Ok((jar, StatusCode::OK))
}

/// POST /auth/logout — clear cookies + revoke refresh token
#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "auth",
    responses(
        (status = 204, description = "Logged out (cookies cleared)"),
    )
)]
pub(crate) async fn auth_logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), Error> {
    if let Some(refresh) = jar.get(&state.cookie_names.refresh) {
        let hash = jwt::hash_token(refresh.value());
        // Look up user_id before deleting, for back-channel logout dispatch
        if let Some(token_row) = db::find_refresh_token(&state.db, &hash).await? {
            db::delete_refresh_token(&state.db, &hash).await?;
            webhooks::dispatch_backchannel_logout(
                &state.db, &state.keys, &state.config, &state.http_client,
                token_row.user_id,
            ).await;
        }
    }

    let jar = jar
        .remove(removal_cookie(&state.cookie_names.access, "/", &state.config))
        .remove(removal_cookie(&state.cookie_names.refresh, "/auth", &state.config));

    Ok((jar, StatusCode::NO_CONTENT))
}

/// POST /auth/logout-all — revoke all refresh tokens
#[utoipa::path(
    post,
    path = "/auth/logout-all",
    tag = "auth",
    responses(
        (status = 204, description = "All sessions revoked"),
        (status = 401, description = "Not authenticated", body = ErrorBody),
    )
)]
pub(crate) async fn auth_logout_all(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), Error> {
    let user = extract_user(&state, &jar)?;
    let user_id = user.sub_uuid()?;

    // Dispatch back-channel logout BEFORE deleting tokens (query needs active tokens)
    webhooks::dispatch_backchannel_logout(
        &state.db, &state.keys, &state.config, &state.http_client, user_id,
    ).await;

    db::delete_all_refresh_tokens(&state.db, user_id).await?;

    let jar = jar
        .remove(removal_cookie(&state.cookie_names.access, "/", &state.config))
        .remove(removal_cookie(&state.cookie_names.refresh, "/auth", &state.config));

    Ok((jar, StatusCode::NO_CONTENT))
}

// --- Session List/Revoke Endpoints ---

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SessionResponse {
    id: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: String,
    last_used_at: Option<String>,
    is_current: bool,
}

/// GET /auth/sessions — list active sessions for the current user
#[utoipa::path(
    get,
    path = "/auth/sessions",
    tag = "auth",
    responses(
        (status = 200, description = "Active sessions", body = Vec<SessionResponse>),
        (status = 401, description = "Not authenticated", body = ErrorBody),
    )
)]
pub(crate) async fn list_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<SessionResponse>>, Error> {
    let claims = extract_user(&state, &jar)?;
    let user_id = claims.sub_uuid()?;

    // Identify the current session by its refresh token
    let current_token_hash = jar
        .get(&state.cookie_names.refresh)
        .map(|c| jwt::hash_token(c.value()));

    let sessions = db::list_sessions(&state.db, user_id).await?;

    // Look up the current session's ID from its token hash
    let current_session_id = if let Some(ref hash) = current_token_hash {
        db::find_refresh_token(&state.db, hash)
            .await?
            .map(|row| row.id)
    } else {
        None
    };

    let response: Vec<SessionResponse> = sessions
        .into_iter()
        .map(|s| SessionResponse {
            is_current: current_session_id.is_some_and(|id| id == s.id),
            id: s.id.to_string(),
            user_agent: s.user_agent,
            ip_address: s.ip_address,
            created_at: s.created_at.to_rfc3339(),
            last_used_at: s.last_used_at.map(|t| t.to_rfc3339()),
        })
        .collect();

    Ok(Json(response))
}

/// DELETE /auth/sessions/{id} — revoke a specific session
#[utoipa::path(
    delete,
    path = "/auth/sessions/{id}",
    tag = "auth",
    params(("id" = String, Path, description = "Session ID to revoke")),
    responses(
        (status = 204, description = "Session revoked"),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 404, description = "Session not found", body = ErrorBody),
    )
)]
pub(crate) async fn revoke_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    jar: CookieJar,
) -> Result<StatusCode, Error> {
    let claims = extract_user(&state, &jar)?;
    let user_id = claims.sub_uuid()?;

    let session_uuid = uuid::Uuid::parse_str(&session_id)
        .map_err(|_| Error::BadRequest("invalid session id".to_string()))?;

    // Prevent revoking the current session (use /auth/logout for that)
    if let Some(refresh) = jar.get(&state.cookie_names.refresh) {
        let hash = jwt::hash_token(refresh.value());
        if let Some(token_row) = db::find_refresh_token(&state.db, &hash).await? {
            if token_row.id == session_uuid {
                return Err(Error::BadRequest(
                    "cannot revoke current session; use /auth/logout instead".to_string(),
                ));
            }
        }
    }

    let deleted = db::revoke_session(&state.db, session_uuid, user_id).await?;
    if !deleted {
        return Err(Error::NotFound);
    }

    // Dispatch back-channel logout for the user
    webhooks::dispatch_backchannel_logout(
        &state.db, &state.keys, &state.config, &state.http_client, user_id,
    ).await;

    Ok(StatusCode::NO_CONTENT)
}

// --- Profile Endpoints ---

/// GET /auth/me — current user profile
#[utoipa::path(
    get,
    path = "/auth/me",
    tag = "auth",
    responses(
        (status = 200, description = "Current user info", body = MeResponse),
        (status = 401, description = "Not authenticated", body = ErrorBody),
    )
)]
pub(crate) async fn auth_me(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<MeResponse>, Error> {
    let claims = extract_user(&state, &jar)?;
    let user = db::find_user_by_id(&state.db, claims.sub_uuid()?)
        .await?
        .ok_or(Error::UserNotFound)?;

    Ok(Json(user_to_me(&user)))
}

/// PATCH /auth/me — update display name
#[utoipa::path(
    patch,
    path = "/auth/me",
    tag = "auth",
    request_body = UpdateDisplayNameRequest,
    responses(
        (status = 200, description = "Display name updated", body = MeResponse),
        (status = 401, description = "Not authenticated", body = ErrorBody),
    )
)]
pub(crate) async fn update_display_name(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<UpdateDisplayNameRequest>,
) -> Result<Json<MeResponse>, Error> {
    if body.display_name.chars().count() > 200 {
        return Err(Error::BadRequest("display name must be at most 200 characters".to_string()));
    }

    let claims = extract_user(&state, &jar)?;

    // Treat empty string as clearing the display name
    let display_name = if body.display_name.trim().is_empty() {
        None
    } else {
        Some(body.display_name.as_str())
    };

    let user = db::update_user_display_name(
        &state.db,
        claims.sub_uuid()?,
        display_name,
    )
    .await?;

    webhooks::dispatch_event(
        &state.db,
        webhooks::USER_UPDATED,
        serde_json::json!({ "user_id": user.id.to_string(), "display_name": user.display_name }),
        state.config.webhooks.max_retry_attempts,
    ).await;

    Ok(Json(user_to_me(&user)))
}

/// PATCH /auth/me/username — change username
#[utoipa::path(
    patch,
    path = "/auth/me/username",
    tag = "auth",
    request_body = UpdateUsernameRequest,
    responses(
        (status = 200, description = "Username updated", body = MeResponse),
        (status = 400, description = "Invalid username or on cooldown", body = ErrorBody),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 409, description = "Username taken", body = ErrorBody),
    )
)]
pub(crate) async fn update_username(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<UpdateUsernameRequest>,
) -> Result<(CookieJar, Json<MeResponse>), Error> {
    let claims = extract_user(&state, &jar)?;
    let user_id = claims.sub_uuid()?;

    if !state.config.usernames.allow_changes {
        return Err(Error::BadRequest("username changes are disabled".to_string()));
    }

    validate_username(&body.username, &state.config, &state.username_regex)?;

    // Check cooldown
    if let Some(last_change) = db::last_username_change(&state.db, user_id).await? {
        let cooldown = Duration::days(state.config.usernames.change_cooldown_days as i64);
        let available_at = last_change + cooldown;
        if Utc::now() < available_at {
            return Err(Error::UsernameChangeCooldown { available_at });
        }
    }

    // Check availability
    if db::find_user_by_username(&state.db, &body.username).await?.is_some() {
        return Err(Error::UsernameTaken);
    }
    if db::is_username_held(&state.db, &body.username, user_id).await? {
        return Err(Error::UsernameTaken);
    }

    // Get current user for old username
    let current_user = db::find_user_by_id(&state.db, user_id)
        .await?
        .ok_or(Error::UserNotFound)?;

    // Record old username + update atomically
    let hold_days = state.config.usernames.old_name_hold_days as i64;
    let held_until = Utc::now() + Duration::days(hold_days);
    let user = db::change_username(
        &state.db,
        user_id,
        &current_user.username,
        &body.username,
        held_until,
    )
    .await
    .map_err(|e| if riley_auth_core::error::is_unique_violation(&e) {
        Error::UsernameTaken
    } else {
        e
    })?;

    // Re-issue access token with new username
    let access_token = state.keys.sign_access_token(
        &state.config.jwt,
        &user.id.to_string(),
        &user.username,
        &user.role,
        &state.config.jwt.issuer,
    )?;

    let jar = jar.add(build_access_cookie(&state.cookie_names.access, &access_token, &state.config));

    webhooks::dispatch_event(
        &state.db,
        webhooks::USER_USERNAME_CHANGED,
        serde_json::json!({
            "user_id": user.id.to_string(),
            "old_username": current_user.username,
            "new_username": user.username,
        }),
        state.config.webhooks.max_retry_attempts,
    ).await;

    Ok((jar, Json(user_to_me(&user))))
}

/// DELETE /auth/me — delete account
#[utoipa::path(
    delete,
    path = "/auth/me",
    tag = "auth",
    responses(
        (status = 204, description = "Account deleted"),
        (status = 400, description = "Cannot delete last admin", body = ErrorBody),
        (status = 401, description = "Not authenticated", body = ErrorBody),
    )
)]
pub(crate) async fn delete_account(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), Error> {
    let claims = extract_user(&state, &jar)?;
    let user_id = claims.sub_uuid()?;

    // Dispatch back-channel logout BEFORE soft delete (which deletes tokens)
    webhooks::dispatch_backchannel_logout(
        &state.db, &state.keys, &state.config, &state.http_client, user_id,
    ).await;

    match db::soft_delete_user(&state.db, user_id).await? {
        db::DeleteUserResult::Deleted => {}
        db::DeleteUserResult::LastAdmin => {
            return Err(Error::BadRequest("cannot delete the last admin".to_string()));
        }
        db::DeleteUserResult::NotFound => {
            return Err(Error::UserNotFound);
        }
    }

    webhooks::dispatch_event(
        &state.db,
        webhooks::USER_DELETED,
        serde_json::json!({ "user_id": user_id.to_string() }),
        state.config.webhooks.max_retry_attempts,
    ).await;

    let jar = jar
        .remove(removal_cookie(&state.cookie_names.access, "/", &state.config))
        .remove(removal_cookie(&state.cookie_names.refresh, "/auth", &state.config));

    Ok((jar, StatusCode::NO_CONTENT))
}

/// GET /auth/me/links — list linked providers
#[utoipa::path(
    get,
    path = "/auth/me/links",
    tag = "auth",
    responses(
        (status = 200, description = "Linked OAuth providers", body = Vec<LinkResponse>),
        (status = 401, description = "Not authenticated", body = ErrorBody),
    )
)]
pub(crate) async fn list_links(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<LinkResponse>>, Error> {
    let claims = extract_user(&state, &jar)?;
    let links = db::find_oauth_links_by_user(&state.db, claims.sub_uuid()?).await?;

    let response: Vec<LinkResponse> = links
        .into_iter()
        .map(|l| LinkResponse {
            provider: l.provider,
            provider_email: l.provider_email,
            created_at: l.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(response))
}

// --- Provider Linking ---

/// GET /auth/link/{provider} — start linking a new provider
#[utoipa::path(
    get,
    path = "/auth/link/{provider}",
    tag = "auth",
    params(("provider" = String, Path, description = "OAuth provider name")),
    responses(
        (status = 302, description = "Redirect to provider for linking"),
        (status = 401, description = "Not authenticated", body = ErrorBody),
        (status = 404, description = "Unknown provider", body = ErrorBody),
    )
)]
pub(crate) async fn link_redirect(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), Error> {
    // Must be authenticated
    let _claims = extract_user(&state, &jar)?;

    let provider = find_provider(&state.providers, &provider_name)?;
    let callback_url = format!(
        "{}/auth/link/{}/callback",
        state.config.server.public_url, provider_name
    );

    let oauth_state = oauth::generate_state();
    let (pkce_verifier, pkce_challenge) = oauth::generate_pkce();

    let auth_url = oauth::build_auth_url(
        provider,
        &callback_url,
        &oauth_state,
        &pkce_challenge,
    )?;

    let jar = jar
        .add(build_temp_cookie(&state.cookie_names.oauth_state, &oauth_state, &state.config))
        .add(build_temp_cookie(&state.cookie_names.pkce, &pkce_verifier, &state.config));

    Ok((jar, Redirect::temporary(&auth_url)))
}

/// GET /auth/link/{provider}/callback — complete linking
#[utoipa::path(
    get,
    path = "/auth/link/{provider}/callback",
    tag = "auth",
    params(("provider" = String, Path, description = "OAuth provider name")),
    responses(
        (status = 302, description = "Redirect after link callback"),
        (status = 400, description = "Invalid OAuth state or code", body = ErrorBody),
    )
)]
pub(crate) async fn link_callback(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    Query(query): Query<CallbackQuery>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), Error> {
    let claims = extract_user(&state, &jar)?;
    let user_id = claims.sub_uuid()?;

    let provider = find_provider(&state.providers, &provider_name)?;

    // Verify state
    let saved_state = jar
        .get(&state.cookie_names.oauth_state)
        .map(|c| c.value().to_string())
        .ok_or(Error::InvalidOAuthState)?;

    if query.state.as_bytes().ct_eq(saved_state.as_bytes()).unwrap_u8() == 0 {
        return Err(Error::InvalidOAuthState);
    }

    let pkce_verifier = jar
        .get(&state.cookie_names.pkce)
        .map(|c| c.value().to_string())
        .ok_or(Error::InvalidOAuthState)?;

    let callback_url = format!(
        "{}/auth/link/{}/callback",
        state.config.server.public_url, provider_name
    );

    let provider_token = oauth::exchange_code(
        provider,
        &query.code,
        &callback_url,
        &pkce_verifier,
        &state.oauth_client,
    )
    .await?;

    let profile = oauth::fetch_profile(provider, &provider_token, &state.oauth_client).await?;

    // Check if this provider account is already linked to someone
    if db::find_oauth_link(&state.db, &profile.provider, &profile.provider_id).await?.is_some() {
        return Err(Error::ProviderAlreadyLinked);
    }

    // Create the link (catch unique violation from concurrent requests)
    db::create_oauth_link(
        &state.db,
        user_id,
        &profile.provider,
        &profile.provider_id,
        profile.email.as_deref(),
        profile.email_verified,
    )
    .await
    .map_err(|e| if riley_auth_core::error::is_unique_violation(&e) {
        Error::ProviderAlreadyLinked
    } else {
        e
    })?;

    webhooks::dispatch_event(
        &state.db,
        webhooks::LINK_CREATED,
        serde_json::json!({
            "user_id": user_id.to_string(),
            "provider": profile.provider,
        }),
        state.config.webhooks.max_retry_attempts,
    ).await;

    let jar = jar
        .remove(removal_cookie(&state.cookie_names.oauth_state, "/", &state.config))
        .remove(removal_cookie(&state.cookie_names.pkce, "/", &state.config));

    let redirect_url = format!("{}/profile", state.config.server.public_url);
    Ok((jar, Redirect::temporary(&redirect_url)))
}

/// DELETE /auth/link/{provider} — unlink provider
#[utoipa::path(
    delete,
    path = "/auth/link/{provider}",
    tag = "auth",
    params(("provider" = String, Path, description = "OAuth provider name")),
    responses(
        (status = 204, description = "Provider unlinked"),
        (status = 400, description = "Cannot unlink last provider", body = ErrorBody),
        (status = 401, description = "Not authenticated", body = ErrorBody),
    )
)]
pub(crate) async fn unlink_provider(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    jar: CookieJar,
) -> Result<StatusCode, Error> {
    let claims = extract_user(&state, &jar)?;
    let user_id = claims.sub_uuid()?;

    match db::delete_oauth_link_if_not_last(&state.db, user_id, &provider_name).await? {
        db::UnlinkResult::Deleted => {
            webhooks::dispatch_event(
                &state.db,
                webhooks::LINK_DELETED,
                serde_json::json!({
                    "user_id": user_id.to_string(),
                    "provider": provider_name,
                }),
                state.config.webhooks.max_retry_attempts,
            ).await;
            Ok(StatusCode::NO_CONTENT)
        }
        db::UnlinkResult::LastProvider => Err(Error::LastProvider),
        db::UnlinkResult::NotFound => Err(Error::NotFound),
    }
}

// --- Helpers ---

fn find_provider<'a>(
    providers: &'a [ResolvedProvider],
    name: &str,
) -> Result<&'a ResolvedProvider, Error> {
    providers
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| Error::BadRequest(format!("unknown provider: {name}")))
}

fn extract_user(state: &AppState, jar: &CookieJar) -> Result<jwt::Claims, Error> {
    let token = jar
        .get(&state.cookie_names.access)
        .map(|c| c.value().to_string())
        .ok_or(Error::Unauthenticated)?;

    let data = state.keys.verify_session_token(&state.config.jwt, &token)?;
    Ok(data.claims)
}

fn validate_username(username: &str, config: &Config, regex: &regex::Regex) -> Result<(), Error> {
    let rules = &config.usernames;

    let char_count = username.chars().count();
    if char_count < rules.min_length {
        return Err(Error::InvalidUsername {
            reason: format!("must be at least {} characters", rules.min_length),
        });
    }
    if char_count > rules.max_length {
        return Err(Error::InvalidUsername {
            reason: format!("must be at most {} characters", rules.max_length),
        });
    }

    if !regex.is_match(username) {
        return Err(Error::InvalidUsername {
            reason: "contains invalid characters".to_string(),
        });
    }

    let check_name = username.to_lowercase();

    for reserved in &rules.reserved {
        if check_name == reserved.to_lowercase() {
            return Err(Error::ReservedUsername);
        }
    }

    Ok(())
}

/// Extract the client IP address from the request.
///
/// Extract client IP as a string for storage in the database.
///
/// Delegates to `super::extract_client_ip` and formats as a String.
fn client_ip_string(headers: &HeaderMap, addr: SocketAddr, behind_proxy: bool) -> String {
    super::extract_client_ip(headers, Some(addr.ip()), behind_proxy)
        .map_or_else(|| addr.ip().to_string(), |ip| ip.to_string())
}

/// Issue new access and refresh tokens, storing the refresh token in the DB.
/// Returns the cookie jar and the new refresh token hash (for touch_refresh_token).
async fn issue_tokens(
    state: &AppState,
    jar: CookieJar,
    user: &db::User,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
) -> Result<(CookieJar, String), Error> {
    let access_token = state.keys.sign_access_token(
        &state.config.jwt,
        &user.id.to_string(),
        &user.username,
        &user.role,
        &state.config.jwt.issuer,
    )?;

    // Truncate user_agent to prevent storage bloat from oversized headers.
    // Use floor_char_boundary to avoid panicking on multi-byte UTF-8 sequences.
    const MAX_USER_AGENT_BYTES: usize = 512;
    let ua_truncated = user_agent.map(|ua| &ua[..ua.floor_char_boundary(MAX_USER_AGENT_BYTES)]);

    let (refresh_raw, refresh_hash) = jwt::generate_refresh_token();
    let family_id = uuid::Uuid::now_v7();
    let now = Utc::now();
    let expires_at = now + Duration::seconds(state.config.jwt.refresh_token_ttl_secs as i64);
    // auth_time = now is correct here: this runs immediately after OAuth callback,
    // so token-issue time ≈ authentication time. The OAuth provider path uses
    // auth_code.created_at instead (also ≈ authentication time from that flow).
    let auth_time = Some(now.timestamp());
    db::store_refresh_token(&state.db, user.id, None, &refresh_hash, expires_at, &[], ua_truncated, ip_address, family_id, None, auth_time).await?;

    let jar = jar
        .add(build_access_cookie(&state.cookie_names.access, &access_token, &state.config))
        .add(build_refresh_cookie(&state.cookie_names.refresh, &refresh_raw, &state.config));

    Ok((jar, refresh_hash))
}

fn build_access_cookie(name: &str, token: &str, config: &Config) -> Cookie<'static> {
    let mut cookie = Cookie::new(name.to_string(), token.to_string());
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    if let Some(ref domain) = config.server.cookie_domain {
        cookie.set_domain(domain.clone());
    }
    cookie.set_max_age(cookie::time::Duration::seconds(
        config.jwt.access_token_ttl_secs as i64,
    ));
    cookie
}

fn build_refresh_cookie(name: &str, token: &str, config: &Config) -> Cookie<'static> {
    let mut cookie = Cookie::new(name.to_string(), token.to_string());
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/auth");
    if let Some(ref domain) = config.server.cookie_domain {
        cookie.set_domain(domain.clone());
    }
    cookie.set_max_age(cookie::time::Duration::seconds(
        config.jwt.refresh_token_ttl_secs as i64,
    ));
    cookie
}

fn build_temp_cookie(name: &str, value: &str, config: &Config) -> Cookie<'static> {
    let mut cookie = Cookie::new(name.to_string(), value.to_string());
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    if let Some(ref domain) = config.server.cookie_domain {
        cookie.set_domain(domain.clone());
    }
    cookie.set_max_age(cookie::time::Duration::minutes(15));
    cookie
}

/// Build a removal cookie with matching path/domain so browsers clear the original.
fn removal_cookie(name: &str, path: &str, config: &Config) -> Cookie<'static> {
    let mut cookie = Cookie::new(name.to_string(), "");
    cookie.set_path(path.to_string());
    if let Some(ref domain) = config.server.cookie_domain {
        cookie.set_domain(domain.clone());
    }
    cookie
}

fn user_to_me(user: &db::User) -> MeResponse {
    MeResponse {
        id: user.id.to_string(),
        username: user.username.clone(),
        display_name: user.display_name.clone(),
        avatar_url: user.avatar_url.clone(),
        role: user.role.clone(),
    }
}

/// Setup token: short-lived JWT containing OAuth profile data.
/// Used to pass profile info between callback and setup endpoints.
/// The JWT signature protects integrity of all claims (profile, purpose, expiry).
#[derive(Serialize, Deserialize)]
struct SetupClaims {
    profile: oauth::OAuthProfile,
    exp: i64,
    iss: String,
    purpose: String,
}

fn create_setup_token(
    keys: &Keys,
    config: &Config,
    profile: &oauth::OAuthProfile,
) -> Result<String, Error> {
    let claims = SetupClaims {
        profile: profile.clone(),
        exp: (Utc::now() + Duration::minutes(15)).timestamp(),
        iss: config.jwt.issuer.clone(),
        purpose: "setup".to_string(),
    };

    let mut header = jsonwebtoken::Header::new(keys.active_algorithm());
    header.kid = Some(keys.active_kid().to_string());
    jsonwebtoken::encode(&header, &claims, &keys.encoding_key())
        .map_err(|e| Error::OAuth(format!("failed to create setup token: {e}")))
}

fn decode_setup_token(
    keys: &Keys,
    config: &Config,
    token: &str,
) -> Result<oauth::OAuthProfile, Error> {
    let data = keys.verify_token::<SetupClaims>(&config.jwt, token)
        .map_err(|_| Error::InvalidToken)?;

    if data.claims.purpose != "setup" {
        return Err(Error::InvalidToken);
    }

    Ok(data.claims.profile)
}

// Extension trait for Claims
trait ClaimsExt {
    fn sub_uuid(&self) -> Result<uuid::Uuid, Error>;
}

impl ClaimsExt for jwt::Claims {
    fn sub_uuid(&self) -> Result<uuid::Uuid, Error> {
        self.sub.parse().map_err(|_| Error::InvalidToken)
    }
}
