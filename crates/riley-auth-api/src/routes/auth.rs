use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Redirect;
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use riley_auth_core::config::Config;
use riley_auth_core::db;
use riley_auth_core::error::Error;
use riley_auth_core::jwt::{self, Keys};
use riley_auth_core::oauth::{self, Provider};

use crate::server::AppState;

// --- Cookie names ---
pub const ACCESS_TOKEN_COOKIE: &str = "riley_auth_access";
const REFRESH_TOKEN_COOKIE: &str = "riley_auth_refresh";
const OAUTH_STATE_COOKIE: &str = "riley_auth_oauth_state";
const PKCE_COOKIE: &str = "riley_auth_pkce";
const SETUP_TOKEN_COOKIE: &str = "riley_auth_setup";

// --- Query params ---

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
pub struct SetupRequest {
    username: String,
}

#[derive(Serialize)]
pub struct MeResponse {
    id: String,
    username: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    role: String,
}

#[derive(Serialize)]
pub struct LinkResponse {
    provider: String,
    provider_email: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
pub struct UpdateDisplayNameRequest {
    display_name: String,
}

#[derive(Deserialize)]
pub struct UpdateUsernameRequest {
    username: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        // OAuth consumer
        .route("/auth/{provider}", get(auth_redirect))
        .route("/auth/{provider}/callback", get(auth_callback))
        .route("/auth/setup", post(auth_setup))
        // Session
        .route("/auth/refresh", post(auth_refresh))
        .route("/auth/logout", post(auth_logout))
        .route("/auth/logout-all", post(auth_logout_all))
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
async fn auth_redirect(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), Error> {
    let provider = Provider::from_str(&provider_name)
        .ok_or_else(|| Error::BadRequest(format!("unknown provider: {provider_name}")))?;

    let provider_config = get_provider_config(&state.config, provider)?;
    let callback_url = format!(
        "{}/auth/{}/callback",
        state.config.server.frontend_url, provider_name
    );

    let oauth_state = oauth::generate_state();
    let (pkce_verifier, pkce_challenge) = oauth::generate_pkce();

    let auth_url = oauth::build_auth_url(
        provider,
        provider_config,
        &callback_url,
        &oauth_state,
        &pkce_challenge,
    )?;

    let jar = jar
        .add(build_temp_cookie(OAUTH_STATE_COOKIE, &oauth_state, &state.config))
        .add(build_temp_cookie(PKCE_COOKIE, &pkce_verifier, &state.config));

    Ok((jar, Redirect::temporary(&auth_url)))
}

/// GET /auth/{provider}/callback — OAuth callback
async fn auth_callback(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    Query(query): Query<CallbackQuery>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), Error> {
    let provider = Provider::from_str(&provider_name)
        .ok_or_else(|| Error::BadRequest(format!("unknown provider: {provider_name}")))?;

    // Verify state
    let saved_state = jar
        .get(OAUTH_STATE_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(Error::InvalidOAuthState)?;

    if query.state != saved_state {
        return Err(Error::InvalidOAuthState);
    }

    // Get PKCE verifier
    let pkce_verifier = jar
        .get(PKCE_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(Error::InvalidOAuthState)?;

    let provider_config = get_provider_config(&state.config, provider)?;
    let callback_url = format!(
        "{}/auth/{}/callback",
        state.config.server.frontend_url, provider_name
    );

    // Exchange code for access token
    let provider_token = oauth::exchange_code(
        provider,
        provider_config,
        &query.code,
        &callback_url,
        &pkce_verifier,
    )
    .await?;

    // Fetch profile from provider
    let profile = oauth::fetch_profile(provider, &provider_token).await?;

    // Clear temp cookies
    let jar = jar
        .remove(Cookie::from(OAUTH_STATE_COOKIE))
        .remove(Cookie::from(PKCE_COOKIE));

    // Look up existing oauth link
    if let Some(link) = db::find_oauth_link(&state.db, &profile.provider, &profile.provider_id).await? {
        // Returning user — issue tokens
        let user = db::find_user_by_id(&state.db, link.user_id)
            .await?
            .ok_or(Error::UserNotFound)?;

        let jar = issue_tokens(&state, jar, &user).await?;
        return Ok((jar, Redirect::temporary(&state.config.server.frontend_url)));
    }

    // Check for email match (suggest linking)
    if let Some(ref email) = profile.email {
        let matching_links = db::find_oauth_links_by_email(&state.db, email).await?;
        if !matching_links.is_empty() {
            // There's an existing account with the same email on a different provider.
            // Redirect to link-accounts page with a setup token.
            let setup_token = create_setup_token(&state.keys, &state.config, &profile)?;
            let jar = jar.add(build_temp_cookie(SETUP_TOKEN_COOKIE, &setup_token, &state.config));
            let mut redirect_url = url::Url::parse(&format!(
                "{}/link-accounts", state.config.server.frontend_url
            )).map_err(|_| Error::Config("invalid frontend_url".to_string()))?;
            redirect_url.query_pairs_mut()
                .append_pair("provider", &profile.provider)
                .append_pair("email", email);
            return Ok((jar, Redirect::temporary(redirect_url.as_str())));
        }
    }

    // New user — redirect to onboarding with setup token
    let setup_token = create_setup_token(&state.keys, &state.config, &profile)?;
    let jar = jar.add(build_temp_cookie(SETUP_TOKEN_COOKIE, &setup_token, &state.config));
    let redirect_url = format!("{}/onboarding", state.config.server.frontend_url);
    Ok((jar, Redirect::temporary(&redirect_url)))
}

/// POST /auth/setup — create account with username after OAuth
async fn auth_setup(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<SetupRequest>,
) -> Result<(CookieJar, Json<MeResponse>), Error> {
    // Get setup token
    let setup_token = jar
        .get(SETUP_TOKEN_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(Error::Unauthenticated)?;

    let profile = decode_setup_token(&state.keys, &state.config, &setup_token)?;

    // Validate username
    validate_username(&body.username, &state.config)?;

    // Check availability
    if db::find_user_by_username(&state.db, &body.username).await?.is_some() {
        return Err(Error::UsernameTaken);
    }
    if db::is_username_held(&state.db, &body.username).await? {
        return Err(Error::UsernameTaken);
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
    )
    .await
    .map_err(|e| if riley_auth_core::error::is_unique_violation(&e) {
        Error::UsernameTaken
    } else {
        e
    })?;

    // Issue tokens, clear setup cookie
    let jar = jar.remove(Cookie::from(SETUP_TOKEN_COOKIE));
    let jar = issue_tokens(&state, jar, &user).await?;

    Ok((jar, Json(user_to_me(&user))))
}

// --- Session Endpoints ---

/// POST /auth/refresh — exchange refresh cookie for new access token
async fn auth_refresh(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), Error> {
    let refresh_raw = jar
        .get(REFRESH_TOKEN_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(Error::Unauthenticated)?;

    let refresh_hash = jwt::hash_token(&refresh_raw);

    // Atomically consume the refresh token (prevents TOCTOU race)
    let token_row = db::consume_refresh_token(&state.db, &refresh_hash)
        .await?
        .ok_or(Error::InvalidToken)?;

    // Reject client-bound refresh tokens at the session endpoint
    if token_row.client_id.is_some() {
        return Err(Error::InvalidToken);
    }

    let user = db::find_user_by_id(&state.db, token_row.user_id)
        .await?
        .ok_or(Error::UserNotFound)?;

    let jar = issue_tokens(&state, jar, &user).await?;

    Ok((jar, StatusCode::OK))
}

/// POST /auth/logout — clear cookies + revoke refresh token
async fn auth_logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), Error> {
    if let Some(refresh) = jar.get(REFRESH_TOKEN_COOKIE) {
        let hash = jwt::hash_token(refresh.value());
        db::delete_refresh_token(&state.db, &hash).await?;
    }

    let jar = jar
        .remove(Cookie::from(ACCESS_TOKEN_COOKIE))
        .remove(Cookie::from(REFRESH_TOKEN_COOKIE));

    Ok((jar, StatusCode::OK))
}

/// POST /auth/logout-all — revoke all refresh tokens
async fn auth_logout_all(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), Error> {
    let user = extract_user(&state, &jar)?;

    db::delete_all_refresh_tokens(&state.db, user.sub_uuid()?).await?;

    let jar = jar
        .remove(Cookie::from(ACCESS_TOKEN_COOKIE))
        .remove(Cookie::from(REFRESH_TOKEN_COOKIE));

    Ok((jar, StatusCode::OK))
}

// --- Profile Endpoints ---

/// GET /auth/me — current user profile
async fn auth_me(
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
async fn update_display_name(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<UpdateDisplayNameRequest>,
) -> Result<Json<MeResponse>, Error> {
    if body.display_name.len() > 200 {
        return Err(Error::BadRequest("display name must be at most 200 characters".to_string()));
    }

    let claims = extract_user(&state, &jar)?;
    let user = db::update_user_display_name(
        &state.db,
        claims.sub_uuid()?,
        &body.display_name,
    )
    .await?;

    Ok(Json(user_to_me(&user)))
}

/// PATCH /auth/me/username — change username
async fn update_username(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<UpdateUsernameRequest>,
) -> Result<(CookieJar, Json<MeResponse>), Error> {
    let claims = extract_user(&state, &jar)?;
    let user_id = claims.sub_uuid()?;

    if !state.config.usernames.allow_changes {
        return Err(Error::BadRequest("username changes are disabled".to_string()));
    }

    validate_username(&body.username, &state.config)?;

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
    if db::is_username_held(&state.db, &body.username).await? {
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

    let jar = jar.add(build_access_cookie(&access_token, &state.config));

    Ok((jar, Json(user_to_me(&user))))
}

/// DELETE /auth/me — delete account
async fn delete_account(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), Error> {
    let claims = extract_user(&state, &jar)?;
    let user_id = claims.sub_uuid()?;

    db::soft_delete_user(&state.db, user_id).await?;

    let jar = jar
        .remove(Cookie::from(ACCESS_TOKEN_COOKIE))
        .remove(Cookie::from(REFRESH_TOKEN_COOKIE));

    Ok((jar, StatusCode::OK))
}

/// GET /auth/me/links — list linked providers
async fn list_links(
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
async fn link_redirect(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), Error> {
    // Must be authenticated
    let _claims = extract_user(&state, &jar)?;

    let provider = Provider::from_str(&provider_name)
        .ok_or_else(|| Error::BadRequest(format!("unknown provider: {provider_name}")))?;

    let provider_config = get_provider_config(&state.config, provider)?;
    let callback_url = format!(
        "{}/auth/link/{}/callback",
        state.config.server.frontend_url, provider_name
    );

    let oauth_state = oauth::generate_state();
    let (pkce_verifier, pkce_challenge) = oauth::generate_pkce();

    let auth_url = oauth::build_auth_url(
        provider,
        provider_config,
        &callback_url,
        &oauth_state,
        &pkce_challenge,
    )?;

    let jar = jar
        .add(build_temp_cookie(OAUTH_STATE_COOKIE, &oauth_state, &state.config))
        .add(build_temp_cookie(PKCE_COOKIE, &pkce_verifier, &state.config));

    Ok((jar, Redirect::temporary(&auth_url)))
}

/// GET /auth/link/{provider}/callback — complete linking
async fn link_callback(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    Query(query): Query<CallbackQuery>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), Error> {
    let claims = extract_user(&state, &jar)?;
    let user_id = claims.sub_uuid()?;

    let provider = Provider::from_str(&provider_name)
        .ok_or_else(|| Error::BadRequest(format!("unknown provider: {provider_name}")))?;

    // Verify state
    let saved_state = jar
        .get(OAUTH_STATE_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(Error::InvalidOAuthState)?;

    if query.state != saved_state {
        return Err(Error::InvalidOAuthState);
    }

    let pkce_verifier = jar
        .get(PKCE_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(Error::InvalidOAuthState)?;

    let provider_config = get_provider_config(&state.config, provider)?;
    let callback_url = format!(
        "{}/auth/link/{}/callback",
        state.config.server.frontend_url, provider_name
    );

    let provider_token = oauth::exchange_code(
        provider,
        provider_config,
        &query.code,
        &callback_url,
        &pkce_verifier,
    )
    .await?;

    let profile = oauth::fetch_profile(provider, &provider_token).await?;

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
    )
    .await
    .map_err(|e| if riley_auth_core::error::is_unique_violation(&e) {
        Error::ProviderAlreadyLinked
    } else {
        e
    })?;

    let jar = jar
        .remove(Cookie::from(OAUTH_STATE_COOKIE))
        .remove(Cookie::from(PKCE_COOKIE));

    let redirect_url = format!("{}/profile", state.config.server.frontend_url);
    Ok((jar, Redirect::temporary(&redirect_url)))
}

/// DELETE /auth/link/{provider} — unlink provider
async fn unlink_provider(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    jar: CookieJar,
) -> Result<StatusCode, Error> {
    let claims = extract_user(&state, &jar)?;
    let user_id = claims.sub_uuid()?;

    match db::delete_oauth_link_if_not_last(&state.db, user_id, &provider_name).await? {
        db::UnlinkResult::Deleted => Ok(StatusCode::OK),
        db::UnlinkResult::LastProvider => Err(Error::LastProvider),
        db::UnlinkResult::NotFound => Err(Error::NotFound),
    }
}

// --- Helpers ---

fn get_provider_config<'a>(
    config: &'a Config,
    provider: Provider,
) -> Result<&'a riley_auth_core::config::OAuthProviderConfig, Error> {
    match provider {
        Provider::Google => config.oauth.google.as_ref(),
        Provider::GitHub => config.oauth.github.as_ref(),
    }
    .ok_or_else(|| Error::Config(format!("{} not configured", provider.as_str())))
}

fn extract_user(state: &AppState, jar: &CookieJar) -> Result<jwt::Claims, Error> {
    let token = jar
        .get(ACCESS_TOKEN_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(Error::Unauthenticated)?;

    let data = state.keys.verify_access_token(&state.config.jwt, &token)?;

    // Enforce audience: session cookies must have aud == issuer.
    // Tokens minted for OAuth clients (aud == client_id) must not be accepted here.
    if data.claims.aud != state.config.jwt.issuer {
        return Err(Error::InvalidToken);
    }

    Ok(data.claims)
}

fn validate_username(username: &str, config: &Config) -> Result<(), Error> {
    let rules = &config.usernames;

    if username.len() < rules.min_length {
        return Err(Error::InvalidUsername {
            reason: format!("must be at least {} characters", rules.min_length),
        });
    }
    if username.len() > rules.max_length {
        return Err(Error::InvalidUsername {
            reason: format!("must be at most {} characters", rules.max_length),
        });
    }

    let re = regex::Regex::new(&rules.pattern).map_err(|e| {
        Error::Config(format!("invalid username pattern: {e}"))
    })?;
    if !re.is_match(username) {
        return Err(Error::InvalidUsername {
            reason: "contains invalid characters".to_string(),
        });
    }

    let check_name = if rules.case_sensitive {
        username.to_string()
    } else {
        username.to_lowercase()
    };

    for reserved in &rules.reserved {
        let check_reserved = if rules.case_sensitive {
            reserved.clone()
        } else {
            reserved.to_lowercase()
        };
        if check_name == check_reserved {
            return Err(Error::ReservedUsername);
        }
    }

    Ok(())
}

async fn issue_tokens(
    state: &AppState,
    jar: CookieJar,
    user: &db::User,
) -> Result<CookieJar, Error> {
    let access_token = state.keys.sign_access_token(
        &state.config.jwt,
        &user.id.to_string(),
        &user.username,
        &user.role,
        &state.config.jwt.issuer,
    )?;

    let (refresh_raw, refresh_hash) = jwt::generate_refresh_token();
    let expires_at = Utc::now() + Duration::seconds(state.config.jwt.refresh_token_ttl_secs as i64);
    db::store_refresh_token(&state.db, user.id, None, &refresh_hash, expires_at).await?;

    let jar = jar
        .add(build_access_cookie(&access_token, &state.config))
        .add(build_refresh_cookie(&refresh_raw, &state.config));

    Ok(jar)
}

fn build_access_cookie(token: &str, config: &Config) -> Cookie<'static> {
    let mut cookie = Cookie::new(ACCESS_TOKEN_COOKIE, token.to_string());
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

fn build_refresh_cookie(token: &str, config: &Config) -> Cookie<'static> {
    let mut cookie = Cookie::new(REFRESH_TOKEN_COOKIE, token.to_string());
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
    cookie.set_max_age(cookie::time::Duration::minutes(10));
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

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    // We need access to the encoding key — use the Keys struct directly
    // For now, sign with the same key. Setup tokens are short-lived and same-origin.
    jsonwebtoken::encode(&header, &claims, &keys.encoding_key())
        .map_err(|e| Error::OAuth(format!("failed to create setup token: {e}")))
}

fn decode_setup_token(
    keys: &Keys,
    config: &Config,
    token: &str,
) -> Result<oauth::OAuthProfile, Error> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[&config.jwt.issuer]);
    validation.validate_aud = false;
    validation.leeway = 0;

    let data = jsonwebtoken::decode::<SetupClaims>(token, &keys.decoding_key(), &validation)
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
