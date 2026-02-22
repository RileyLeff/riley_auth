use std::path::PathBuf;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // Config
    #[error("config not found (searched: {searched:?})")]
    ConfigNotFound { searched: Vec<PathBuf> },

    #[error("config parse error in {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("config error: {0}")]
    Config(String),

    // Database
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    // Auth
    #[error("invalid or expired token")]
    InvalidToken,

    #[error("missing authentication")]
    Unauthenticated,

    #[error("insufficient permissions")]
    Forbidden,

    #[error("OAuth error: {0}")]
    OAuth(String),

    #[error("invalid OAuth state")]
    InvalidOAuthState,

    // User
    #[error("user not found")]
    UserNotFound,

    #[error("username taken")]
    UsernameTaken,

    #[error("username held until {held_until}")]
    UsernameHeld { held_until: chrono::DateTime<chrono::Utc> },

    #[error("username change on cooldown until {available_at}")]
    UsernameChangeCooldown {
        available_at: chrono::DateTime<chrono::Utc>,
    },

    #[error("invalid username: {reason}")]
    InvalidUsername { reason: String },

    #[error("reserved username")]
    ReservedUsername,

    #[error("cannot unlink last provider")]
    LastProvider,

    #[error("provider already linked")]
    ProviderAlreadyLinked,

    // OAuth client
    #[error("invalid client")]
    InvalidClient,

    #[error("invalid redirect URI")]
    InvalidRedirectUri,

    #[error("invalid authorization code")]
    InvalidAuthorizationCode,

    #[error("invalid grant")]
    InvalidGrant,

    // General
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("not found")]
    NotFound,

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("unsupported media type")]
    UnsupportedMediaType,

    #[error("rate limited")]
    RateLimited,

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::ConfigNotFound { .. }
            | Self::ConfigParse { .. }
            | Self::Config(_)
            | Self::Migration(_) => StatusCode::INTERNAL_SERVER_ERROR,

            Self::Database(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,

            Self::InvalidToken | Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,

            Self::OAuth(_) | Self::InvalidOAuthState => StatusCode::BAD_REQUEST,

            Self::UserNotFound | Self::NotFound => StatusCode::NOT_FOUND,

            Self::UsernameTaken
            | Self::UsernameHeld { .. }
            | Self::UsernameChangeCooldown { .. }
            | Self::InvalidUsername { .. }
            | Self::ReservedUsername
            | Self::LastProvider
            | Self::ProviderAlreadyLinked
            | Self::InvalidClient
            | Self::InvalidRedirectUri
            | Self::InvalidAuthorizationCode
            | Self::InvalidGrant
            | Self::BadRequest(_) => StatusCode::BAD_REQUEST,

            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    /// User-facing error code (short, stable string).
    fn error_code(&self) -> &'static str {
        match self {
            Self::ConfigNotFound { .. } => "config_not_found",
            Self::ConfigParse { .. } => "config_parse_error",
            Self::Config(_) => "config_error",
            Self::Database(_) => "internal_error",
            Self::Migration(_) => "migration_error",
            Self::InvalidToken => "invalid_token",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::OAuth(_) => "oauth_error",
            Self::InvalidOAuthState => "invalid_oauth_state",
            Self::UserNotFound => "user_not_found",
            Self::UsernameTaken => "username_taken",
            Self::UsernameHeld { .. } => "username_held",
            Self::UsernameChangeCooldown { .. } => "username_change_cooldown",
            Self::InvalidUsername { .. } => "invalid_username",
            Self::ReservedUsername => "reserved_username",
            Self::LastProvider => "last_provider",
            Self::ProviderAlreadyLinked => "provider_already_linked",
            Self::InvalidClient => "invalid_client",
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidAuthorizationCode => "invalid_authorization_code",
            Self::InvalidGrant => "invalid_grant",
            Self::BadRequest(_) => "bad_request",
            Self::NotFound => "not_found",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::RateLimited => "rate_limited",
            Self::Internal(_) => "internal_error",
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status_code();

        // Log internal errors, don't expose details to client
        let detail = if status.is_server_error() {
            tracing::error!(error = %self, "internal error");
            None
        } else {
            Some(self.to_string())
        };

        let body = ErrorBody {
            error: self.error_code().to_string(),
            detail,
        };

        (status, axum::Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
