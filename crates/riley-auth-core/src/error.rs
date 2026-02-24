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

    #[error("token expired")]
    ExpiredToken,

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

    #[error("unsupported grant type")]
    UnsupportedGrantType,

    #[error("invalid scope")]
    InvalidScope,

    #[error("consent required")]
    ConsentRequired,

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

#[derive(Serialize, utoipa::ToSchema)]
pub struct ErrorBody {
    /// Short, stable error code (e.g., "invalid_token", "forbidden").
    error: String,
    /// Human-readable error description (omitted for server errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

impl Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::ConfigNotFound { .. }
            | Self::ConfigParse { .. }
            | Self::Config(_)
            | Self::Migration(_) => StatusCode::INTERNAL_SERVER_ERROR,

            Self::Database(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,

            Self::InvalidToken | Self::ExpiredToken | Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,

            Self::OAuth(_) | Self::InvalidOAuthState => StatusCode::BAD_REQUEST,

            Self::UserNotFound | Self::NotFound => StatusCode::NOT_FOUND,

            Self::InvalidClient => StatusCode::UNAUTHORIZED,

            Self::UsernameTaken | Self::ProviderAlreadyLinked => StatusCode::CONFLICT,

            Self::UsernameHeld { .. }
            | Self::UsernameChangeCooldown { .. }
            | Self::InvalidUsername { .. }
            | Self::ReservedUsername
            | Self::LastProvider
            | Self::InvalidRedirectUri
            | Self::InvalidAuthorizationCode
            | Self::InvalidGrant
            | Self::UnsupportedGrantType
            | Self::InvalidScope
            | Self::ConsentRequired
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
            Self::ExpiredToken => "invalid_token",
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
            Self::InvalidAuthorizationCode => "invalid_grant",
            Self::InvalidGrant => "invalid_grant",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::ConsentRequired => "consent_required",
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
        let error_description = if status.is_server_error() {
            tracing::error!(error = %self, "internal error");
            None
        } else {
            Some(self.to_string())
        };

        let body = ErrorBody {
            error: self.error_code().to_string(),
            error_description,
        };

        (status, axum::Json(body)).into_response()
    }
}

/// Check if a sqlx error is a unique constraint violation (Postgres code 23505).
pub fn is_unique_violation(err: &Error) -> bool {
    if let Error::Database(sqlx::Error::Database(db_err)) = err {
        return db_err.code().as_deref() == Some("23505");
    }
    false
}

/// Return the constraint name from a unique violation error, if available.
pub fn unique_violation_constraint(err: &Error) -> Option<String> {
    if let Error::Database(sqlx::Error::Database(db_err)) = err {
        if db_err.code().as_deref() == Some("23505") {
            return db_err.constraint().map(|s| s.to_string());
        }
    }
    None
}

/// Build a `WWW-Authenticate: Bearer` header value per RFC 6750 §3.1.
///
/// Returns `Some(value)` for errors that should include the header on
/// Bearer-token-protected endpoints; `None` for errors where it doesn't apply.
pub fn www_authenticate_value(issuer: &str, error: &Error) -> Option<String> {
    // Escape `\` and `"` in the issuer for use in a quoted-string (RFC 7230 §3.2.6).
    let realm = issuer.replace('\\', "\\\\").replace('"', "\\\"");
    match error {
        Error::Unauthenticated => {
            Some(format!("Bearer realm=\"{realm}\""))
        }
        Error::ExpiredToken => {
            Some(format!(
                "Bearer realm=\"{realm}\", error=\"invalid_token\", error_description=\"token expired\""
            ))
        }
        Error::InvalidToken => {
            Some(format!(
                "Bearer realm=\"{realm}\", error=\"invalid_token\""
            ))
        }
        Error::Forbidden => {
            Some(format!(
                "Bearer realm=\"{realm}\", error=\"insufficient_scope\""
            ))
        }
        _ => None,
    }
}

pub type Result<T> = std::result::Result<T, Error>;
