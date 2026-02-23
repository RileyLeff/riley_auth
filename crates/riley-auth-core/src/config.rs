use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    #[serde(default)]
    pub oauth: OAuthProvidersConfig,
    pub storage: Option<StorageConfig>,
    #[serde(default)]
    pub usernames: UsernameConfig,
    #[serde(default)]
    pub scopes: ScopesConfig,
    #[serde(default)]
    pub rate_limiting: RateLimitingConfig,
    #[serde(default)]
    pub webhooks: WebhooksConfig,
    #[serde(default)]
    pub maintenance: MaintenanceConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub cors_origins: Vec<String>,
    pub cookie_domain: Option<String>,
    /// Public base URL for this service (used for OAuth callback URLs,
    /// post-login redirects, etc.). Typically the reverse proxy origin
    /// that fronts both the API and frontend.
    pub public_url: String,
    #[serde(default)]
    pub behind_proxy: bool,
    #[serde(default = "default_cookie_prefix")]
    pub cookie_prefix: String,
}

fn default_cookie_prefix() -> String {
    "riley_auth".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: ConfigValue,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Optional PostgreSQL schema. When set, each connection runs
    /// `SET search_path TO <schema>` on connect.
    pub schema: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    #[serde(default = "default_access_ttl")]
    pub access_token_ttl_secs: u64,
    #[serde(default = "default_refresh_ttl")]
    pub refresh_token_ttl_secs: u64,
    #[serde(default = "default_issuer")]
    pub issuer: String,
    #[serde(default = "default_authz_code_ttl")]
    pub authorization_code_ttl_secs: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OAuthProvidersConfig {
    pub google: Option<OAuthProviderConfig>,
    pub github: Option<OAuthProviderConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthProviderConfig {
    pub client_id: ConfigValue,
    pub client_secret: ConfigValue,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_storage_backend")]
    pub backend: String,
    pub bucket: String,
    #[serde(default = "default_region")]
    pub region: String,
    pub endpoint: Option<String>,
    pub public_url_base: String,
    #[serde(default = "default_max_avatar_size")]
    pub max_avatar_size: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsernameConfig {
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    #[serde(default = "default_max_length")]
    pub max_length: usize,
    #[serde(default = "default_pattern")]
    pub pattern: String,
    #[serde(default = "default_true")]
    pub allow_changes: bool,
    #[serde(default = "default_change_cooldown")]
    pub change_cooldown_days: u32,
    #[serde(default = "default_hold_days")]
    pub old_name_hold_days: u32,
    #[serde(default)]
    pub reserved: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScopesConfig {
    #[serde(default)]
    pub definitions: Vec<ScopeDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScopeDefinition {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitingConfig {
    #[serde(default = "default_rate_limit_backend")]
    pub backend: String,
    pub redis_url: Option<ConfigValue>,
    #[serde(default)]
    pub tiers: RateLimitTiersConfig,
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            backend: default_rate_limit_backend(),
            redis_url: None,
            tiers: RateLimitTiersConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitTiersConfig {
    #[serde(default = "default_auth_tier")]
    pub auth: RateLimitTierConfig,
    #[serde(default = "default_standard_tier")]
    pub standard: RateLimitTierConfig,
    #[serde(default = "default_public_tier")]
    pub public: RateLimitTierConfig,
}

impl Default for RateLimitTiersConfig {
    fn default() -> Self {
        Self {
            auth: default_auth_tier(),
            standard: default_standard_tier(),
            public: default_public_tier(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitTierConfig {
    pub requests: u32,
    pub window_secs: u64,
}

fn default_auth_tier() -> RateLimitTierConfig {
    RateLimitTierConfig { requests: 15, window_secs: 60 }
}

fn default_standard_tier() -> RateLimitTierConfig {
    RateLimitTierConfig { requests: 60, window_secs: 60 }
}

fn default_public_tier() -> RateLimitTierConfig {
    RateLimitTierConfig { requests: 300, window_secs: 60 }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebhooksConfig {
    #[serde(default = "default_max_concurrent_deliveries")]
    pub max_concurrent_deliveries: usize,
    #[serde(default = "default_max_retry_attempts")]
    pub max_retry_attempts: u32,
    /// When false (default), webhook delivery blocks URLs that resolve to
    /// private/loopback/link-local IP addresses (SSRF protection).
    #[serde(default)]
    pub allow_private_ips: bool,
    /// Seconds before a "processing" outbox entry is considered stuck and
    /// reset to "pending" for retry. Default: 300 (5 minutes).
    #[serde(default = "default_stuck_processing_timeout_secs")]
    pub stuck_processing_timeout_secs: u64,
}

impl Default for WebhooksConfig {
    fn default() -> Self {
        Self {
            max_concurrent_deliveries: default_max_concurrent_deliveries(),
            max_retry_attempts: default_max_retry_attempts(),
            allow_private_ips: false,
            stuck_processing_timeout_secs: default_stuck_processing_timeout_secs(),
        }
    }
}

fn default_max_concurrent_deliveries() -> usize { 10 }
fn default_max_retry_attempts() -> u32 { 5 }
fn default_stuck_processing_timeout_secs() -> u64 { 300 }

#[derive(Debug, Clone, Deserialize)]
pub struct MaintenanceConfig {
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
    #[serde(default = "default_delivery_retention")]
    pub webhook_delivery_retention_days: u32,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            cleanup_interval_secs: default_cleanup_interval(),
            webhook_delivery_retention_days: default_delivery_retention(),
        }
    }
}

fn default_cleanup_interval() -> u64 { 3600 }      // 1 hour
fn default_delivery_retention() -> u32 { 7 }        // 7 days

/// Validate that a scope name uses only safe characters.
/// Allowed: lowercase ASCII letters, digits, colons, dots, underscores, hyphens.
/// Must start with a letter and be non-empty.
pub fn validate_scope_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Config("scope name cannot be empty".to_string()));
    }
    // ^[a-z][a-z0-9:._-]*$
    let first = name.as_bytes()[0];
    if !first.is_ascii_lowercase() {
        return Err(Error::Config(format!(
            "scope name must start with a lowercase letter: {name}"
        )));
    }
    for ch in name.bytes() {
        if !matches!(ch, b'a'..=b'z' | b'0'..=b'9' | b':' | b'.' | b'_' | b'-') {
            return Err(Error::Config(format!(
                "scope name contains invalid character '{}': {name}",
                ch as char
            )));
        }
    }
    Ok(())
}

// --- ConfigValue: supports "env:VAR_NAME" syntax ---

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ConfigValue {
    Literal(String),
}

impl ConfigValue {
    pub fn resolve(&self) -> Result<String> {
        let ConfigValue::Literal(s) = self;
        if let Some(var_name) = s.strip_prefix("env:") {
            std::env::var(var_name).map_err(|_| {
                Error::Config(format!("environment variable {var_name} not set"))
            })
        } else {
            Ok(s.clone())
        }
    }
}

// --- Config resolution ---

const CONFIG_FILENAME: &str = "riley_auth.toml";
const CONFIG_ENV_VAR: &str = "RILEY_AUTH_CONFIG";

impl Config {
    pub fn from_path(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            Error::Config(format!("cannot read {}: {e}", path.display()))
        })?;
        let config: Config = toml::from_str(&content).map_err(|e| Error::ConfigParse {
            path: path.to_path_buf(),
            source: e,
        })?;
        // Validate scope definition names
        for def in &config.scopes.definitions {
            validate_scope_name(&def.name)?;
        }
        // Validate maintenance config
        if config.maintenance.cleanup_interval_secs == 0 {
            return Err(Error::Config(
                "maintenance.cleanup_interval_secs must be at least 1".to_string(),
            ));
        }
        if config.maintenance.webhook_delivery_retention_days == 0 {
            return Err(Error::Config(
                "maintenance.webhook_delivery_retention_days must be at least 1".to_string(),
            ));
        }
        // Validate webhook config
        if config.webhooks.max_concurrent_deliveries == 0 {
            return Err(Error::Config(
                "webhooks.max_concurrent_deliveries must be at least 1".to_string(),
            ));
        }
        // Validate rate limiting config
        match config.rate_limiting.backend.as_str() {
            "memory" => {}
            "redis" => {
                if config.rate_limiting.redis_url.is_none() {
                    return Err(Error::Config(
                        "rate_limiting.redis_url is required when backend is \"redis\"".to_string(),
                    ));
                }
            }
            other => {
                return Err(Error::Config(format!(
                    "unknown rate_limiting.backend: \"{other}\" (expected \"memory\" or \"redis\")"
                )));
            }
        }
        // Validate rate limit tiers
        for (name, tier) in [
            ("auth", &config.rate_limiting.tiers.auth),
            ("standard", &config.rate_limiting.tiers.standard),
            ("public", &config.rate_limiting.tiers.public),
        ] {
            if tier.requests == 0 {
                return Err(Error::Config(format!(
                    "rate_limiting.tiers.{name}.requests must be at least 1"
                )));
            }
            if tier.window_secs == 0 {
                return Err(Error::Config(format!(
                    "rate_limiting.tiers.{name}.window_secs must be at least 1"
                )));
            }
        }
        Ok(config)
    }
}

/// Resolve config file location using the standard search order:
/// 1. Explicit path (CLI flag)
/// 2. RILEY_AUTH_CONFIG env var
/// 3. Current directory
/// 4. Walk up parent directories
/// 5. ~/.config/riley_auth/config.toml
/// 6. /etc/riley_auth/config.toml
pub fn resolve_config(explicit_path: Option<&Path>) -> Result<Config> {
    let mut searched = Vec::new();

    // 1. Explicit path — fail immediately if specified but missing
    if let Some(path) = explicit_path {
        if path.exists() {
            return Config::from_path(path);
        }
        return Err(Error::Config(format!(
            "config file not found: {}",
            path.display()
        )));
    }

    // 2. Environment variable
    if let Ok(env_path) = std::env::var(CONFIG_ENV_VAR) {
        let path = PathBuf::from(&env_path);
        if path.exists() {
            return Config::from_path(&path);
        }
        searched.push(path);
    }

    // 3 & 4. Current directory and walk up
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = Some(cwd.as_path());
        while let Some(d) = dir {
            let config_path = d.join(CONFIG_FILENAME);
            if config_path.exists() {
                return Config::from_path(&config_path);
            }
            searched.push(config_path);
            dir = d.parent();
        }
    }

    // 5. User config
    if let Some(config_dir) = dirs::config_dir() {
        let user_config = config_dir.join("riley_auth").join("config.toml");
        if user_config.exists() {
            return Config::from_path(&user_config);
        }
        searched.push(user_config);
    }

    // 6. System config
    let system_config = PathBuf::from("/etc/riley_auth/config.toml");
    if system_config.exists() {
        return Config::from_path(&system_config);
    }
    searched.push(system_config);

    Err(Error::ConfigNotFound { searched })
}

// --- Defaults ---

impl Default for UsernameConfig {
    fn default() -> Self {
        Self {
            min_length: default_min_length(),
            max_length: default_max_length(),
            pattern: default_pattern(),
            allow_changes: true,
            change_cooldown_days: default_change_cooldown(),
            old_name_hold_days: default_hold_days(),
            reserved: Vec::new(),
        }
    }
}

fn default_host() -> String { "0.0.0.0".to_string() }
fn default_port() -> u16 { 8081 }
fn default_max_connections() -> u32 { 10 }
fn default_access_ttl() -> u64 { 900 }        // 15 minutes
fn default_refresh_ttl() -> u64 { 2_592_000 } // 30 days
fn default_issuer() -> String { "riley-auth".to_string() }
fn default_authz_code_ttl() -> u64 { 300 }    // 5 minutes
fn default_storage_backend() -> String { "s3".to_string() }
fn default_region() -> String { "auto".to_string() }
fn default_max_avatar_size() -> u64 { 2_097_152 } // 2MB
fn default_min_length() -> usize { 3 }
fn default_max_length() -> usize { 24 }
fn default_pattern() -> String { r"^[a-zA-Z][a-zA-Z0-9_-]*$".to_string() }
fn default_true() -> bool { true }
fn default_change_cooldown() -> u32 { 30 }
fn default_hold_days() -> u32 { 90 }
fn default_rate_limit_backend() -> String { "memory".to_string() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[server]
public_url = "https://example.com"

[database]
url = "postgres://localhost/test"

[jwt]
private_key_path = "/tmp/private.pem"
public_key_path = "/tmp/public.pem"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.server.port, 8081);
        assert_eq!(config.server.cookie_prefix, "riley_auth");
        assert_eq!(config.jwt.access_token_ttl_secs, 900);
        assert_eq!(config.usernames.min_length, 3);
        assert!(config.oauth.google.is_none());
        assert_eq!(config.rate_limiting.backend, "memory");
        assert!(config.rate_limiting.redis_url.is_none());
        // Tier defaults
        assert_eq!(config.rate_limiting.tiers.auth.requests, 15);
        assert_eq!(config.rate_limiting.tiers.auth.window_secs, 60);
        assert_eq!(config.rate_limiting.tiers.standard.requests, 60);
        assert_eq!(config.rate_limiting.tiers.public.requests, 300);
        // Maintenance defaults
        assert_eq!(config.maintenance.cleanup_interval_secs, 3600);
        assert_eq!(config.maintenance.webhook_delivery_retention_days, 7);
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[server]
host = "127.0.0.1"
port = 9000
cors_origins = ["https://example.com"]
cookie_domain = ".example.com"
public_url = "https://example.com"

[database]
url = "postgres://localhost/test"
max_connections = 20

[jwt]
private_key_path = "/tmp/private.pem"
public_key_path = "/tmp/public.pem"
access_token_ttl_secs = 600
refresh_token_ttl_secs = 86400
issuer = "my-auth"

[oauth.google]
client_id = "google-id"
client_secret = "env:GOOGLE_SECRET"

[oauth.github]
client_id = "github-id"
client_secret = "github-secret"

[storage]
bucket = "avatars"
endpoint = "https://s3.example.com"
public_url_base = "https://cdn.example.com"

[usernames]
min_length = 4
max_length = 20
reserved = ["admin", "root"]

[[scopes.definitions]]
name = "read:profile"
description = "Read your profile information"

[[scopes.definitions]]
name = "write:profile"
description = "Update your profile information"

[rate_limiting]
backend = "redis"
redis_url = "redis://localhost:6379"

[rate_limiting.tiers]
auth = { requests = 10, window_secs = 30 }
standard = { requests = 100, window_secs = 120 }
public = { requests = 500, window_secs = 60 }
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.server.port, 9000);
        assert_eq!(config.database.max_connections, 20);
        assert!(config.oauth.google.is_some());
        assert!(config.storage.is_some());
        assert_eq!(config.usernames.reserved.len(), 2);
        assert_eq!(config.scopes.definitions.len(), 2);
        assert_eq!(config.scopes.definitions[0].name, "read:profile");
        assert_eq!(config.scopes.definitions[1].description, "Update your profile information");
        assert_eq!(config.rate_limiting.backend, "redis");
        assert_eq!(
            config.rate_limiting.redis_url.as_ref().unwrap().resolve().unwrap(),
            "redis://localhost:6379"
        );
        // Custom tiers
        assert_eq!(config.rate_limiting.tiers.auth.requests, 10);
        assert_eq!(config.rate_limiting.tiers.auth.window_secs, 30);
        assert_eq!(config.rate_limiting.tiers.standard.requests, 100);
        assert_eq!(config.rate_limiting.tiers.standard.window_secs, 120);
        assert_eq!(config.rate_limiting.tiers.public.requests, 500);
    }

    #[test]
    fn config_value_literal() {
        let val = ConfigValue::Literal("hello".to_string());
        assert_eq!(val.resolve().unwrap(), "hello");
    }

    #[test]
    fn config_value_env() {
        // SAFETY: test-only, single-threaded
        unsafe { std::env::set_var("RILEY_AUTH_TEST_VAR", "secret123") };
        let val = ConfigValue::Literal("env:RILEY_AUTH_TEST_VAR".to_string());
        assert_eq!(val.resolve().unwrap(), "secret123");
        unsafe { std::env::remove_var("RILEY_AUTH_TEST_VAR") };
    }

    #[test]
    fn config_value_env_missing() {
        let val = ConfigValue::Literal("env:NONEXISTENT_VAR_12345".to_string());
        assert!(val.resolve().is_err());
    }

    #[test]
    fn scope_name_validation() {
        // Valid scope names
        assert!(validate_scope_name("read:profile").is_ok());
        assert!(validate_scope_name("write:profile").is_ok());
        assert!(validate_scope_name("admin:users.list").is_ok());
        assert!(validate_scope_name("openid").is_ok());
        assert!(validate_scope_name("a").is_ok());
        assert!(validate_scope_name("scope-with-dash").is_ok());
        assert!(validate_scope_name("scope_with_underscore").is_ok());

        // Invalid scope names
        assert!(validate_scope_name("").is_err()); // empty
        assert!(validate_scope_name("Read:Profile").is_err()); // uppercase
        assert!(validate_scope_name("1scope").is_err()); // starts with digit
        assert!(validate_scope_name("scope with space").is_err()); // whitespace
        assert!(validate_scope_name("scope\nnewline").is_err()); // newline
        assert!(validate_scope_name(":leading-colon").is_err()); // starts with colon
    }
}
