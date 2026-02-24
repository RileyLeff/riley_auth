use std::sync::LazyLock;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::OAuthProviderConfig;
use crate::error::{Error, Result};

/// Shared HTTP client for OAuth provider communication.
/// Separate from the webhook client which has SSRF protection and disabled redirects.
static OAUTH_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .user_agent("riley-auth")
        .build()
        .expect("failed to build OAuth HTTP client")
});

/// Supported OAuth providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Google,
    GitHub,
}

impl Provider {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "google" => Some(Self::Google),
            "github" => Some(Self::GitHub),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::GitHub => "github",
        }
    }

    fn auth_url(&self) -> &'static str {
        match self {
            Self::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            Self::GitHub => "https://github.com/login/oauth/authorize",
        }
    }

    fn token_url(&self) -> &'static str {
        match self {
            Self::Google => "https://oauth2.googleapis.com/token",
            Self::GitHub => "https://github.com/login/oauth/access_token",
        }
    }

    fn userinfo_url(&self) -> &'static str {
        match self {
            Self::Google => "https://www.googleapis.com/oauth2/v2/userinfo",
            Self::GitHub => "https://api.github.com/user",
        }
    }

    fn scopes(&self) -> &'static str {
        match self {
            Self::Google => "openid email profile",
            Self::GitHub => "read:user user:email",
        }
    }
}

/// Profile data from an OAuth provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProfile {
    pub provider: String,
    pub provider_id: String,
    pub email: Option<String>,
    /// Whether the provider verified the email address.
    #[serde(default)]
    pub email_verified: bool,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

/// Generate a random state parameter.
pub fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate PKCE code verifier and challenge.
pub fn generate_pkce() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = {
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    };
    (verifier, challenge)
}

/// Build the authorization redirect URL for a provider.
pub fn build_auth_url(
    provider: Provider,
    config: &OAuthProviderConfig,
    callback_url: &str,
    state: &str,
    code_challenge: &str,
) -> Result<String> {
    let client_id = config.client_id.resolve()?;

    let mut url = url::Url::parse(provider.auth_url())
        .map_err(|e| Error::OAuth(format!("invalid auth URL: {e}")))?;

    {
        let mut params = url.query_pairs_mut();
        params.append_pair("client_id", &client_id);
        params.append_pair("redirect_uri", callback_url);
        params.append_pair("response_type", "code");
        params.append_pair("state", state);
        params.append_pair("scope", provider.scopes());
        params.append_pair("code_challenge", code_challenge);
        params.append_pair("code_challenge_method", "S256");

        if provider == Provider::Google {
            params.append_pair("access_type", "offline");
        }
    }

    Ok(url.to_string())
}

/// Exchange an authorization code for an access token.
pub async fn exchange_code(
    provider: Provider,
    config: &OAuthProviderConfig,
    code: &str,
    callback_url: &str,
    pkce_verifier: &str,
) -> Result<String> {
    let client_id = config.client_id.resolve()?;
    let client_secret = config.client_secret.resolve()?;

    let client = &*OAUTH_CLIENT;

    let mut params = vec![
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("code", code),
        ("redirect_uri", callback_url),
        ("code_verifier", pkce_verifier),
    ];

    if provider == Provider::Google {
        params.push(("grant_type", "authorization_code"));
    }

    let mut request = client.post(provider.token_url()).form(&params);

    if provider == Provider::GitHub {
        request = request.header("Accept", "application/json");
    }

    let response = request.send().await.map_err(|e| Error::OAuth(e.to_string()))?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.map_err(|e| Error::OAuth(e.to_string()))?;

    if !status.is_success() {
        let err_desc = body["error_description"]
            .as_str()
            .or_else(|| body["error"].as_str())
            .unwrap_or("token exchange failed");
        return Err(Error::OAuth(err_desc.to_string()));
    }

    body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Error::OAuth("no access_token in response".to_string()))
}

/// Fetch the user's profile from the provider using an access token.
pub async fn fetch_profile(
    provider: Provider,
    access_token: &str,
) -> Result<OAuthProfile> {
    let client = &*OAUTH_CLIENT;

    let response = client.get(provider.userinfo_url())
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .map_err(|e| Error::OAuth(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::OAuth("failed to fetch user profile".to_string()));
    }

    let body: serde_json::Value = response.json().await.map_err(|e| Error::OAuth(e.to_string()))?;

    let profile = match provider {
        Provider::Google => parse_google_profile(&body),
        Provider::GitHub => parse_github_profile(&body, access_token).await,
    }?;

    Ok(profile)
}

fn parse_google_profile(body: &serde_json::Value) -> Result<OAuthProfile> {
    let provider_id = body["id"]
        .as_str()
        .ok_or_else(|| Error::OAuth("missing id in Google profile".to_string()))?;

    Ok(OAuthProfile {
        provider: "google".to_string(),
        provider_id: provider_id.to_string(),
        email: body["email"].as_str().map(|s| s.to_string()),
        email_verified: body["verified_email"].as_bool().unwrap_or(false),
        name: body["name"].as_str().map(|s| s.to_string()),
        avatar_url: body["picture"].as_str().map(|s| s.to_string()),
    })
}

async fn parse_github_profile(
    body: &serde_json::Value,
    access_token: &str,
) -> Result<OAuthProfile> {
    let provider_id = body["id"]
        .as_u64()
        .ok_or_else(|| Error::OAuth("missing id in GitHub profile".to_string()))?;

    let (email, email_verified) = if let Some(email) = body["email"].as_str() {
        // GitHub user API includes email but not verification status.
        // Fall through to emails API to get verified status.
        let verified = fetch_github_email_verified(access_token, email).await.unwrap_or(false);
        (Some(email.to_string()), verified)
    } else {
        match fetch_github_primary_email(access_token).await {
            Ok((email, verified)) => (Some(email), verified),
            Err(_) => (None, false),
        }
    };

    Ok(OAuthProfile {
        provider: "github".to_string(),
        provider_id: provider_id.to_string(),
        email,
        email_verified,
        name: body["name"].as_str().or(body["login"].as_str()).map(|s| s.to_string()),
        avatar_url: body["avatar_url"].as_str().map(|s| s.to_string()),
    })
}

/// Fetch the primary email and its verification status from GitHub's emails API.
async fn fetch_github_primary_email(access_token: &str) -> Result<(String, bool)> {
    let emails = fetch_github_emails(access_token).await?;

    for email_entry in &emails {
        if email_entry["primary"].as_bool() == Some(true) {
            if let Some(email) = email_entry["email"].as_str() {
                let verified = email_entry["verified"].as_bool().unwrap_or(false);
                return Ok((email.to_string(), verified));
            }
        }
    }

    Err(Error::OAuth("no primary email found".to_string()))
}

/// Check whether a specific email is verified according to GitHub's emails API.
async fn fetch_github_email_verified(access_token: &str, target_email: &str) -> Result<bool> {
    let emails = fetch_github_emails(access_token).await?;

    for email_entry in &emails {
        if email_entry["email"].as_str() == Some(target_email) {
            return Ok(email_entry["verified"].as_bool().unwrap_or(false));
        }
    }

    Ok(false)
}

async fn fetch_github_emails(access_token: &str) -> Result<Vec<serde_json::Value>> {
    let response = OAUTH_CLIENT
        .get("https://api.github.com/user/emails")
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .map_err(|e| Error::OAuth(e.to_string()))?;

    response.json().await.map_err(|e| Error::OAuth(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_from_str() {
        assert_eq!(Provider::from_str("google"), Some(Provider::Google));
        assert_eq!(Provider::from_str("github"), Some(Provider::GitHub));
        assert_eq!(Provider::from_str("twitter"), None);
    }

    #[test]
    fn pkce_generation() {
        let (verifier, challenge) = generate_pkce();
        assert!(!verifier.is_empty());
        assert!(!challenge.is_empty());

        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let expected_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(challenge, expected_challenge);
    }

    #[test]
    fn state_uniqueness() {
        let s1 = generate_state();
        let s2 = generate_state();
        assert_ne!(s1, s2);
        assert_eq!(s1.len(), 43); // 32 bytes base64url
    }

    #[test]
    fn build_google_auth_url() {
        let config = OAuthProviderConfig {
            client_id: crate::config::ConfigValue::Literal("test-client-id".to_string()),
            client_secret: crate::config::ConfigValue::Literal("test-secret".to_string()),
        };

        let url = build_auth_url(
            Provider::Google,
            &config,
            "https://example.com/callback",
            "test-state",
            "test-challenge",
        )
        .unwrap();

        assert!(url.contains("accounts.google.com"));
        assert!(url.contains("client_id=test-client-id"));
        assert!(url.contains("state=test-state"));
        assert!(url.contains("code_challenge=test-challenge"));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn build_github_auth_url() {
        let config = OAuthProviderConfig {
            client_id: crate::config::ConfigValue::Literal("gh-client-id".to_string()),
            client_secret: crate::config::ConfigValue::Literal("gh-secret".to_string()),
        };

        let url = build_auth_url(
            Provider::GitHub,
            &config,
            "https://example.com/callback",
            "test-state",
            "test-challenge",
        )
        .unwrap();

        assert!(url.contains("github.com/login/oauth/authorize"));
        assert!(url.contains("client_id=gh-client-id"));
    }
}
