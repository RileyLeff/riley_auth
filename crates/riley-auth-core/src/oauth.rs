use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{ProfileMapping, ProviderEntry};
use crate::error::{Error, Result};

/// A fully resolved provider with all endpoints and configuration ready for use.
#[derive(Debug, Clone)]
pub struct ResolvedProvider {
    pub name: String,
    pub display_name: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: String,
    pub client_id: String,
    pub client_secret: String,
    pub profile_mapping: ProfileMapping,
    /// Extra query parameters for the auth URL (e.g., Google: access_type=offline).
    pub extra_auth_params: Vec<(String, String)>,
    /// Whether to send Accept: application/json on the token request (e.g., GitHub).
    pub token_request_accept_json: bool,
    /// Optional secondary email endpoint (e.g., GitHub: /user/emails).
    pub extra_email_endpoint: Option<String>,
    /// Whether to always send grant_type on the token request.
    pub send_grant_type: bool,
}

/// Built-in Google preset.
fn google_preset() -> PresetConfig {
    PresetConfig {
        auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
        token_url: "https://oauth2.googleapis.com/token".to_string(),
        userinfo_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
        scopes: "openid email profile".to_string(),
        profile_mapping: ProfileMapping {
            provider_id: "id".to_string(),
            email: Some("email".to_string()),
            email_verified: Some("verified_email".to_string()),
            name: Some("name".to_string()),
            avatar_url: Some("picture".to_string()),
        },
        extra_auth_params: vec![("access_type".to_string(), "offline".to_string())],
        token_request_accept_json: false,
        extra_email_endpoint: None,
        send_grant_type: true,
    }
}

/// Built-in GitHub preset.
fn github_preset() -> PresetConfig {
    PresetConfig {
        auth_url: "https://github.com/login/oauth/authorize".to_string(),
        token_url: "https://github.com/login/oauth/access_token".to_string(),
        userinfo_url: "https://api.github.com/user".to_string(),
        scopes: "read:user user:email".to_string(),
        profile_mapping: ProfileMapping {
            provider_id: "id".to_string(),
            email: Some("email".to_string()),
            email_verified: None, // GitHub email verification comes from separate endpoint
            name: Some("name".to_string()),
            avatar_url: Some("avatar_url".to_string()),
        },
        extra_auth_params: vec![],
        token_request_accept_json: true,
        extra_email_endpoint: Some("https://api.github.com/user/emails".to_string()),
        send_grant_type: false,
    }
}

struct PresetConfig {
    auth_url: String,
    token_url: String,
    userinfo_url: String,
    scopes: String,
    profile_mapping: ProfileMapping,
    extra_auth_params: Vec<(String, String)>,
    token_request_accept_json: bool,
    extra_email_endpoint: Option<String>,
    send_grant_type: bool,
}

/// Standard OIDC profile mapping using standard claims.
fn oidc_profile_mapping() -> ProfileMapping {
    ProfileMapping {
        provider_id: "sub".to_string(),
        email: Some("email".to_string()),
        email_verified: Some("email_verified".to_string()),
        name: Some("name".to_string()),
        avatar_url: Some("picture".to_string()),
    }
}

/// OIDC discovery document fields we care about.
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
}

/// Resolve all provider entries into ready-to-use providers.
/// OIDC discovery is performed for providers with an `issuer` URL.
pub async fn resolve_providers(
    entries: &[ProviderEntry],
    http: &reqwest::Client,
) -> Result<Vec<ResolvedProvider>> {
    let mut resolved = Vec::with_capacity(entries.len());

    for entry in entries {
        let client_id = entry.client_id.resolve()?;
        let client_secret = entry.client_secret.resolve()?;
        let display_name = entry
            .display_name
            .clone()
            .unwrap_or_else(|| capitalize(&entry.name));

        // Determine tier
        let is_preset = matches!(entry.name.as_str(), "google" | "github")
            && entry.issuer.is_none()
            && entry.auth_url.is_none();

        if is_preset {
            let preset = match entry.name.as_str() {
                "google" => google_preset(),
                "github" => github_preset(),
                _ => unreachable!(),
            };
            resolved.push(ResolvedProvider {
                name: entry.name.clone(),
                display_name,
                auth_url: preset.auth_url,
                token_url: preset.token_url,
                userinfo_url: preset.userinfo_url,
                scopes: entry.scopes.clone().unwrap_or(preset.scopes),
                client_id,
                client_secret,
                profile_mapping: entry.profile_mapping.clone().unwrap_or(preset.profile_mapping),
                extra_auth_params: preset.extra_auth_params,
                token_request_accept_json: preset.token_request_accept_json,
                extra_email_endpoint: preset.extra_email_endpoint,
                send_grant_type: preset.send_grant_type,
            });
        } else if let Some(issuer) = &entry.issuer {
            // OIDC auto-discovery
            let discovered = discover_oidc(issuer, http).await.map_err(|e| {
                Error::Config(format!(
                    "provider '{}': OIDC discovery for {} failed: {e}",
                    entry.name, issuer
                ))
            })?;
            let userinfo_url = entry.userinfo_url.clone().or(discovered.userinfo_endpoint);
            if userinfo_url.is_none() {
                return Err(Error::Config(format!(
                    "provider '{}': OIDC discovery did not return a userinfo_endpoint and none was configured",
                    entry.name
                )));
            }
            resolved.push(ResolvedProvider {
                name: entry.name.clone(),
                display_name,
                auth_url: entry.auth_url.clone().unwrap_or(discovered.authorization_endpoint),
                token_url: entry.token_url.clone().unwrap_or(discovered.token_endpoint),
                userinfo_url: userinfo_url.unwrap(),
                scopes: entry.scopes.clone().unwrap_or_else(|| "openid email profile".to_string()),
                client_id,
                client_secret,
                profile_mapping: entry.profile_mapping.clone().unwrap_or_else(oidc_profile_mapping),
                extra_auth_params: vec![],
                token_request_accept_json: false,
                extra_email_endpoint: None,
                send_grant_type: true,
            });
        } else {
            // Manual OAuth2
            let mapping = entry.profile_mapping.clone().ok_or_else(|| {
                Error::Config(format!(
                    "provider '{}': manual OAuth2 requires profile_mapping",
                    entry.name
                ))
            })?;
            resolved.push(ResolvedProvider {
                name: entry.name.clone(),
                display_name,
                auth_url: entry.auth_url.clone().unwrap(),
                token_url: entry.token_url.clone().unwrap(),
                userinfo_url: entry.userinfo_url.clone().unwrap(),
                scopes: entry.scopes.clone().unwrap_or_default(),
                client_id,
                client_secret,
                profile_mapping: mapping,
                extra_auth_params: vec![],
                token_request_accept_json: false,
                extra_email_endpoint: None,
                send_grant_type: true,
            });
        }
    }

    Ok(resolved)
}

/// Fetch OIDC discovery document from `{issuer}/.well-known/openid-configuration`.
async fn discover_oidc(issuer: &str, http: &reqwest::Client) -> Result<OidcDiscovery> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::OAuth(format!("discovery fetch failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(Error::OAuth(format!(
            "discovery returned HTTP {}",
            resp.status()
        )));
    }

    resp.json()
        .await
        .map_err(|e| Error::OAuth(format!("discovery parse failed: {e}")))
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
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
    provider: &ResolvedProvider,
    callback_url: &str,
    state: &str,
    code_challenge: &str,
) -> Result<String> {
    let mut url = url::Url::parse(&provider.auth_url)
        .map_err(|e| Error::OAuth(format!("invalid auth URL: {e}")))?;

    {
        let mut params = url.query_pairs_mut();
        params.append_pair("client_id", &provider.client_id);
        params.append_pair("redirect_uri", callback_url);
        params.append_pair("response_type", "code");
        params.append_pair("state", state);
        params.append_pair("scope", &provider.scopes);
        params.append_pair("code_challenge", code_challenge);
        params.append_pair("code_challenge_method", "S256");

        for (key, value) in &provider.extra_auth_params {
            params.append_pair(key, value);
        }
    }

    Ok(url.to_string())
}

/// Exchange an authorization code for an access token.
pub async fn exchange_code(
    provider: &ResolvedProvider,
    code: &str,
    callback_url: &str,
    pkce_verifier: &str,
    client: &reqwest::Client,
) -> Result<String> {
    let mut params = vec![
        ("client_id", provider.client_id.as_str()),
        ("client_secret", provider.client_secret.as_str()),
        ("code", code),
        ("redirect_uri", callback_url),
        ("code_verifier", pkce_verifier),
    ];

    if provider.send_grant_type {
        params.push(("grant_type", "authorization_code"));
    }

    let mut request = client.post(&provider.token_url).form(&params);

    if provider.token_request_accept_json {
        request = request.header("Accept", "application/json");
    }

    let response = request
        .send()
        .await
        .map_err(|e| Error::OAuth(e.to_string()))?;
    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| Error::OAuth(e.to_string()))?;

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
    provider: &ResolvedProvider,
    access_token: &str,
    client: &reqwest::Client,
) -> Result<OAuthProfile> {
    let response = client
        .get(&provider.userinfo_url)
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .map_err(|e| Error::OAuth(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::OAuth("failed to fetch user profile".to_string()));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| Error::OAuth(e.to_string()))?;

    let mut profile = parse_profile(&body, &provider.profile_mapping)?;
    profile.provider = provider.name.clone();

    // Handle secondary email endpoint (e.g., GitHub's /user/emails)
    if let Some(email_url) = &provider.extra_email_endpoint {
        match fetch_email_from_secondary_endpoint(&client, email_url, access_token).await {
            Ok((email, verified)) => {
                if profile.email.is_none() {
                    profile.email = Some(email);
                    profile.email_verified = verified;
                } else {
                    // We have an email from the main profile; update verification status
                    // from the emails endpoint which is more authoritative
                    let main_email = profile.email.as_ref().unwrap();
                    if let Ok(v) =
                        check_email_verified(&client, email_url, access_token, main_email).await
                    {
                        profile.email_verified = v;
                    }
                }
            }
            Err(_) => {
                // Email endpoint failed; keep whatever we got from the main profile
            }
        }
    }

    Ok(profile)
}

/// Parse a profile response using the configured field mapping.
fn parse_profile(body: &serde_json::Value, mapping: &ProfileMapping) -> Result<OAuthProfile> {
    let provider_id = body[&mapping.provider_id]
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| body[&mapping.provider_id].as_u64().map(|n| n.to_string()))
        .or_else(|| body[&mapping.provider_id].as_i64().map(|n| n.to_string()))
        .ok_or_else(|| Error::OAuth("missing provider user ID in profile".to_string()))?;

    let email = mapping
        .email
        .as_ref()
        .and_then(|f| body[f].as_str().map(String::from));

    let email_verified = mapping
        .email_verified
        .as_ref()
        .and_then(|f| body[f].as_bool())
        .unwrap_or(false);

    let name = mapping
        .name
        .as_ref()
        .and_then(|f| body[f].as_str().map(String::from));

    let avatar_url = mapping
        .avatar_url
        .as_deref()
        .filter(|f| !f.is_empty())
        .and_then(|f| body[f].as_str().map(String::from));

    Ok(OAuthProfile {
        provider: String::new(), // Set by caller
        provider_id,
        email,
        email_verified,
        name,
        avatar_url,
    })
}

/// Fetch primary email from a secondary endpoint (e.g., GitHub's /user/emails).
async fn fetch_email_from_secondary_endpoint(
    client: &reqwest::Client,
    url: &str,
    access_token: &str,
) -> Result<(String, bool)> {
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .map_err(|e| Error::OAuth(e.to_string()))?;

    let emails: Vec<serde_json::Value> = response
        .json()
        .await
        .map_err(|e| Error::OAuth(e.to_string()))?;

    for entry in &emails {
        if entry["primary"].as_bool() == Some(true) {
            if let Some(email) = entry["email"].as_str() {
                let verified = entry["verified"].as_bool().unwrap_or(false);
                return Ok((email.to_string(), verified));
            }
        }
    }

    Err(Error::OAuth("no primary email found".to_string()))
}

/// Check whether a specific email is verified at the secondary email endpoint.
async fn check_email_verified(
    client: &reqwest::Client,
    url: &str,
    access_token: &str,
    target_email: &str,
) -> Result<bool> {
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .map_err(|e| Error::OAuth(e.to_string()))?;

    let emails: Vec<serde_json::Value> = response
        .json()
        .await
        .map_err(|e| Error::OAuth(e.to_string()))?;

    for entry in &emails {
        if entry["email"].as_str() == Some(target_email) {
            return Ok(entry["verified"].as_bool().unwrap_or(false));
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let provider = ResolvedProvider {
            name: "google".to_string(),
            display_name: "Google".to_string(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            scopes: "openid email profile".to_string(),
            client_id: "test-client-id".to_string(),
            client_secret: "test-secret".to_string(),
            profile_mapping: oidc_profile_mapping(),
            extra_auth_params: vec![("access_type".to_string(), "offline".to_string())],
            token_request_accept_json: false,
            extra_email_endpoint: None,
            send_grant_type: true,
        };

        let url = build_auth_url(
            &provider,
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
        assert!(url.contains("access_type=offline"));
    }

    #[test]
    fn build_github_auth_url() {
        let provider = ResolvedProvider {
            name: "github".to_string(),
            display_name: "GitHub".to_string(),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            userinfo_url: "https://api.github.com/user".to_string(),
            scopes: "read:user user:email".to_string(),
            client_id: "gh-client-id".to_string(),
            client_secret: "gh-secret".to_string(),
            profile_mapping: ProfileMapping {
                provider_id: "id".to_string(),
                email: Some("email".to_string()),
                email_verified: None,
                name: Some("name".to_string()),
                avatar_url: Some("avatar_url".to_string()),
            },
            extra_auth_params: vec![],
            token_request_accept_json: true,
            extra_email_endpoint: Some("https://api.github.com/user/emails".to_string()),
            send_grant_type: false,
        };

        let url = build_auth_url(
            &provider,
            "https://example.com/callback",
            "test-state",
            "test-challenge",
        )
        .unwrap();

        assert!(url.contains("github.com/login/oauth/authorize"));
        assert!(url.contains("client_id=gh-client-id"));
        assert!(!url.contains("access_type")); // GitHub doesn't use this
    }

    #[test]
    fn parse_google_profile_test() {
        let body = serde_json::json!({
            "id": "12345",
            "email": "user@gmail.com",
            "verified_email": true,
            "name": "Test User",
            "picture": "https://lh3.googleusercontent.com/photo.jpg"
        });

        let mapping = ProfileMapping {
            provider_id: "id".to_string(),
            email: Some("email".to_string()),
            email_verified: Some("verified_email".to_string()),
            name: Some("name".to_string()),
            avatar_url: Some("picture".to_string()),
        };

        let profile = parse_profile(&body, &mapping).unwrap();
        assert_eq!(profile.provider_id, "12345");
        assert_eq!(profile.email.as_deref(), Some("user@gmail.com"));
        assert!(profile.email_verified);
        assert_eq!(profile.name.as_deref(), Some("Test User"));
        assert!(profile.avatar_url.is_some());
    }

    #[test]
    fn parse_github_profile_test() {
        let body = serde_json::json!({
            "id": 67890,
            "login": "testuser",
            "name": "Test User",
            "email": "user@github.com",
            "avatar_url": "https://avatars.githubusercontent.com/u/67890"
        });

        let mapping = ProfileMapping {
            provider_id: "id".to_string(),
            email: Some("email".to_string()),
            email_verified: None,
            name: Some("name".to_string()),
            avatar_url: Some("avatar_url".to_string()),
        };

        let profile = parse_profile(&body, &mapping).unwrap();
        assert_eq!(profile.provider_id, "67890"); // numeric ID converted to string
        assert_eq!(profile.email.as_deref(), Some("user@github.com"));
        assert!(!profile.email_verified); // No email_verified field in mapping
        assert_eq!(profile.name.as_deref(), Some("Test User"));
    }

    #[test]
    fn parse_profile_missing_id_fails() {
        let body = serde_json::json!({
            "email": "user@example.com"
        });

        let mapping = ProfileMapping {
            provider_id: "id".to_string(),
            email: Some("email".to_string()),
            email_verified: None,
            name: None,
            avatar_url: None,
        };

        assert!(parse_profile(&body, &mapping).is_err());
    }

    #[test]
    fn parse_profile_empty_avatar_field() {
        let body = serde_json::json!({
            "sub": "user-123",
            "avatar": "https://example.com/photo.jpg"
        });

        // Empty string avatar_url means "not available"
        let mapping = ProfileMapping {
            provider_id: "sub".to_string(),
            email: None,
            email_verified: None,
            name: None,
            avatar_url: Some("".to_string()),
        };

        let profile = parse_profile(&body, &mapping).unwrap();
        assert!(profile.avatar_url.is_none());
    }

    #[test]
    fn capitalize_test() {
        assert_eq!(capitalize("google"), "Google");
        assert_eq!(capitalize("github"), "Github");
        assert_eq!(capitalize("corporate-sso"), "Corporate-sso");
        assert_eq!(capitalize(""), "");
    }
}
