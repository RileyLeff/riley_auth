use std::collections::HashMap;
use std::path::Path;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
    decode, encode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{JwtConfig, KeyConfig, SigningAlgorithm};
use crate::error::{Error, Result};

/// JWT claims for access tokens.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: String,
    pub aud: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// OIDC ID Token claims (per OpenID Connect Core 1.0 Section 2).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub preferred_username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

/// OIDC Back-Channel Logout Token claims (per OpenID Connect Back-Channel
/// Logout 1.0 Section 2.4).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogoutTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub events: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

/// JWKS parameters for a single key, varies by algorithm.
#[derive(Clone)]
enum JwksParams {
    Rsa {
        /// Base64url-encoded modulus
        n: String,
        /// Base64url-encoded exponent
        e: String,
    },
    Ec {
        /// P-256 curve name
        crv: &'static str,
        /// Base64url-encoded x coordinate
        x: String,
        /// Base64url-encoded y coordinate
        y: String,
    },
}

/// A single loaded signing/verification key.
#[derive(Clone)]
struct KeyEntry {
    algorithm: Algorithm,
    encoding: EncodingKey,
    decoding: DecodingKey,
    kid: String,
    jwks_params: JwksParams,
}

/// Multi-key key set supporting rotation and algorithm agility.
/// The first key is the active signing key. All keys are available for verification.
#[derive(Clone)]
pub struct KeySet {
    entries: Vec<KeyEntry>,
    kid_index: HashMap<String, usize>,
}

/// Backward-compatible type alias.
pub type Keys = KeySet;

impl KeySet {
    /// Load keys from a list of key configs.
    pub fn from_configs(configs: &[KeyConfig]) -> Result<Self> {
        if configs.is_empty() {
            return Err(Error::Config("at least one signing key is required".to_string()));
        }

        let mut entries = Vec::with_capacity(configs.len());
        let mut kid_index = HashMap::new();

        for (i, kc) in configs.iter().enumerate() {
            let private_pem = std::fs::read(&kc.private_key_path).map_err(|e| {
                Error::Config(format!("cannot read private key {}: {e}", kc.private_key_path.display()))
            })?;
            let public_pem = std::fs::read(&kc.public_key_path).map_err(|e| {
                Error::Config(format!("cannot read public key {}: {e}", kc.public_key_path.display()))
            })?;

            let kid = kc.kid.clone().unwrap_or_else(|| compute_kid(&public_pem));

            let (algorithm, encoding, decoding, jwks_params) = match kc.algorithm {
                SigningAlgorithm::RS256 => {
                    let enc = EncodingKey::from_rsa_pem(&private_pem)
                        .map_err(|e| Error::Config(format!("invalid RSA private key: {e}")))?;
                    let dec = DecodingKey::from_rsa_pem(&public_pem)
                        .map_err(|e| Error::Config(format!("invalid RSA public key: {e}")))?;
                    let (n, e) = extract_rsa_components(&public_pem)?;
                    (Algorithm::RS256, enc, dec, JwksParams::Rsa { n, e })
                }
                SigningAlgorithm::ES256 => {
                    let enc = EncodingKey::from_ec_pem(&private_pem)
                        .map_err(|e| Error::Config(format!("invalid EC private key: {e}")))?;
                    let dec = DecodingKey::from_ec_pem(&public_pem)
                        .map_err(|e| Error::Config(format!("invalid EC public key: {e}")))?;
                    let (x, y) = extract_ec_point(&public_pem)?;
                    (Algorithm::ES256, enc, dec, JwksParams::Ec { crv: "P-256", x, y })
                }
            };

            if kid_index.contains_key(&kid) {
                return Err(Error::Config(format!(
                    "duplicate kid '{}' — each key must have a unique identifier", kid
                )));
            }
            kid_index.insert(kid.clone(), i);
            entries.push(KeyEntry { algorithm, encoding, decoding, kid, jwks_params });
        }

        Ok(Self { entries, kid_index })
    }

    /// Load a single RS256 key from PEM files (backward compat).
    /// Assumes RS256 algorithm. For ES256 keys, use `from_configs` instead.
    pub fn from_pem_files(private_path: &Path, public_path: &Path) -> Result<Self> {
        let config = KeyConfig {
            algorithm: SigningAlgorithm::RS256,
            private_key_path: private_path.to_path_buf(),
            public_key_path: public_path.to_path_buf(),
            kid: None,
        };
        Self::from_configs(&[config])
    }

    /// The active signing key's kid.
    pub fn active_kid(&self) -> &str {
        &self.entries[0].kid
    }

    /// The distinct algorithms configured across all keys.
    pub fn algorithms(&self) -> Vec<String> {
        let mut algs: Vec<String> = self.entries.iter()
            .map(|e| match e.algorithm {
                Algorithm::RS256 => "RS256".to_string(),
                Algorithm::ES256 => "ES256".to_string(),
                _ => format!("{:?}", e.algorithm),
            })
            .collect();
        algs.sort();
        algs.dedup();
        algs
    }

    /// Create a signed access token.
    pub fn sign_access_token(
        &self,
        config: &JwtConfig,
        user_id: &str,
        username: &str,
        role: &str,
        audience: &str,
    ) -> Result<String> {
        self.sign_access_token_with_scopes(config, user_id, username, role, audience, None)
    }

    /// Create a signed access token with optional scope claim.
    pub fn sign_access_token_with_scopes(
        &self,
        config: &JwtConfig,
        user_id: &str,
        username: &str,
        role: &str,
        audience: &str,
        scope: Option<&str>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(config.access_token_ttl_secs as i64);
        let active = &self.entries[0];

        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            role: role.to_string(),
            aud: audience.to_string(),
            iss: config.issuer.clone(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            scope: scope.map(String::from),
        };

        let mut header = Header::new(active.algorithm);
        header.kid = Some(active.kid.clone());

        encode(&header, &claims, &active.encoding)
            .map_err(|e| Error::Config(format!("failed to sign token: {e}")))
    }

    /// Verify and decode an access token.
    pub fn verify_access_token(
        &self,
        config: &JwtConfig,
        token: &str,
    ) -> Result<TokenData<Claims>> {
        self.verify_token(config, token)
    }

    /// Encoding key for the active (first) signing key.
    pub fn encoding_key(&self) -> &EncodingKey {
        &self.entries[0].encoding
    }

    /// The active signing algorithm.
    pub fn active_algorithm(&self) -> Algorithm {
        self.entries[0].algorithm
    }

    /// Create a signed OIDC ID token.
    pub fn sign_id_token(
        &self,
        config: &JwtConfig,
        user_id: &str,
        username: &str,
        display_name: Option<&str>,
        avatar_url: Option<&str>,
        audience: &str,
        nonce: Option<&str>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(config.access_token_ttl_secs as i64);
        let active = &self.entries[0];

        let claims = IdTokenClaims {
            sub: user_id.to_string(),
            iss: config.issuer.clone(),
            aud: audience.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nonce: nonce.map(String::from),
            name: display_name.map(String::from),
            preferred_username: username.to_string(),
            picture: avatar_url.map(String::from),
        };

        let mut header = Header::new(active.algorithm);
        header.kid = Some(active.kid.clone());

        encode(&header, &claims, &active.encoding)
            .map_err(|e| Error::Config(format!("failed to sign id token: {e}")))
    }

    /// Create a signed OIDC Back-Channel Logout Token (per OpenID Connect
    /// Back-Channel Logout 1.0 Section 2.4).
    pub fn sign_logout_token(
        &self,
        config: &JwtConfig,
        user_id: &str,
        audience: &str,
        sid: Option<&str>,
    ) -> Result<String> {
        let now = Utc::now();
        // Logout tokens get a short 2-minute validity window
        let exp = now + Duration::seconds(120);
        let active = &self.entries[0];

        let claims = LogoutTokenClaims {
            iss: config.issuer.clone(),
            sub: user_id.to_string(),
            aud: audience.to_string(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            events: serde_json::json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
            sid: sid.map(String::from),
        };

        let mut header = Header::new(active.algorithm);
        header.kid = Some(active.kid.clone());

        encode(&header, &claims, &active.encoding)
            .map_err(|e| Error::Config(format!("failed to sign logout token: {e}")))
    }

    /// JWKS response body containing all keys.
    pub fn jwks(&self) -> serde_json::Value {
        let keys: Vec<serde_json::Value> = self.entries.iter().map(|entry| {
            match &entry.jwks_params {
                JwksParams::Rsa { n, e } => serde_json::json!({
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": entry.kid,
                    "n": n,
                    "e": e,
                }),
                JwksParams::Ec { crv, x, y } => serde_json::json!({
                    "kty": "EC",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": entry.kid,
                    "crv": crv,
                    "x": x,
                    "y": y,
                }),
            }
        }).collect();

        serde_json::json!({ "keys": keys })
    }

    /// Verify and decode a token, trying kid-matched key first, then all keys.
    /// Generic over the claims type — works with access tokens, setup tokens, etc.
    pub fn verify_token<T: for<'de> Deserialize<'de>>(
        &self,
        config: &JwtConfig,
        token: &str,
    ) -> Result<TokenData<T>> {
        // Try to extract kid from the token header without full verification
        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| Error::InvalidToken)?;

        // If the token has a kid, try that key first
        if let Some(ref kid) = header.kid {
            if let Some(&idx) = self.kid_index.get(kid) {
                let entry = &self.entries[idx];
                let mut validation = Validation::new(entry.algorithm);
                validation.set_issuer(&[&config.issuer]);
                validation.leeway = 0;
                validation.validate_aud = false;

                return decode::<T>(token, &entry.decoding, &validation)
                    .map_err(|_| Error::InvalidToken);
            }
        }

        // Fall back: try all keys
        for entry in &self.entries {
            let mut validation = Validation::new(entry.algorithm);
            validation.set_issuer(&[&config.issuer]);
            validation.leeway = 0;
            validation.validate_aud = false;

            if let Ok(data) = decode::<T>(token, &entry.decoding, &validation) {
                return Ok(data);
            }
        }

        Err(Error::InvalidToken)
    }
}

/// Generate a random refresh token and return (raw_token, sha256_hash).
pub fn generate_refresh_token() -> (String, String) {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let raw = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&raw);
    (raw, hash)
}

/// SHA-256 hash a token string (for storage).
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a keypair and write PEM files.
pub fn generate_keypair(output_dir: &Path) -> Result<()> {
    generate_keypair_with_algorithm(output_dir, SigningAlgorithm::ES256, None)
}

/// Generate a keypair with the specified algorithm and write PEM files.
pub fn generate_keypair_with_algorithm(
    output_dir: &Path,
    algorithm: SigningAlgorithm,
    key_size: Option<u32>,
) -> Result<()> {
    use std::process::Command;

    let private_path = output_dir.join("private.pem");
    let public_path = output_dir.join("public.pem");

    match algorithm {
        SigningAlgorithm::RS256 => {
            let size = key_size.unwrap_or(4096).to_string();
            let status = Command::new("openssl")
                .args(["genrsa", "-out"])
                .arg(&private_path)
                .arg(&size)
                .status()
                .map_err(|e| Error::Config(format!("failed to run openssl: {e}")))?;

            if !status.success() {
                return Err(Error::Config("openssl genrsa failed".to_string()));
            }

            let status = Command::new("openssl")
                .args(["rsa", "-in"])
                .arg(&private_path)
                .args(["-pubout", "-out"])
                .arg(&public_path)
                .status()
                .map_err(|e| Error::Config(format!("failed to run openssl: {e}")))?;

            if !status.success() {
                return Err(Error::Config("openssl rsa -pubout failed".to_string()));
            }

            tracing::info!(
                algorithm = "RS256",
                key_size = %size,
                private = %private_path.display(),
                public = %public_path.display(),
                "generated RS256 keypair"
            );
        }
        SigningAlgorithm::ES256 => {
            if key_size.is_some() {
                tracing::warn!("--key-size is ignored for ES256 (P-256 keys are always 256 bits)");
            }
            // Use genpkey to produce PKCS#8 format (required by jsonwebtoken crate)
            let status = Command::new("openssl")
                .args(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out"])
                .arg(&private_path)
                .status()
                .map_err(|e| Error::Config(format!("failed to run openssl: {e}")))?;

            if !status.success() {
                return Err(Error::Config("openssl genpkey (ES256) failed".to_string()));
            }

            let status = Command::new("openssl")
                .args(["pkey", "-in"])
                .arg(&private_path)
                .args(["-pubout", "-out"])
                .arg(&public_path)
                .status()
                .map_err(|e| Error::Config(format!("failed to run openssl: {e}")))?;

            if !status.success() {
                return Err(Error::Config("openssl pkey -pubout failed".to_string()));
            }

            tracing::info!(
                algorithm = "ES256",
                private = %private_path.display(),
                public = %public_path.display(),
                "generated ES256 keypair"
            );
        }
    }

    Ok(())
}

// --- Internal helpers ---

/// Extract RSA modulus (n) and exponent (e) from a PEM public key.
fn extract_rsa_components(public_pem: &[u8]) -> Result<(String, String)> {
    let pem_str = std::str::from_utf8(public_pem)
        .map_err(|_| Error::Config("public key is not valid UTF-8".to_string()))?;

    // Strip PEM headers and decode base64
    let b64: String = pem_str
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    use base64::engine::general_purpose::STANDARD;
    let der = STANDARD
        .decode(&b64)
        .map_err(|e| Error::Config(format!("invalid PEM base64: {e}")))?;

    // Parse SubjectPublicKeyInfo -> RSAPublicKey
    let (n_bytes, e_bytes) = parse_rsa_public_key_der(&der)
        .ok_or_else(|| Error::Config("failed to parse RSA public key DER".to_string()))?;

    Ok((
        URL_SAFE_NO_PAD.encode(n_bytes),
        URL_SAFE_NO_PAD.encode(e_bytes),
    ))
}

/// Extract EC point (x, y) from a PEM public key for P-256/ES256.
fn extract_ec_point(public_pem: &[u8]) -> Result<(String, String)> {
    let pem_str = std::str::from_utf8(public_pem)
        .map_err(|_| Error::Config("public key is not valid UTF-8".to_string()))?;

    let b64: String = pem_str
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    use base64::engine::general_purpose::STANDARD;
    let der = STANDARD
        .decode(&b64)
        .map_err(|e| Error::Config(format!("invalid PEM base64: {e}")))?;

    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    let (_, inner) = parse_sequence(&der)
        .ok_or_else(|| Error::Config("invalid EC public key DER".to_string()))?;

    // Skip AlgorithmIdentifier
    let (rest, _alg_id) = parse_tlv(inner)
        .ok_or_else(|| Error::Config("invalid EC public key DER: missing algorithm".to_string()))?;

    // BIT STRING containing the uncompressed point
    let (_, bit_string) = parse_tlv(rest)
        .ok_or_else(|| Error::Config("invalid EC public key DER: missing bit string".to_string()))?;

    // Skip unused-bits byte (should be 0x00)
    if bit_string.is_empty() {
        return Err(Error::Config("empty EC public key bit string".to_string()));
    }
    let point = &bit_string[1..];

    // Uncompressed point format: 0x04 || x (32 bytes) || y (32 bytes)
    if point.len() != 65 || point[0] != 0x04 {
        return Err(Error::Config(format!(
            "expected uncompressed P-256 point (65 bytes starting with 0x04), got {} bytes starting with 0x{:02x}",
            point.len(),
            point.first().copied().unwrap_or(0)
        )));
    }

    let x = URL_SAFE_NO_PAD.encode(&point[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&point[33..65]);

    Ok((x, y))
}

/// Minimal ASN.1 DER parser for RSA public keys.
fn parse_rsa_public_key_der(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (_, inner) = parse_sequence(der)?;
    let (rest, _alg_id) = parse_tlv(inner)?;
    let (_, bit_string_content) = parse_tlv(rest)?;
    if bit_string_content.is_empty() { return None; }
    let rsa_pub_key_der = &bit_string_content[1..];
    let (_, rsa_inner) = parse_sequence(rsa_pub_key_der)?;
    let (rest, n_bytes) = parse_integer(rsa_inner)?;
    let (_, e_bytes) = parse_integer(rest)?;
    Some((n_bytes, e_bytes))
}

fn parse_sequence(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.first()? != &0x30 { return None; }
    parse_tlv(data)
}

fn parse_integer(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.first()? != &0x02 { return None; }
    let (rest, content) = parse_tlv(data)?;
    let content = if content.first() == Some(&0x00) && content.len() > 1 {
        &content[1..]
    } else {
        content
    };
    Some((rest, content))
}

fn parse_tlv(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.len() < 2 { return None; }
    let _tag = data[0];
    let (len, header_size) = parse_der_length(&data[1..])?;
    let total_header = 1 + header_size;
    let content = data.get(total_header..total_header + len)?;
    let rest = data.get(total_header + len..)?;
    Some((rest, content))
}

fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first < 0x80 {
        Some((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes > 4 || data.len() < 1 + num_bytes { return None; }
        let mut len = 0usize;
        for &b in &data[1..1 + num_bytes] {
            len = (len << 8) | b as usize;
        }
        Some((len, 1 + num_bytes))
    }
}

fn compute_kid(public_pem: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_pem);
    let hash = hasher.finalize();
    // Use first 8 bytes as kid (16 hex chars)
    hex::encode(&hash[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn generate_rsa_test_keys() -> (NamedTempFile, NamedTempFile) {
        use std::process::Command;

        let mut private_file = NamedTempFile::new().unwrap();
        let mut public_file = NamedTempFile::new().unwrap();

        let output = Command::new("openssl")
            .args(["genrsa", "2048"])
            .output()
            .unwrap();
        private_file.write_all(&output.stdout).unwrap();

        let output = Command::new("openssl")
            .args(["rsa", "-pubout"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .and_then(|mut child| {
                child.stdin.take().unwrap().write_all(&std::fs::read(private_file.path()).unwrap()).unwrap();
                child.wait_with_output()
            })
            .unwrap();
        public_file.write_all(&output.stdout).unwrap();

        (private_file, public_file)
    }

    fn generate_ec_test_keys() -> (NamedTempFile, NamedTempFile) {
        use std::process::Command;

        let mut private_file = NamedTempFile::new().unwrap();
        let mut public_file = NamedTempFile::new().unwrap();

        // Generate PKCS#8 format EC key (required by jsonwebtoken crate)
        let output = Command::new("openssl")
            .args(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])
            .output()
            .unwrap();
        assert!(output.status.success(), "openssl genpkey failed");
        private_file.write_all(&output.stdout).unwrap();

        let output = Command::new("openssl")
            .args(["pkey", "-pubout"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .and_then(|mut child| {
                child.stdin.take().unwrap().write_all(&std::fs::read(private_file.path()).unwrap()).unwrap();
                child.wait_with_output()
            })
            .unwrap();
        public_file.write_all(&output.stdout).unwrap();

        (private_file, public_file)
    }

    fn test_jwt_config(issuer: &str) -> JwtConfig {
        JwtConfig {
            keys: vec![],
            private_key_path: None,
            public_key_path: None,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 2_592_000,
            issuer: issuer.to_string(),
            authorization_code_ttl_secs: 300,
            jwks_cache_max_age_secs: 3600,
        }
    }

    #[test]
    fn sign_and_verify_token() {
        let (priv_file, pub_file) = generate_rsa_test_keys();
        let keys = KeySet::from_pem_files(priv_file.path(), pub_file.path()).unwrap();
        let config = test_jwt_config("test-auth");

        let token = keys.sign_access_token(&config, "user-123", "testuser", "user", "test-auth").unwrap();
        let decoded = keys.verify_access_token(&config, &token).unwrap();

        assert_eq!(decoded.claims.sub, "user-123");
        assert_eq!(decoded.claims.username, "testuser");
        assert_eq!(decoded.claims.role, "user");
        assert_eq!(decoded.claims.iss, "test-auth");
    }

    #[test]
    fn es256_sign_and_verify() {
        let (priv_file, pub_file) = generate_ec_test_keys();
        let keys = KeySet::from_configs(&[KeyConfig {
            algorithm: SigningAlgorithm::ES256,
            private_key_path: priv_file.path().to_path_buf(),
            public_key_path: pub_file.path().to_path_buf(),
            kid: Some("test-ec-key".to_string()),
        }]).unwrap();
        let config = test_jwt_config("test-auth");

        let token = keys.sign_access_token(&config, "user-456", "ecuser", "user", "test-auth").unwrap();
        let decoded = keys.verify_access_token(&config, &token).unwrap();

        assert_eq!(decoded.claims.sub, "user-456");
        assert_eq!(decoded.claims.username, "ecuser");
    }

    #[test]
    fn multi_key_rotation() {
        let (rsa_priv, rsa_pub) = generate_rsa_test_keys();
        let (ec_priv, ec_pub) = generate_ec_test_keys();

        // Start with RSA only, sign a token
        let rsa_only = KeySet::from_pem_files(rsa_priv.path(), rsa_pub.path()).unwrap();
        let config = test_jwt_config("test-auth");
        let rsa_token = rsa_only.sign_access_token(&config, "user-1", "rsa_user", "user", "test-auth").unwrap();

        // Now create a key set with EC as primary, RSA as secondary (rotation)
        let rotated = KeySet::from_configs(&[
            KeyConfig {
                algorithm: SigningAlgorithm::ES256,
                private_key_path: ec_priv.path().to_path_buf(),
                public_key_path: ec_pub.path().to_path_buf(),
                kid: Some("new-ec".to_string()),
            },
            KeyConfig {
                algorithm: SigningAlgorithm::RS256,
                private_key_path: rsa_priv.path().to_path_buf(),
                public_key_path: rsa_pub.path().to_path_buf(),
                kid: None,
            },
        ]).unwrap();

        // Old RSA token should still verify against the rotated key set
        let decoded = rotated.verify_access_token(&config, &rsa_token).unwrap();
        assert_eq!(decoded.claims.sub, "user-1");

        // New tokens should be signed with ES256
        let new_token = rotated.sign_access_token(&config, "user-2", "ec_user", "user", "test-auth").unwrap();
        let decoded = rotated.verify_access_token(&config, &new_token).unwrap();
        assert_eq!(decoded.claims.sub, "user-2");

        // Verify the new token header uses ES256
        let header = jsonwebtoken::decode_header(&new_token).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid, Some("new-ec".to_string()));
    }

    #[test]
    fn expired_token_rejected() {
        let (priv_file, pub_file) = generate_rsa_test_keys();
        let keys = KeySet::from_pem_files(priv_file.path(), pub_file.path()).unwrap();
        let mut config = test_jwt_config("test-auth");
        config.access_token_ttl_secs = 0;

        let token = keys.sign_access_token(&config, "user-123", "testuser", "user", "test-auth").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(keys.verify_access_token(&config, &token).is_err());
    }

    #[test]
    fn wrong_issuer_rejected() {
        let (priv_file, pub_file) = generate_rsa_test_keys();
        let keys = KeySet::from_pem_files(priv_file.path(), pub_file.path()).unwrap();

        let sign_config = test_jwt_config("issuer-a");
        let verify_config = test_jwt_config("issuer-b");

        let token = keys.sign_access_token(&sign_config, "user-123", "testuser", "user", "test").unwrap();
        assert!(keys.verify_access_token(&verify_config, &token).is_err());
    }

    #[test]
    fn jwks_format_rsa() {
        let (priv_file, pub_file) = generate_rsa_test_keys();
        let keys = KeySet::from_pem_files(priv_file.path(), pub_file.path()).unwrap();
        let jwks = keys.jwks();

        let keys_array = jwks["keys"].as_array().unwrap();
        assert_eq!(keys_array.len(), 1);
        let key = &keys_array[0];
        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["alg"], "RS256");
        assert_eq!(key["use"], "sig");
        assert!(key["n"].as_str().unwrap().len() > 100);
        assert!(key["e"].as_str().unwrap().len() > 0);
    }

    #[test]
    fn jwks_format_ec() {
        let (priv_file, pub_file) = generate_ec_test_keys();
        let keys = KeySet::from_configs(&[KeyConfig {
            algorithm: SigningAlgorithm::ES256,
            private_key_path: priv_file.path().to_path_buf(),
            public_key_path: pub_file.path().to_path_buf(),
            kid: Some("ec-kid".to_string()),
        }]).unwrap();
        let jwks = keys.jwks();

        let keys_array = jwks["keys"].as_array().unwrap();
        assert_eq!(keys_array.len(), 1);
        let key = &keys_array[0];
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["alg"], "ES256");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["kid"], "ec-kid");
        // P-256 x and y are 32 bytes = 43 base64url chars
        assert_eq!(key["x"].as_str().unwrap().len(), 43);
        assert_eq!(key["y"].as_str().unwrap().len(), 43);
    }

    #[test]
    fn jwks_multi_key() {
        let (rsa_priv, rsa_pub) = generate_rsa_test_keys();
        let (ec_priv, ec_pub) = generate_ec_test_keys();

        let keys = KeySet::from_configs(&[
            KeyConfig {
                algorithm: SigningAlgorithm::ES256,
                private_key_path: ec_priv.path().to_path_buf(),
                public_key_path: ec_pub.path().to_path_buf(),
                kid: Some("ec-1".to_string()),
            },
            KeyConfig {
                algorithm: SigningAlgorithm::RS256,
                private_key_path: rsa_priv.path().to_path_buf(),
                public_key_path: rsa_pub.path().to_path_buf(),
                kid: Some("rsa-1".to_string()),
            },
        ]).unwrap();

        let jwks = keys.jwks();
        let keys_array = jwks["keys"].as_array().unwrap();
        assert_eq!(keys_array.len(), 2);
        assert_eq!(keys_array[0]["alg"], "ES256");
        assert_eq!(keys_array[0]["kid"], "ec-1");
        assert_eq!(keys_array[1]["alg"], "RS256");
        assert_eq!(keys_array[1]["kid"], "rsa-1");
    }

    #[test]
    fn sign_and_verify_token_with_scopes() {
        let (priv_file, pub_file) = generate_rsa_test_keys();
        let keys = KeySet::from_pem_files(priv_file.path(), pub_file.path()).unwrap();
        let config = test_jwt_config("test-auth");

        let token = keys.sign_access_token_with_scopes(
            &config, "user-123", "testuser", "user", "my-client",
            Some("read:profile write:profile"),
        ).unwrap();
        let decoded = keys.verify_access_token(&config, &token).unwrap();
        assert_eq!(decoded.claims.scope.as_deref(), Some("read:profile write:profile"));
        assert_eq!(decoded.claims.aud, "my-client");

        let token = keys.sign_access_token(&config, "user-123", "testuser", "user", "test-auth").unwrap();
        let decoded = keys.verify_access_token(&config, &token).unwrap();
        assert!(decoded.claims.scope.is_none());
    }

    #[test]
    fn sign_id_token_claims() {
        let (priv_file, pub_file) = generate_rsa_test_keys();
        let keys = KeySet::from_pem_files(priv_file.path(), pub_file.path()).unwrap();
        let config = test_jwt_config("test-auth");

        let token = keys.sign_id_token(
            &config, "user-123", "testuser",
            Some("Test User"), Some("https://example.com/avatar.png"),
            "my-client", Some("test-nonce-123"),
        ).unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: IdTokenClaims = serde_json::from_slice(&payload).unwrap();

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.iss, "test-auth");
        assert_eq!(claims.aud, "my-client");
        assert_eq!(claims.preferred_username, "testuser");
        assert_eq!(claims.name.as_deref(), Some("Test User"));
        assert_eq!(claims.picture.as_deref(), Some("https://example.com/avatar.png"));
        assert_eq!(claims.nonce.as_deref(), Some("test-nonce-123"));

        let token = keys.sign_id_token(
            &config, "user-456", "minimaluser",
            None, None,
            "another-client", None,
        ).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: IdTokenClaims = serde_json::from_slice(&payload).unwrap();

        assert_eq!(claims.sub, "user-456");
        assert_eq!(claims.preferred_username, "minimaluser");
        assert!(claims.name.is_none());
        assert!(claims.picture.is_none());
        assert!(claims.nonce.is_none());
    }

    #[test]
    fn refresh_token_generation() {
        let (raw1, hash1) = generate_refresh_token();
        let (raw2, hash2) = generate_refresh_token();

        assert_ne!(raw1, raw2);
        assert_ne!(hash1, hash2);
        assert_eq!(hash_token(&raw1), hash1);
        assert!(URL_SAFE_NO_PAD.decode(&raw1).is_ok());
    }

    #[test]
    fn algorithms_returns_configured_algs() {
        let (priv_file, pub_file) = generate_rsa_test_keys();
        let keys = KeySet::from_pem_files(priv_file.path(), pub_file.path()).unwrap();
        assert_eq!(keys.algorithms(), vec!["RS256"]);

        let (ec_priv, ec_pub) = generate_ec_test_keys();
        let keys = KeySet::from_configs(&[
            KeyConfig {
                algorithm: SigningAlgorithm::ES256,
                private_key_path: ec_priv.path().to_path_buf(),
                public_key_path: ec_pub.path().to_path_buf(),
                kid: None,
            },
        ]).unwrap();
        assert_eq!(keys.algorithms(), vec!["ES256"]);
    }

    #[test]
    fn verify_token_by_kid_secondary_key() {
        // T1: Sign with the secondary (RSA) key, verify via kid lookup
        let (ec_priv, ec_pub) = generate_ec_test_keys();
        let (rsa_priv, rsa_pub) = generate_rsa_test_keys();

        // Build a KeySet with EC as active, RSA as secondary
        let keys = KeySet::from_configs(&[
            KeyConfig {
                algorithm: SigningAlgorithm::ES256,
                private_key_path: ec_priv.path().to_path_buf(),
                public_key_path: ec_pub.path().to_path_buf(),
                kid: Some("ec-active".to_string()),
            },
            KeyConfig {
                algorithm: SigningAlgorithm::RS256,
                private_key_path: rsa_priv.path().to_path_buf(),
                public_key_path: rsa_pub.path().to_path_buf(),
                kid: Some("rsa-secondary".to_string()),
            },
        ]).unwrap();

        let config = test_jwt_config("test-auth");

        // Manually sign a token with the RSA (secondary) key and its kid
        let now = chrono::Utc::now();
        let claims = Claims {
            sub: "user-kid-test".to_string(),
            username: "kiduser".to_string(),
            role: "user".to_string(),
            aud: "test".to_string(),
            iss: "test-auth".to_string(),
            iat: now.timestamp(),
            exp: (now + chrono::Duration::seconds(900)).timestamp(),
            scope: None,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("rsa-secondary".to_string());
        let rsa_entry = &keys.entries[1];
        let token = encode(&header, &claims, &rsa_entry.encoding).unwrap();

        // Verify should succeed via kid lookup (not brute-force)
        let decoded = keys.verify_access_token(&config, &token).unwrap();
        assert_eq!(decoded.claims.sub, "user-kid-test");
    }

    #[test]
    fn duplicate_kid_rejected() {
        // T7: Two keys with the same kid should error
        let (ec_priv1, ec_pub1) = generate_ec_test_keys();
        let (ec_priv2, ec_pub2) = generate_ec_test_keys();

        let result = KeySet::from_configs(&[
            KeyConfig {
                algorithm: SigningAlgorithm::ES256,
                private_key_path: ec_priv1.path().to_path_buf(),
                public_key_path: ec_pub1.path().to_path_buf(),
                kid: Some("same-kid".to_string()),
            },
            KeyConfig {
                algorithm: SigningAlgorithm::ES256,
                private_key_path: ec_priv2.path().to_path_buf(),
                public_key_path: ec_pub2.path().to_path_buf(),
                kid: Some("same-kid".to_string()),
            },
        ]);

        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected duplicate kid error, got Ok"),
        };
        assert!(err.contains("duplicate kid"), "expected duplicate kid error, got: {err}");
    }

    #[test]
    fn empty_configs_rejected() {
        let result = KeySet::from_configs(&[]);
        assert!(result.is_err());
    }
}
