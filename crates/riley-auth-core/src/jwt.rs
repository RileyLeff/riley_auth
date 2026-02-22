use std::path::Path;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
    decode, encode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::JwtConfig;
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
}

/// Loaded key material for signing and verification.
#[derive(Clone)]
pub struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    /// RSA public key modulus (n) for JWKS, base64url-encoded
    pub n: String,
    /// RSA public key exponent (e) for JWKS, base64url-encoded
    pub e: String,
    /// Key ID (SHA-256 thumbprint of the public key)
    pub kid: String,
}

impl Keys {
    /// Load RS256 keys from PEM files.
    pub fn from_pem_files(private_path: &Path, public_path: &Path) -> Result<Self> {
        let private_pem = std::fs::read(private_path).map_err(|e| {
            Error::Config(format!("cannot read private key {}: {e}", private_path.display()))
        })?;
        let public_pem = std::fs::read(public_path).map_err(|e| {
            Error::Config(format!("cannot read public key {}: {e}", public_path.display()))
        })?;

        let encoding = EncodingKey::from_rsa_pem(&private_pem)
            .map_err(|e| Error::Config(format!("invalid private key: {e}")))?;
        let decoding = DecodingKey::from_rsa_pem(&public_pem)
            .map_err(|e| Error::Config(format!("invalid public key: {e}")))?;

        // Parse public key to extract n and e for JWKS
        let (n, e) = extract_rsa_components(&public_pem)?;

        // Key ID = truncated SHA-256 of the DER-encoded public key
        let kid = compute_kid(&public_pem);

        Ok(Self { encoding, decoding, n, e, kid })
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
        let now = Utc::now();
        let exp = now + Duration::seconds(config.access_token_ttl_secs as i64);

        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            role: role.to_string(),
            aud: audience.to_string(),
            iss: config.issuer.clone(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        encode(&header, &claims, &self.encoding)
            .map_err(|e| Error::Config(format!("failed to sign token: {e}")))
    }

    /// Verify and decode an access token.
    pub fn verify_access_token(
        &self,
        config: &JwtConfig,
        token: &str,
    ) -> Result<TokenData<Claims>> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&config.issuer]);
        validation.leeway = 0;
        // We validate audience per-route, not globally
        validation.validate_aud = false;

        decode::<Claims>(token, &self.decoding, &validation)
            .map_err(|_| Error::InvalidToken)
    }

    /// Encoding key for signing (used by setup tokens etc.)
    pub fn encoding_key(&self) -> &EncodingKey {
        &self.encoding
    }

    /// Decoding key for verification.
    pub fn decoding_key(&self) -> &DecodingKey {
        &self.decoding
    }

    /// JWKS response body.
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": self.kid,
                "n": self.n,
                "e": self.e,
            }]
        })
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

/// Generate an RS256 keypair and write PEM files.
pub fn generate_keypair(output_dir: &Path) -> Result<()> {
    use std::process::Command;

    let private_path = output_dir.join("private.pem");
    let public_path = output_dir.join("public.pem");

    // Generate private key
    let status = Command::new("openssl")
        .args(["genrsa", "-out"])
        .arg(&private_path)
        .arg("2048")
        .status()
        .map_err(|e| Error::Config(format!("failed to run openssl: {e}")))?;

    if !status.success() {
        return Err(Error::Config("openssl genrsa failed".to_string()));
    }

    // Extract public key
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
        private = %private_path.display(),
        public = %public_path.display(),
        "generated RS256 keypair"
    );

    Ok(())
}

// --- Internal helpers ---

/// Extract RSA modulus (n) and exponent (e) from a PEM public key.
fn extract_rsa_components(public_pem: &[u8]) -> Result<(String, String)> {
    // Use simple_asn1/pem parsing via jsonwebtoken's internal decoding
    // The DecodingKey already validates the PEM — here we just need n and e
    // for the JWKS endpoint. We'll parse the PEM -> DER -> ASN.1 manually.

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
    // SubjectPublicKeyInfo is: SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
    // RSAPublicKey is: SEQUENCE { INTEGER (n), INTEGER (e) }
    let (n_bytes, e_bytes) = parse_rsa_public_key_der(&der)
        .ok_or_else(|| Error::Config("failed to parse RSA public key DER".to_string()))?;

    Ok((
        URL_SAFE_NO_PAD.encode(n_bytes),
        URL_SAFE_NO_PAD.encode(e_bytes),
    ))
}

/// Minimal ASN.1 DER parser for RSA public keys.
fn parse_rsa_public_key_der(der: &[u8]) -> Option<(&[u8], &[u8])> {
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm AlgorithmIdentifier,
    //   subjectPublicKey BIT STRING
    // }
    let (_, inner) = parse_sequence(der)?;

    // Skip AlgorithmIdentifier (first element)
    let (rest, _alg_id) = parse_tlv(inner)?;

    // BIT STRING containing RSAPublicKey
    let (_, bit_string_content) = parse_tlv(rest)?;
    // Skip the unused-bits byte
    let rsa_pub_key_der = &bit_string_content[1..];

    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER }
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
    // Strip leading zero byte (ASN.1 sign byte for positive integers)
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

    fn generate_test_keys() -> (NamedTempFile, NamedTempFile) {
        use std::process::Command;

        let mut private_file = NamedTempFile::new().unwrap();
        let mut public_file = NamedTempFile::new().unwrap();

        // Generate private key
        let output = Command::new("openssl")
            .args(["genrsa", "2048"])
            .output()
            .unwrap();
        private_file.write_all(&output.stdout).unwrap();

        // Extract public key
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

    #[test]
    fn sign_and_verify_token() {
        let (priv_file, pub_file) = generate_test_keys();
        let keys = Keys::from_pem_files(priv_file.path(), pub_file.path()).unwrap();
        let config = JwtConfig {
            private_key_path: priv_file.path().to_path_buf(),
            public_key_path: pub_file.path().to_path_buf(),
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 2_592_000,
            issuer: "test-auth".to_string(),
            authorization_code_ttl_secs: 300,
        };

        let token = keys.sign_access_token(&config, "user-123", "testuser", "user", "test-auth").unwrap();
        let decoded = keys.verify_access_token(&config, &token).unwrap();

        assert_eq!(decoded.claims.sub, "user-123");
        assert_eq!(decoded.claims.username, "testuser");
        assert_eq!(decoded.claims.role, "user");
        assert_eq!(decoded.claims.iss, "test-auth");
    }

    #[test]
    fn expired_token_rejected() {
        let (priv_file, pub_file) = generate_test_keys();
        let keys = Keys::from_pem_files(priv_file.path(), pub_file.path()).unwrap();
        let config = JwtConfig {
            private_key_path: priv_file.path().to_path_buf(),
            public_key_path: pub_file.path().to_path_buf(),
            access_token_ttl_secs: 0, // Immediate expiry
            refresh_token_ttl_secs: 0,
            issuer: "test-auth".to_string(),
            authorization_code_ttl_secs: 300,
        };

        let token = keys.sign_access_token(&config, "user-123", "testuser", "user", "test-auth").unwrap();
        // Token should be expired immediately
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(keys.verify_access_token(&config, &token).is_err());
    }

    #[test]
    fn wrong_issuer_rejected() {
        let (priv_file, pub_file) = generate_test_keys();
        let keys = Keys::from_pem_files(priv_file.path(), pub_file.path()).unwrap();

        let sign_config = JwtConfig {
            private_key_path: priv_file.path().to_path_buf(),
            public_key_path: pub_file.path().to_path_buf(),
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 2_592_000,
            issuer: "issuer-a".to_string(),
            authorization_code_ttl_secs: 300,
        };

        let verify_config = JwtConfig {
            issuer: "issuer-b".to_string(),
            ..sign_config.clone()
        };

        let token = keys.sign_access_token(&sign_config, "user-123", "testuser", "user", "test").unwrap();
        assert!(keys.verify_access_token(&verify_config, &token).is_err());
    }

    #[test]
    fn jwks_format() {
        let (priv_file, pub_file) = generate_test_keys();
        let keys = Keys::from_pem_files(priv_file.path(), pub_file.path()).unwrap();
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
    fn refresh_token_generation() {
        let (raw1, hash1) = generate_refresh_token();
        let (raw2, hash2) = generate_refresh_token();

        // Tokens should be unique
        assert_ne!(raw1, raw2);
        assert_ne!(hash1, hash2);

        // Hash should be deterministic
        assert_eq!(hash_token(&raw1), hash1);

        // Raw should be base64url
        assert!(URL_SAFE_NO_PAD.decode(&raw1).is_ok());
    }
}
