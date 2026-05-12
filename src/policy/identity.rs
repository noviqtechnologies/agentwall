//! Identity validation and OIDC background fetcher (FR-202)

use dashmap::DashMap;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::logging::{self, Level};

/// JWT Claims subset required for identity binding
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub exp: usize,
}

#[derive(Debug, Deserialize)]
struct OidcConfig {
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct JwkKey {
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

/// Thread-safe validator with background JWK rotation
pub struct IdentityValidator {
    pub issuer: String,
    pub audience: String,
    keys: DashMap<String, DecodingKey>,
    last_fetched: RwLock<Instant>,
    client: reqwest::Client,
}

impl IdentityValidator {
    pub fn new(issuer: String, audience: String) -> Arc<Self> {
        Arc::new(Self {
            issuer,
            audience,
            keys: DashMap::new(),
            last_fetched: RwLock::new(Instant::now()),
            client: reqwest::Client::new(),
        })
    }

    /// Start the background JWK rotation task
    pub fn start_background_rotation(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                if let Err(e) = self.refresh_keys().await {
                    logging::log_event(
                        Level::Error,
                        "jwk_refresh_failed",
                        serde_json::json!({"issuer": &self.issuer, "error": e.to_string()}),
                    );
                }
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
    }

    async fn refresh_keys(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 1. Fetch OIDC Configuration
        let oidc_url = if self.issuer.ends_with('/') {
            format!("{}.well-known/openid-configuration", self.issuer)
        } else {
            format!("{}/.well-known/openid-configuration", self.issuer)
        };

        let oidc_config: OidcConfig = self.client.get(oidc_url).send().await?.json().await?;

        // 2. Fetch JWKS
        let jwks: JwksResponse = self.client.get(oidc_config.jwks_uri).send().await?.json().await?;

        // 3. Update Cache
        // We don't clear the old keys immediately to avoid race conditions with inflight requests
        for key in jwks.keys {
            if let Ok(decoding_key) = DecodingKey::from_rsa_components(&key.n, &key.e) {
                self.keys.insert(key.kid, decoding_key);
            }
        }

        let mut last_fetched = self.last_fetched.write().await;
        *last_fetched = Instant::now();

        logging::log_event(
            Level::Info,
            "jwks_rotated",
            serde_json::json!({"issuer": &self.issuer, "key_count": self.keys.len()}),
        );

        Ok(())
    }

    /// Validate a JWT and return the subject (sub)
    pub async fn validate_token(&self, token: &str) -> Result<String, String> {
        // 1. Decode header to get kid
        let header = decode_header(token).map_err(|e| format!("Invalid JWT header: {}", e))?;
        let kid = header.kid.ok_or_else(|| "Missing 'kid' in JWT header".to_string())?;

        // 2. Get decoding key from cache
        let decoding_key = self.keys.get(&kid).ok_or_else(|| {
            format!("No matching JWK found for kid: {}. Fail-Closed.", kid)
        })?;

        // 3. Validate claims
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);

        let token_data = decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| format!("JWT validation failed: {}", e))?;

        Ok(token_data.claims.sub)
    }

    /// Check if keys have ever been fetched (fail-closed check)
    pub async fn is_ready(&self) -> bool {
        !self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn test_jwt_validation_success() {
        let issuer = "https://example.com".to_string();
        let audience = "my-agent".to_string();
        let validator = IdentityValidator::new(issuer.clone(), audience.clone());

        let key_secret = b"secret";
        let decoding_key = jsonwebtoken::DecodingKey::from_secret(key_secret);
        let encoding_key = EncodingKey::from_secret(key_secret);

        let kid = "test-kid";
        validator.keys.insert(kid.to_string(), decoding_key);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
        let claims = Claims {
            sub: "user-123".to_string(),
            aud: audience.clone(),
            iss: issuer.clone(),
            exp: now + 3600,
        };

        let mut header = Header::default();
        header.kid = Some(kid.to_string());

        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = validator.validate_token(&token).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "user-123");
    }

    #[tokio::test]
    async fn test_jwt_validation_expired() {
        let issuer = "https://example.com".to_string();
        let audience = "my-agent".to_string();
        let validator = IdentityValidator::new(issuer.clone(), audience.clone());

        let key_secret = b"secret";
        validator.keys.insert("test-kid".to_string(), jsonwebtoken::DecodingKey::from_secret(key_secret));

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
        let claims = Claims {
            sub: "user-123".to_string(),
            aud: audience.clone(),
            iss: issuer.clone(),
            exp: now - 120, // Expired beyond 60s clock skew
        };

        let mut header = Header::default();
        header.kid = Some("test-kid".to_string());

        let token = encode(&header, &claims, &EncodingKey::from_secret(key_secret)).unwrap();

        let result = validator.validate_token(&token).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ExpiredSignature"));
    }
}
