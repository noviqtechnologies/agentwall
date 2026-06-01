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
    kty: String,
    kid: String,
    // RSA components
    n: Option<String>,
    e: Option<String>,
    // EC components
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
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
    cache_ttl: Duration,
}

impl IdentityValidator {
    pub fn new(issuer: String, audience: String, cache_ttl_minutes: Option<u64>) -> Arc<Self> {
        let ttl_secs = cache_ttl_minutes.unwrap_or(15) * 60;
        let keys = DashMap::new();
        if issuer == "mock" || issuer.starts_with("mock:") {
            // Pre-populate with a test key
            let test_n = "u1Wdo5gT6K4aZlXg9o1Qy2s3t4u5v6w7x8y9z0_A-B_C-D_E-F_G-H_I-J_K-L_M-N_O-P_Q-R_S-T_U-V_W-X_Y-Z";
            let test_e = "AQAB";
            if let Ok(decoding_key) = DecodingKey::from_rsa_components(test_n, test_e) {
                keys.insert("mock-kid".to_string(), decoding_key);
            }
        }

        Arc::new(Self {
            issuer,
            audience,
            keys,
            last_fetched: RwLock::new(Instant::now()),
            client: reqwest::Client::new(),
            cache_ttl: Duration::from_secs(ttl_secs),
        })
    }

    /// Start the background JWK rotation task
    pub fn start_background_rotation(self: Arc<Self>) {
        let ttl = self.cache_ttl;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(ttl).await;
                if let Err(e) = self.refresh_keys().await {
                    logging::log_event(
                        Level::Error,
                        "jwk_refresh_failed",
                        serde_json::json!({"issuer": &self.issuer, "error": e.to_string()}),
                    );
                }
            }
        });
    }

    async fn refresh_keys(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.issuer == "mock" || self.issuer.starts_with("mock:") {
            return Ok(());
        }

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
        for key in jwks.keys {
            if key.kty == "RSA" {
                if let (Some(n), Some(e)) = (&key.n, &key.e) {
                    if let Ok(decoding_key) = DecodingKey::from_rsa_components(n, e) {
                        self.keys.insert(key.kid, decoding_key);
                    }
                }
            } else if key.kty == "EC" {
                if let (Some(x), Some(y)) = (&key.x, &key.y) {
                    if let Ok(decoding_key) = DecodingKey::from_ec_components(x, y) {
                        self.keys.insert(key.kid, decoding_key);
                    }
                }
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

        // Enforce RS256 and ES256 signatures only (FR-201)
        use jsonwebtoken::Algorithm;
        if header.alg != Algorithm::RS256 && header.alg != Algorithm::ES256 {
            return Err(format!("Algorithm {:?} is not supported. Only RS256 and ES256 are permitted.", header.alg));
        }

        // 2. Get decoding key from cache (with cache miss dynamic refresh)
        let decoding_key = if let Some(key) = self.keys.get(&kid) {
            key
        } else {
            if let Err(e) = self.refresh_keys().await {
                logging::log_event(
                    Level::Warn,
                    "jwk_dynamic_refresh_failed",
                    serde_json::json!({"kid": &kid, "error": e.to_string()}),
                );
            }
            self.keys.get(&kid).ok_or_else(|| {
                format!("No matching JWK found for kid: {}. Fail-Closed.", kid)
            })?
        };

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
        let validator = IdentityValidator::new(issuer.clone(), audience.clone(), None);

        let rsa_private_key_pem = br#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAudhbe1QgN8OIKg2CTLUctcCzszFAtY19k04MNrqv/Bxz9Eud
GdRlFnRP62y6nj9/N0w7VGe3uHxwggBSR0lbTfN0AUzHkFn/tFS/B24wSYJZHqxx
Q2LwlaaB52S9iZhf5edPBuUKkugLjMEusXY3CQQtPvITzFpEa0FzJgUQzIo0M4f4
QX1QVe4ufIt+LxqPK8bBrSjoEs2wosUQEVd/Zua2Ho37gL7PUCXTxgrWwhrCNrl4
NZcZQBBrC/jC/ArSTNbwkGOx7Mzv6BdfIGUlvEYTaYa+MfRRG7FAnBC9SqibsMj5
uXRrsTCQ754eF9Kqpj/ZL6ZZaFLdT3BATCAnKwIDAQABAoIBABSRSkaS3+HsBOTK
i/IbVSsUQY8CU2wEVbJ4v8dKz/Ex4O9XcvKJ3AopIzMl3F1pH5YqHKLRu7ZyJy1s
Ba8YAj/VQrBmI+vo2fDGNEIJQtTP1Tcc1IglqgSV4eiO8J8KuwpBmDBmJs5tWeHg
+17ue1bHHI7L0b8a+ll4a9r4UoygSoZi+n5gpZMih7konWXpYnh7Su36LD9L2bMm
suhiE/8AB2ssFNFm8CWCiT+wlIN+y3qhQg3oCbGErF6AiXn23LGnyH0ghQZPsOL1
jXARD5gICiLQR5Rl2c3DAOBpvQriAJ00zZlnLQwL1tgXd545qU7nAGRLOpd331Mf
5NYxkPECgYEA7QaJYeo8ukThIq7v0nRGR1g/QJ43bfdXzCcP/EIRJUCzVZ67A08T
lUvWbV0NKRobqoybOH2tEH3QfBHqG1BX23SSwCPj8NuFXNoxAaV92o68738NQgEx
89LOnyp96l2aZ1czYqWnMfZxi5wkC74yOg9AUJVgCVCiPEhjPBVIiBkCgYEAyLj1
qWNRh6NrL1JX6yxHA3aRlY5AWuOnjcL0koS7D9BKO9rwp1B9muxR/DKAFsOoTRZY
HBll1Jt7aSoZGm9Lzo3YmkdnJc64y9J7TJY9dmlyDQypVQ8SaHOrpxOGIv13Z09D
ZKryKgziJNj9WMalOKBOKYFnkMPYoFtmYvruYeMCgYAbAXKnuFOA+ZYZKItklCDp
whE64Iv6OINFXHIC0Ng5QVztdW9jWiAmE4Tz4vU76KCcVvbcgd01EtCtQjFFOWs5
MtgBklVHPQu935JT2LI1M6wtMXGmQpKZcDxggCvmhxGvkozlQXCCTcz0Fi85M0tv
uAsg41QU254QdkLwNpCUCQKBgEp1SjPustTFC0K/ofuMLj+boT/ASCEvJ/2PX1hm
wlmIY7E2c2Utl5p7paIPPbK0G9+UtVSfG0Y18x68zhkfRhi2R65bZGkC+UwqpTBw
3xXo4bTziHEUKTj0B63vsSeTrNJ29cIHI9PzeYQ/tiNTdQC/fp8o8Lkj3V0G6sE2
4m0PAoGBAJ91qG5CsWaBmZrLiSPnCezSY7Mph5B8FI+YpX02FuczlWlYyQqX/M7Z
3tMxTz7zd083mxuBu9P9jQFFxZnvnOonFgE8LOxWRvZ5vE2UThQL100tmzxE6Ldw
l2llvDdv/ChIHKXEhXqLTdHKDXvSw+xrw43rGW1RegijQmNwaDgC
-----END RSA PRIVATE KEY-----"#;
        let rsa_public_key_pem = br#"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAudhbe1QgN8OIKg2CTLUctcCzszFAtY19k04MNrqv/Bxz9EudGdRl
FnRP62y6nj9/N0w7VGe3uHxwggBSR0lbTfN0AUzHkFn/tFS/B24wSYJZHqxxQ2Lw
laaB52S9iZhf5edPBuUKkugLjMEusXY3CQQtPvITzFpEa0FzJgUQzIo0M4f4QX1Q
Ve4ufIt+LxqPK8bBrSjoEs2wosUQEVd/Zua2Ho37gL7PUCXTxgrWwhrCNrl4NZcZ
QBBrC/jC/ArSTNbwkGOx7Mzv6BdfIGUlvEYTaYa+MfRRG7FAnBC9SqibsMj5uXRr
sTCQ754eF9Kqpj/ZL6ZZaFLdT3BATCAnKwIDAQAB
-----END RSA PUBLIC KEY-----"#;

        let encoding_key = EncodingKey::from_rsa_pem(rsa_private_key_pem).unwrap();
        let decoding_key = DecodingKey::from_rsa_pem(rsa_public_key_pem).unwrap();

        let kid = "test-kid";
        validator.keys.insert(kid.to_string(), decoding_key);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
        let claims = Claims {
            sub: "user-123".to_string(),
            aud: audience.clone(),
            iss: issuer.clone(),
            exp: now + 3600,
        };

        let header = Header {
            alg: jsonwebtoken::Algorithm::RS256,
            kid: Some(kid.to_string()),
            ..Default::default()
        };

        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = validator.validate_token(&token).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "user-123");
    }

    #[tokio::test]
    async fn test_jwt_validation_expired() {
        let issuer = "https://example.com".to_string();
        let audience = "my-agent".to_string();
        let validator = IdentityValidator::new(issuer.clone(), audience.clone(), None);

        let rsa_private_key_pem = br#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAudhbe1QgN8OIKg2CTLUctcCzszFAtY19k04MNrqv/Bxz9Eud
GdRlFnRP62y6nj9/N0w7VGe3uHxwggBSR0lbTfN0AUzHkFn/tFS/B24wSYJZHqxx
Q2LwlaaB52S9iZhf5edPBuUKkugLjMEusXY3CQQtPvITzFpEa0FzJgUQzIo0M4f4
QX1QVe4ufIt+LxqPK8bBrSjoEs2wosUQEVd/Zua2Ho37gL7PUCXTxgrWwhrCNrl4
NZcZQBBrC/jC/ArSTNbwkGOx7Mzv6BdfIGUlvEYTaYa+MfRRG7FAnBC9SqibsMj5
uXRrsTCQ754eF9Kqpj/ZL6ZZaFLdT3BATCAnKwIDAQABAoIBABSRSkaS3+HsBOTK
i/IbVSsUQY8CU2wEVbJ4v8dKz/Ex4O9XcvKJ3AopIzMl3F1pH5YqHKLRu7ZyJy1s
Ba8YAj/VQrBmI+vo2fDGNEIJQtTP1Tcc1IglqgSV4eiO8J8KuwpBmDBmJs5tWeHg
+17ue1bHHI7L0b8a+ll4a9r4UoygSoZi+n5gpZMih7konWXpYnh7Su36LD9L2bMm
suhiE/8AB2ssFNFm8CWCiT+wlIN+y3qhQg3oCbGErF6AiXn23LGnyH0ghQZPsOL1
jXARD5gICiLQR5Rl2c3DAOBpvQriAJ00zZlnLQwL1tgXd545qU7nAGRLOpd331Mf
5NYxkPECgYEA7QaJYeo8ukThIq7v0nRGR1g/QJ43bfdXzCcP/EIRJUCzVZ67A08T
lUvWbV0NKRobqoybOH2tEH3QfBHqG1BX23SSwCPj8NuFXNoxAaV92o68738NQgEx
89LOnyp96l2aZ1czYqWnMfZxi5wkC74yOg9AUJVgCVCiPEhjPBVIiBkCgYEAyLj1
qWNRh6NrL1JX6yxHA3aRlY5AWuOnjcL0koS7D9BKO9rwp1B9muxR/DKAFsOoTRZY
HBll1Jt7aSoZGm9Lzo3YmkdnJc64y9J7TJY9dmlyDQypVQ8SaHOrpxOGIv13Z09D
ZKryKgziJNj9WMalOKBOKYFnkMPYoFtmYvruYeMCgYAbAXKnuFOA+ZYZKItklCDp
whE64Iv6OINFXHIC0Ng5QVztdW9jWiAmE4Tz4vU76KCcVvbcgd01EtCtQjFFOWs5
MtgBklVHPQu935JT2LI1M6wtMXGmQpKZcDxggCvmhxGvkozlQXCCTcz0Fi85M0tv
uAsg41QU254QdkLwNpCUCQKBgEp1SjPustTFC0K/ofuMLj+boT/ASCEvJ/2PX1hm
wlmIY7E2c2Utl5p7paIPPbK0G9+UtVSfG0Y18x68zhkfRhi2R65bZGkC+UwqpTBw
3xXo4bTziHEUKTj0B63vsSeTrNJ29cIHI9PzeYQ/tiNTdQC/fp8o8Lkj3V0G6sE2
4m0PAoGBAJ91qG5CsWaBmZrLiSPnCezSY7Mph5B8FI+YpX02FuczlWlYyQqX/M7Z
3tMxTz7zd083mxuBu9P9jQFFxZnvnOonFgE8LOxWRvZ5vE2UThQL100tmzxE6Ldw
l2llvDdv/ChIHKXEhXqLTdHKDXvSw+xrw43rGW1RegijQmNwaDgC
-----END RSA PRIVATE KEY-----"#;
        let rsa_public_key_pem = br#"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAudhbe1QgN8OIKg2CTLUctcCzszFAtY19k04MNrqv/Bxz9EudGdRl
FnRP62y6nj9/N0w7VGe3uHxwggBSR0lbTfN0AUzHkFn/tFS/B24wSYJZHqxxQ2Lw
laaB52S9iZhf5edPBuUKkugLjMEusXY3CQQtPvITzFpEa0FzJgUQzIo0M4f4QX1Q
Ve4ufIt+LxqPK8bBrSjoEs2wosUQEVd/Zua2Ho37gL7PUCXTxgrWwhrCNrl4NZcZ
QBBrC/jC/ArSTNbwkGOx7Mzv6BdfIGUlvEYTaYa+MfRRG7FAnBC9SqibsMj5uXRr
sTCQ754eF9Kqpj/ZL6ZZaFLdT3BATCAnKwIDAQAB
-----END RSA PUBLIC KEY-----"#;

        let encoding_key = EncodingKey::from_rsa_pem(rsa_private_key_pem).unwrap();
        let decoding_key = DecodingKey::from_rsa_pem(rsa_public_key_pem).unwrap();

        let kid = "test-kid";
        validator.keys.insert(kid.to_string(), decoding_key);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
        let claims = Claims {
            sub: "user-123".to_string(),
            aud: audience.clone(),
            iss: issuer.clone(),
            exp: now - 120, // Expired beyond 60s clock skew
        };

        let header = Header {
            alg: jsonwebtoken::Algorithm::RS256,
            kid: Some(kid.to_string()),
            ..Default::default()
        };

        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = validator.validate_token(&token).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ExpiredSignature"));
    }
}
