//! Unit tests for IdentityValidator — FR-201 acceptance criteria
//!
//! Tests: signature verification, expiration, algorithm enforcement,
//! audience/issuer validation, missing kid, cache miss path, and
//! the `is_ready` fail-closed check.

use agentwall::policy::identity::{Claims, IdentityValidator};
use jsonwebtoken::{encode, EncodingKey, Header};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Shared test keys ─────────────────────────────────────────────────────────

static RSA_PRIVATE_PEM: &[u8] = br#"-----BEGIN RSA PRIVATE KEY-----
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

static RSA_PUBLIC_PEM: &[u8] = br#"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAudhbe1QgN8OIKg2CTLUctcCzszFAtY19k04MNrqv/Bxz9EudGdRl
FnRP62y6nj9/N0w7VGe3uHxwggBSR0lbTfN0AUzHkFn/tFS/B24wSYJZHqxxQ2Lw
laaB52S9iZhf5edPBuUKkugLjMEusXY3CQQtPvITzFpEa0FzJgUQzIo0M4f4QX1Q
Ve4ufIt+LxqPK8bBrSjoEs2wosUQEVd/Zua2Ho37gL7PUCXTxgrWwhrCNrl4NZcZ
QBBrC/jC/ArSTNbwkGOx7Mzv6BdfIGUlvEYTaYa+MfRRG7FAnBC9SqibsMj5uXRr
sTCQ754eF9Kqpj/ZL6ZZaFLdT3BATCAnKwIDAQAB
-----END RSA PUBLIC KEY-----"#;

fn now_secs() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
}

fn make_validator(issuer: &str, audience: &str) -> std::sync::Arc<IdentityValidator> {
    let v = IdentityValidator::new(issuer.to_string(), audience.to_string(), None);
    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_pem(RSA_PUBLIC_PEM).expect("valid public key");
    v.keys.insert("test-kid".to_string(), decoding_key);
    v
}

fn make_token(issuer: &str, audience: &str, sub: &str, exp_offset_secs: i64) -> String {
    let encoding_key =
        EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM).expect("valid private key");
    let exp = (now_secs() as i64 + exp_offset_secs) as usize;
    let claims = Claims {
        sub: sub.to_string(),
        aud: audience.to_string(),
        iss: issuer.to_string(),
        exp,
    };
    let header = Header {
        alg: jsonwebtoken::Algorithm::RS256,
        kid: Some("test-kid".to_string()),
        ..Default::default()
    };
    encode(&header, &claims, &encoding_key).unwrap()
}

// ── AC-201-2: Valid token succeeds and extracts sub claim ────────────────────

#[tokio::test]
async fn test_ac201_2_valid_token_returns_sub() {
    let issuer = "https://example.com";
    let audience = "agentwall";
    let v = make_validator(issuer, audience);
    let token = make_token(issuer, audience, "agent-alpha", 3600);

    let result = v.validate_token(&token).await;
    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
    assert_eq!(result.unwrap(), "agent-alpha");
}

// ── AC-201-2: Expired token returns error ────────────────────────────────────

#[tokio::test]
async fn test_ac201_2_expired_token_rejected() {
    let issuer = "https://example.com";
    let audience = "agentwall";
    let v = make_validator(issuer, audience);
    // Expire 2 minutes ago (beyond 60s clock skew)
    let token = make_token(issuer, audience, "agent-alpha", -120);

    let result = v.validate_token(&token).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("ExpiredSignature"),
        "Expected ExpiredSignature in error"
    );
}

// ── AC-201-2: Wrong audience rejected ────────────────────────────────────────

#[tokio::test]
async fn test_ac201_2_wrong_audience_rejected() {
    let issuer = "https://example.com";
    let v = make_validator(issuer, "agentwall");
    // Token issued for a different audience
    let token = make_token(issuer, "other-service", "agent-alpha", 3600);

    let result = v.validate_token(&token).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("InvalidAudience") || err.contains("audience"),
        "Expected audience error, got: {}", err
    );
}

// ── AC-201-2: Wrong issuer rejected ──────────────────────────────────────────

#[tokio::test]
async fn test_ac201_2_wrong_issuer_rejected() {
    let v = make_validator("https://expected-issuer.com", "agentwall");
    // Token was issued by a different issuer
    let token = make_token("https://attacker.com", "agentwall", "agent-alpha", 3600);

    let result = v.validate_token(&token).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("InvalidIssuer") || err.contains("issuer"),
        "Expected issuer error, got: {}", err
    );
}

// ── AC-201-2: Missing kid in header rejected ──────────────────────────────────

#[tokio::test]
async fn test_ac201_2_missing_kid_rejected() {
    let issuer = "https://example.com";
    let audience = "agentwall";
    let v = make_validator(issuer, audience);
    let encoding_key = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM).unwrap();
    let claims = Claims {
        sub: "agent-alpha".to_string(),
        aud: audience.to_string(),
        iss: issuer.to_string(),
        exp: now_secs() + 3600,
    };
    // Header WITHOUT kid
    let header = Header {
        alg: jsonwebtoken::Algorithm::RS256,
        ..Default::default()
    };
    let token = encode(&header, &claims, &encoding_key).unwrap();

    let result = v.validate_token(&token).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'kid'"));
}

// ── AC-201-2: HMAC algorithm (HS256) rejected (only RS256/ES256 allowed) ─────

#[tokio::test]
async fn test_ac201_2_hmac_algorithm_rejected() {
    let issuer = "https://example.com";
    let audience = "agentwall";
    let v = make_validator(issuer, audience);
    let hmac_key = EncodingKey::from_secret(b"super-secret");
    let claims = Claims {
        sub: "agent-alpha".to_string(),
        aud: audience.to_string(),
        iss: issuer.to_string(),
        exp: now_secs() + 3600,
    };
    let header = Header {
        alg: jsonwebtoken::Algorithm::HS256,
        kid: Some("test-kid".to_string()),
        ..Default::default()
    };
    let token = encode(&header, &claims, &hmac_key).unwrap();

    let result = v.validate_token(&token).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("not supported"),
        "Expected algorithm rejection"
    );
}

// ── AC-201-2: Unknown kid causes fail-closed (no key match) ──────────────────

#[tokio::test]
async fn test_ac201_2_unknown_kid_fail_closed() {
    // Validator with keys for "test-kid" only
    let issuer = "https://example.com";
    let audience = "agentwall";
    let v = make_validator(issuer, audience);
    let encoding_key = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM).unwrap();
    let claims = Claims {
        sub: "agent-alpha".to_string(),
        aud: audience.to_string(),
        iss: issuer.to_string(),
        exp: now_secs() + 3600,
    };
    let header = Header {
        alg: jsonwebtoken::Algorithm::RS256,
        kid: Some("unknown-kid-9999".to_string()),
        ..Default::default()
    };
    let token = encode(&header, &claims, &encoding_key).unwrap();

    let result = v.validate_token(&token).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No matching JWK"));
}

// ── AC-201-5: is_ready returns false when no keys loaded ─────────────────────

#[tokio::test]
async fn test_ac201_5_not_ready_when_no_keys() {
    let v = IdentityValidator::new("https://example.com".to_string(), "aud".to_string(), None);
    // No keys populated
    assert!(!v.is_ready().await, "Should not be ready with empty key cache");
}

// ── AC-201-5: is_ready returns true when a key is present ────────────────────

#[tokio::test]
async fn test_ac201_5_ready_when_key_present() {
    let v = make_validator("https://example.com", "agentwall");
    assert!(v.is_ready().await, "Should be ready after key is inserted");
}

// ── AC-201-5: Custom cache TTL is respected ───────────────────────────────────

#[test]
fn test_ac201_5_custom_cache_ttl_applied() {
    // 30-minute TTL
    let v = IdentityValidator::new("https://example.com".to_string(), "aud".to_string(), Some(30));
    assert_eq!(v.cache_ttl.as_secs(), 30 * 60);
}
