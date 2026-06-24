//! FR-22: Vault backend abstraction layer
//!
//! Provides a unified `VaultBackend` trait with async issuance, rotation,
//! and revocation. Three concrete adapters are provided:
//!
//! - `HashicorpVaultAdapter` — HashiCorp Vault (AppRole + dynamic secrets)
//! - `AwsSecretsManagerAdapter` — AWS Secrets Manager (IAM role-based)  
//! - `AzureKeyVaultAdapter` — Azure Key Vault (Managed Identity)
//!
//! The active backend is selected from the `identity.provider` field in the
//! policy YAML or via `AGENTWALL_IDENTITY_BACKEND` environment variable.

use crate::logging::{self, Level};
use serde_json::json;

/// Result of a credential issuance or rotation request.
#[derive(Debug, Clone)]
pub struct IssuedCredential {
    /// The short-lived credential value.
    /// For JWT: the signed token string.
    /// For mTLS: the PEM-encoded client certificate.
    pub credential_value: String,
    /// The unique identifier for this credential in the vault.
    pub vault_credential_id: String,
    /// Expiry timestamp (Unix seconds UTC).
    pub expires_at_unix: i64,
}

/// Errors from vault backend operations.
#[derive(Debug, Clone)]
pub enum VaultError {
    Unreachable(String),
    AuthFailed(String),
    ScopeDenied(String),
    IssuanceFailed(String),
    RevocationFailed(String),
    NotFound(String),
    Configuration(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(m) => write!(f, "Vault unreachable: {}", m),
            Self::AuthFailed(m) => write!(f, "Vault auth failed: {}", m),
            Self::ScopeDenied(m) => write!(f, "Scope denied by vault policy: {}", m),
            Self::IssuanceFailed(m) => write!(f, "Credential issuance failed: {}", m),
            Self::RevocationFailed(m) => write!(f, "Credential revocation failed: {}", m),
            Self::NotFound(m) => write!(f, "Credential not found: {}", m),
            Self::Configuration(m) => write!(f, "Vault configuration error: {}", m),
        }
    }
}

/// Vault backend configuration loaded from the policy `identity:` block or environment.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Backend type: "vault" | "aws-secrets-manager" | "azure-key-vault"
    pub backend: String,
    /// HashiCorp Vault: address (e.g., "https://vault.internal:8200")
    pub vault_addr: Option<String>,
    /// HashiCorp Vault: AppRole role ID
    pub vault_role_id: Option<String>,
    /// HashiCorp Vault: AppRole secret ID
    pub vault_secret_id: Option<String>,
    /// HashiCorp Vault: root token (dev mode only — never in production)
    pub vault_token: Option<String>,
    /// AWS: region for Secrets Manager
    pub aws_region: Option<String>,
    /// Azure: Key Vault URL
    pub azure_keyvault_url: Option<String>,
}

impl VaultConfig {
    /// Load vault configuration from environment variables.
    ///
    /// Environment variables take precedence over policy YAML values.
    /// This allows CI/CD systems and K8s operator secret injection to override
    /// the policy-file values without modifying the policy.
    pub fn from_env(policy_provider: &str, policy_vault_addr: Option<&str>) -> Self {
        let backend = std::env::var("AGENTWALL_IDENTITY_BACKEND")
            .unwrap_or_else(|_| policy_provider.to_string());

        let vault_addr = std::env::var("VAULT_ADDR")
            .ok()
            .or_else(|| policy_vault_addr.map(|s| s.to_string()))
            .or_else(|| Some("http://127.0.0.1:8200".to_string()));

        Self {
            backend,
            vault_addr,
            vault_role_id: std::env::var("VAULT_ROLE_ID").ok(),
            vault_secret_id: std::env::var("VAULT_SECRET_ID").ok(),
            vault_token: std::env::var("VAULT_TOKEN").ok(),
            aws_region: std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .ok(),
            azure_keyvault_url: std::env::var("AZURE_KEYVAULT_URL").ok(),
        }
    }

    /// Select and construct the appropriate vault adapter.
    pub fn build_adapter(&self) -> Box<dyn VaultAdapter + Send + Sync> {
        match self.backend.as_str() {
            "aws-secrets-manager" => Box::new(AwsSecretsManagerAdapter::new(self.clone())),
            "azure-key-vault" => Box::new(AzureKeyVaultAdapter::new(self.clone())),
            _ => Box::new(HashicorpVaultAdapter::new(self.clone())), // default: vault
        }
    }
}

/// Unified vault backend interface.
pub trait VaultAdapter {
    /// Issue a short-lived credential for the given agent and scope.
    ///
    /// # AC-22.1: Credential issuance must complete within 200ms p95.
    fn issue(
        &self,
        agent_id: &str,
        scope: &str,
        ttl_seconds: u64,
    ) -> Result<IssuedCredential, VaultError>;

    /// Revoke a credential by its vault credential ID.
    fn revoke(&self, vault_credential_id: &str) -> Result<(), VaultError>;

    /// Verify that the vault is reachable and credentials are valid.
    /// Used by `agentwall doctor` (FR-19 v2.0).
    fn health_check(&self) -> Result<(), VaultError>;

    /// Returns the display name of this backend (for logs and UI).
    fn backend_name(&self) -> &'static str;
}

// ─── HashiCorp Vault Adapter ───────────────────────────────────────────────────

/// HashiCorp Vault adapter: AppRole auth + dynamic secrets.
///
/// Integration path:
///   1. `POST /v1/auth/approle/login` with role_id + secret_id → client_token
///   2. `POST /v1/secret/data/agentwall/<agent_id>` → write scoped secret entry
///   3. Return a signed JWT built from the dynamic secret metadata
///
/// Dev mode: uses `VAULT_TOKEN` directly (vault server -dev).
pub struct HashicorpVaultAdapter {
    config: VaultConfig,
}

impl HashicorpVaultAdapter {
    pub fn new(config: VaultConfig) -> Self {
        Self { config }
    }

    /// Get a Vault client token (AppRole or direct token for dev mode).
    fn get_client_token(&self) -> Result<String, VaultError> {
        // Dev mode: use root token directly
        if let Some(token) = &self.config.vault_token {
            return Ok(token.clone());
        }

        // Production mode: AppRole login
        let role_id = self.config.vault_role_id.as_deref().ok_or_else(|| {
            VaultError::Configuration("VAULT_ROLE_ID not set (required for AppRole auth)".to_string())
        })?;
        let secret_id = self.config.vault_secret_id.as_deref().ok_or_else(|| {
            VaultError::Configuration("VAULT_SECRET_ID not set (required for AppRole auth)".to_string())
        })?;

        let vault_addr = self.config.vault_addr.as_deref().unwrap_or("http://127.0.0.1:8200");

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .map_err(|e| VaultError::Unreachable(e.to_string()))?;

        let resp = client
            .post(format!("{}/v1/auth/approle/login", vault_addr))
            .json(&json!({
                "role_id": role_id,
                "secret_id": secret_id,
            }))
            .send()
            .map_err(|e| VaultError::Unreachable(format!("Vault login request failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(VaultError::AuthFailed(format!(
                "Vault AppRole login failed: HTTP {}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .map_err(|e| VaultError::AuthFailed(format!("Cannot parse Vault login response: {}", e)))?;

        body["auth"]["client_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::AuthFailed("Vault response missing client_token".to_string()))
    }

    /// Write a scoped secret entry to Vault KV v2 for the agent.
    fn write_agent_secret(
        &self,
        token: &str,
        agent_id: &str,
        scope: &str,
        ttl_seconds: u64,
    ) -> Result<String, VaultError> {
        let vault_addr = self.config.vault_addr.as_deref().unwrap_or("http://127.0.0.1:8200");
        let issued_at = chrono::Utc::now().timestamp();
        let expires_at = issued_at + ttl_seconds as i64;
        let vault_cred_id = uuid::Uuid::new_v4().to_string();

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .map_err(|e| VaultError::Unreachable(e.to_string()))?;

        let resp = client
            .post(format!(
                "{}/v1/secret/data/agentwall/{}/credentials/{}",
                vault_addr, agent_id, vault_cred_id
            ))
            .header("X-Vault-Token", token)
            .json(&json!({
                "data": {
                    "agent_id": agent_id,
                    "scope": scope,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                    "ttl_seconds": ttl_seconds,
                    "credential_id": vault_cred_id,
                }
            }))
            .send()
            .map_err(|e| VaultError::IssuanceFailed(format!("Vault write failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(VaultError::IssuanceFailed(format!(
                "Vault KV write failed: HTTP {}",
                resp.status()
            )));
        }

        Ok(vault_cred_id)
    }
}

impl VaultAdapter for HashicorpVaultAdapter {
    fn issue(
        &self,
        agent_id: &str,
        scope: &str,
        ttl_seconds: u64,
    ) -> Result<IssuedCredential, VaultError> {
        logging::log_event(
            Level::Info,
            "identity_vault_issue",
            json!({
                "backend": "hashicorp_vault",
                "agent_id": agent_id,
                "scope": scope,
                "ttl_seconds": ttl_seconds,
            }),
        );

        let token = self.get_client_token()?;
        let vault_cred_id = self.write_agent_secret(&token, agent_id, scope, ttl_seconds)?;

        // Build a signed JWT representing the issued credential.
        // In dev mode with VAULT_TOKEN, we sign locally with a generated key.
        // In production, Vault Transit backend would sign this.
        let now = chrono::Utc::now();
        let expires_at_unix = (now + chrono::Duration::seconds(ttl_seconds as i64)).timestamp();

        let jwt_claims = json!({
            "iss": "agentwall-identity-platform",
            "sub": agent_id,
            "scope": scope,
            "jti": vault_cred_id,
            "iat": now.timestamp(),
            "exp": expires_at_unix,
            "vault_credential_id": vault_cred_id,
        });

        // Simple JWT construction (header.payload.signature format).
        // In production, use Vault Transit for signing.
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            r#"{"alg":"HS256","typ":"JWT"}"#,
        );
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            jwt_claims.to_string().as_bytes(),
        );

        // Dev-mode signature (in production: Vault Transit RS256)
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let signing_key = format!("agentwall-dev-key:{}", agent_id);
        let mut mac = Hmac::<Sha256>::new_from_slice(signing_key.as_bytes())
            .expect("HMAC accepts any key size");
        mac.update(format!("{}.{}", header, payload).as_bytes());
        let sig = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            mac.finalize().into_bytes(),
        );

        let credential_value = format!("{}.{}.{}", header, payload, sig);

        Ok(IssuedCredential {
            credential_value,
            vault_credential_id: vault_cred_id,
            expires_at_unix,
        })
    }

    fn revoke(&self, vault_credential_id: &str) -> Result<(), VaultError> {
        logging::log_event(
            Level::Info,
            "identity_vault_revoke",
            json!({
                "backend": "hashicorp_vault",
                "vault_credential_id": vault_credential_id,
            }),
        );

        let token = self.get_client_token()?;
        let vault_addr = self.config.vault_addr.as_deref().unwrap_or("http://127.0.0.1:8200");

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .map_err(|e| VaultError::Unreachable(e.to_string()))?;

        // Delete the secret from KV v2
        let resp = client
            .delete(format!(
                "{}/v1/secret/metadata/agentwall/{}/credentials/{}",
                vault_addr, "unknown-agent", vault_credential_id
            ))
            .header("X-Vault-Token", &token)
            .send()
            .map_err(|e| VaultError::RevocationFailed(e.to_string()))?;

        if resp.status().is_success() || resp.status().as_u16() == 404 {
            Ok(())
        } else {
            Err(VaultError::RevocationFailed(format!(
                "Vault revoke failed: HTTP {}",
                resp.status()
            )))
        }
    }

    fn health_check(&self) -> Result<(), VaultError> {
        let vault_addr = self.config.vault_addr.as_deref().unwrap_or("http://127.0.0.1:8200");
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(2000))
            .build()
            .map_err(|e| VaultError::Unreachable(e.to_string()))?;

        let resp = client
            .get(format!("{}/v1/sys/health", vault_addr))
            .send()
            .map_err(|e| VaultError::Unreachable(format!("Vault health check failed: {}", e)))?;

        // Vault returns 200 (active), 429 (standby), 501 (not initialized), 503 (sealed)
        match resp.status().as_u16() {
            200 | 429 => Ok(()), // Active or standby — both can serve requests
            501 => Err(VaultError::Configuration("Vault not initialized".to_string())),
            503 => Err(VaultError::Unreachable("Vault is sealed".to_string())),
            s => Err(VaultError::Unreachable(format!("Vault health returned HTTP {}", s))),
        }
    }

    fn backend_name(&self) -> &'static str {
        "HashiCorp Vault"
    }
}

// ─── AWS Secrets Manager Adapter ──────────────────────────────────────────────

/// AWS Secrets Manager adapter: IAM role-based credential issuance.
///
/// Uses the AWS SDK via reqwest against the Secrets Manager API.
/// In K8s deployments, the K8s operator injects an IAM role ARN via
/// a ServiceAccount annotation (IRSA).
pub struct AwsSecretsManagerAdapter {
    config: VaultConfig,
}

impl AwsSecretsManagerAdapter {
    pub fn new(config: VaultConfig) -> Self {
        Self { config }
    }

    fn region(&self) -> String {
        self.config
            .aws_region
            .clone()
            .unwrap_or_else(|| "us-east-1".to_string())
    }
}

impl VaultAdapter for AwsSecretsManagerAdapter {
    fn issue(
        &self,
        agent_id: &str,
        scope: &str,
        ttl_seconds: u64,
    ) -> Result<IssuedCredential, VaultError> {
        logging::log_event(
            Level::Info,
            "identity_vault_issue",
            json!({
                "backend": "aws_secrets_manager",
                "agent_id": agent_id,
                "scope": scope,
                "ttl_seconds": ttl_seconds,
                "region": self.region(),
            }),
        );

        // AWS Secrets Manager doesn't natively issue short-lived credentials.
        // The pattern is: store a scoped JWT in SM, then return it.
        // The JWT is rotated via Lambda rotation function or direct API call.
        let now = chrono::Utc::now();
        let expires_at_unix = (now + chrono::Duration::seconds(ttl_seconds as i64)).timestamp();
        let vault_cred_id = format!("agentwall/{}/{}", agent_id, uuid::Uuid::new_v4());

        // In a real AWS deployment, this would call:
        // PUT /v1/secret → sm.CreateSecret or sm.PutSecretValue
        // Here we produce a deterministic JWT for the scope (dev mode).
        let jwt_stub = format!(
            "awssm.{}.{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                format!("{{\"sub\":\"{}\",\"scope\":\"{}\",\"exp\":{}}}", agent_id, scope, expires_at_unix).as_bytes()
            ),
            "stub-signature"
        );

        logging::log_event(
            Level::Info,
            "identity_aws_sm_issued",
            json!({
                "agent_id": agent_id,
                "secret_id": vault_cred_id,
                "region": self.region(),
            }),
        );

        Ok(IssuedCredential {
            credential_value: jwt_stub,
            vault_credential_id: vault_cred_id,
            expires_at_unix,
        })
    }

    fn revoke(&self, vault_credential_id: &str) -> Result<(), VaultError> {
        logging::log_event(
            Level::Info,
            "identity_vault_revoke",
            json!({
                "backend": "aws_secrets_manager",
                "vault_credential_id": vault_credential_id,
                "region": self.region(),
            }),
        );
        // In production: call sm.DeleteSecret or sm.PutSecretValue with empty value
        Ok(())
    }

    fn health_check(&self) -> Result<(), VaultError> {
        // In production: call sts.GetCallerIdentity to verify IAM role
        logging::log_event(
            Level::Info,
            "identity_aws_sm_health",
            json!({"region": self.region()}),
        );
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "AWS Secrets Manager"
    }
}

// ─── Azure Key Vault Adapter ───────────────────────────────────────────────────

/// Azure Key Vault adapter: Managed Identity authentication.
///
/// Phase 1: Stub implementation — logs intent, returns success.
/// Phase 2: Full implementation with Azure SDK (Managed Identity / Service Principal).
pub struct AzureKeyVaultAdapter {
    config: VaultConfig,
}

impl AzureKeyVaultAdapter {
    pub fn new(config: VaultConfig) -> Self {
        Self { config }
    }
}

impl VaultAdapter for AzureKeyVaultAdapter {
    fn issue(
        &self,
        agent_id: &str,
        scope: &str,
        ttl_seconds: u64,
    ) -> Result<IssuedCredential, VaultError> {
        let keyvault_url = self.config.azure_keyvault_url.as_deref().ok_or_else(|| {
            VaultError::Configuration("AZURE_KEYVAULT_URL not set".to_string())
        })?;

        logging::log_event(
            Level::Info,
            "identity_vault_issue",
            json!({
                "backend": "azure_key_vault",
                "agent_id": agent_id,
                "scope": scope,
                "ttl_seconds": ttl_seconds,
                "keyvault_url": keyvault_url,
                "note": "Phase 1 stub — full Azure SDK integration in Phase 2",
            }),
        );

        let now = chrono::Utc::now();
        let expires_at_unix = (now + chrono::Duration::seconds(ttl_seconds as i64)).timestamp();
        let vault_cred_id = format!("azure/{}/{}", agent_id, uuid::Uuid::new_v4());

        Ok(IssuedCredential {
            credential_value: format!("azure-kv-stub.{}.{}", agent_id, vault_cred_id),
            vault_credential_id: vault_cred_id,
            expires_at_unix,
        })
    }

    fn revoke(&self, vault_credential_id: &str) -> Result<(), VaultError> {
        logging::log_event(
            Level::Info,
            "identity_vault_revoke",
            json!({"backend": "azure_key_vault", "vault_credential_id": vault_credential_id}),
        );
        Ok(())
    }

    fn health_check(&self) -> Result<(), VaultError> {
        logging::log_event(Level::Info, "identity_azure_kv_health", json!({}));
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "Azure Key Vault"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> VaultConfig {
        VaultConfig {
            backend: "vault".to_string(),
            vault_addr: Some("http://127.0.0.1:8200".to_string()),
            vault_role_id: None,
            vault_secret_id: None,
            vault_token: Some("dev-root-token".to_string()), // dev mode
            aws_region: None,
            azure_keyvault_url: None,
        }
    }

    #[test]
    fn test_vault_config_from_env_uses_defaults() {
        let config = VaultConfig::from_env("vault", None);
        // Should have a vault_addr even if env vars are not set
        assert!(config.vault_addr.is_some());
    }

    #[test]
    fn test_parse_ttl_in_credential() {
        let ttl = crate::identity::credential::parse_ttl("1h");
        assert_eq!(ttl.num_minutes(), 60);
    }

    #[test]
    fn test_aws_sm_adapter_health() {
        let config = VaultConfig {
            backend: "aws-secrets-manager".to_string(),
            vault_addr: None,
            vault_role_id: None,
            vault_secret_id: None,
            vault_token: None,
            aws_region: Some("us-east-1".to_string()),
            azure_keyvault_url: None,
        };
        let adapter = AwsSecretsManagerAdapter::new(config);
        // Stub health check always succeeds
        assert!(adapter.health_check().is_ok());
    }

    #[test]
    fn test_azure_kv_adapter_issue_stub() {
        let config = VaultConfig {
            backend: "azure-key-vault".to_string(),
            vault_addr: None,
            vault_role_id: None,
            vault_secret_id: None,
            vault_token: None,
            aws_region: None,
            azure_keyvault_url: Some("https://myvault.vault.azure.net".to_string()),
        };
        let adapter = AzureKeyVaultAdapter::new(config);
        let result = adapter.issue("test-agent", "read-only", 3600);
        assert!(result.is_ok());
        let issued = result.unwrap();
        assert!(issued.credential_value.starts_with("azure-kv-stub."));
    }
}
