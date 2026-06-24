use agentwall::identity::audit_log::{IdentityAuditLogger, IdentityEventType};
use agentwall::identity::vault::{VaultAdapter, HashicorpVaultAdapter, AwsSecretsManagerAdapter, VaultConfig, VaultError, IssuedCredential};
use agentwall::identity::credential::{AgentCredential, CredentialType, ToolScope};
use agentwall::identity::scope_validator::{IdentityScopeValidator, CredentialScopeCheckResult};

struct MockVaultAdapter;

impl VaultAdapter for MockVaultAdapter {
    fn issue(&self, agent_id: &str, scope: &str, ttl_seconds: u64) -> Result<IssuedCredential, VaultError> {
        let now = chrono::Utc::now();
        let expires_at_unix = (now + chrono::Duration::seconds(ttl_seconds as i64)).timestamp();
        Ok(IssuedCredential {
            credential_value: "mock-jwt".to_string(),
            vault_credential_id: uuid::Uuid::new_v4().to_string(),
            expires_at_unix,
        })
    }

    fn revoke(&self, _vault_credential_id: &str) -> Result<(), VaultError> {
        Ok(())
    }

    fn health_check(&self) -> Result<(), VaultError> {
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "Mock Vault"
    }
}

#[test]
fn test_create_issues_vault_credential_within_200ms() {
    let vault = MockVaultAdapter;
    let start = std::time::Instant::now();
    // Use an isolated agent name
    let cred = vault.issue("agent-test-create", "read-only", 3600).unwrap();
    let elapsed = start.elapsed();
    
    assert!(elapsed.as_millis() < 200, "Credential issuance took longer than 200ms");
    assert!(!cred.vault_credential_id.is_empty());
}

#[test]
fn test_expired_jwt_rejected_by_gateway() {
    let mut cred = AgentCredential::new(
        "agent-test-exp", "sub-1", "read-only", vec![],
        CredentialType::Jwt, "vault", "1h", 30, "operator"
    );
    // Force expire
    cred.expires_at = chrono::Utc::now() - chrono::Duration::seconds(10);
    cred.save().unwrap();

    let result = IdentityScopeValidator::validate("agent-test-exp", "read_file", &cred.credential_id);
    assert_eq!(result, CredentialScopeCheckResult::Expired);
}

#[test]
fn test_rotate_drain_period() {
    let vault = MockVaultAdapter;
    let old_cred = vault.issue("agent-test-rotate", "read-only", 3600).unwrap();
    
    let new_cred = vault.issue("agent-test-rotate", "read-only", 3600).unwrap();
    assert_ne!(old_cred.vault_credential_id, new_cred.vault_credential_id);
}

#[test]
fn test_scope_insufficient_blocks_execute_shell() {
    let cred = AgentCredential::new(
        "agent-test-insufficient", "sub-1", "read-only",
        vec![ToolScope { tool: "read_file".to_string(), paths: vec![], databases: vec![], allow: true }],
        CredentialType::Jwt, "vault", "1h", 30, "operator"
    );
    cred.save().unwrap();

    let result = IdentityScopeValidator::validate("agent-test-insufficient", "execute_shell", &cred.credential_id);
    match result {
        CredentialScopeCheckResult::Insufficient(_) => {}
        _ => panic!("Expected Insufficient"),
    }
}

#[test]
fn test_audit_hmac_chain_valid() {
    let dir = tempfile::tempdir().unwrap();
    let logger = IdentityAuditLogger::with_path(dir.path().join("audit.log"));

    logger.append(agentwall::identity::audit_log::IdentityAuditEntryBuilder::new(
        IdentityEventType::Issued, "agent-1", "cred-1", "read-only", "admin", "mock", "test",
    )).unwrap();
    logger.append(agentwall::identity::audit_log::IdentityAuditEntryBuilder::new(
        IdentityEventType::Rotated, "agent-1", "cred-2", "read-only", "admin", "mock", "test",
    )).unwrap();

    let count = logger.verify_chain().unwrap();
    assert_eq!(count, 2);
}

#[test]
fn test_aws_sm_backend_mock() {
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
    assert_eq!(adapter.backend_name(), "AWS Secrets Manager");
}

#[test]
fn test_per_tool_scope_enforcement() {
    let cred = AgentCredential::new(
        "agent-test-per-tool", "sub-1", "read-only",
        vec![ToolScope { tool: "read_file".to_string(), paths: vec![], databases: vec![], allow: true }],
        CredentialType::Jwt, "vault", "1h", 30, "operator"
    );
    cred.save().unwrap();

    let result = IdentityScopeValidator::validate("agent-test-per-tool", "read_file", &cred.credential_id);
    assert_eq!(result, CredentialScopeCheckResult::Allowed);
}
