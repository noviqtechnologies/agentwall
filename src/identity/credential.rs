//! FR-22: Agent credential data model and JWT issuance
//!
//! Defines `AgentCredential` — the credential binding record stored locally
//! at `~/.agentwall/credentials/<agent_name>.json`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The type of credential issued by the identity platform.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    /// Short-lived JWT (RS256-signed). Default TTL: 1 hour.
    Jwt,
    /// mTLS client certificate. Default TTL: 24 hours.
    Mtls,
    /// SPIFFE/SPIRE SVID (Phase 3 only).
    Spiffe,
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jwt => write!(f, "jwt"),
            Self::Mtls => write!(f, "mtls"),
            Self::Spiffe => write!(f, "spiffe"),
        }
    }
}

/// Lifecycle state of a credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CredentialStatus {
    /// Active — within TTL, valid for use.
    Active,
    /// Draining — rotation in progress; valid for drain_secs after rotation.
    Draining,
    /// Revoked — credential has been invalidated.
    Revoked,
    /// Expired — TTL has elapsed; not explicitly revoked.
    Expired,
}

impl std::fmt::Display for CredentialStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Draining => write!(f, "draining"),
            Self::Revoked => write!(f, "revoked"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

/// Per-tool scope constraint from the credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolScope {
    /// Tool name this scope constraint applies to.
    pub tool: String,
    /// Specific allowed paths (for read_file, write_file). Empty = no restriction.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Specific allowed databases (for execute_query). Empty = no restriction.
    #[serde(default)]
    pub databases: Vec<String>,
    /// If true, this tool is explicitly allowed by this credential.
    pub allow: bool,
}

/// The credential binding record stored locally.
///
/// Written to `~/.agentwall/credentials/<agent_name>.json` after `identity create`.
/// The raw credential value (JWT token / mTLS cert) is NOT stored here —
/// it is returned to the caller at issuance time and must be stored securely
/// by the agent runtime (e.g., injected as an environment variable by the K8s operator).
///
/// This record contains only the metadata needed for policy validation and auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCredential {
    /// Unique credential binding identifier (UUIDv4).
    pub credential_id: String,
    /// Agent identifier (matches `agents[].id` in the policy YAML).
    pub agent_id: String,
    /// OIDC `sub` claim this credential is bound to.
    /// An agent can only use this credential if its JWT `sub` matches.
    pub agent_sub: String,
    /// The scope string used to issue this credential (e.g., "read-only", "analytics").
    pub scope: String,
    /// Per-tool scope constraints (AC-22.10: per-tool-call scoping).
    #[serde(default)]
    pub tool_scopes: Vec<ToolScope>,
    /// Credential type (jwt / mtls / spiffe).
    pub credential_type: CredentialType,
    /// Vault backend used to issue this credential.
    pub vault_backend: String,
    /// Timestamp when this credential was issued.
    pub issued_at: DateTime<Utc>,
    /// Timestamp when this credential expires.
    pub expires_at: DateTime<Utc>,
    /// TTL string used at issuance (e.g., "1h").
    pub ttl: String,
    /// Rotation drain period in seconds (old credential valid for this long after rotation).
    pub drain_secs: u64,
    /// Authorizing operator (the identity of the operator who provisioned this credential).
    pub authorized_by: String,
    /// Current lifecycle status.
    pub status: CredentialStatus,
    /// SHA-256 binding hash (HMAC of agent_id + agent_sub + scope + issued_at).
    /// Used to cryptographically link this binding record to the audit log entry.
    pub binding_hash: String,
    /// JWT `jti` claim (if credential_type = jwt). Used for revocation lookups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,
}

impl AgentCredential {
    /// Create a new credential binding record.
    ///
    /// # Arguments
    /// - `agent_id`: The agent name / ID (from `--agent` flag)
    /// - `agent_sub`: The OIDC `sub` claim to bind to
    /// - `scope`: The scope string requested
    /// - `tool_scopes`: Per-tool-call scope constraints
    /// - `credential_type`: jwt / mtls
    /// - `vault_backend`: Which vault backend issued this
    /// - `ttl`: TTL string (e.g., "1h")
    /// - `drain_secs`: Drain period after rotation
    /// - `authorized_by`: Operator identity
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent_id: &str,
        agent_sub: &str,
        scope: &str,
        tool_scopes: Vec<ToolScope>,
        credential_type: CredentialType,
        vault_backend: &str,
        ttl: &str,
        drain_secs: u64,
        authorized_by: &str,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + parse_ttl(ttl);
        let credential_id = Uuid::new_v4().to_string();

        let binding_hash = compute_binding_hash(agent_id, agent_sub, scope, &now.to_rfc3339());

        Self {
            credential_id,
            agent_id: agent_id.to_string(),
            agent_sub: agent_sub.to_string(),
            scope: scope.to_string(),
            tool_scopes,
            credential_type,
            vault_backend: vault_backend.to_string(),
            issued_at: now,
            expires_at,
            ttl: ttl.to_string(),
            drain_secs,
            authorized_by: authorized_by.to_string(),
            status: CredentialStatus::Active,
            binding_hash,
            jwt_id: None,
        }
    }

    /// Check if this credential is currently valid (active and not expired).
    pub fn is_valid(&self) -> bool {
        matches!(self.status, CredentialStatus::Active | CredentialStatus::Draining)
            && Utc::now() < self.expires_at
    }

    /// Check if the credential permits calling the given tool.
    ///
    /// This implements AC-22.10: per-tool-call credential scoping.
    /// If no tool_scopes are configured, all tools allowed by the policy are permitted.
    pub fn permits_tool(&self, tool_name: &str) -> bool {
        if self.tool_scopes.is_empty() {
            return true; // No per-tool restrictions configured
        }
        self.tool_scopes
            .iter()
            .any(|ts| ts.tool == tool_name && ts.allow)
    }

    /// Returns TTL remaining in seconds (0 if expired).
    pub fn ttl_remaining_secs(&self) -> i64 {
        let remaining = (self.expires_at - Utc::now()).num_seconds();
        remaining.max(0)
    }

    /// Returns the directory where credential files are stored.
    pub fn credentials_dir() -> std::path::PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".agentwall")
            .join("credentials")
    }

    /// Returns the file path for this agent's credential.
    pub fn credential_file_path(agent_id: &str) -> std::path::PathBuf {
        Self::credentials_dir().join(format!("{}.json", agent_id))
    }

    /// Persist this credential binding to disk.
    ///
    /// WARNING: The raw credential (JWT token / mTLS cert) is NOT stored here.
    /// Only the binding metadata is persisted for policy validation and auditing.
    pub fn save(&self) -> std::io::Result<()> {
        let dir = Self::credentials_dir();
        std::fs::create_dir_all(&dir)?;
        let path = Self::credential_file_path(&self.agent_id);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load a credential binding from disk.
    pub fn load(agent_id: &str) -> Result<Self, String> {
        let path = Self::credential_file_path(agent_id);
        if !path.exists() {
            return Err(format!(
                "No credential found for agent '{}'. Run: agentwall identity create --agent {}",
                agent_id, agent_id
            ));
        }
        let json = std::fs::read_to_string(&path)
            .map_err(|e| format!("Cannot read credential file: {}", e))?;
        serde_json::from_str(&json)
            .map_err(|e| format!("Cannot parse credential file: {}", e))
    }
}

/// Parse a TTL string (e.g., "1h", "30m", "24h") into a chrono Duration.
pub fn parse_ttl(ttl: &str) -> chrono::Duration {
    if let Some(h) = ttl.strip_suffix('h') {
        if let Ok(n) = h.parse::<i64>() {
            return chrono::Duration::hours(n);
        }
    }
    if let Some(m) = ttl.strip_suffix('m') {
        if let Ok(n) = m.parse::<i64>() {
            return chrono::Duration::minutes(n);
        }
    }
    if let Some(s) = ttl.strip_suffix('s') {
        if let Ok(n) = s.parse::<i64>() {
            return chrono::Duration::seconds(n);
        }
    }
    // Default: 1 hour
    chrono::Duration::hours(1)
}

/// Compute a binding hash for a credential record.
/// HMAC-SHA256(agent_id + ":" + agent_sub + ":" + scope + ":" + issued_at)
fn compute_binding_hash(agent_id: &str, agent_sub: &str, scope: &str, issued_at: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Use a deterministic salt derived from the agent identity for the binding hash.
    // In production with Vault, this would use a hardware-rooted key.
    let salt = format!("agentwall-v2-identity-binding:{}", agent_id);
    let mut mac = Hmac::<Sha256>::new_from_slice(salt.as_bytes())
        .expect("HMAC accepts any key size");
    mac.update(format!("{}:{}:{}:{}", agent_id, agent_sub, scope, issued_at).as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ttl_hours() {
        assert_eq!(parse_ttl("1h"), chrono::Duration::hours(1));
        assert_eq!(parse_ttl("24h"), chrono::Duration::hours(24));
    }

    #[test]
    fn test_parse_ttl_minutes() {
        assert_eq!(parse_ttl("30m"), chrono::Duration::minutes(30));
    }

    #[test]
    fn test_parse_ttl_invalid_defaults_to_1h() {
        assert_eq!(parse_ttl("invalid"), chrono::Duration::hours(1));
    }

    #[test]
    fn test_credential_is_valid_when_active() {
        let cred = AgentCredential::new(
            "test-agent",
            "test@example.com",
            "read-only",
            vec![],
            CredentialType::Jwt,
            "vault",
            "1h",
            30,
            "operator",
        );
        assert!(cred.is_valid());
        assert!(cred.ttl_remaining_secs() > 3500); // At least 58.3 min left
    }

    #[test]
    fn test_permits_tool_no_restrictions() {
        let cred = AgentCredential::new(
            "test-agent", "test@example.com", "read-only",
            vec![], CredentialType::Jwt, "vault", "1h", 30, "operator",
        );
        // No tool_scopes = all tools permitted
        assert!(cred.permits_tool("read_file"));
        assert!(cred.permits_tool("execute_shell"));
    }

    #[test]
    fn test_permits_tool_with_restrictions() {
        let cred = AgentCredential::new(
            "test-agent", "test@example.com", "read-only",
            vec![
                ToolScope { tool: "read_file".to_string(), paths: vec![], databases: vec![], allow: true },
                ToolScope { tool: "execute_shell".to_string(), paths: vec![], databases: vec![], allow: false },
            ],
            CredentialType::Jwt, "vault", "1h", 30, "operator",
        );
        assert!(cred.permits_tool("read_file"));       // allowed
        assert!(!cred.permits_tool("execute_shell"));  // denied (allow=false)
        assert!(!cred.permits_tool("execute_query"));  // not listed = denied
    }

    #[test]
    fn test_binding_hash_is_deterministic() {
        let h1 = super::compute_binding_hash("agent-a", "sub-1", "read-only", "2026-01-01T00:00:00Z");
        let h2 = super::compute_binding_hash("agent-a", "sub-1", "read-only", "2026-01-01T00:00:00Z");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_binding_hash_differs_for_different_inputs() {
        let h1 = super::compute_binding_hash("agent-a", "sub-1", "read-only", "2026-01-01T00:00:00Z");
        let h2 = super::compute_binding_hash("agent-b", "sub-2", "admin", "2026-01-01T00:00:00Z");
        assert_ne!(h1, h2);
    }
}
