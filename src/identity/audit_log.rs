//! FR-22: HMAC-chained identity audit log
//!
//! Separate from the egress audit log (src/audit/logger.rs), this log records
//! all identity governance events:
//!
//! - Credential issuance (ISSUED)
//! - Credential rotation (ROTATED)
//! - Credential revocation (REVOKED)
//! - Scope policy changes (SCOPE_CHANGED)
//! - Validation failures (VALIDATION_FAILED)
//!
//! Each entry is HMAC-SHA256 chained to the previous entry, providing
//! tamper-evident audit history.
//!
//! File location: `~/.agentwall/identity_audit.log`

use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::PathBuf;

/// Identity audit event type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityEventType {
    /// A new credential was provisioned.
    Issued,
    /// A credential was rotated (new credential issued, old one draining).
    Rotated,
    /// A credential was explicitly revoked.
    Revoked,
    /// A credential was allowed to expire naturally (no revocation call).
    Expired,
    /// A per-tool scope rule was added or modified.
    ScopeChanged,
    /// An identity validation check failed at the gateway.
    ValidationFailed,
    /// A credential was used for a tool call.
    Used,
}

impl std::fmt::Display for IdentityEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Issued => write!(f, "ISSUED"),
            Self::Rotated => write!(f, "ROTATED"),
            Self::Revoked => write!(f, "REVOKED"),
            Self::Expired => write!(f, "EXPIRED"),
            Self::ScopeChanged => write!(f, "SCOPE_CHANGED"),
            Self::ValidationFailed => write!(f, "VALIDATION_FAILED"),
            Self::Used => write!(f, "USED"),
        }
    }
}

/// A single entry in the identity audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAuditEntry {
    /// Sequential index within this log file (1-indexed).
    pub index: u64,
    /// Event type.
    pub event_type: IdentityEventType,
    /// Agent identifier.
    pub agent_id: String,
    /// Credential binding ID this event relates to.
    pub credential_id: String,
    /// New credential ID (for ROTATED events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_credential_id: Option<String>,
    /// Credential scope.
    pub scope: String,
    /// Tool name (for SCOPE_CHANGED and USED events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Operator or system that triggered this event.
    pub authorized_by: String,
    /// ISO-8601 timestamp (UTC, nanosecond precision).
    pub timestamp: String,
    /// Unix nanosecond timestamp for sorting.
    pub timestamp_ns: i64,
    /// Vault backend used.
    pub vault_backend: String,
    /// Human-readable description of what happened.
    pub description: String,
    /// HMAC-SHA256 of (index + event_type + agent_id + credential_id + scope + timestamp_ns + prev_hmac).
    pub hmac: String,
    /// HMAC of the previous entry (or "genesis" for the first entry).
    pub prev_hmac: String,
}

/// HMAC-chained identity audit logger.
pub struct IdentityAuditLogger {
    log_path: PathBuf,
}

impl IdentityAuditLogger {
    /// Create a new logger pointing at `~/.agentwall/identity_audit.log`.
    pub fn new() -> Self {
        let path = identity_log_path();
        Self { log_path: path }
    }

    /// Create with a custom log path (for testing).
    pub fn with_path(path: PathBuf) -> Self {
        Self { log_path: path }
    }

    /// Append a new audit entry to the log.
    ///
    /// Reads the last entry to get the previous HMAC, computes the new HMAC,
    /// and appends the entry as a JSONL record.
    pub fn append(&self, entry_builder: IdentityAuditEntryBuilder) -> Result<IdentityAuditEntry, String> {
        // Ensure the directory exists
        if let Some(parent) = self.log_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create identity audit log directory: {}", e))?;
        }

        // Read existing entries to get the last index and prev_hmac
        let (next_index, prev_hmac) = self.read_last_entry_meta()?;

        let now = Utc::now();
        let timestamp_ns = now.timestamp_nanos_opt().unwrap_or(0);
        let timestamp = now.to_rfc3339();

        // Build the entry
        let hmac = compute_entry_hmac(
            next_index,
            &entry_builder.event_type,
            &entry_builder.agent_id,
            &entry_builder.credential_id,
            &entry_builder.scope,
            timestamp_ns,
            &prev_hmac,
        );

        let entry = IdentityAuditEntry {
            index: next_index,
            event_type: entry_builder.event_type,
            agent_id: entry_builder.agent_id,
            credential_id: entry_builder.credential_id,
            new_credential_id: entry_builder.new_credential_id,
            scope: entry_builder.scope,
            tool_name: entry_builder.tool_name,
            authorized_by: entry_builder.authorized_by,
            timestamp,
            timestamp_ns,
            vault_backend: entry_builder.vault_backend,
            description: entry_builder.description,
            hmac,
            prev_hmac,
        };

        // Append as a JSONL record
        let line = serde_json::to_string(&entry)
            .map_err(|e| format!("Cannot serialize identity audit entry: {}", e))?;

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| format!("Cannot open identity audit log: {}", e))?;
        writeln!(file, "{}", line)
            .map_err(|e| format!("Cannot write identity audit entry: {}", e))?;

        Ok(entry)
    }

    /// Read all entries from the log, sorted by index.
    pub fn read_all(&self) -> Result<Vec<IdentityAuditEntry>, String> {
        if !self.log_path.exists() {
            return Ok(vec![]);
        }
        let content = std::fs::read_to_string(&self.log_path)
            .map_err(|e| format!("Cannot read identity audit log: {}", e))?;
        let mut entries = Vec::new();
        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: IdentityAuditEntry = serde_json::from_str(line).map_err(|e| {
                format!("Cannot parse identity audit log at line {}: {}", line_num + 1, e)
            })?;
            entries.push(entry);
        }
        entries.sort_by_key(|e| e.index);
        Ok(entries)
    }

    /// Read all entries for a specific agent.
    pub fn read_for_agent(&self, agent_id: &str) -> Result<Vec<IdentityAuditEntry>, String> {
        let all = self.read_all()?;
        Ok(all.into_iter().filter(|e| e.agent_id == agent_id).collect())
    }

    /// Verify the HMAC chain integrity.
    ///
    /// Returns `Ok(entry_count)` if the chain is intact, `Err(reason)` if broken.
    pub fn verify_chain(&self) -> Result<u64, String> {
        let entries = self.read_all()?;
        if entries.is_empty() {
            return Ok(0);
        }

        let mut prev_hmac = "genesis".to_string();
        for entry in &entries {
            let expected_hmac = compute_entry_hmac(
                entry.index,
                &entry.event_type,
                &entry.agent_id,
                &entry.credential_id,
                &entry.scope,
                entry.timestamp_ns,
                &entry.prev_hmac,
            );

            if entry.hmac != expected_hmac {
                return Err(format!(
                    "HMAC chain broken at entry {} (agent: {}, type: {}): expected {}, got {}",
                    entry.index, entry.agent_id, entry.event_type, expected_hmac, entry.hmac
                ));
            }

            if entry.prev_hmac != prev_hmac {
                return Err(format!(
                    "HMAC chain linkage broken at entry {}: prev_hmac mismatch",
                    entry.index
                ));
            }

            prev_hmac = entry.hmac.clone();
        }

        Ok(entries.len() as u64)
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    fn read_last_entry_meta(&self) -> Result<(u64, String), String> {
        if !self.log_path.exists() {
            return Ok((1, "genesis".to_string()));
        }

        let content = std::fs::read_to_string(&self.log_path)
            .map_err(|e| format!("Cannot read identity audit log: {}", e))?;

        let last_line = content.lines().rfind(|l| !l.trim().is_empty());

        match last_line {
            None => Ok((1, "genesis".to_string())),
            Some(line) => {
                let entry: IdentityAuditEntry = serde_json::from_str(line)
                    .map_err(|e| format!("Cannot parse last identity audit entry: {}", e))?;
                Ok((entry.index + 1, entry.hmac))
            }
        }
    }
}

impl Default for IdentityAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating audit log entries.
#[derive(Debug)]
pub struct IdentityAuditEntryBuilder {
    pub event_type: IdentityEventType,
    pub agent_id: String,
    pub credential_id: String,
    pub new_credential_id: Option<String>,
    pub scope: String,
    pub tool_name: Option<String>,
    pub authorized_by: String,
    pub vault_backend: String,
    pub description: String,
}

impl IdentityAuditEntryBuilder {
    pub fn new(
        event_type: IdentityEventType,
        agent_id: &str,
        credential_id: &str,
        scope: &str,
        authorized_by: &str,
        vault_backend: &str,
        description: &str,
    ) -> Self {
        Self {
            event_type,
            agent_id: agent_id.to_string(),
            credential_id: credential_id.to_string(),
            new_credential_id: None,
            scope: scope.to_string(),
            tool_name: None,
            authorized_by: authorized_by.to_string(),
            vault_backend: vault_backend.to_string(),
            description: description.to_string(),
        }
    }
}

/// Returns the default path for the identity audit log.
fn identity_log_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agentwall")
        .join("identity_audit.log")
}

/// Compute HMAC for a single audit entry.
///
/// HMAC-SHA256 of (index + event_type + agent_id + credential_id + scope + timestamp_ns + prev_hmac)
fn compute_entry_hmac(
    index: u64,
    event_type: &IdentityEventType,
    agent_id: &str,
    credential_id: &str,
    scope: &str,
    timestamp_ns: i64,
    prev_hmac: &str,
) -> String {
    // Key: derivation seed specific to identity audit log
    let key = b"agentwall-identity-audit-v2-hmac-key";
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC accepts any key size");

    let data = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        index, event_type, agent_id, credential_id, scope, timestamp_ns, prev_hmac
    );
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_logger(dir: &std::path::Path) -> IdentityAuditLogger {
        IdentityAuditLogger::with_path(dir.join("identity_audit.log"))
    }

    #[test]
    fn test_append_and_read() {
        let dir = tempdir().unwrap();
        let logger = make_logger(dir.path());

        let entry = logger.append(IdentityAuditEntryBuilder::new(
            IdentityEventType::Issued,
            "test-agent",
            "cred-001",
            "read-only",
            "operator",
            "vault",
            "Credential issued for test-agent",
        )).unwrap();

        assert_eq!(entry.index, 1);
        assert_eq!(entry.prev_hmac, "genesis");
        assert!(!entry.hmac.is_empty());

        let entries = logger.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].agent_id, "test-agent");
    }

    #[test]
    fn test_chain_integrity_valid() {
        let dir = tempdir().unwrap();
        let logger = make_logger(dir.path());

        logger.append(IdentityAuditEntryBuilder::new(
            IdentityEventType::Issued, "agent-a", "cred-001", "read-only",
            "operator", "vault", "First entry",
        )).unwrap();

        logger.append(IdentityAuditEntryBuilder::new(
            IdentityEventType::Rotated, "agent-a", "cred-001", "read-only",
            "operator", "vault", "Rotation",
        )).unwrap();

        let count = logger.verify_chain().unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_chain_integrity_detects_tampering() {
        let dir = tempdir().unwrap();
        let logger = make_logger(dir.path());

        logger.append(IdentityAuditEntryBuilder::new(
            IdentityEventType::Issued, "agent-a", "cred-001", "read-only",
            "operator", "vault", "First entry",
        )).unwrap();

        // Tamper with the log file
        let log_path = dir.path().join("identity_audit.log");
        let content = std::fs::read_to_string(&log_path).unwrap();
        let tampered = content.replace("read-only", "admin"); // scope escalation attempt
        std::fs::write(&log_path, tampered).unwrap();

        let result = logger.verify_chain();
        assert!(result.is_err(), "Chain verification should fail after tampering");
    }

    #[test]
    fn test_read_for_agent_filters_correctly() {
        let dir = tempdir().unwrap();
        let logger = make_logger(dir.path());

        logger.append(IdentityAuditEntryBuilder::new(
            IdentityEventType::Issued, "agent-a", "cred-001", "read-only",
            "operator", "vault", "Entry for agent-a",
        )).unwrap();

        logger.append(IdentityAuditEntryBuilder::new(
            IdentityEventType::Issued, "agent-b", "cred-002", "admin",
            "operator", "vault", "Entry for agent-b",
        )).unwrap();

        let agent_a_entries = logger.read_for_agent("agent-a").unwrap();
        assert_eq!(agent_a_entries.len(), 1);
        assert_eq!(agent_a_entries[0].agent_id, "agent-a");
    }
}
