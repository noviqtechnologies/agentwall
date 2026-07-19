//! Sanitized credential metadata — never the credential itself.

use serde::{Deserialize, Serialize};

/// Metadata for a single agent credential, safe for dashboard display.
///
/// # Non-representability
/// - `credential_id` is an opaque identifier assigned at provisioning time.
///   It is NOT derived from the secret value.
/// - There is no field into which the credential value could be placed.
/// - [`RotationRecord`] holds only rotation timestamps and reasons — never
///   past secret values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizedCredentialMeta {
    pub credential_id: String,
    pub agent_id: String,
    pub scope: Vec<String>,
    pub ttl_seconds: u64,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub last_rotated_at_ms: Option<i64>,
    pub rotation_history: Vec<RotationRecord>,
}

/// A single rotation event in the credential's history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationRecord {
    pub rotated_at_ms: i64,
    pub reason: RotationReason,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    Scheduled,
    Manual,
    Compromise,
    PolicyChange,
}
