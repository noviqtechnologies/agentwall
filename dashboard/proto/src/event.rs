//! Redacted event — the top-level wire-boundary type.
//!
//! Every field here is either an opaque identifier, a category/enum
//! discriminant, a count, a duration, or a static pattern label. There is
//! deliberately NO `String` field into which arbitrary user data, tool
//! parameters, or DLP match content is placed.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single agent activity event, fully redacted, safe for dashboard-api ingest.
///
/// # Invariants (enforced by construction path)
/// - No raw tool parameters, response bodies, or DLP match content.
/// - `session_id`, `agent_id`, `tool_name` are caller-vouched-for identifiers.
///   See [`crate::redact::redact_event`] for the trust contract — in
///   particular, `tool_name` is replaced with `<unlisted_tool>` when the
///   gateway signals the tool was not on the policy allowlist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RedactedEvent {
    pub event_id: Uuid,
    pub timestamp_ms: i64,
    pub session_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub decision: RedactedDecision,
    pub dlp_findings: Vec<RedactedDlpFinding>,
    pub injection_findings: Vec<RedactedInjectionFinding>,
    pub semantic_findings: Vec<RedactedSemanticFinding>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RedactedDecision {
    Allowed,
    Denied,
    Warned,
}

/// A single DLP finding, with the raw match stripped.
///
/// Deliberately absent, compared to `crate::policy::dlp::SecretFinding` in
/// the gateway: `position`, `length`, `preview`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactedDlpFinding {
    pub category: SecretCategory,
    pub pattern_name: String,
    pub count: u32,
}

/// Category of secret detected.
///
/// Mirrors `crate::policy::dlp::SecretCategory` in the gateway crate.
/// Duplicated here (rather than re-exported) to keep the dependency
/// direction one-way: gateway → dashboard-proto, never the reverse.
///
/// Drift protection: the gateway provides
/// `impl From<dlp::SecretCategory> for dashboard_proto::SecretCategory`
/// with an exhaustive match. If either enum grows a variant the other
/// doesn't, that impl fails to compile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SecretCategory {
    AwsAccessKey,
    GitHubToken,
    OpenAiApiKey,
    AnthropicApiKey,
    SshPrivateKey,
    StripeKey,
    DatabaseUri,
    Pii,
    HighEntropy,
    CryptoSeedPhrase,
    EnvVar,
    AzureStorageKey,
    GcpApiKey,
    SlackToken,
    SendGridKey,
    CreditCard,
    Other,
}

/// A single injection scanner finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactedInjectionFinding {
    pub pattern_name: String,
    pub count: u32,
}

/// A single semantic scanner finding.
///
/// Deliberately absent, compared to `crate::policy::semantic::SemanticFinding`
/// in the gateway: `explanation`. Dropped entirely — the dashboard renders
/// human-readable text client-side from `finding_type`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RedactedSemanticFinding {
    pub anomaly_score: f32,
    pub finding_type: SemanticFindingType,
}

/// Semantic finding category.
///
/// Mirrors `crate::policy::semantic::SemanticFindingType` — same drift-
/// protection contract as [`SecretCategory`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SemanticFindingType {
    ToolDescriptionPoisoning,
    ResponseInstructionManipulation,
    SemanticExfiltration,
}
