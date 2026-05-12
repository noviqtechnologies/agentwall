//! Policy YAML schema types — strict deserialization (FR-103)
//!
//! Implements the v1 policy schema exactly as specified in PRD §6.1.
//! Uses `#[serde(deny_unknown_fields)]` for strict parsing at all levels.

use serde::Deserialize;

/// The supported policy schema versions.
pub const SUPPORTED_VERSIONS: &[&str] = &["1", "2"];

/// Top-level policy document.
/// Unknown fields at any level cause a fatal startup error.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Required. Must be "1" or "2". Any other value = fatal error.
    pub version: String,

    /// Required. Must be "deny". "allow" = fatal error. Absent = fatal error.
    pub default_action: String,

    /// Identity binding configuration (v2 only).
    pub identity: Option<IdentityConfig>,

    /// Optional session configuration.
    pub session: Option<SessionConfig>,

    /// FR-303b: Response scanning configuration.
    pub response_scanning: Option<ResponseScanningConfig>,

    /// Tool allowlist. Empty = all denied.
    pub tools: Option<Vec<ToolRule>>,
}

/// Identity configuration (OIDC).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub issuer: String,
    pub audience: String,
}

/// Response scanning configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseScanningConfig {
    /// Tools whose output should be scanned for secrets.
    pub scannable_tools: Option<Vec<String>>,
    /// Tools whose output is guaranteed safe and should never be scanned.
    pub safe_tools: Option<Vec<String>>,
}

/// Session-level configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// Max tool calls per second. 0 = unlimited. Optional.
    pub max_calls_per_second: Option<u32>,
}

/// Tool risk level.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ToolRisk {
    Low,
    Medium,
    High,
}

/// A single tool rule in the allowlist.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    /// Exact case-sensitive tool name or regex (v2).
    pub name: String,

    /// "allow", "deny", or "notify" (v2).
    pub action: String,

    /// Tool risk score (v2).
    pub risk: Option<ToolRisk>,

    /// Parameter constraints. Optional.
    pub parameters: Option<Vec<ParameterRule>>,
}

/// Parameter type enumeration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    String,
    Number,
    Boolean,
    Object,
    Array,
}

impl std::fmt::Display for ParamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamType::String => write!(f, "string"),
            ParamType::Number => write!(f, "number"),
            ParamType::Boolean => write!(f, "boolean"),
            ParamType::Object => write!(f, "object"),
            ParamType::Array => write!(f, "array"),
        }
    }
}

/// A single parameter constraint within a tool rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterRule {
    /// Parameter name (case-sensitive).
    pub name: String,

    /// Expected JSON type.
    #[serde(rename = "type")]
    pub param_type: ParamType,

    /// Nested JSON Schema (Draft 7 subset) (FR-201).
    pub schema: Option<serde_json::Value>,

    /// Regex pattern (string type only). Auto-anchored with ^(?:...)$ unless unanchored: true.
    pub pattern: Option<String>,

    /// If true, do not auto-anchor the pattern. Default: false.
    /// Logs a startup WARNING for each unanchored parameter.
    #[serde(default)]
    pub unanchored: bool,

    /// Max byte length (string type only). Optional.
    pub max_length: Option<usize>,

    /// If true, parameter must be present. Default: false.
    #[serde(default)]
    pub required: bool,
}
