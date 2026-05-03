//! Policy YAML schema types — strict deserialization (FR-103)
//!
//! Implements the v1 policy schema exactly as specified in PRD §6.1.
//! Uses `#[serde(deny_unknown_fields)]` for strict parsing at all levels.

use serde::Deserialize;

/// The supported policy schema versions.
pub const SUPPORTED_VERSIONS: &[&str] = &["1"];

/// Top-level policy document.
/// Unknown fields at any level cause a fatal startup error.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Required. Must be "1". Any other value = fatal error.
    pub version: String,

    /// Required. Must be "deny". "allow" = fatal error. Absent = fatal error.
    pub default_action: String,

    /// Optional session configuration.
    pub session: Option<SessionConfig>,

    /// Tool allowlist. Empty = all denied.
    pub tools: Option<Vec<ToolRule>>,
}

/// Session-level configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// Max tool calls per second. 0 = unlimited. Optional.
    pub max_calls_per_second: Option<u32>,
}

/// A single tool rule in the allowlist.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    /// Exact case-sensitive tool name.
    pub name: String,

    /// "allow" or "deny" (deny is redundant but valid). No other values.
    pub action: String,

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
