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

    /// OIDC authentication configuration (FR-201).
    pub auth: Option<AuthConfig>,

    /// Optional session configuration.
    pub session: Option<SessionConfig>,

    /// FR-303b: Response scanning configuration.
    pub response_scanning: Option<ResponseScanningConfig>,

    /// FR-306: Agent Firewall — cycle detection and loop prevention.
    pub firewall: Option<FirewallConfig>,

    /// Tool allowlist. Empty = all denied.
    pub tools: Option<Vec<ToolRule>>,
}

/// FR-306: Action to take when a cycle is detected.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CycleAction {
    /// Return a custom JSON-RPC error (-32010) telling the agent to try a different approach.
    PivotError,
    /// Return a standard policy violation error (-32001) and trigger kill mode.
    Block,
    /// Pause and ask the developer interactively (falls back to block in non-TTY).
    PauseInteractive,
}

impl Default for CycleAction {
    fn default() -> Self {
        CycleAction::PivotError
    }
}

/// FR-306: Cycle detection configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycleDetectionConfig {
    /// Number of consecutive identical calls before triggering. Default: 3.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// What to do when a cycle is detected. Default: pivot_error.
    #[serde(default)]
    pub action: CycleAction,
}

impl Default for CycleDetectionConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            action: CycleAction::default(),
        }
    }
}

fn default_max_attempts() -> u32 {
    3
}

/// FR-306: Top-level firewall configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    /// Master toggle. Default: true.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Cycle detection settings.
    #[serde(default)]
    pub cycle_detection: CycleDetectionConfig,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            cycle_detection: CycleDetectionConfig::default(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

/// Identity configuration (OIDC).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub issuer: String,
    pub audience: String,
}

/// OIDC provider authentication configuration (FR-201).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub provider: String,
    pub jwks_uri: String,
    pub audience: String,
    pub issuer: String,
    pub cache_ttl_minutes: Option<u64>,
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

    /// FR-201: Bound to specific agent sub claim
    pub identity: Option<String>,
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

/// Structural value-level parameter validator rules (FR-202)
#[derive(Debug, Clone, PartialEq)]
pub enum ValidatorRule {
    /// Rejects parameters containing "../" or "..\"
    PathTraversal,
    /// Rejects file://, javascript://, and configurable schemes
    UrlSchemeAllowlist(Option<Vec<String>>),
    /// Rejects UNION SELECT, DROP TABLE, and common SQLi patterns
    SqlInjectionBasic,
    /// Rejects ;, &&, ||, $(), and backtick sequences
    ShellInjectionBasic,
    /// Runs a custom compiled regex pattern
    Regex(String),
}

impl<'de> Deserialize<'de> for ValidatorRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValidatorRuleVisitor;
        impl<'de> serde::de::Visitor<'de> for ValidatorRuleVisitor {
            type Value = ValidatorRule;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or map representing a ValidatorRule")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "path_traversal" => Ok(ValidatorRule::PathTraversal),
                    "url_scheme_allowlist" => Ok(ValidatorRule::UrlSchemeAllowlist(None)),
                    "sql_injection_basic" => Ok(ValidatorRule::SqlInjectionBasic),
                    "shell_injection_basic" => Ok(ValidatorRule::ShellInjectionBasic),
                    _ => Err(E::custom(format!("unknown validator rule: {}", value))),
                }
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let key: String = map.next_key()?
                    .ok_or_else(|| serde::de::Error::custom("expected a validator key"))?;
                match key.as_str() {
                    "regex" => {
                        let val: String = map.next_value()?;
                        Ok(ValidatorRule::Regex(val))
                    }
                    "url_scheme_allowlist" => {
                        let val: Vec<String> = map.next_value()?;
                        Ok(ValidatorRule::UrlSchemeAllowlist(Some(val)))
                    }
                    _ => Err(serde::de::Error::custom(format!("unknown validator key: {}", key))),
                }
            }
        }
        deserializer.deserialize_any(ValidatorRuleVisitor)
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

    /// FR-202: Structural parameter validators.
    pub validators: Option<Vec<ValidatorRule>>,
}
