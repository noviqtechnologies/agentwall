//! Response Scanner — Secret Detection in Tool Outputs (FR-303b)
//!
//! Scans MCP tool responses for leaked secrets (API keys, SSH keys, etc.)
//! using high-signal regex patterns. Supports redaction and blocking modes.

use regex::{Regex, RegexSet};
use serde_json::Value;

/// Categories of detected secrets
#[derive(Debug, Clone, PartialEq)]
pub enum SecretCategory {
    AwsAccessKey,
    GitHubToken,
    OpenAiApiKey,
    AnthropicApiKey,
    SshPrivateKey,
    StripeKey,
}

impl SecretCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretCategory::AwsAccessKey => "AWS Access Key",
            SecretCategory::GitHubToken => "GitHub Token",
            SecretCategory::OpenAiApiKey => "OpenAI API Key",
            SecretCategory::AnthropicApiKey => "Anthropic API Key",
            SecretCategory::SshPrivateKey => "SSH Private Key",
            SecretCategory::StripeKey => "Stripe Key",
        }
    }
}

/// A single secret finding with metadata for logging
#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub category: SecretCategory,
    pub pattern_name: String,
    pub field_path: String,
    pub position: usize,
    pub length: usize,
    pub preview: String, // truncated, e.g. "sk-****abcd"
}

/// Result of scanning a response
#[derive(Debug)]
pub enum ScanResult {
    /// Scanning disabled or tool whitelisted
    Pass,
    /// No secrets found
    Clean,
    /// Response too large, skipped
    Skipped { reason: String },
    /// Secrets found, should be redacted
    Redact { findings: Vec<SecretFinding> },
    /// Secrets found, entire response should be blocked
    Block { findings: Vec<SecretFinding> },
    /// Scanner error — fail-open
    ScannerError { error: String },
}

/// Configuration for response scanning
#[derive(Debug, Clone)]
pub struct ResponseScanConfig {
    pub enabled: bool,
    pub block_mode: bool,
    pub dry_run: bool,
    pub max_scan_bytes: usize,
}

impl Default for ResponseScanConfig {
    fn default() -> Self {
        Self {
            enabled: false,     // opt-in per PRD
            block_mode: false,
            dry_run: false,
            max_scan_bytes: 1_048_576, // 1MB
        }
    }
}

/// Pattern definition used internally
struct PatternDef {
    name: &'static str,
    category: SecretCategory,
    individual_regex: Regex,
}

/// High-risk tools whose output should be scanned
const SCANNABLE_TOOLS: &[&str] = &[
    "read_file", "exec_command", "run_shell", "run_command",
    "http_get", "list_files", "bash", "execute", "terminal",
    "read", "cat", "shell", "leak_secret", "secret",
];

/// Content fields to extract and scan from JSON-RPC result
const CONTENT_FIELDS: &[&str] = &[
    "content", "stdout", "result", "data", "text",
];

/// Known safe tools — skip entirely
const SAFE_TOOL_WHITELIST: &[&str] = &[
    "tools/list", "get_schema", "get_metadata", "ping",
];

/// The 10 regex patterns (mapping to 7 PRD categories)
const PATTERN_DEFS: &[(&str, &str)] = &[
    // AWS Access Key IDs
    ("AWS Access Key (AKIA)", r"AKIA[0-9A-Z]{16}"),
    ("AWS Access Key (ASIA)", r"ASIA[0-9A-Z]{16}"),
    // GitHub Tokens
    ("GitHub PAT (ghp)", r"ghp_[0-9a-zA-Z\-]{36,}"),
    ("GitHub OAuth (gho)", r"gho_[0-9a-zA-Z\-]{36,}"),
    ("GitHub Fine-Grained PAT", r"github_pat_[0-9a-zA-Z_]{80,96}"),
    // OpenAI API Key
    ("OpenAI API Key", r"sk-[a-zA-Z0-9\-]{20,}"),
    // Anthropic API Key (must be checked before OpenAI due to sk- prefix overlap)
    ("Anthropic API Key", r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
    // SSH Private Key Headers
    ("SSH Private Key", r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
    // Stripe Keys
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{20,}"),
    ("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{20,}"),
];

/// Maps pattern index to its SecretCategory
fn category_for_index(idx: usize) -> SecretCategory {
    match idx {
        0 | 1 => SecretCategory::AwsAccessKey,
        2 | 3 | 4 => SecretCategory::GitHubToken,
        5 => SecretCategory::OpenAiApiKey,
        6 => SecretCategory::AnthropicApiKey,
        7 => SecretCategory::SshPrivateKey,
        8 | 9 => SecretCategory::StripeKey,
        _ => SecretCategory::OpenAiApiKey, // unreachable
    }
}

/// The response scanner — thread-safe, constructed once at startup.
pub struct ResponseScanner {
    regex_set: RegexSet,
    patterns: Vec<PatternDef>,
}

impl ResponseScanner {
    /// Create a new ResponseScanner with all built-in patterns compiled.
    pub fn new() -> Result<Self, regex::Error> {
        let raw_patterns: Vec<String> = PATTERN_DEFS.iter().map(|(_, p)| p.to_string()).collect();
        let regex_set = RegexSet::new(&raw_patterns)?;

        let mut patterns = Vec::new();
        for (i, (name, pat)) in PATTERN_DEFS.iter().enumerate() {
            patterns.push(PatternDef {
                name,
                category: category_for_index(i),
                individual_regex: Regex::new(pat)?,
            });
        }

        Ok(Self { regex_set, patterns })
    }

    /// Scan a JSON-RPC response value for secrets.
    pub fn scan_response(
        &self,
        response: &Value,
        tool_name: &str,
        config: &ResponseScanConfig,
    ) -> ScanResult {
        if !config.enabled {
            return ScanResult::Pass;
        }

        // Tool-aware filtering
        if SAFE_TOOL_WHITELIST.iter().any(|t| tool_name.eq_ignore_ascii_case(t)) {
            return ScanResult::Pass;
        }
        if !is_scannable_tool(tool_name) {
            return ScanResult::Pass;
        }

        // Extract content fields from JSON-RPC result
        let content_pairs = match extract_content_fields(response) {
            Ok(pairs) => pairs,
            Err(e) => return ScanResult::ScannerError { error: e },
        };

        if content_pairs.is_empty() {
            return ScanResult::Clean;
        }

        // Size guard
        let total_size: usize = content_pairs.iter().map(|(_, s)| s.len()).sum();
        if total_size > config.max_scan_bytes {
            return ScanResult::Skipped {
                reason: format!(
                    "Large response skipped – potential secret leak risk ({}B > {}B limit)",
                    total_size, config.max_scan_bytes
                ),
            };
        }

        // Run regex matching
        let mut findings: Vec<SecretFinding> = Vec::new();

        for (field_path, content) in &content_pairs {
            // Fast O(n) check — any patterns match at all?
            let matched_indices: Vec<usize> = self.regex_set.matches(content).into_iter().collect();
            if matched_indices.is_empty() {
                continue;
            }

            // For each matched pattern, find exact positions
            for idx in matched_indices {
                let pat = &self.patterns[idx];
                for m in pat.individual_regex.find_iter(content) {
                    let matched_text = m.as_str();

                    // For Anthropic keys, skip if the OpenAI pattern also matched
                    // (OpenAI pattern is broader — sk-ant-* should be categorized as Anthropic)
                    if idx == 5 && matched_text.starts_with("sk-ant-") {
                        continue; // Let the Anthropic pattern (idx 6) handle it
                    }

                    let finding = SecretFinding {
                        category: pat.category.clone(),
                        pattern_name: pat.name.to_string(),
                        field_path: field_path.clone(),
                        position: m.start(),
                        length: m.len(),
                        preview: truncated_preview(matched_text),
                    };

                    if config.block_mode {
                        // Fail-fast: block on first match
                        return ScanResult::Block { findings: vec![finding] };
                    }

                    findings.push(finding);
                }
            }
        }

        if findings.is_empty() {
            ScanResult::Clean
        } else {
            ScanResult::Redact { findings }
        }
    }

    /// Apply redaction to a response Value, returning the modified Value.
    /// Per PRD §6: parse JSON envelope first, extract strings, redact, re-serialize.
    pub fn redact_response(&self, response: &Value, config: &ResponseScanConfig) -> Value {
        let mut modified = response.clone();

        // Navigate into result object
        if let Some(result) = modified.get_mut("result") {
            self.redact_value(result, config);
        }

        modified
    }

    /// Recursively redact secret matches in a Value tree (only string leaves).
    fn redact_value(&self, value: &mut Value, config: &ResponseScanConfig) {
        match value {
            Value::String(s) => {
                if s.len() > config.max_scan_bytes {
                    return;
                }
                let matched_indices: Vec<usize> =
                    self.regex_set.matches(s.as_str()).into_iter().collect();
                if matched_indices.is_empty() {
                    return;
                }
                let mut result = s.clone();
                for idx in matched_indices {
                    let pat = &self.patterns[idx];
                    result = pat
                        .individual_regex
                        .replace_all(&result, |_caps: &regex::Captures| {
                            format!("[REDACTED:{}]", pat.name)
                        })
                        .to_string();
                }
                *s = result;
            }
            Value::Object(map) => {
                for (key, val) in map.iter_mut() {
                    // Only scan known content fields for performance
                    if CONTENT_FIELDS.iter().any(|f| key.eq_ignore_ascii_case(f)) {
                        self.redact_value(val, config);
                    }
                    // Also recurse into nested arrays/objects within content
                    match val {
                        Value::Array(_) | Value::Object(_) => self.redact_value(val, config),
                        _ => {}
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.redact_value(item, config);
                }
            }
            _ => {}
        }
    }
}

/// Check if a tool name matches any scannable tool pattern.
fn is_scannable_tool(tool_name: &str) -> bool {
    let lower = tool_name.to_ascii_lowercase();
    SCANNABLE_TOOLS.iter().any(|t| lower.contains(t))
}

/// Extract content field strings from a JSON-RPC response.
/// Returns Vec<(field_path, content_string)>.
fn extract_content_fields(response: &Value) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::new();

    // JSON-RPC result is in response["result"]
    let result = match response.get("result") {
        Some(r) => r,
        None => return Ok(pairs), // No result field (might be an error response)
    };

    extract_from_value(result, "result", &mut pairs);
    Ok(pairs)
}

/// Recursively extract string values from content fields.
fn extract_from_value(value: &Value, path: &str, pairs: &mut Vec<(String, String)>) {
    match value {
        Value::String(s) => {
            pairs.push((path.to_string(), s.clone()));
        }
        Value::Object(map) => {
            for (key, val) in map {
                let child_path = format!("{}.{}", path, key);
                if CONTENT_FIELDS.iter().any(|f| key.eq_ignore_ascii_case(f)) {
                    extract_from_value(val, &child_path, pairs);
                }
                // Also check nested objects/arrays
                match val {
                    Value::Object(_) | Value::Array(_) => {
                        extract_from_value(val, &child_path, pairs);
                    }
                    _ => {}
                }
            }
        }
        Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                extract_from_value(item, &format!("{}[{}]", path, i), pairs);
            }
        }
        _ => {}
    }
}

/// Generate a truncated preview for logging — never expose the full secret.
/// Examples: "AKIA****WXYZ" , "sk-****abcd" , "ghp_****efgh"
pub fn truncated_preview(secret: &str) -> String {
    if secret.len() <= 8 {
        return "****".to_string();
    }

    // Find a good prefix boundary (up to first _ or - after initial prefix, max 6 chars)
    let prefix_len = secret
        .char_indices()
        .skip(2)
        .find(|(_, c)| *c == '_' || *c == '-')
        .map(|(i, _)| (i + 1).min(6))
        .unwrap_or(4)
        .min(secret.len());

    let suffix_len = 4.min(secret.len().saturating_sub(prefix_len + 4));
    let suffix_start = secret.len() - suffix_len;

    format!("{}****{}", &secret[..prefix_len], &secret[suffix_start..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scanner() -> ResponseScanner {
        ResponseScanner::new().unwrap()
    }

    fn enabled_config() -> ResponseScanConfig {
        ResponseScanConfig {
            enabled: true,
            block_mode: false,
            dry_run: false,
            max_scan_bytes: 1_048_576,
        }
    }

    // ── Pattern Detection Tests ──

    #[test]
    fn test_aws_akia_detection() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE" }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Redact { findings } => {
                assert_eq!(findings[0].category, SecretCategory::AwsAccessKey);
                assert!(findings[0].pattern_name.contains("AKIA"));
            }
            other => panic!("Expected Redact, got {:?}", other),
        }
    }

    #[test]
    fn test_aws_asia_detection() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "stdout": "ASIA1234567890123456" }
        });
        match s.scan_response(&resp, "exec_command", &enabled_config()) {
            ScanResult::Redact { findings } => {
                assert_eq!(findings[0].category, SecretCategory::AwsAccessKey);
            }
            other => panic!("Expected Redact, got {:?}", other),
        }
    }

    #[test]
    fn test_github_pat_ghp() {
        let s = scanner();
        let token = format!("ghp_{}", "a".repeat(36));
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": format!("token={}", token) }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Redact { findings } => {
                assert_eq!(findings[0].category, SecretCategory::GitHubToken);
            }
            other => panic!("Expected Redact, got {:?}", other),
        }
    }

    #[test]
    fn test_github_pat_gho() {
        let s = scanner();
        let token = format!("gho_{}", "b".repeat(40));
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "data": token }
        });
        match s.scan_response(&resp, "exec_command", &enabled_config()) {
            ScanResult::Redact { findings } => {
                assert_eq!(findings[0].category, SecretCategory::GitHubToken);
            }
            other => panic!("Expected Redact, got {:?}", other),
        }
    }

    #[test]
    fn test_openai_key() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "text": "OPENAI_API_KEY=sk-proj-abcdefghij1234567890" }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Redact { findings } => {
                assert_eq!(findings[0].category, SecretCategory::OpenAiApiKey);
            }
            other => panic!("Expected Redact, got {:?}", other),
        }
    }

    #[test]
    fn test_anthropic_key() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": "key=sk-ant-api03-abcdefghijklmnopqrst" }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Redact { findings } => {
                assert!(findings.iter().any(|f| f.category == SecretCategory::AnthropicApiKey));
            }
            other => panic!("Expected Redact, got {:?}", other),
        }
    }

    #[test]
    fn test_ssh_private_key() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..." }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Redact { findings } => {
                assert_eq!(findings[0].category, SecretCategory::SshPrivateKey);
            }
            other => panic!("Expected Redact, got {:?}", other),
        }
    }

    #[test]
    fn test_ssh_openssh_key() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn..." }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Redact { findings } => {
                assert_eq!(findings[0].category, SecretCategory::SshPrivateKey);
            }
            other => panic!("Expected Redact, got {:?}", other),
        }
    }

    #[test]
    fn test_stripe_secret_key() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "stdout": "sk_live_abcdefghijklmnopqrst" }
        });
        match s.scan_response(&resp, "exec_command", &enabled_config()) {
            ScanResult::Redact { findings } => {
                assert_eq!(findings[0].category, SecretCategory::StripeKey);
            }
            other => panic!("Expected Redact, got {:?}", other),
        }
    }

    #[test]
    fn test_stripe_restricted_key() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "stdout": "rk_live_abcdefghijklmnopqrst" }
        });
        match s.scan_response(&resp, "exec_command", &enabled_config()) {
            ScanResult::Redact { findings } => {
                assert_eq!(findings[0].category, SecretCategory::StripeKey);
            }
            other => panic!("Expected Redact, got {:?}", other),
        }
    }

    // ── Behavior Tests ──

    #[test]
    fn test_disabled_by_default() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": "AKIAIOSFODNN7EXAMPLE" }
        });
        let config = ResponseScanConfig::default(); // enabled=false
        match s.scan_response(&resp, "read_file", &config) {
            ScanResult::Pass => {}
            other => panic!("Expected Pass, got {:?}", other),
        }
    }

    #[test]
    fn test_safe_tool_whitelist_skip() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": "AKIAIOSFODNN7EXAMPLE" }
        });
        match s.scan_response(&resp, "tools/list", &enabled_config()) {
            ScanResult::Pass => {}
            other => panic!("Expected Pass, got {:?}", other),
        }
    }

    #[test]
    fn test_non_scannable_tool_skip() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": "AKIAIOSFODNN7EXAMPLE" }
        });
        match s.scan_response(&resp, "get_weather", &enabled_config()) {
            ScanResult::Pass => {}
            other => panic!("Expected Pass, got {:?}", other),
        }
    }

    #[test]
    fn test_size_cutoff_skip() {
        let s = scanner();
        let large_content = "x".repeat(2_000_000); // 2MB
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": large_content }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Skipped { reason } => {
                assert!(reason.contains("Large response skipped"));
            }
            other => panic!("Expected Skipped, got {:?}", other),
        }
    }

    #[test]
    fn test_block_mode_first_match() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": "key1=AKIAIOSFODNN7EXAMPLE key2=sk_live_abcdefghijklmnopqrst" }
        });
        let mut config = enabled_config();
        config.block_mode = true;
        match s.scan_response(&resp, "read_file", &config) {
            ScanResult::Block { findings } => {
                assert_eq!(findings.len(), 1); // fail-fast
            }
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_multiple_secrets_all_redacted() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": "aws=AKIAIOSFODNN7EXAMPLE stripe=sk_live_abcdefghijklmnopqrst" }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Redact { findings } => {
                assert!(findings.len() >= 2);
            }
            other => panic!("Expected Redact, got {:?}", other),
        }
    }

    #[test]
    fn test_redaction_preserves_json() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "content": "key=AKIAIOSFODNN7EXAMPLE",
                "status": "ok"
            }
        });
        let redacted = s.redact_response(&resp, &enabled_config());
        // Must still be valid JSON with all fields
        assert_eq!(redacted["jsonrpc"], "2.0");
        assert_eq!(redacted["id"], 1);
        assert!(redacted["result"]["status"] == "ok");
        let content = redacted["result"]["content"].as_str().unwrap();
        assert!(content.contains("[REDACTED:"));
        assert!(!content.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_clean_response_no_match() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": "Hello, this is a normal response with no secrets." }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Clean => {}
            other => panic!("Expected Clean, got {:?}", other),
        }
    }

    #[test]
    fn test_no_false_positive_uuid() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": "id=550e8400-e29b-41d4-a716-446655440000" }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Clean => {}
            other => panic!("Expected Clean, got {:?}", other),
        }
    }

    #[test]
    fn test_no_full_secret_in_preview() {
        let preview = truncated_preview("sk-proj-abcdefghijklmnopqrstuvwxyz1234567890");
        assert!(!preview.contains("abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(preview.contains("****"));
        assert!(preview.len() < 20);
    }

    #[test]
    fn test_error_response_no_result() {
        let s = scanner();
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "error": { "code": -32600, "message": "Invalid Request" }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Clean => {}
            other => panic!("Expected Clean (no result field), got {:?}", other),
        }
    }

    #[test]
    fn test_field_targeting() {
        let s = scanner();
        // Secret in a non-target field should NOT be detected
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "metadata": "AKIAIOSFODNN7EXAMPLE" }
        });
        match s.scan_response(&resp, "read_file", &enabled_config()) {
            ScanResult::Clean => {}
            other => panic!("Expected Clean (non-target field), got {:?}", other),
        }
    }
}
