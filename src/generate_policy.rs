//! FR-4: Auto-Policy Generation from Observed Traffic.
//!
//! Analyses all recorded tool-call events from the SQLite event store and
//! produces a lint-passing `agentwall-policy.yaml` draft.
//!
//! ## Design decisions (approved 2026-06-11)
//! - `observed_pattern` is emitted as a YAML comment (informational, not enforced).
//! - `required: true` is only emitted when a parameter appeared in ≥ 90 % of calls
//!   for that tool.
//! - Fetch limit is 500 events (hardcoded cap on the caller side).
//! - Nested JSON objects are flattened up to 5 levels using dot-notation keys so
//!   that the output remains a flat `parameters:` list and the linter stays happy.

use std::collections::{HashMap, HashSet};

use crate::proxy::db::EgressEvent;
use crate::self_healing::{AnomalyScorer, ConfidenceDecay};

// ──────────────────────────────────────────────────────────────────────────────
// Internal aggregation types
// ──────────────────────────────────────────────────────────────────────────────

/// Per-parameter statistics accumulated across all events for a single tool.
#[derive(Default)]
struct ParamStats {
    /// Distinct JSON type strings observed (e.g. "string", "integer", "array").
    types: HashSet<String>,
    /// Maximum observed raw string length (before headroom padding).
    max_raw_len: usize,
    /// Maximum observed array item count (before headroom padding).
    max_raw_items: usize,
    /// Number of events in which this parameter was present.
    presence_count: usize,
    /// All distinct string values observed (capped at 200 for memory safety).
    string_values: Vec<String>,
    /// Whether any observed string value looks like a file-system path.
    has_path_like_value: bool,
}

/// Per-tool aggregated analysis built from all events.
struct ToolAnalysis<'a> {
    /// All events attributed to this tool.
    events: Vec<&'a EgressEvent>,
    /// Parameter stats keyed by flattened parameter name.
    params: HashMap<String, ParamStats>,
    /// Earliest observed timestamp string (lexicographic min).
    first_seen: Option<&'a str>,
    /// Latest observed timestamp string (lexicographic max).
    last_seen: Option<&'a str>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Helper functions
// ──────────────────────────────────────────────────────────────────────────────

/// Classify a tool into TIER_1 / TIER_2 / TIER_3 based on its name keywords.
fn classify_risk_tier(tool_name: &str) -> &'static str {
    let l = tool_name.to_lowercase();
    // TIER_1 — destructive / external execution
    if l.contains("delete")
        || l.contains("drop")
        || l.contains("wipe")
        || l.contains("rm")
        || l.contains("remove")
        || l.contains("execute")
        || l.contains("exec")
        || l.contains("bash")
        || l.contains("shell")
        || l.contains("truncate")
        || l.contains("purge")
    {
        return "TIER_1";
    }
    // TIER_2 — data-access / mutation / external communication
    if l.contains("write")
        || l.contains("insert")
        || l.contains("update")
        || l.contains("send")
        || l.contains("post")
        || l.contains("query")
        || l.contains("database")
        || l.contains("email")
        || l.contains("message")
        || l.contains("upload")
        || l.contains("publish")
    {
        return "TIER_2";
    }
    "TIER_3"
}

/// Infer the JSON type name from a `serde_json::Value`.
fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Returns `true` if a string value looks like a file-system path.
fn looks_like_path(s: &str) -> bool {
    s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('~')
        || (s.len() >= 3 && s.chars().nth(1) == Some(':') && (s.chars().nth(2) == Some('\\') || s.chars().nth(2) == Some('/')))
}

/// Flatten a JSON object into dot-notation key-value pairs up to `max_depth` levels.
///
/// `prefix` is the accumulated key path (empty for top-level).
pub fn flatten_json(
    value: &serde_json::Value,
    prefix: &str,
    depth: usize,
    max_depth: usize,
    out: &mut Vec<(String, serde_json::Value)>,
) {
    if depth > max_depth {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                if matches!(v, serde_json::Value::Object(_)) && depth < max_depth {
                    flatten_json(v, &key, depth + 1, max_depth, out);
                } else {
                    out.push((key, v.clone()));
                }
            }
        }
        _ => {
            if !prefix.is_empty() {
                out.push((prefix.to_string(), value.clone()));
            }
        }
    }
}

/// Derive a simple informational regex pattern from a set of observed string values.
///
/// Returns `None` if fewer than 3 samples are present or no common prefix exists.
fn derive_observed_pattern(values: &[String]) -> Option<String> {
    if values.len() < 3 {
        return None;
    }
    // Find longest common prefix
    let first = &values[0];
    let mut common_prefix_len = first.len();
    for v in &values[1..] {
        let common = first
            .chars()
            .zip(v.chars())
            .take_while(|(a, b)| a == b)
            .count();
        common_prefix_len = common_prefix_len.min(common);
    }
    if common_prefix_len >= 2 {
        let prefix = &first[..common_prefix_len];
        // Escape special regex chars in prefix
        let escaped = regex_escape(prefix);
        Some(format!("^{}.*$", escaped))
    } else {
        None
    }
}

/// Minimal regex escaping for common special characters.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Apply +20 % headroom with a minimum floor.
fn with_headroom(raw: usize, floor: usize) -> usize {
    let padded = ((raw as f64) * 1.2).ceil() as usize;
    padded.max(floor)
}

// ──────────────────────────────────────────────────────────────────────────────
// Public entry point
// ──────────────────────────────────────────────────────────────────────────────

/// Generate a full FR-4 compliant YAML policy draft from the observed events.
///
/// The output is a valid `agentwall-policy.yaml` that passes `agentwall lint`
/// (exit code 0). Every observed tool is allowlisted with inferred parameter
/// constraints, confidence level, risk tier, and an anomalies section.
pub fn generate_from_events(events: &[EgressEvent], decay_window_days: u32) -> String {
    if events.is_empty() {
        return format!(
            "# Auto-generated by AgentWall\n\
             # No tool calls observed yet. Run 'agentwall dev' and route MCP traffic through it.\n\
             version: \"2\"\n\
             default_action: deny\n\n\
             self_healing:\n  \
               enabled: true\n  \
               decay_window: {}d\n  \
               auto_suggest: true\n  \
               suggest_threshold: 0.9\n  \
               approval_required: true\n\n\
             tools: []\n",
            decay_window_days
        );
    }

    // ── Phase 1: Build per-tool analysis ─────────────────────────────────────
    let mut tool_map: HashMap<String, ToolAnalysis> = HashMap::new();
    let mut scorer = AnomalyScorer::new();

    for event in events {
        if event.transport != "mcp" {
            continue;
        }
        let tool_name = match &event.url_path {
            Some(path) => path.clone(),
            None => continue,
        };
        let analysis = tool_map
            .entry(tool_name.clone())
            .or_insert_with(|| ToolAnalysis {
                events: Vec::new(),
                params: HashMap::new(),
                first_seen: None,
                last_seen: None,
            });

        // Track observation window (using string timestamp is a bit tricky with timestamp_ns, we'll format it if needed, or just use string repr of ns)
        let ts_str = event.timestamp_ns.to_string();
        analysis.first_seen = Some(match analysis.first_seen {
            None => Box::leak(ts_str.clone().into_boxed_str()),
            Some(prev) => {
                if ts_str.as_str() < prev {
                    Box::leak(ts_str.clone().into_boxed_str())
                } else {
                    prev
                }
            }
        });
        analysis.last_seen = Some(match analysis.last_seen {
            None => Box::leak(ts_str.clone().into_boxed_str()),
            Some(prev) => {
                if ts_str.as_str() > prev {
                    Box::leak(ts_str.into_boxed_str())
                } else {
                    prev
                }
            }
        });

        analysis.events.push(event);

        // Flatten and aggregate parameter data (up to 5 nesting levels)
        if let Some(params_str) = &event.request_body {
            if let Ok(params_val) = serde_json::from_str::<serde_json::Value>(params_str) {
                let mut flat: Vec<(String, serde_json::Value)> = Vec::new();
                flatten_json(&params_val, "", 0, 5, &mut flat);

            for (key, val) in flat {
                let stats = analysis.params.entry(key.clone()).or_default();
                stats.presence_count += 1;
                stats.types.insert(json_type_name(&val).to_string());

                match &val {
                    serde_json::Value::String(s) => {
                        if s.len() > stats.max_raw_len {
                            stats.max_raw_len = s.len();
                        }
                        if looks_like_path(s) {
                            stats.has_path_like_value = true;
                        }
                        // Cap stored values at 200 to avoid memory issues
                        if stats.string_values.len() < 200 {
                            stats.string_values.push(s.clone());
                        }
                        scorer.observe(&tool_name, &key, s);
                    }
                    serde_json::Value::Array(arr) if arr.len() > stats.max_raw_items => {
                        stats.max_raw_items = arr.len();
                    }
                    serde_json::Value::Array(_) => {}
                    _ => {}
                }
            }
        }
        }
    }

    // ── Phase 2: Compute observation window ──────────────────────────────────
    let global_first = events.iter().map(|e| e.timestamp_ns).min().unwrap_or(0);
    let global_last = events.iter().map(|e| e.timestamp_ns).max().unwrap_or(0);

    // Trim to date portion (first 10 chars of ISO 8601 timestamp) - we will just convert to datetime
    let window_start_dt = chrono::DateTime::from_timestamp(global_first / 1_000_000_000, 0).unwrap_or_default();
    let window_end_dt = chrono::DateTime::from_timestamp(global_last / 1_000_000_000, 0).unwrap_or_default();
    let window_start = window_start_dt.format("%Y-%m-%d").to_string();
    let window_end = window_end_dt.format("%Y-%m-%d").to_string();

    let total_events = events.len();
    let tool_count = tool_map.len();

    // ── Phase 3: Render YAML ──────────────────────────────────────────────────
    let mut out = format!(
        "# Auto-generated by AgentWall from {} observed tool calls\n\
         # Observation window: {} to {}\n\
         # Tools observed: {}\n\
         # Review this policy carefully before enabling enforcement.\n\
         # Run: agentwall lint agentwall-policy.yaml\n\n\
         version: \"2\"\n\
         default_action: deny\n\n\
         self_healing:\n  \
           enabled: true\n  \
           decay_window: {}d\n  \
           auto_suggest: true\n  \
           suggest_threshold: 0.9\n  \
           approval_required: true\n\n\
         tools:\n",
        total_events, window_start, window_end, tool_count, decay_window_days
    );

    let mut sorted_tools: Vec<&String> = tool_map.keys().collect();
    sorted_tools.sort();

    // Collect anomalies across all tools for the trailing comment block
    let mut anomaly_lines: Vec<String> = Vec::new();

    for tool_name in &sorted_tools {
        let analysis = &tool_map[*tool_name];
        let call_count = analysis.events.len();

        let confidence = if call_count >= 50 {
            "high"
        } else if call_count >= 10 {
            "medium"
        } else {
            "low"
        };

        let risk_tier = classify_risk_tier(tool_name);

        // Check if any param value is an external URL → upgrade to TIER_1
        let has_external_url = analysis.params.values().any(|s| {
            s.string_values
                .iter()
                .any(|v| v.starts_with("http://") || v.starts_with("https://"))
        });
        let effective_risk_tier = if has_external_url && risk_tier == "TIER_3" {
            "TIER_2" // External URL access is at least data-access tier
        } else {
            risk_tier
        };

        // FR-4 Self-Healing: calculate confidence decay and stale status
        let last_seen_ns = analysis.last_seen.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
        let decay = ConfidenceDecay::calculate(last_seen_ns, decay_window_days);
        let stale = decay == 0.0;
        
        let last_seen_str = if last_seen_ns > 0 {
            chrono::DateTime::from_timestamp(last_seen_ns / 1_000_000_000, 0)
                .unwrap_or_default()
                .to_rfc3339()
        } else {
            "unknown".to_string()
        };

        out.push_str(&format!(
            "  - name: {}\n    action: allow\n    # risk_tier: {}  confidence: {}  ({} observations)\n    # confidence_decay: {:.2}  last_seen: {}  stale: {}\n",
            tool_name, effective_risk_tier, confidence, call_count, decay, last_seen_str, stale
        ));

        if !analysis.params.is_empty() {
            out.push_str("    parameters:\n");
            let mut sorted_params: Vec<&String> = analysis.params.keys().collect();
            sorted_params.sort();

            for param_name in sorted_params {
                let stats = &analysis.params[param_name];

                // Determine primary type (prefer the one seen most; fall back to "string")
                let inferred_type = if stats.types.len() == 1 {
                    stats.types.iter().next().unwrap().as_str().to_string()
                } else {
                    "string".to_string()
                };

                // required: true only if present in ≥ 90 % of calls
                let required = stats.presence_count * 10 >= call_count * 9;

                out.push_str(&format!(
                    "      - name: {}\n        type: {}\n        required: {}\n",
                    param_name, inferred_type, required
                ));

                // max_length for strings
                if inferred_type == "string" && stats.max_raw_len > 0 {
                    let max_len = with_headroom(stats.max_raw_len, 64);
                    out.push_str(&format!("        max_length: {}\n", max_len));
                }

                // max_items for arrays (emitted as comment to pass strict validation)
                if inferred_type == "array" && stats.max_raw_items > 0 {
                    let max_items = with_headroom(stats.max_raw_items, 1);
                    out.push_str(&format!("        # max_items: {}\n", max_items));
                }

                // Emit inline JSON Schema for array/object parameters to comply with Policy Schema v2 (Guidance #6)
                if inferred_type == "array" {
                    out.push_str("        schema:\n          type: array\n          items:\n            type: string\n");
                } else if inferred_type == "object" {
                    out.push_str("        schema:\n          type: object\n");
                }

                // validators: auto-emit path_traversal when path-like values observed
                if stats.has_path_like_value && inferred_type == "string" {
                    out.push_str("        validators:\n          - path_traversal\n");
                }

                // enum: emit if ≤ 10 distinct string values observed
                if inferred_type == "string" {
                    let unique_vals: Vec<String> = {
                        let mut seen: HashSet<&String> = HashSet::new();
                        let mut unique = Vec::new();
                        for v in &stats.string_values {
                            if seen.insert(v) {
                                unique.push(v.clone());
                            }
                        }
                        unique
                    };
                    if !unique_vals.is_empty() && unique_vals.len() <= 10 {
                        out.push_str("        # enum:\n");
                        for val in &unique_vals {
                            // Escape quotes in enum values
                            out.push_str(&format!("        #  - \"{}\"\n", val.replace('"', "\\\"")));
                        }
                    }

                    // observed_pattern as informational comment
                    if let Some(pattern) = derive_observed_pattern(&stats.string_values) {
                        out.push_str(&format!(
                            "        # observed_pattern: \"{}\"  # informational only\n",
                            pattern
                        ));
                    }

                    // Anomaly detection using self_healing AnomalyScorer
                    let mut value_freq: HashMap<&String, usize> = HashMap::new();
                    for v in &stats.string_values {
                        *value_freq.entry(v).or_insert(0) += 1;
                    }
                    for val in value_freq.keys() {
                        let score = scorer.score(tool_name, param_name, val);
                        if score > 0.9 {
                            anomaly_lines.push(format!(
                                "# - {}.{}: observed anomalous value \"{}\" (anomaly_score: {:.2})\n\
                                 #   → Is this expected? Review before enabling enforcement.",
                                tool_name, param_name, val, score
                            ));
                        }
                    }
                }
            }
        }

        out.push('\n');
    }

    // ── Phase 4: Anomalies block ──────────────────────────────────────────────
    if !anomaly_lines.is_empty() {
        out.push_str("# ── Anomalies (review required) ");
        out.push_str(&"─".repeat(40));
        out.push('\n');
        for line in &anomaly_lines {
            out.push_str(line);
            out.push('\n');
        }
    }

    out
}

// ──────────────────────────────────────────────────────────────────────────────
// Inline unit tests (lightweight — full suite is in tests/unit/)
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::db::EgressEvent;

    fn make_event(tool: &str, params: &str) -> EgressEvent {
        EgressEvent {
            timestamp_ns: 1718090000000000000, // Roughly 2024
            session_id: "test-session".to_string(),
            transport: "mcp".to_string(),
            method: Some("tools/call".to_string()),
            target_host: "127.0.0.1".to_string(),
            target_port: Some(3000),
            url_path: Some(tool.to_string()),
            request_headers: None,
            request_body: Some(params.to_string()),
            request_body_hash: None,
            response_status: Some(200),
            response_body: Some("{}".to_string()),
            response_body_hash: None,
            dlp_findings: None,
            injection_findings: None,
            latency_ms: Some(5.0),
            verdict: Some("allow".to_string()),
            semantic_anomaly_score: None,
            identity_context: None,
        }
    }

    #[test]
    fn test_empty_events_returns_valid_yaml() {
        let yaml = generate_from_events(&[], 30);
        assert!(yaml.contains("version: \"2\""));
        assert!(yaml.contains("default_action: deny"));
        assert!(yaml.contains("tools: []"));
    }

    #[test]
    fn test_risk_tier_destructive_is_tier1() {
        assert_eq!(classify_risk_tier("delete_file"), "TIER_1");
        assert_eq!(classify_risk_tier("execute_shell"), "TIER_1");
    }

    #[test]
    fn test_risk_tier_data_access_is_tier2() {
        assert_eq!(classify_risk_tier("send_email"), "TIER_2");
        assert_eq!(classify_risk_tier("write_data"), "TIER_2");
    }

    #[test]
    fn test_risk_tier_readonly_is_tier3() {
        assert_eq!(classify_risk_tier("get_weather"), "TIER_3");
        assert_eq!(classify_risk_tier("list_files"), "TIER_3");
    }

    #[test]
    fn test_with_headroom_applies_20_percent() {
        assert_eq!(with_headroom(100, 64), 120);
        assert_eq!(with_headroom(10, 64), 64); // floor wins
        assert_eq!(with_headroom(0, 64), 64);  // floor on zero
    }

    #[test]
    fn test_flatten_json_nested() {
        let v: serde_json::Value = serde_json::json!({
            "a": { "b": { "c": "deep" } }
        });
        let mut flat = Vec::new();
        flatten_json(&v, "", 0, 5, &mut flat);
        assert!(flat.iter().any(|(k, _)| k == "a.b.c"));
    }

    #[test]
    fn test_generation_contains_observed_tool() {
        let events = vec![make_event("read_file", "{\"path\": \"/workspace/foo.txt\"}")];
        let yaml = generate_from_events(&events, 30);
        assert!(yaml.contains("name: read_file"));
        assert!(yaml.contains("path"));
    }

    #[test]
    fn test_looks_like_path_detection() {
        assert!(looks_like_path("/etc/passwd"));
        assert!(looks_like_path("./relative/path"));
        assert!(looks_like_path("C:\\Users\\test"));
        assert!(!looks_like_path("hello world"));
        assert!(!looks_like_path("https://example.com"));
    }
}
