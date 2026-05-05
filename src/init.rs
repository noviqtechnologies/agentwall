//! `agentwall init` — Policy generation from dry-run audit log (FR-112)
//!
//! Reads an audit log, extracts all observed tools and their parameter structures,
//! and generates a valid v1 policy YAML pre-populated with `action: allow` and
//! parameter stubs. String parameters receive `# TODO: add constraints` comments.
//! The generated policy passes `agentwall check` against the source log by design.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::audit::logger::AuditEntry;

/// Information gathered about a single tool from log observations
#[derive(Debug, Clone)]
struct ObservedTool {
    name: String,
    /// Map from param name → set of observed JSON types
    params: BTreeMap<String, BTreeSet<String>>,
    /// Whether the param was always present across calls (for `required`)
    param_presence: BTreeMap<String, (u64, u64)>, // (present_count, total_count)
}

/// Generate a policy YAML from an audit log file.
///
/// Scans all `tool_allow`, `tool_deny`, and `tool_dry_run_deny` entries,
/// extracts unique tool names and observed parameter structures,
/// and produces a valid v1 policy string.
pub fn generate_policy_from_log(log_path: &Path) -> Result<String, String> {
    let file =
        std::fs::File::open(log_path).map_err(|e| format!("Cannot open log file: {}", e))?;
    let reader = BufReader::new(file);

    let mut tools: BTreeMap<String, ObservedTool> = BTreeMap::new();

    for (i, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Read error at line {}: {}", i + 1, e))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let entry: AuditEntry = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => {
                // Try streaming parse for robustness
                let mut stream = serde_json::Deserializer::from_str(trimmed)
                    .into_iter::<AuditEntry>();
                if let Some(Ok(e)) = stream.next() {
                    e
                } else {
                    continue; // Skip unparseable lines
                }
            }
        };

        // Only process tool call events
        match entry.event.as_str() {
            "tool_allow" | "tool_deny" | "tool_dry_run_deny" => {}
            _ => continue,
        }

        let tool_name = match &entry.tool_name {
            Some(name) if !name.is_empty() => name.clone(),
            _ => continue,
        };

        let observed = tools.entry(tool_name.clone()).or_insert_with(|| ObservedTool {
            name: tool_name,
            params: BTreeMap::new(),
            param_presence: BTreeMap::new(),
        });

        // Extract parameter info from the params field
        if let Some(params) = &entry.params {
            if let Value::Object(map) = params {
                // Track all known param names for presence counting
                let all_known: BTreeSet<String> = observed.params.keys().cloned().collect();

                for (param_name, param_value) in map {
                    let json_type = infer_json_type(param_value);
                    observed
                        .params
                        .entry(param_name.clone())
                        .or_insert_with(BTreeSet::new)
                        .insert(json_type);

                    let (present, total) = observed
                        .param_presence
                        .entry(param_name.clone())
                        .or_insert((0, 0));
                    *present += 1;
                    *total += 1;
                }

                // Increment total for params we know about but weren't in this call
                for known in &all_known {
                    if !map.contains_key(known) {
                        let (_, total) = observed
                            .param_presence
                            .entry(known.clone())
                            .or_insert((0, 0));
                        *total += 1;
                    }
                }
            }
        }
    }

    if tools.is_empty() {
        return Err(
            "No tool calls found in the audit log. Run your agent in dry-run mode first."
                .to_string(),
        );
    }

    // Generate YAML
    Ok(render_policy_yaml(&tools))
}

/// Infer the JSON type string for a serde_json::Value
fn infer_json_type(value: &Value) -> String {
    match value {
        Value::String(_) => "string".to_string(),
        Value::Number(_) => "number".to_string(),
        Value::Bool(_) => "boolean".to_string(),
        Value::Object(_) => "object".to_string(),
        Value::Array(_) => "array".to_string(),
        Value::Null => "string".to_string(), // default to string for null
    }
}

/// Map a JSON type string to the policy schema type
fn policy_type_from_observed(types: &BTreeSet<String>) -> &str {
    // If mixed types observed, default to string (safest)
    if types.len() > 1 {
        return "string";
    }
    match types.iter().next().map(|s| s.as_str()) {
        Some("string") => "string",
        Some("number") => "number",
        Some("boolean") => "boolean",
        Some("object") => "object",
        Some("array") => "array",
        _ => "string",
    }
}

/// Render the observed tools into a valid v1 policy YAML string
fn render_policy_yaml(tools: &BTreeMap<String, ObservedTool>) -> String {
    let mut out = String::new();

    out.push_str("# AgentWall Policy — auto-generated by `agentwall init --from-log`\n");
    out.push_str("#\n");
    out.push_str("# This policy was generated from a dry-run session log.\n");
    out.push_str("# All observed tools are pre-populated with action: allow.\n");
    out.push_str("# Review each tool and its parameters carefully before enabling enforcement.\n");
    out.push_str("#\n");
    out.push_str("# Next steps:\n");
    out.push_str("#   1. Review each tool — remove any tools your agent should NOT call.\n");
    out.push_str("#   2. Add pattern constraints for string parameters (see TODO comments).\n");
    out.push_str("#   3. Validate: <path-to-binary> check --policy policy.yaml <audit.log>\n");
    out.push_str("#   4. Enforce:  <path-to-binary> start --policy policy.yaml ...\n");
    out.push_str("#\n");
    out.push_str("# (e.g. .\\agentwall.exe check ...)\n\n");

    out.push_str("version: \"1\"\n");
    out.push_str("default_action: deny\n\n");

    out.push_str("session:\n");
    out.push_str("  max_calls_per_second: 10\n\n");

    out.push_str("tools:\n");

    for tool in tools.values() {
        out.push_str(&format!("  - name: \"{}\"\n", tool.name));
        out.push_str("    action: allow\n");

        if !tool.params.is_empty() {
            out.push_str("    parameters:\n");

            for (param_name, observed_types) in &tool.params {
                let ptype = policy_type_from_observed(observed_types);

                out.push_str(&format!("      - name: \"{}\"\n", param_name));
                out.push_str(&format!("        type: {}\n", ptype));

                // Check if parameter was present in every call
                let required = if let Some((present, total)) =
                    tool.param_presence.get(param_name)
                {
                    *present == *total && *total > 0
                } else {
                    false
                };

                if required {
                    out.push_str("        required: true\n");
                }

                // Add TODO comment for string params that need pattern constraints
                if ptype == "string" {
                    out.push_str("        # TODO: add pattern constraint for this parameter\n");
                    out.push_str("        # pattern: \".*\"  # Example: restrict to safe values\n");
                }

                // Note for object/array params about Phase 1 blind pass-through
                if ptype == "object" || ptype == "array" {
                    out.push_str("        # NOTE: object/array content is NOT validated in Phase 1 (blind pass-through)\n");
                }
            }
        }

        out.push('\n');
    }

    out
}

/// Run the `init` subcommand
pub fn run_init(from_log: &str, output: &str) -> i32 {
    use colored::*;
    let log_path = Path::new(from_log);
    if !log_path.exists() {
        eprintln!("{} Log file not found: {}", "✖".red(), from_log);
        return 2;
    }

    match generate_policy_from_log(log_path) {
        Ok(yaml) => {
            if let Err(e) = std::fs::write(output, &yaml) {
                eprintln!("{} Cannot write policy file: {}", "✖".red(), e);
                return 2;
            }
            println!("{} Policy generated: {}", "✓".green(), output.cyan().bold());
            println!("  {} Scanning tools... Done.", "ℹ".blue());
            println!();
            println!("{}", "Next steps:".bold().underline());
            println!("  1. Review and tighten the policy (add regex patterns, remove unnecessary tools)");
            println!("  2. Validate: {}", format!(".\\agentwall.exe check --policy {} {}", output, from_log).cyan());
            println!("  3. Enforce:  {}", format!(".\\agentwall.exe start --policy {} --listen 127.0.0.1:8080 --log-path audit.log", output).cyan());
            0
        }
        Err(e) => {
            eprintln!("{} {}", "✖".red(), e);
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_json_type() {
        assert_eq!(infer_json_type(&Value::String("hello".into())), "string");
        assert_eq!(infer_json_type(&serde_json::json!(42)), "number");
        assert_eq!(infer_json_type(&serde_json::json!(true)), "boolean");
        assert_eq!(infer_json_type(&serde_json::json!({})), "object");
        assert_eq!(infer_json_type(&serde_json::json!([])), "array");
        assert_eq!(infer_json_type(&Value::Null), "string");
    }

    #[test]
    fn test_policy_type_from_single_type() {
        let mut types = BTreeSet::new();
        types.insert("number".to_string());
        assert_eq!(policy_type_from_observed(&types), "number");
    }

    #[test]
    fn test_policy_type_from_mixed_types() {
        let mut types = BTreeSet::new();
        types.insert("string".to_string());
        types.insert("number".to_string());
        // Mixed types default to string
        assert_eq!(policy_type_from_observed(&types), "string");
    }
}
