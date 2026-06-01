//! Loader-level unit tests — FR-102 / FR-103 acceptance criteria
//!
//! These tests exercise `load_policy()` end-to-end against real YAML strings
//! written to temp files, validating every fatal startup error path mandated
//! by FR-103 and the auto-anchoring behaviour mandated by FR-102.
//!
//! Key principle (Karpathy clean code): each test writes the minimal YAML
//! that provokes one specific failure mode — no shared fixtures, no helpers
//! that obscure what's being tested.

use std::io::Write;
use tempfile::NamedTempFile;

use agentwall::policy::engine::EvalResult;
use agentwall::policy::loader::{load_policy, PolicyLoadResult};

// ---------------------------------------------------------------------------
// Utility: write a YAML string to a temp file and return the path.
// ---------------------------------------------------------------------------

fn yaml_to_tempfile(yaml: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("cannot create temp file");
    write!(f, "{}", yaml).expect("cannot write yaml");
    f
}

// ---------------------------------------------------------------------------
// FR-103: Fatal startup errors
// ---------------------------------------------------------------------------

/// Missing policy file → FileNotFound.
#[test]
fn test_missing_policy_file_is_fatal() {
    let path = std::path::Path::new("/nonexistent/path/policy.yaml");
    match load_policy(path, None) {
        PolicyLoadResult::Fatal { .. } => {}
        other => panic!("Expected Fatal, got: {:?}", std::mem::discriminant(&other)),
    }
}

/// Malformed YAML → InvalidYaml.
#[test]
fn test_malformed_yaml_is_fatal() {
    let f = yaml_to_tempfile("version: [\nunclosed bracket");
    match load_policy(f.path(), None) {
        PolicyLoadResult::Fatal { .. } => {}
        other => panic!("Expected Fatal for malformed YAML, got discriminant: {:?}", std::mem::discriminant(&other)),
    }
}

/// `default_action: allow` → permanently invalid.
#[test]
fn test_default_action_allow_is_fatal() {
    let yaml = r#"
version: "2"
default_action: allow
tools: []
"#;
    let f = yaml_to_tempfile(yaml);
    match load_policy(f.path(), None) {
        PolicyLoadResult::Fatal { error } => {
            let msg = error.to_string();
            assert!(
                msg.contains("allow"),
                "Error message must mention 'allow', got: {}",
                msg
            );
        }
        other => panic!("Expected Fatal, got: {:?}", std::mem::discriminant(&other)),
    }
}

/// `default_action` field absent → fatal (serde will reject it due to
/// the required field, but check the loader surfaces the right error).
#[test]
fn test_default_action_missing_is_fatal() {
    // 'deny_unknown_fields' + required field absence causes serde to fail.
    let yaml = r#"
version: "2"
tools: []
"#;
    let f = yaml_to_tempfile(yaml);
    // Expect either Fatal or Degraded — either way the gateway must not start permissively.
    match load_policy(f.path(), None) {
        PolicyLoadResult::Loaded { .. } => {
            panic!("Must not load successfully when default_action is absent")
        }
        _ => {} // Fatal or Degraded — both acceptable here
    }
}

/// Unsupported version string → VersionMismatch.
#[test]
fn test_version_mismatch_is_fatal() {
    let yaml = r#"
version: "99"
default_action: deny
tools: []
"#;
    let f = yaml_to_tempfile(yaml);
    match load_policy(f.path(), None) {
        PolicyLoadResult::Fatal { error } => {
            let msg = error.to_string();
            assert!(
                msg.contains("99"),
                "Error message must include the bad version, got: {}",
                msg
            );
        }
        other => panic!("Expected Fatal, got: {:?}", std::mem::discriminant(&other)),
    }
}

/// `type: object` parameter with no `schema:` block → fatal.
/// This is the v6.1 blind pass-through removal — the most critical FR-102 AC.
#[test]
fn test_object_param_without_schema_is_fatal() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: transfer_funds
    action: allow
    parameters:
      - name: payload
        type: object
        required: true
"#;
    let f = yaml_to_tempfile(yaml);
    match load_policy(f.path(), None) {
        PolicyLoadResult::Fatal { error } => {
            let msg = error.to_string();
            assert!(
                msg.contains("transfer_funds") || msg.contains("payload") || msg.contains("object"),
                "Error must identify the offending tool/param, got: {}",
                msg
            );
        }
        other => panic!(
            "Expected Fatal for object param without schema, got: {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

/// `type: array` parameter with no `schema:` block → fatal (same rule).
#[test]
fn test_array_param_without_schema_is_fatal() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: bulk_insert
    action: allow
    parameters:
      - name: rows
        type: array
        required: true
"#;
    let f = yaml_to_tempfile(yaml);
    match load_policy(f.path(), None) {
        PolicyLoadResult::Fatal { .. } => {}
        other => panic!(
            "Expected Fatal for array param without schema, got: {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

/// Invalid regex pattern → InvalidRegex.
#[test]
fn test_invalid_regex_is_fatal() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: run_cmd
    action: allow
    parameters:
      - name: command
        type: string
        required: true
        pattern: "[unclosed"
"#;
    let f = yaml_to_tempfile(yaml);
    match load_policy(f.path(), None) {
        PolicyLoadResult::Fatal { error } => {
            let msg = error.to_string();
            assert!(
                msg.contains("run_cmd") || msg.contains("command") || msg.contains("regex"),
                "Error must identify the offending param, got: {}",
                msg
            );
        }
        other => panic!("Expected Fatal for invalid regex, got: {:?}", std::mem::discriminant(&other)),
    }
}

/// Unknown top-level field → fatal (strict `deny_unknown_fields` parsing).
#[test]
fn test_unknown_top_level_field_is_fatal() {
    let yaml = r#"
version: "2"
default_action: deny
unknown_enterprise_field: true
tools: []
"#;
    let f = yaml_to_tempfile(yaml);
    match load_policy(f.path(), None) {
        PolicyLoadResult::Fatal { .. } => {}
        other => panic!(
            "Expected Fatal for unknown top-level field, got: {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

/// Invalid action value (not "allow" or "deny") → InvalidAction.
#[test]
fn test_invalid_tool_action_is_fatal() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: my_tool
    action: notify
"#;
    let f = yaml_to_tempfile(yaml);
    match load_policy(f.path(), None) {
        PolicyLoadResult::Fatal { error } => {
            let msg = error.to_string();
            assert!(
                msg.contains("notify") || msg.contains("my_tool"),
                "Error must mention the invalid action, got: {}",
                msg
            );
        }
        other => panic!("Expected Fatal for invalid action, got: {:?}", std::mem::discriminant(&other)),
    }
}

// ---------------------------------------------------------------------------
// FR-102 AC-4: Auto-anchoring via the loader
// ---------------------------------------------------------------------------

/// Pattern written without anchors → loader wraps it as `^(?:...)$`.
/// Test verifies that partial matches are rejected after loading.
#[test]
fn test_auto_anchoring_via_loader() {
    // Pattern written as just `workspace/.*` (no `^` or `$`)
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        pattern: "workspace/.*"
"#;
    let f = yaml_to_tempfile(yaml);
    let (policy, _) = extract_loaded(f.path());

    // Exact match → allow.
    assert!(matches!(
        policy.evaluate("read_file", &serde_json::json!({"path": "workspace/src/main.rs"}), None),
        EvalResult::Allow
    ));

    // Partial prefix match that would succeed without anchoring → must deny.
    match policy.evaluate("read_file", &serde_json::json!({"path": "evil/workspace/src/main.rs"}), None) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(
                reason_code, "param_pattern_mismatch",
                "Auto-anchored pattern must reject partial prefix match"
            );
        }
        _ => panic!("Expected param_pattern_mismatch — auto-anchoring is not working"),
    }
}

/// `unanchored: true` suppresses auto-anchoring.
/// The engine then accepts a partial match that the anchored form would reject.
#[test]
fn test_unanchored_flag_via_loader() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: search
    action: allow
    parameters:
      - name: query
        type: string
        required: true
        pattern: "safe"
        unanchored: true
"#;
    let f = yaml_to_tempfile(yaml);
    let (policy, warnings) = extract_loaded(f.path());

    // Partial match allowed when unanchored.
    assert!(matches!(
        policy.evaluate("search", &serde_json::json!({"query": "totally_safe_query"}), None),
        EvalResult::Allow
    ));

    // Loader must emit a warning for unanchored patterns.
    assert!(
        warnings.iter().any(|w| w.contains("unanchored")),
        "Loader must warn about unanchored patterns; warnings: {:?}",
        warnings
    );
}

// ---------------------------------------------------------------------------
// FR-102 AC-1 via loader: 10 allowed + 1 unlisted → evaluate returns -32001
//   (the JSON-RPC error code is applied by the proxy layer; the engine
//    returns `not_in_policy` which the proxy maps to -32001)
// ---------------------------------------------------------------------------

#[test]
fn test_10_tools_allowed_1_unlisted_denied() {
    let tools: String = (0..10)
        .map(|i| {
            format!(
                "  - name: tool_{i}\n    action: allow\n",
                i = i
            )
        })
        .collect();

    let yaml = format!(
        "version: \"2\"\ndefault_action: deny\ntools:\n{}",
        tools
    );

    let f = yaml_to_tempfile(&yaml);
    let (policy, _) = extract_loaded(f.path());

    for i in 0..10u32 {
        let name = format!("tool_{}", i);
        assert!(
            matches!(policy.evaluate(&name, &serde_json::json!({}), None), EvalResult::Allow),
            "tool_{} must be allowed",
            i
        );
    }

    match policy.evaluate("tool_10", &serde_json::json!({}), None) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(
                reason_code, "not_in_policy",
                "Unlisted tool must return not_in_policy (maps to JSON-RPC -32001)"
            );
        }
        _ => panic!("Expected not_in_policy for unlisted tool"),
    }
}

// ---------------------------------------------------------------------------
// FR-102: Valid complete policy loads successfully and evaluates correctly
// ---------------------------------------------------------------------------

#[test]
fn test_valid_policy_with_object_schema_loads_and_evaluates() {
    let yaml = r#"
version: "2"
default_action: deny
session:
  max_calls_per_second: 10
tools:
  - name: configure_db
    action: allow
    parameters:
      - name: options
        type: object
        required: true
        schema:
          type: object
          properties:
            pool_size:
              type: integer
              minimum: 1
              maximum: 100
            read_only:
              type: boolean
          required:
            - pool_size
      - name: db_name
        type: string
        required: true
        pattern: "[a-z][a-z0-9_]*"
"#;
    let f = yaml_to_tempfile(yaml);
    let (policy, _) = extract_loaded(f.path());

    // Valid call → allow.
    assert!(matches!(
        policy.evaluate(
            "configure_db",
            &serde_json::json!({
                "options": {"pool_size": 10, "read_only": false},
                "db_name": "analytics_db"
            }),
            None
        ),
        EvalResult::Allow
    ));

    // Schema violation (pool_size too large) → deny.
    match policy.evaluate(
        "configure_db",
        &serde_json::json!({
            "options": {"pool_size": 9999},
            "db_name": "analytics_db"
        }),
        None,
    ) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "schema_validation_failed");
        }
        _ => panic!("Expected schema_validation_failed for pool_size > 100"),
    }

    // Pattern violation (uppercase in db_name) → deny.
    match policy.evaluate(
        "configure_db",
        &serde_json::json!({
            "options": {"pool_size": 5},
            "db_name": "Analytics_DB"
        }),
        None,
    ) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "param_pattern_mismatch");
        }
        _ => panic!("Expected param_pattern_mismatch for uppercase db_name"),
    }
}

// ---------------------------------------------------------------------------
// Internal: extract a loaded policy or panic — keeps test bodies clean.
// ---------------------------------------------------------------------------

fn extract_loaded(path: &std::path::Path) -> (agentwall::policy::engine::CompiledPolicy, Vec<String>) {
    match load_policy(path, None) {
        PolicyLoadResult::Loaded { policy, warnings, .. } => (policy, warnings),
        PolicyLoadResult::Fatal { error } => {
            panic!("Policy load failed unexpectedly: {}", error)
        }
        PolicyLoadResult::Degraded { reason } => {
            panic!("Policy degraded unexpectedly: {}", reason)
        }
    }
}
