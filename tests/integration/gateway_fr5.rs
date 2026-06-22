//! FR-5 Gateway Integration Tests — AC-5.1, AC-5.2, AC-5.6, AC-5.8
//!
//! These tests validate the core acceptance criteria for the Centralized
//! Enforcement Gateway without requiring a live Docker/K8s deployment.
//! They operate directly against the gateway handler and credential scope
//! validator logic for deterministic, fast CI coverage.

use agentwall::policy::credential_scope::{CredentialScopeResult, CredentialScopeValidator};
use agentwall::policy::engine::{CompiledPolicy, CompiledTool, EvalResult};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_deny_policy() -> CompiledPolicy {
    CompiledPolicy {
        tools: vec![CompiledTool {
            name: "restricted_tool".to_string(),
            action: "deny".to_string(),
            risk: None,
            parameters: vec![],
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }],
        max_calls_per_second: 0,
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
    }
}



// ── AC-5.1: DENY returns correct JSON-RPC error structure ────────────────────

#[test]
fn test_ac5_1_policy_engine_deny_not_in_policy() {
    let policy = make_deny_policy();
    // Call a tool that is not in the allowlist at all → should be denied
    let result = policy.evaluate("unknown_tool", &serde_json::json!({}), None);
    assert!(
        matches!(result, EvalResult::Deny { ref reason_code, .. } if reason_code == "not_in_policy"),
        "Expected not_in_policy deny, got: {:?}",
        result
    );
}

#[test]
fn test_ac5_1_policy_engine_deny_explicit_deny_action() {
    let policy = make_deny_policy();
    // Tool in policy but action = "deny"
    let result = policy.evaluate("restricted_tool", &serde_json::json!({}), None);
    assert!(
        matches!(result, EvalResult::Deny { ref reason_code, .. } if reason_code == "default_deny"),
        "Expected default_deny, got: {:?}",
        result
    );
}

// ── AC-5.2: Allow latency — policy evaluation under 5ms ─────────────────────

#[test]
fn test_ac5_2_policy_evaluation_latency_under_5ms() {
    // Build a policy with 50 allow-listed tools to simulate a real-world load
    let tools: Vec<CompiledTool> = (0..50)
        .map(|i| CompiledTool {
            name: format!("tool_{}", i),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![],
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        })
        .collect();

    let policy = CompiledPolicy {
        tools,
        max_calls_per_second: 0,
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
    };

    let iterations = 1000;
    let start = std::time::Instant::now();
    for i in 0..iterations {
        let tool_name = format!("tool_{}", i % 50);
        let _ = policy.evaluate(&tool_name, &serde_json::json!({}), None);
    }
    let elapsed = start.elapsed();
    let avg_ns = elapsed.as_nanos() / iterations;
    let avg_ms = avg_ns as f64 / 1_000_000.0;

    assert!(
        avg_ms < 5.0,
        "AC-5.2 FAILED: Average policy evaluation latency was {:.4}ms (must be < 5ms)",
        avg_ms
    );
    println!(
        "AC-5.2 PASS: Average evaluation latency = {:.4}ms over {} iterations",
        avg_ms, iterations
    );
}

// ── AC-5.8: Credential scope insufficient → DENY in strict mode ──────────────

#[test]
fn test_ac5_8_strict_mode_denies_on_scope_mismatch() {
    let v = CredentialScopeValidator::new(true); // strict = DENY
    let result = v.validate(
        "delete_db",
        &["admin".to_string(), "dba".to_string()],
        Some("read-only"),
        "test-session-001",
    );
    assert!(
        matches!(result, CredentialScopeResult::Insufficient { .. }),
        "Strict mode must DENY on scope mismatch"
    );
}

#[test]
fn test_ac5_8_warn_mode_permits_on_scope_mismatch() {
    let v = CredentialScopeValidator::new(false); // default WARN mode
    let result = v.validate(
        "delete_db",
        &["admin".to_string()],
        Some("read-only"),
        "test-session-002",
    );
    assert_eq!(
        result,
        CredentialScopeResult::Permitted,
        "WARN mode must permit on scope mismatch (just log)"
    );
}

#[test]
fn test_ac5_8_strict_mode_denies_missing_header() {
    let v = CredentialScopeValidator::new(true);
    let result = v.validate(
        "exec_command",
        &["shell-access".to_string()],
        None, // no header
        "test-session-003",
    );
    assert!(
        matches!(result, CredentialScopeResult::Insufficient { .. }),
        "Strict mode must DENY when no X-AgentWall-Credential-Scope header is present"
    );
}

#[test]
fn test_ac5_8_not_configured_when_no_scopes_required() {
    let v = CredentialScopeValidator::new(true);
    let result = v.validate("read_file", &[], None, "test-session-004");
    assert_eq!(
        result,
        CredentialScopeResult::NotConfigured,
        "Must be NotConfigured when tool has no credential_scope policy"
    );
}

#[test]
fn test_ac5_8_wildcard_scope_permits_all_in_strict_mode() {
    let v = CredentialScopeValidator::new(true);
    let result = v.validate(
        "any_tool",
        &["admin".to_string(), "write".to_string()],
        Some("*"),
        "test-session-005",
    );
    assert_eq!(
        result,
        CredentialScopeResult::Permitted,
        "Wildcard scope '*' must permit all tools even in strict mode"
    );
}

// ── AC-5.6: Policy hot-reload — schema round-trip ───────────────────────────

#[test]
fn test_ac5_6_policy_reload_schema_round_trip() {
    // Validate that a policy YAML with the new v2.0 fields parses correctly
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: read_file
    action: allow
    credential_scope:
      - read-only
      - read-write
    semantic_anomaly_threshold: 0.85
    a2a_trust_level: same-org
    parameters:
      - name: path
        type: string
        required: true
"#;

    let policy_file: agentwall::policy::schema::PolicyFile =
        serde_yaml::from_str(yaml).expect("v2.0 policy YAML should parse without error");

    let tools = policy_file.tools.expect("tools must be present");
    assert_eq!(tools.len(), 1);

    let tool = &tools[0];
    assert_eq!(tool.name, "read_file");
    assert_eq!(tool.credential_scope, vec!["read-only", "read-write"]);
    assert_eq!(tool.semantic_anomaly_threshold, Some(0.85f32));
    assert_eq!(tool.a2a_trust_level.as_deref(), Some("same-org"));

    println!("AC-5.6 PASS: v2.0 policy schema parsed credential_scope, semantic_anomaly_threshold, a2a_trust_level correctly");
}

// ── AC-5.5: Fail-closed — no policy loaded ───────────────────────────────────

#[test]
fn test_ac5_5_deny_all_when_policy_loaded_but_missing() {
    // Simulate: policy_loaded = true but compiled policy is None (degraded)
    // The engine should deny any tool call
    let policy = CompiledPolicy {
        tools: vec![],   // empty — no tools allowed
        max_calls_per_second: 0,
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
    };

    let result = policy.evaluate("any_tool", &serde_json::json!({}), None);
    assert!(
        matches!(result, EvalResult::Deny { ref reason_code, .. } if reason_code == "not_in_policy"),
        "AC-5.5: Gateway with empty policy must deny ALL tool calls"
    );
}
