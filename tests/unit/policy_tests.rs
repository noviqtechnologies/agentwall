//! Unit tests for CompiledPolicy::evaluate — FR-102 acceptance criteria
//!
//! Tests exercise the engine directly with pre-compiled artefacts so there is
//! no I/O in the hot path. Loader-level startup error tests live in
//! `policy_loader_tests.rs`.

use jsonschema::JSONSchema;
use regex::Regex;
use serde_json::json;
use std::sync::Arc;

use agentwall::policy::engine::{CompiledParam, CompiledPolicy, CompiledTool, EvalResult};
use agentwall::policy::schema::ParamType;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal policy builder — keeps individual tests small and focused.
fn policy(tools: Vec<CompiledTool>) -> CompiledPolicy {
    CompiledPolicy {
        tools,
        max_calls_per_second: 0,
        identity_validator: None,
        scannable_tools: vec!["read_file".to_string()],
        safe_tools: vec!["ping".to_string()],
        firewall: None,
    }
}

fn allow_tool(name: &str, params: Vec<CompiledParam>) -> CompiledTool {
    CompiledTool {
        name: name.to_string(),
        action: "allow".to_string(),
        risk: None,
        parameters: params,
        identity: None,
    }
}

fn deny_tool(name: &str) -> CompiledTool {
    CompiledTool {
        name: name.to_string(),
        action: "deny".to_string(),
        risk: None,
        parameters: vec![],
        identity: None,
    }
}

fn string_param(name: &str, required: bool) -> CompiledParam {
    CompiledParam {
        name: name.to_string(),
        param_type: ParamType::String,
        pattern: None,
        schema: None,
        max_length: None,
        required,
        validators: vec![],
    }
}

// Extension trait to avoid changing all .evaluate calls to pass None
trait EvalExt {
    fn evaluate_test(&self, tool_name: &str, params: &serde_json::Value) -> EvalResult;
}
impl EvalExt for CompiledPolicy {
    fn evaluate_test(&self, tool_name: &str, params: &serde_json::Value) -> EvalResult {
        self.evaluate(tool_name, params, None)
    }
}

// ---------------------------------------------------------------------------
// FR-102 AC-1: 10 allowed tools pass, 1 unlisted → not_in_policy
// ---------------------------------------------------------------------------

#[test]
fn test_allowlist_evaluation() {
    // Build a policy with 10 named allowed tools + 1 explicit deny tool.
    let mut tools: Vec<CompiledTool> = (0..10)
        .map(|i| allow_tool(&format!("tool_{}", i), vec![]))
        .collect();
    tools.push(deny_tool("blocked_tool"));

    let p = policy(tools);

    // All 10 allowed tools must pass.
    for i in 0..10u32 {
        let name = format!("tool_{}", i);
        assert!(
            matches!(p.evaluate_test(&name, &json!({})), EvalResult::Allow),
            "tool_{} should be allowed",
            i
        );
    }

    // Explicit deny entry → default_deny.
    match p.evaluate_test("blocked_tool", &json!({})) {
        EvalResult::Deny { reason_code, .. } => assert_eq!(reason_code, "default_deny"),
        _ => panic!("Expected deny for blocked_tool"),
    }

    // Tool not in policy at all → not_in_policy.
    match p.evaluate_test("unlisted_tool", &json!({})) {
        EvalResult::Deny { reason_code, .. } => assert_eq!(reason_code, "not_in_policy"),
        _ => panic!("Expected not_in_policy for unlisted_tool"),
    }
}

// ---------------------------------------------------------------------------
// FR-102 AC-4: Auto-anchoring — pattern applied as ^(?:...)$ by loader
//   The loader wraps patterns; tests here verify the engine uses whatever
//   compiled Regex it receives. Loader-level anchoring is in
//   policy_loader_tests.rs.
// ---------------------------------------------------------------------------

#[test]
fn test_regex_anchoring_engine_level() {
    // Simulates what the loader produces after auto-anchoring "workspace/.*"
    let anchored = Regex::new(r"^(?:workspace/.*)$").unwrap();

    let p = policy(vec![allow_tool(
        "fs_read",
        vec![CompiledParam {
            name: "path".to_string(),
            param_type: ParamType::String,
            pattern: Some(anchored),
            schema: None,
            max_length: None,
            required: true,
            validators: vec![],
        }],
    )]);

    assert!(matches!(
        p.evaluate_test("fs_read", &json!({"path": "workspace/src/main.rs"})),
        EvalResult::Allow
    ));

    // Without the leading anchor a partial match like "bad/workspace/file"
    // must still be rejected.
    match p.evaluate_test("fs_read", &json!({"path": "bad/workspace/file"})) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "param_pattern_mismatch")
        }
        _ => panic!("Expected deny for path outside anchor"),
    }
}

// ---------------------------------------------------------------------------
// FR-102: max_length enforcement on string params
// ---------------------------------------------------------------------------

#[test]
fn test_max_length_string_enforcement() {
    let p = policy(vec![allow_tool(
        "log_event",
        vec![CompiledParam {
            name: "message".to_string(),
            param_type: ParamType::String,
            pattern: None,
            schema: None,
            max_length: Some(32),
            required: true,
            validators: vec![],
        }],
    )]);

    // Exactly at the limit → allow.
    let at_limit = "a".repeat(32);
    assert!(matches!(
        p.evaluate_test("log_event", &json!({"message": at_limit})),
        EvalResult::Allow
    ));

    // One byte over → deny.
    let over_limit = "a".repeat(33);
    match p.evaluate_test("log_event", &json!({"message": over_limit})) {
        EvalResult::Deny { reason_code, param_name, .. } => {
            assert_eq!(reason_code, "param_max_length_exceeded");
            assert_eq!(param_name.as_deref(), Some("message"));
        }
        _ => panic!("Expected param_max_length_exceeded"),
    }
}

// ---------------------------------------------------------------------------
// FR-102: Number type enforcement
// ---------------------------------------------------------------------------

#[test]
fn test_number_type_enforcement() {
    let p = policy(vec![allow_tool(
        "set_timeout",
        vec![CompiledParam {
            name: "seconds".to_string(),
            param_type: ParamType::Number,
            pattern: None,
            schema: None,
            max_length: None,
            required: true,
            validators: vec![],
        }],
    )]);

    assert!(matches!(
        p.evaluate_test("set_timeout", &json!({"seconds": 30})),
        EvalResult::Allow
    ));

    assert!(matches!(
        p.evaluate_test("set_timeout", &json!({"seconds": 1.5})),
        EvalResult::Allow
    ));

    match p.evaluate_test("set_timeout", &json!({"seconds": "thirty"})) {
        EvalResult::Deny { reason_code, param_name, .. } => {
            assert_eq!(reason_code, "param_type_mismatch");
            assert_eq!(param_name.as_deref(), Some("seconds"));
        }
        _ => panic!("Expected param_type_mismatch for string-as-number"),
    }
}

// ---------------------------------------------------------------------------
// FR-102: Boolean type enforcement
// ---------------------------------------------------------------------------

#[test]
fn test_boolean_type_enforcement() {
    let p = policy(vec![allow_tool(
        "toggle_feature",
        vec![CompiledParam {
            name: "enabled".to_string(),
            param_type: ParamType::Boolean,
            pattern: None,
            schema: None,
            max_length: None,
            required: true,
            validators: vec![],
        }],
    )]);

    assert!(matches!(
        p.evaluate_test("toggle_feature", &json!({"enabled": true})),
        EvalResult::Allow
    ));

    assert!(matches!(
        p.evaluate_test("toggle_feature", &json!({"enabled": false})),
        EvalResult::Allow
    ));

    // String "true" is not a boolean.
    match p.evaluate_test("toggle_feature", &json!({"enabled": "true"})) {
        EvalResult::Deny { reason_code, param_name, .. } => {
            assert_eq!(reason_code, "param_type_mismatch");
            assert_eq!(param_name.as_deref(), Some("enabled"));
        }
        _ => panic!("Expected param_type_mismatch for string-as-boolean"),
    }
}

// ---------------------------------------------------------------------------
// FR-102: Required parameter missing → deny
// ---------------------------------------------------------------------------

#[test]
fn test_required_parameter_missing() {
    let p = policy(vec![allow_tool(
        "run_query",
        vec![
            CompiledParam {
                name: "sql".to_string(),
                param_type: ParamType::String,
                pattern: None,
                schema: None,
                max_length: None,
                required: true,
                validators: vec![],
            },
            CompiledParam {
                name: "timeout".to_string(),
                param_type: ParamType::Number,
                pattern: None,
                schema: None,
                max_length: None,
                required: false, // optional — absence must be allowed
                validators: vec![],
            },
        ],
    )]);

    // Required present, optional absent → allow.
    assert!(matches!(
        p.evaluate_test("run_query", &json!({"sql": "SELECT 1"})),
        EvalResult::Allow
    ));

    // Required absent → deny.
    match p.evaluate_test("run_query", &json!({"timeout": 5})) {
        EvalResult::Deny { reason_code, param_name, .. } => {
            assert_eq!(reason_code, "param_required_missing");
            assert_eq!(param_name.as_deref(), Some("sql"));
        }
        _ => panic!("Expected param_required_missing when required param is absent"),
    }
}

// ---------------------------------------------------------------------------
// FR-102 AC-2: type: object parameter violating inline JSON Schema → DENY
// ---------------------------------------------------------------------------

#[test]
fn test_object_schema_violation_is_denied() {
    let schema_json = json!({
        "type": "object",
        "properties": {
            "limit": { "type": "integer", "maximum": 50 }
        },
        "required": ["limit"],
        "additionalProperties": false
    });
    let compiled = Arc::new(JSONSchema::compile(&schema_json).unwrap());

    let p = policy(vec![allow_tool(
        "query_db",
        vec![CompiledParam {
            name: "options".to_string(),
            param_type: ParamType::Object,
            pattern: None,
            schema: Some(compiled),
            max_length: None,
            required: true,
            validators: vec![],
        }],
    )]);

    // Valid payload → allow.
    assert!(matches!(
        p.evaluate_test("query_db", &json!({"options": {"limit": 10}})),
        EvalResult::Allow
    ));

    // Limit exceeds maximum → schema_validation_failed at /limit.
    match p.evaluate_test("query_db", &json!({"options": {"limit": 100}})) {
        EvalResult::Deny { reason_code, json_pointer, .. } => {
            assert_eq!(reason_code, "schema_validation_failed");
            assert_eq!(json_pointer.as_deref(), Some("/limit"));
        }
        _ => panic!("Expected schema_validation_failed when limit > 50"),
    }

    // Required field missing → schema_validation_failed at root.
    match p.evaluate_test("query_db", &json!({"options": {}})) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "schema_validation_failed");
        }
        _ => panic!("Expected schema_validation_failed when required field absent"),
    }

    // Additional property injected → rejected (additionalProperties: false).
    match p.evaluate_test("query_db", &json!({"options": {"limit": 5, "evil": true}})) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "schema_validation_failed");
        }
        _ => panic!("Expected schema_validation_failed for additional property"),
    }
}

// ---------------------------------------------------------------------------
// FR-102: type: array parameter validated against inline JSON Schema
// ---------------------------------------------------------------------------

#[test]
fn test_array_schema_validation() {
    let schema_json = json!({
        "type": "array",
        "items": { "type": "string" },
        "maxItems": 3
    });
    let compiled = Arc::new(JSONSchema::compile(&schema_json).unwrap());

    let p = policy(vec![allow_tool(
        "bulk_tag",
        vec![CompiledParam {
            name: "tags".to_string(),
            param_type: ParamType::Array,
            pattern: None,
            schema: Some(compiled),
            max_length: None,
            required: true,
            validators: vec![],
        }],
    )]);

    // Valid array → allow.
    assert!(matches!(
        p.evaluate_test("bulk_tag", &json!({"tags": ["alpha", "beta"]})),
        EvalResult::Allow
    ));

    // Too many items → deny.
    match p.evaluate_test("bulk_tag", &json!({"tags": ["a", "b", "c", "d"]})) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "schema_validation_failed");
        }
        _ => panic!("Expected schema_validation_failed for maxItems exceeded"),
    }

    // Wrong item type → deny.
    match p.evaluate_test("bulk_tag", &json!({"tags": [1, 2]})) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "schema_validation_failed");
        }
        _ => panic!("Expected schema_validation_failed for wrong item type"),
    }
}

// ---------------------------------------------------------------------------
// FR-102: type: object with NO schema block — engine passes through
//   (blind pass-through is blocked by the loader, not the engine itself;
//   see policy_loader_tests.rs for the fatal startup test)
// ---------------------------------------------------------------------------

#[test]
fn test_object_without_schema_engine_passthrough() {
    // The engine does not enforce schema-presence — that is the loader's job.
    // If code somehow constructs a CompiledParam{Object, schema: None}, the
    // engine should still do type-checking and allow a valid object.
    let p = policy(vec![allow_tool(
        "legacy",
        vec![CompiledParam {
            name: "data".to_string(),
            param_type: ParamType::Object,
            pattern: None,
            schema: None, // no schema — type-check only
            max_length: None,
            required: false,
            validators: vec![],
        }],
    )]);

    // Object value → passes type check.
    assert!(matches!(
        p.evaluate_test("legacy", &json!({"data": {"key": "value"}})),
        EvalResult::Allow
    ));

    // Non-object value → param_type_mismatch.
    match p.evaluate_test("legacy", &json!({"data": "not-an-object"})) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "param_type_mismatch");
        }
        _ => panic!("Expected param_type_mismatch"),
    }
}

// ---------------------------------------------------------------------------
// FR-102: Payload size limit (100 KB ceiling)
// ---------------------------------------------------------------------------

#[test]
fn test_payload_size_limit_100kb() {
    let p = policy(vec![allow_tool("upload", vec![])]);

    // 110 KB payload → payload_too_large.
    let big = json!({ "blob": "x".repeat(110 * 1024) });
    match p.evaluate_test("upload", &big) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "payload_too_large");
        }
        _ => panic!("Expected payload_too_large"),
    }

    // Exactly 1 byte under 100 KB → allow.
    let fine = json!({ "blob": "x".repeat(100 * 1024 - 20) }); // account for JSON overhead
    assert!(matches!(p.evaluate_test("upload", &fine), EvalResult::Allow));
}

// ---------------------------------------------------------------------------
// FR-102: Params must be a JSON object (not array, not scalar)
// ---------------------------------------------------------------------------

#[test]
fn test_params_must_be_object_or_null() {
    let p = policy(vec![allow_tool("noop", vec![string_param("x", false)])]);

    // null params → treated as empty object → allow (no required params).
    assert!(matches!(
        p.evaluate_test("noop", &json!(null)),
        EvalResult::Allow
    ));

    // Array params → param_type_mismatch at call level.
    match p.evaluate_test("noop", &json!(["not", "an", "object"])) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "param_type_mismatch");
        }
        _ => panic!("Expected param_type_mismatch for array-as-params"),
    }
}
