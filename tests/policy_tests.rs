use regex::Regex;
use serde_json::json;
use agentwall::policy::engine::{CompiledParam, CompiledPolicy, CompiledTool, EvalResult};
use agentwall::policy::schema::ParamType;

#[test]
fn test_allowlist_evaluation() {
    let policy = CompiledPolicy {
        max_calls_per_second: 10,
        tools: vec![
            CompiledTool {
                name: "allowed_tool".to_string(),
                action: "allow".to_string(),
                risk: None,
                parameters: vec![],
            },
            CompiledTool {
                name: "denied_tool".to_string(),
                action: "deny".to_string(),
                risk: None,
                parameters: vec![],
            },
        ],
        identity_validator: None,
    };

    assert!(matches!(
        policy.evaluate("allowed_tool", &json!({})),
        EvalResult::Allow
    ));

    match policy.evaluate("denied_tool", &json!({})) {
        EvalResult::Deny { reason_code, .. } => assert_eq!(reason_code, "default_deny"),
        _ => panic!("Expected deny"),
    }

    match policy.evaluate("unknown_tool", &json!({})) {
        EvalResult::Deny { reason_code, .. } => assert_eq!(reason_code, "not_in_policy"),
        _ => panic!("Expected deny"),
    }
}

#[test]
fn test_regex_anchoring() {
    let policy = CompiledPolicy {
        max_calls_per_second: 10,
        tools: vec![CompiledTool {
            name: "regex_tool".to_string(),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![CompiledParam {
                name: "path".to_string(),
                param_type: ParamType::String,
                pattern: Some(Regex::new(r"^(?:/workspace/.*)$").unwrap()),
                schema: None,
                max_length: None,
                required: true,
            }],
        }],
        identity_validator: None,
    };

    assert!(matches!(
        policy.evaluate("regex_tool", &json!({"path": "/workspace/foo.txt"})),
        EvalResult::Allow
    ));

    match policy.evaluate("regex_tool", &json!({"path": "bar/workspace/foo.txt"})) {
        EvalResult::Deny { reason_code, .. } => assert_eq!(reason_code, "param_pattern_mismatch"),
        _ => panic!("Expected deny for unanchored match"),
    }
}

#[test]
fn test_object_blind_passthrough_if_no_schema() {
    let policy = CompiledPolicy {
        max_calls_per_second: 10,
        tools: vec![CompiledTool {
            name: "obj_tool".to_string(),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![CompiledParam {
                name: "data".to_string(),
                param_type: ParamType::Object,
                pattern: None,
                schema: None,
                max_length: None,
                required: true,
            }],
        }],
        identity_validator: None,
    };

    assert!(matches!(
        policy.evaluate(
            "obj_tool",
            &json!({"data": {"arbitrary": "content", "nested": {"a": 1}}})
        ),
        EvalResult::Allow
    ));
}

#[test]
fn test_nested_schema_validation() {
    use jsonschema::JSONSchema;
    use std::sync::Arc;

    let schema_json = json!({
        "type": "object",
        "properties": {
            "limit": { "type": "integer", "maximum": 50 }
        },
        "required": ["limit"],
        "additionalProperties": false
    });
    let compiled_schema = Arc::new(JSONSchema::compile(&schema_json).unwrap());

    let policy = CompiledPolicy {
        max_calls_per_second: 0,
        tools: vec![CompiledTool {
            name: "query_db".to_string(),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![CompiledParam {
                name: "options".to_string(),
                param_type: ParamType::Object,
                pattern: None,
                schema: Some(compiled_schema),
                max_length: None,
                required: true,
            }],
        }],
        identity_validator: None,
    };

    // Valid call
    assert!(matches!(
        policy.evaluate("query_db", &json!({"options": {"limit": 10}})),
        EvalResult::Allow
    ));

    // Invalid: missing required field
    match policy.evaluate("query_db", &json!({"options": {}})) {
        EvalResult::Deny { reason_code, json_pointer, .. } => {
            assert_eq!(reason_code, "schema_validation_failed");
            assert_eq!(json_pointer, Some("".to_string())); // root of options fails required
        }
        _ => panic!("Expected schema failure"),
    }

    // Invalid: maximum exceeded
    match policy.evaluate("query_db", &json!({"options": {"limit": 100}})) {
        EvalResult::Deny { reason_code, json_pointer, .. } => {
            assert_eq!(reason_code, "schema_validation_failed");
            assert_eq!(json_pointer, Some("/limit".to_string()));
        }
        _ => panic!("Expected schema failure"),
    }

    // Invalid: additional properties (defaulted to false in loader, but here we set it in schema)
    match policy.evaluate("query_db", &json!({"options": {"limit": 10, "bogus": true}})) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "schema_validation_failed");
        }
        _ => panic!("Expected schema failure"),
    }
}

#[test]
fn test_payload_size_limit() {
    let policy = CompiledPolicy {
        max_calls_per_second: 0,
        tools: vec![CompiledTool {
            name: "tool".to_string(),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![],
        }],
        identity_validator: None,
    };

    let large_params = json!({ "data": "a".repeat(110 * 1024) });
    match policy.evaluate("tool", &large_params) {
        EvalResult::Deny { reason_code, .. } => assert_eq!(reason_code, "payload_too_large"),
        _ => panic!("Expected payload_too_large"),
    }
}
