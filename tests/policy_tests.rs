use regex::Regex;
use serde_json::json;
use vexa::policy::engine::{CompiledParam, CompiledPolicy, CompiledTool, EvalResult};
use vexa::policy::schema::ParamType;

#[test]
fn test_allowlist_evaluation() {
    let policy = CompiledPolicy {
        max_calls_per_second: 10,
        tools: vec![
            CompiledTool {
                name: "allowed_tool".to_string(),
                action: "allow".to_string(),
                parameters: vec![],
            },
            CompiledTool {
                name: "denied_tool".to_string(),
                action: "deny".to_string(),
                parameters: vec![],
            },
        ],
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
            parameters: vec![CompiledParam {
                name: "path".to_string(),
                param_type: ParamType::String,
                pattern: Some(Regex::new(r"^(?:/workspace/.*)$").unwrap()),
                max_length: None,
                required: true,
            }],
        }],
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
fn test_object_blind_passthrough() {
    let policy = CompiledPolicy {
        max_calls_per_second: 10,
        tools: vec![CompiledTool {
            name: "obj_tool".to_string(),
            action: "allow".to_string(),
            parameters: vec![CompiledParam {
                name: "data".to_string(),
                param_type: ParamType::Object,
                pattern: None,
                max_length: None,
                required: true,
            }],
        }],
    };

    assert!(matches!(
        policy.evaluate(
            "obj_tool",
            &json!({"data": {"arbitrary": "content", "nested": {"a": 1}}})
        ),
        EvalResult::Allow
    ));

    match policy.evaluate("obj_tool", &json!({})) {
        EvalResult::Deny { reason_code, .. } => assert_eq!(reason_code, "param_required_missing"),
        _ => panic!("Expected deny for missing object"),
    }

    match policy.evaluate("obj_tool", &json!({"data": "string_instead_of_object"})) {
        EvalResult::Deny { reason_code, .. } => assert_eq!(reason_code, "param_type_mismatch"),
        _ => panic!("Expected deny for wrong type"),
    }
}

#[test]
fn test_type_enforcement_and_max_length() {
    let policy = CompiledPolicy {
        max_calls_per_second: 10,
        tools: vec![CompiledTool {
            name: "type_tool".to_string(),
            action: "allow".to_string(),
            parameters: vec![
                CompiledParam {
                    name: "s".to_string(),
                    param_type: ParamType::String,
                    pattern: None,
                    max_length: Some(5),
                    required: true,
                },
                CompiledParam {
                    name: "n".to_string(),
                    param_type: ParamType::Number,
                    pattern: None,
                    max_length: None,
                    required: true,
                },
                CompiledParam {
                    name: "b".to_string(),
                    param_type: ParamType::Boolean,
                    pattern: None,
                    max_length: None,
                    required: true,
                },
            ],
        }],
    };

    assert!(matches!(
        policy.evaluate("type_tool", &json!({"s": "12345", "n": 42, "b": true})),
        EvalResult::Allow
    ));

    match policy.evaluate("type_tool", &json!({"s": "123456", "n": 42, "b": true})) {
        EvalResult::Deny { reason_code, .. } => {
            assert_eq!(reason_code, "param_max_length_exceeded")
        }
        _ => panic!("Expected deny for max_length"),
    }
}
