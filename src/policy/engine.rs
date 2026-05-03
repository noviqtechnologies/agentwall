//! Policy engine — allowlist evaluation, type enforcement (FR-102)

use super::schema::ParamType;
use regex::Regex;
use serde_json::Value;

/// A compiled, ready-to-evaluate policy
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub tools: Vec<CompiledTool>,
    pub max_calls_per_second: u32,
}

/// A compiled tool rule with pre-compiled regex patterns
#[derive(Debug, Clone)]
pub struct CompiledTool {
    pub name: String,
    pub action: String,
    pub parameters: Vec<CompiledParam>,
}

/// A compiled parameter constraint
#[derive(Debug, Clone)]
pub struct CompiledParam {
    pub name: String,
    pub param_type: ParamType,
    pub pattern: Option<Regex>,
    pub max_length: Option<usize>,
    pub required: bool,
}

/// Result of policy evaluation
#[derive(Debug, Clone)]
pub enum EvalResult {
    Allow,
    Deny {
        reason_code: String,
        param_name: Option<String>,
        param_value: Option<String>,
        pattern: Option<String>,
    },
}

impl CompiledPolicy {
    /// Check if any allowed tool has object or array parameters (for session report disclosure)
    pub fn has_object_or_array_params(&self) -> bool {
        self.tools.iter().any(|t| {
            t.action == "allow"
                && t.parameters
                    .iter()
                    .any(|p| p.param_type == ParamType::Object || p.param_type == ParamType::Array)
        })
    }

    /// Get tool names that have object or array parameters
    pub fn object_param_tool_names(&self) -> Vec<String> {
        self.tools
            .iter()
            .filter(|t| {
                t.action == "allow"
                    && t.parameters.iter().any(|p| {
                        p.param_type == ParamType::Object || p.param_type == ParamType::Array
                    })
            })
            .map(|t| t.name.clone())
            .collect()
    }

    /// Evaluate a tool call against the policy.
    /// Returns Allow or Deny with reason.
    pub fn evaluate(&self, tool_name: &str, params: &Value) -> EvalResult {
        // Find tool in allowlist (case-sensitive exact match)
        let tool = match self.tools.iter().find(|t| t.name == tool_name) {
            Some(t) => t,
            None => {
                return EvalResult::Deny {
                    reason_code: "not_in_policy".to_string(),
                    param_name: None,
                    param_value: None,
                    pattern: None,
                }
            }
        };

        // Tool explicitly set to deny
        if tool.action == "deny" {
            return EvalResult::Deny {
                reason_code: "default_deny".to_string(),
                param_name: None,
                param_value: None,
                pattern: None,
            };
        }

        // Evaluate parameters
        let params_obj = match params {
            Value::Object(map) => map,
            Value::Null => &serde_json::Map::new(),
            _ => {
                return EvalResult::Deny {
                    reason_code: "param_type_mismatch".to_string(),
                    param_name: None,
                    param_value: None,
                    pattern: None,
                }
            }
        };

        for param_rule in &tool.parameters {
            let value = params_obj.get(&param_rule.name);

            // Check required
            if param_rule.required {
                if value.is_none() || value == Some(&Value::Null) {
                    return EvalResult::Deny {
                        reason_code: "param_required_missing".to_string(),
                        param_name: Some(param_rule.name.clone()),
                        param_value: None,
                        pattern: None,
                    };
                }
            }

            // Skip validation if parameter is absent and not required
            let value = match value {
                Some(v) if *v != Value::Null => v,
                _ => continue,
            };

            // Type enforcement
            match &param_rule.param_type {
                ParamType::String => {
                    let s = match value.as_str() {
                        Some(s) => s,
                        None => {
                            return EvalResult::Deny {
                                reason_code: "param_type_mismatch".to_string(),
                                param_name: Some(param_rule.name.clone()),
                                param_value: Some(value.to_string()),
                                pattern: None,
                            }
                        }
                    };
                    // max_length (bytes)
                    if let Some(max_len) = param_rule.max_length {
                        if s.len() > max_len {
                            return EvalResult::Deny {
                                reason_code: "param_max_length_exceeded".to_string(),
                                param_name: Some(param_rule.name.clone()),
                                param_value: Some(s.to_string()),
                                pattern: None,
                            };
                        }
                    }
                    // pattern
                    if let Some(re) = &param_rule.pattern {
                        if !re.is_match(s) {
                            return EvalResult::Deny {
                                reason_code: "param_pattern_mismatch".to_string(),
                                param_name: Some(param_rule.name.clone()),
                                param_value: Some(s.to_string()),
                                pattern: Some(re.as_str().to_string()),
                            };
                        }
                    }
                }
                ParamType::Number => {
                    if !value.is_number() {
                        return EvalResult::Deny {
                            reason_code: "param_type_mismatch".to_string(),
                            param_name: Some(param_rule.name.clone()),
                            param_value: Some(value.to_string()),
                            pattern: None,
                        };
                    }
                }
                ParamType::Boolean => {
                    if !value.is_boolean() {
                        return EvalResult::Deny {
                            reason_code: "param_type_mismatch".to_string(),
                            param_name: Some(param_rule.name.clone()),
                            param_value: Some(value.to_string()),
                            pattern: None,
                        };
                    }
                }
                ParamType::Object => {
                    // Enforce presence if required (already checked above)
                    // DO NOT validate content — blind pass-through
                    if !value.is_object() {
                        return EvalResult::Deny {
                            reason_code: "param_type_mismatch".to_string(),
                            param_name: Some(param_rule.name.clone()),
                            param_value: Some(value.to_string()),
                            pattern: None,
                        };
                    }
                }
                ParamType::Array => {
                    if !value.is_array() {
                        return EvalResult::Deny {
                            reason_code: "param_type_mismatch".to_string(),
                            param_name: Some(param_rule.name.clone()),
                            param_value: Some(value.to_string()),
                            pattern: None,
                        };
                    }
                }
            }
        }

        EvalResult::Allow
    }
}
