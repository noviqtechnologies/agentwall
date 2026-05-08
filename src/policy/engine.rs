//! Policy engine — allowlist evaluation, type enforcement (FR-102)

use super::schema::ParamType;
use regex::Regex;
use serde_json::Value;
use std::sync::Arc;
use jsonschema::JSONSchema;

/// A compiled, ready-to-evaluate policy
#[derive(Clone)]
pub struct CompiledPolicy {
    pub tools: Vec<CompiledTool>,
    pub max_calls_per_second: u32,
    pub identity_validator: Option<Arc<super::identity::IdentityValidator>>,
}

impl std::fmt::Debug for CompiledPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledPolicy")
            .field("tools", &self.tools)
            .field("max_calls_per_second", &self.max_calls_per_second)
            .field("identity_validator", &self.identity_validator.as_ref().map(|_| "Some(IdentityValidator)"))
            .finish()
    }
}

/// A compiled tool rule with pre-compiled regex patterns
#[derive(Debug, Clone)]
pub struct CompiledTool {
    pub name: String,
    pub action: String,
    pub risk: Option<super::schema::ToolRisk>,
    pub parameters: Vec<CompiledParam>,
}

/// A compiled parameter constraint
#[derive(Clone)]
pub struct CompiledParam {
    pub name: String,
    pub param_type: ParamType,
    pub pattern: Option<Regex>,
    pub schema: Option<Arc<JSONSchema>>,
    pub max_length: Option<usize>,
    pub required: bool,
}

impl std::fmt::Debug for CompiledParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledParam")
            .field("name", &self.name)
            .field("param_type", &self.param_type)
            .field("pattern", &self.pattern)
            .field("schema", &self.schema.as_ref().map(|_| "Some(JSONSchema)"))
            .field("max_length", &self.max_length)
            .field("required", &self.required)
            .finish()
    }
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
        json_pointer: Option<String>, // FR-201
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
                    json_pointer: None,
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
                json_pointer: None,
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
                    json_pointer: None,
                }
            }
        };

        // Payload size limit (FR-201: 100KB)
        let payload_str = params.to_string();
        if payload_str.len() > 100 * 1024 {
            return EvalResult::Deny {
                reason_code: "payload_too_large".to_string(),
                param_name: None,
                param_value: None,
                pattern: None,
                json_pointer: None,
            };
        }

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
                        json_pointer: None,
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
                                json_pointer: None,
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
                                json_pointer: None,
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
                                json_pointer: None,
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
                            json_pointer: None,
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
                            json_pointer: None,
                        };
                    }
                }
                ParamType::Object => {
                    if !value.is_object() {
                        return EvalResult::Deny {
                            reason_code: "param_type_mismatch".to_string(),
                            param_name: Some(param_rule.name.clone()),
                            param_value: Some(value.to_string()),
                            pattern: None,
                            json_pointer: None,
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
                            json_pointer: None,
                        };
                    }
                }
            }

            // Nested JSON Schema Validation (FR-201)
            if let Some(schema) = &param_rule.schema {
                if let Err(errors) = schema.validate(value) {
                    // Get the first error and return as JSON Pointer (RFC 6901)
                    let first_error = errors.into_iter().next();
                    let pointer = first_error.map(|e| e.instance_path.to_string());
                    
                    return EvalResult::Deny {
                        reason_code: "schema_validation_failed".to_string(),
                        param_name: Some(param_rule.name.clone()),
                        param_value: Some(value.to_string()),
                        pattern: None,
                        json_pointer: pointer,
                    };
                }
            }
        }

        EvalResult::Allow
    }
}
