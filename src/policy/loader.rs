//! Policy file loading, validation, and hashing (FR-103, NFR-203)
//!
//! ## v6.1 Changes — Nested Object Blind Pass-Through Removed (Guidance #6)
//!
//! Policies with `type: object` or `type: array` parameters that do not define an
//! inline JSON Schema are **rejected with a fatal error** at startup.
//!
//! This enforces Policy Schema v2 compliance. A security gateway that cannot inspect
//! deeply nested data structures is fundamentally flawed for DLP and policy enforcement.
//!
//! **Migration:** Add a `schema:` block to every `type: object` and `type: array`
//! parameter in your policy. Use `vexa check` in CI/CD to validate before deploying.

use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::Path;

use super::engine::CompiledPolicy;
use super::schema::{ParamType, PolicyFile, SUPPORTED_VERSIONS};
use crate::logging::{self, Level};
use std::sync::Arc;
use jsonschema::JSONSchema;

/// Errors during policy loading
#[derive(Debug)]
pub enum PolicyLoadError {
    FileNotFound(String),
    FileUnreadable(String),
    InvalidYaml(String),
    DefaultActionAllow,
    DefaultActionMissing,
    VersionMismatch(String),
    InvalidRegex {
        tool: String,
        param: String,
        pattern: String,
        error: String,
    },
    InvalidAction {
        tool: String,
        action: String,
    },
}

impl std::fmt::Display for PolicyLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileNotFound(p) => write!(f, "Policy file not found: {}", p),
            Self::FileUnreadable(e) => write!(f, "Policy file unreadable: {}", e),
            Self::InvalidYaml(e) => write!(f, "Invalid policy YAML: {}", e),
            Self::DefaultActionAllow => write!(f, "default_action: allow is not permitted"),
            Self::DefaultActionMissing => write!(f, "default_action field is required"),
            Self::VersionMismatch(v) => write!(
                f,
                "Unsupported version \"{}\". Supported: {:?}",
                v, SUPPORTED_VERSIONS
            ),
            Self::InvalidRegex {
                tool,
                param,
                pattern,
                error,
            } => {
                write!(
                    f,
                    "Invalid regex tool \"{}\" param \"{}\": \"{}\" — {}",
                    tool, param, pattern, error
                )
            }
            Self::InvalidAction { tool, action } => {
                write!(f, "Invalid action \"{}\" for tool \"{}\"", action, tool)
            }
        }
    }
}

pub enum PolicyLoadResult {
    Loaded {
        policy: CompiledPolicy,
        raw_hash: String,
        warnings: Vec<String>,
    },
    Degraded {
        reason: String,
    },
    Fatal {
        error: PolicyLoadError,
    },
}

/// Load, validate, and compile a policy file.
pub fn load_policy(path: &Path, issuer_override: Option<String>) -> PolicyLoadResult {
    let raw_bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                let reason = format!("Policy file not found: {}", path.display());
                logging::log_event(
                    Level::Error,
                    "policy_load_failed",
                    serde_json::json!({"reason": &reason}),
                );
                return PolicyLoadResult::Fatal {
                    error: PolicyLoadError::FileNotFound(reason),
                };
            }
            let reason = format!("Policy file unreadable: {}", e);
            logging::log_event(
                Level::Error,
                "policy_load_failed",
                serde_json::json!({"reason": &reason}),
            );
            return PolicyLoadResult::Fatal {
                error: PolicyLoadError::FileUnreadable(reason),
            };
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(&raw_bytes);
    let raw_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

    let mut warnings = Vec::new();
    check_world_writable(path, &mut warnings);

    let raw_str = match std::str::from_utf8(&raw_bytes) {
        Ok(s) => s,
        Err(e) => {
            let reason = format!("Policy file is not valid UTF-8: {}", e);
            return PolicyLoadResult::Degraded { reason };
        }
    };

    let policy_file: PolicyFile = match serde_yaml::from_str(raw_str) {
        Ok(p) => p,
        Err(e) => {
            let err_str = e.to_string();
            logging::log_event(
                Level::Error,
                "policy_load_failed",
                serde_json::json!({"reason": &err_str}),
            );
            return PolicyLoadResult::Fatal {
                error: PolicyLoadError::InvalidYaml(err_str),
            };
        }
    };

    if !SUPPORTED_VERSIONS.contains(&policy_file.version.as_str()) {
        return PolicyLoadResult::Fatal {
            error: PolicyLoadError::VersionMismatch(policy_file.version),
        };
    }

    match policy_file.default_action.as_str() {
        "deny" => {}
        "allow" => {
            return PolicyLoadResult::Fatal {
                error: PolicyLoadError::DefaultActionAllow,
            }
        }
        other => {
            return PolicyLoadResult::Fatal {
                error: PolicyLoadError::InvalidYaml(format!(
                    "default_action must be \"deny\", got \"{}\"",
                    other
                )),
            }
        }
    }

    let tools = policy_file.tools.unwrap_or_default();
    let mut compiled_tools = Vec::with_capacity(tools.len());

    for tool in &tools {
        match tool.action.as_str() {
            "allow" | "deny" => {}
            other => {
                return PolicyLoadResult::Fatal {
                    error: PolicyLoadError::InvalidAction {
                        tool: tool.name.clone(),
                        action: other.to_string(),
                    },
                }
            }
        }

        let identity_bound = if let Some(ident) = &tool.identity {
            if ident == "*" {
                let allow_wildcard = std::env::var("ALLOW_WILDCARD_IDENTITY")
                    .map(|v| v == "true")
                    .unwrap_or(false);
                if !allow_wildcard {
                    return PolicyLoadResult::Fatal {
                        error: PolicyLoadError::InvalidYaml(format!(
                            "Tool \"{}\" uses wildcard identity (\"*\") which is strictly gated behind ALLOW_WILDCARD_IDENTITY=true environment variable.",
                            tool.name
                        )),
                    };
                }
            }
            Some(ident.clone())
        } else {
            None
        };

        let mut compiled_params = Vec::new();
        if let Some(params) = &tool.parameters {
            for param in params {
                let compiled_regex = if let Some(pattern) = &param.pattern {
                    if param.param_type != ParamType::String {
                        return PolicyLoadResult::Fatal {
                            error: PolicyLoadError::InvalidYaml(format!(
                                "pattern only valid for string, tool \"{}\" param \"{}\" is {}",
                                tool.name, param.name, param.param_type
                            )),
                        };
                    }
                    let effective_pattern = if param.unanchored {
                        warnings.push(format!(
                            "Tool \"{}\" param \"{}\" has unanchored pattern.",
                            tool.name, param.name
                        ));
                        logging::log_event(
                            Level::Warn,
                            "unanchored_pattern",
                            serde_json::json!({"tool": &tool.name, "param": &param.name}),
                        );
                        pattern.clone()
                    } else {
                        format!("^(?:{})$", pattern)
                    };
                    match Regex::new(&effective_pattern) {
                        Ok(re) => Some(re),
                        Err(e) => {
                            return PolicyLoadResult::Fatal {
                                error: PolicyLoadError::InvalidRegex {
                                    tool: tool.name.clone(),
                                    param: param.name.clone(),
                                    pattern: pattern.clone(),
                                    error: e.to_string(),
                                },
                            }
                        }
                    }
                } else {
                    None
                };

                if param.max_length.is_some() && param.param_type != ParamType::String {
                    return PolicyLoadResult::Fatal {
                        error: PolicyLoadError::InvalidYaml(format!(
                            "max_length only valid for string, tool \"{}\" param \"{}\" is {}",
                            tool.name, param.name, param.param_type
                        )),
                    };
                }

                // v6.1 Guidance #6: Reject object/array params without inline JSON Schema.
                // Blind pass-through of complex parameter types is a critical security
                // vulnerability removed in v6.1. All object and array parameters MUST
                // define a schema for DLP inspection and policy enforcement.
                if (param.param_type == ParamType::Object || param.param_type == ParamType::Array)
                    && param.schema.is_none()
                {
                    return PolicyLoadResult::Fatal {
                        error: PolicyLoadError::InvalidYaml(format!(
                            "Tool \"{}\" param \"{}\" has type {} but no 'schema' is defined. \
                             Policy Schema v2 requires inline JSON Schema for all object and array \
                             parameters (v6.1 — blind pass-through removal). \
                             Add a 'schema:' block or change the parameter type to 'string'. \
                             See docs/VexaAgentWall-PRD-v6.1.md §6.2 for the migration guide.",
                            tool.name, param.name, param.param_type
                        )),
                    };
                }

                // Nested JSON Schema Compilation (FR-201)
                let compiled_schema = if let Some(schema_val) = &param.schema {
                    let mut schema_to_compile = schema_val.clone();

                    // Security: Enforce recursion depth (FR-201: 5 levels)
                    if let Err(e) = check_schema_depth(&schema_to_compile, 0) {
                        return PolicyLoadResult::Fatal {
                            error: PolicyLoadError::InvalidYaml(format!(
                                "Tool \"{}\" param \"{}\" schema exceeds depth limit: {}",
                                tool.name, param.name, e
                            )),
                        };
                    }

                    // Security: Default additionalProperties to false (FR-201)
                    inject_additional_properties_false(&mut schema_to_compile);

                    match JSONSchema::compile(&schema_to_compile) {
                        Ok(s) => Some(Arc::new(s)),
                        Err(e) => {
                            return PolicyLoadResult::Fatal {
                                error: PolicyLoadError::InvalidYaml(format!(
                                    "Tool \"{}\" param \"{}\" has invalid JSON Schema: {}",
                                    tool.name, param.name, e
                                )),
                            };
                        }
                    }
                } else {
                    None
                };

                let mut compiled_validators = Vec::new();
                if let Some(vals) = &param.validators {
                    for val in vals {
                        let compiled = match val {
                            super::schema::ValidatorRule::PathTraversal => {
                                super::engine::CompiledValidator::PathTraversal
                            }
                            super::schema::ValidatorRule::UrlSchemeAllowlist(ref schemes) => {
                                super::engine::CompiledValidator::UrlSchemeAllowlist(schemes.clone())
                            }
                            super::schema::ValidatorRule::SqlInjectionBasic => {
                                super::engine::CompiledValidator::SqlInjectionBasic
                            }
                            super::schema::ValidatorRule::ShellInjectionBasic => {
                                super::engine::CompiledValidator::ShellInjectionBasic
                            }
                            super::schema::ValidatorRule::Regex(ref pattern) => {
                                match Regex::new(pattern) {
                                    Ok(re) => super::engine::CompiledValidator::Regex(re),
                                    Err(e) => {
                                        return PolicyLoadResult::Fatal {
                                            error: PolicyLoadError::InvalidRegex {
                                                tool: tool.name.clone(),
                                                param: param.name.clone(),
                                                pattern: pattern.clone(),
                                                error: e.to_string(),
                                            },
                                        };
                                    }
                                }
                            }
                        };
                        compiled_validators.push(compiled);
                    }
                }

                compiled_params.push(super::engine::CompiledParam {
                    name: param.name.clone(),
                    param_type: param.param_type.clone(),
                    pattern: compiled_regex,
                    schema: compiled_schema,
                    max_length: param.max_length,
                    required: param.required,
                    validators: compiled_validators,
                });
            }
        }
        compiled_tools.push(super::engine::CompiledTool {
            name: tool.name.clone(),
            action: tool.action.clone(),
            risk: tool.risk.clone(),
            parameters: compiled_params,
            identity: identity_bound,
            // FR-5 v2.0 fields
            credential_scope: tool.credential_scope.clone(),
            semantic_anomaly_threshold: tool.semantic_anomaly_threshold,
            a2a_trust_level: tool.a2a_trust_level.clone(),
        });
    }

    let max_calls_per_second = policy_file
        .session
        .and_then(|s| s.max_calls_per_second)
        .unwrap_or(0);

    let (oidc_issuer, oidc_audience, oidc_cache_ttl) = if let Some(auth_cfg) = policy_file.auth {
        (Some(auth_cfg.issuer), Some(auth_cfg.audience), auth_cfg.cache_ttl_minutes)
    } else if let Some(ident) = policy_file.identity {
        (Some(ident.issuer), Some(ident.audience), None)
    } else {
        (None, None, None)
    };

    let identity_validator = if let (Some(issuer), Some(audience)) = (oidc_issuer, oidc_audience) {
        let final_issuer = issuer_override.unwrap_or(issuer);
        let validator = super::identity::IdentityValidator::new(final_issuer, audience, oidc_cache_ttl);
        validator.clone().start_background_rotation();
        Some(validator)
    } else {
        if let Some(issuer) = issuer_override {
             logging::log_event(
                Level::Warn,
                "oidc_issuer_ignored",
                serde_json::json!({"reason": "no auth or identity section in policy", "issuer": &issuer}),
            );
        }
        None
    };

    let (scannable_tools, safe_tools) = if let Some(scanning) = policy_file.response_scanning {
        (
            scanning.scannable_tools.unwrap_or_else(|| vec![
                "read_file".to_string(), "exec_command".to_string(), "run_shell".to_string(), 
                "run_command".to_string(), "http_get".to_string(), "list_files".to_string(), 
                "bash".to_string(), "execute".to_string(), "terminal".to_string(), 
                "read".to_string(), "cat".to_string(), "shell".to_string(), 
                "leak_secret".to_string(), "secret".to_string()
            ]),
            scanning.safe_tools.unwrap_or_else(|| vec![
                "tools/list".to_string(), "get_schema".to_string(), "get_metadata".to_string(), "ping".to_string()
            ])
        )
    } else {
        (
            vec![
                "read_file".to_string(), "exec_command".to_string(), "run_shell".to_string(), 
                "run_command".to_string(), "http_get".to_string(), "list_files".to_string(), 
                "bash".to_string(), "execute".to_string(), "terminal".to_string(), 
                "read".to_string(), "cat".to_string(), "shell".to_string(), 
                "leak_secret".to_string(), "secret".to_string()
            ],
            vec![
                "tools/list".to_string(), "get_schema".to_string(), "get_metadata".to_string(), "ping".to_string()
            ]
        )
    };

    // FR-306: Extract firewall configuration
    let firewall_config = policy_file.firewall.clone();
    if let Some(ref fw) = firewall_config {
        if fw.enabled {
            logging::log_event(
                Level::Info,
                "firewall_enabled",
                serde_json::json!({
                    "max_attempts": fw.cycle_detection.max_attempts,
                    "action": format!("{:?}", fw.cycle_detection.action)
                }),
            );
        }
    }

    PolicyLoadResult::Loaded {
        policy: CompiledPolicy {
            tools: compiled_tools,
            max_calls_per_second,
            identity_validator,
            scannable_tools,
            safe_tools,
            firewall: firewall_config,
        },
        raw_hash,
        warnings,
    }
}

fn check_world_writable(path: &Path, warnings: &mut Vec<String>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.permissions().mode() & 0o022 != 0 {
                let abs_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
                warnings.push(format!(
                    "Policy file is world-writable: {}",
                    abs_path.display()
                ));
                logging::log_event(
                    Level::Warn,
                    "policy_world_writable",
                    serde_json::json!({"path": abs_path.display().to_string()}),
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, warnings);
    }
}

/// Recursively inject "additionalProperties": false into objects if not specified (FR-201)
fn inject_additional_properties_false(value: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = value {
        if let Some(serde_json::Value::String(t)) = map.get("type") {
            if t == "object" && !map.contains_key("additionalProperties") {
                map.insert(
                    "additionalProperties".to_string(),
                    serde_json::Value::Bool(false),
                );
            }
        }

        // Recurse into properties
        if let Some(serde_json::Value::Object(props)) = map.get_mut("properties") {
            for (_, v) in props.iter_mut() {
                inject_additional_properties_false(v);
            }
        }

        // Recurse into items (for arrays)
        if let Some(items) = map.get_mut("items") {
            inject_additional_properties_false(items);
        }
    }
}

/// Check schema recursion depth (FR-201: limit 5)
fn check_schema_depth(value: &serde_json::Value, current_depth: usize) -> Result<(), String> {
    if current_depth > 5 {
        return Err("Recursion depth limit of 5 exceeded".to_string());
    }

    if let serde_json::Value::Object(map) = value {
        // Check properties
        if let Some(serde_json::Value::Object(props)) = map.get("properties") {
            for (_, v) in props.iter() {
                check_schema_depth(v, current_depth + 1)?;
            }
        }

        // Check items
        if let Some(items) = map.get("items") {
            check_schema_depth(items, current_depth + 1)?;
        }
    }

    Ok(())
}
