//! Policy file loading, validation, and hashing (FR-103, NFR-203)

use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::Path;

use super::engine::CompiledPolicy;
use super::schema::{ParamType, PolicyFile, SUPPORTED_VERSIONS};
use crate::logging::{self, Level};

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
pub fn load_policy(path: &Path) -> PolicyLoadResult {
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

                compiled_params.push(super::engine::CompiledParam {
                    name: param.name.clone(),
                    param_type: param.param_type.clone(),
                    pattern: compiled_regex,
                    max_length: param.max_length,
                    required: param.required,
                });
            }
        }
        compiled_tools.push(super::engine::CompiledTool {
            name: tool.name.clone(),
            action: tool.action.clone(),
            parameters: compiled_params,
        });
    }

    let max_calls_per_second = policy_file
        .session
        .and_then(|s| s.max_calls_per_second)
        .unwrap_or(0);

    PolicyLoadResult::Loaded {
        policy: CompiledPolicy {
            tools: compiled_tools,
            max_calls_per_second,
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
