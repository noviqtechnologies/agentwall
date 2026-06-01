use std::path::Path;
use std::fs;
use serde_json::Value;
use crate::policy::loader::{load_policy, PolicyLoadResult};
use crate::policy::engine::EvalResult;

pub fn execute(policy_path: &str, tool_name: &str, payload_path: &str) -> Result<(), String> {
    // 1. Load Policy
    let load_res = load_policy(Path::new(policy_path), None);
    let policy = match load_res {
        PolicyLoadResult::Loaded { policy, .. } => policy,
        PolicyLoadResult::Degraded { reason } => {
            return Err(format!("Policy load degraded: {}", reason));
        }
        PolicyLoadResult::Fatal { error } => {
            return Err(format!("Policy load fatal error: {}", error));
        }
    };

    // 2. Read Payload
    let payload_bytes = fs::read(payload_path)
        .map_err(|e| format!("Failed to read payload file {}: {}", payload_path, e))?;
    let payload_str = std::str::from_utf8(&payload_bytes)
        .map_err(|e| format!("Payload is not valid UTF-8: {}", e))?;
    let payload_val: Value = serde_json::from_str(payload_str)
        .map_err(|e| format!("Failed to parse payload JSON: {}", e))?;

    // 3. Evaluate Tool Call
    // Locally validating tool call parameters. If identity checks are used, they default to unrestricted here.
    match policy.evaluate(tool_name, &payload_val, None) {
        EvalResult::Allow => {
            println!("VALIDATION SUCCESSFUL: Tool call parameters conform to policy.");
            Ok(())
        }
        EvalResult::Deny {
            reason_code,
            param_name,
            param_value,
            pattern,
            json_pointer,
            validator_name,
        } => {
            let mut err_msg = format!("VALIDATION FAILED: reason={}", reason_code);
            if let Some(p) = param_name {
                err_msg.push_str(&format!(", parameter={}", p));
            }
            if let Some(v) = param_value {
                err_msg.push_str(&format!(", value={}", v));
            }
            if let Some(pat) = pattern {
                err_msg.push_str(&format!(", pattern={}", pat));
            }
            if let Some(ptr) = json_pointer {
                err_msg.push_str(&format!(", json_pointer={}", ptr));
            }
            if let Some(val_name) = validator_name {
                err_msg.push_str(&format!(", validator={}", val_name));
            }
            Err(err_msg)
        }
    }
}
