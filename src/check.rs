//! `vexa check` subcommand — pre-flight policy check (FR-108)

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::policy::engine::EvalResult;
use crate::policy::loader::{load_policy, PolicyLoadResult};

/// A single fixture entry
#[derive(Debug, Deserialize)]
pub struct FixtureCall {
    pub tool: String,
    pub params: serde_json::Value,
}

/// Result of a single check
#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub tool: String,
    pub verdict: String, // "ALLOW" or "DENY"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Run the check subcommand.
/// Returns exit code: 0 = all allowed, 1 = any denied, 2 = error
pub fn run_check(policy_path: &Path, fixture_path: &Path, dry_run: bool) -> i32 {
    // Load policy
    let policy = match load_policy(policy_path) {
        PolicyLoadResult::Loaded { policy, .. } => policy,
        PolicyLoadResult::Degraded { reason } => {
            eprintln!("ERROR: Policy degraded — {}", reason);
            return 2;
        }
        PolicyLoadResult::Fatal { error } => {
            eprintln!("ERROR: Policy fatal — {}", error);
            return 2;
        }
    };

    // Load fixture
    let fixture_bytes = match std::fs::read(fixture_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: Cannot read fixture file: {}", e);
            return 2;
        }
    };

    let calls: Vec<FixtureCall> = match serde_json::from_slice(&fixture_bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: Invalid fixture JSON: {}", e);
            return 2;
        }
    };

    let mut any_denied = false;

    for call in &calls {
        let result = policy.evaluate(&call.tool, &call.params);
        let check_result = match &result {
            EvalResult::Allow => {
                let mut params_str = Vec::new();
                if let Some(obj) = call.params.as_object() {
                    for (k, v) in obj {
                        let v_str = v.as_str().unwrap_or_else(|| "");
                        if !v_str.is_empty() {
                            params_str.push(format!("{}={}", k, v_str));
                        } else {
                            params_str.push(format!("{}={}", k, v));
                        }
                    }
                }
                let detail = params_str.join(" ");
                CheckResult {
                    tool: call.tool.clone(),
                    verdict: "ALLOW".to_string(),
                    reason: if detail.is_empty() {
                        None
                    } else {
                        Some(detail)
                    },
                }
            }
            EvalResult::Deny {
                reason_code,
                param_name,
                param_value,
                pattern,
            } => {
                any_denied = true;
                let mut reason_parts = vec![format!("reason={}", reason_code)];
                if let Some(n) = param_name {
                    reason_parts.push(format!("param={}", n));
                }
                if let Some(v) = param_value {
                    reason_parts.push(format!("value={}", v));
                }
                if let Some(p) = pattern {
                    reason_parts.push(format!("pattern={}", p));
                }

                CheckResult {
                    tool: call.tool.clone(),
                    verdict: "DENY".to_string(),
                    reason: Some(reason_parts.join(" ")),
                }
            }
        };

        // Output one line per call
        match &check_result.reason {
            Some(detail) => println!(
                "{}\t{}\t{}",
                check_result.verdict, check_result.tool, detail
            ),
            None => println!("{}\t{}", check_result.verdict, check_result.tool),
        }
    }

    if any_denied && !dry_run {
        1
    } else {
        0
    }
}
