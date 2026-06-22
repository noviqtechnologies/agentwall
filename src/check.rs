//! `agentwall test` subcommand — policy security unit tests (FR-108)
//!
//! ## v6.1 Changes
//!
//! File-only local validation is **deprecated**. In v6.1, `agentwall test` should be
//! run with `--gateway <URL>` and `--oidc-token <TOKEN>` pointing to a deployed gateway
//! instance so that DLP inspection, cycle detection, and OIDC validation are accurately
//! simulated.
//!
//! When `--gateway` is not provided, a deprecation warning is emitted and local schema
//! evaluation is used as a fallback for basic syntax validation only.

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

/// Run the test subcommand.
///
/// If `gateway_url` is provided, emits a note that gateway-mode is the production
/// validation path (full implementation is a future milestone).
///
/// If `gateway_url` is not provided, emits a deprecation warning and falls back to
/// local schema evaluation.
///
/// Returns exit code: 0 = all allowed, 1 = any denied, 2 = error
pub fn run_check(
    policy_path: &Path,
    fixture_path: &Path,
    dry_run: bool,
    gateway_url: Option<&str>,
    _oidc_token: Option<&str>,
) -> i32 {
    use colored::*;

    // v6.1: Emit appropriate mode message
    match gateway_url {
        Some(url) => {
            println!(
                "{} {} {}",
                "ℹ".blue(),
                "Gateway validation mode:".bold(),
                url.cyan()
            );
            println!(
                "{} {}",
                "⚠".yellow(),
                "NOTE: Full gateway-mode validation (network round-trip) is a future milestone. \
                 Proceeding with local schema evaluation as the base check. \
                 Deploy this policy to your test gateway and run integration fixtures for full coverage.".yellow()
            );
        }
        None => {
            eprintln!(
                "{} {}",
                "⚠ DEPRECATED:".yellow().bold(),
                "File-only validation is deprecated in v6.1.".yellow()
            );
            eprintln!(
                "{}",
                "  Run with --gateway <URL> --oidc-token <TOKEN> pointing to a deployed \
                 test gateway instance for accurate policy validation.\n  \
                 File-only mode cannot simulate DLP inspection, cycle detection, or OIDC validation."
                    .yellow()
            );
            eprintln!();
        }
    }

    // Load policy
    let policy = match load_policy(policy_path, None) {
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

    let calls: Vec<FixtureCall> = if let Ok(c) = serde_json::from_slice(&fixture_bytes) {
        c
    } else {
        // Try parsing as JSON lines (audit.log format)
        let mut lines_calls = Vec::new();
        let content = String::from_utf8_lossy(&fixture_bytes);
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(trimmed) {
                // Check if it's a tool call event
                let event = entry.get("event").and_then(|e| e.as_str()).unwrap_or("");
                if event == "tool_allow" || event == "tool_deny" || event == "tool_dry_run_deny" {
                    if let (Some(tool), Some(params)) = (entry.get("tool_name"), entry.get("params")) {
                        lines_calls.push(FixtureCall {
                            tool: tool.as_str().unwrap_or("").to_string(),
                            params: params.clone(),
                        });
                    }
                }
            }
        }
        if lines_calls.is_empty() {
            eprintln!("ERROR: Invalid fixture JSON: expected a sequence [...] or a valid audit.log");
            return 2;
        }
        lines_calls
    };

    let mut any_denied = false;

    for call in &calls {
        let result = policy.evaluate(&call.tool, &call.params, None);
        let check_result = match &result {
            EvalResult::Allow => {
                let mut params_str = Vec::new();
                if let Some(obj) = call.params.as_object() {
                    for (k, v) in obj {
                        let v_str = v.as_str().unwrap_or("");
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
                    verdict: "ALLOW".green().bold().to_string(),
                    reason: if detail.is_empty() {
                        None
                    } else {
                        Some(detail.dimmed().to_string())
                    },
                }
            }
            EvalResult::Deny {
                reason_code,
                param_name,
                param_value,
                pattern,
                json_pointer,
                validator_name,
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
                if let Some(ptr) = json_pointer {
                    reason_parts.push(format!("pointer={}", ptr));
                }
                if let Some(val_name) = validator_name {
                    reason_parts.push(format!("validator={}", val_name));
                }

                CheckResult {
                    tool: call.tool.clone(),
                    verdict: "DENY".red().bold().to_string(),
                    reason: Some(reason_parts.join(" ").yellow().to_string()),
                }
            }
        };

        // Output one line per call
        match &check_result.reason {
            Some(detail) => println!(
                "{}  {:<18}  {}",
                check_result.verdict, check_result.tool.bold(), detail
            ),
            None => println!("{}  {}", check_result.verdict, check_result.tool.bold()),
        }
    }

    if any_denied && !dry_run {
        1
    } else {
        0
    }
}
