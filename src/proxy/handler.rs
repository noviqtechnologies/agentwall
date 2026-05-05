//! JSON-RPC dispatch and method routing (FR-101)

use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

use crate::audit::logger::AuditLogger;
use crate::kill::KillMode;
use crate::logging::{self, Level};
use crate::policy::engine::{CompiledPolicy, EvalResult};
use crate::proxy::forward;

/// Shared proxy state
pub struct ProxyState {
    pub policy: Option<CompiledPolicy>,
    pub audit_logger: Arc<AuditLogger>,
    pub session_id: String,
    pub kill_mode: KillMode,
    pub agent_pid: Option<u32>,
    pub upstream_url: String,
    pub dry_run: bool,
    /// FR-113: Whether a policy file was successfully loaded
    pub policy_loaded: bool,
    pub rate_limiter: RateLimiter,
    pub http_client: reqwest::Client,
    pub ready: bool,
}

pub struct RateLimiter {
    pub max_per_second: u32,
    tokens: std::sync::Mutex<f64>,
    last_updated: std::sync::Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            tokens: std::sync::Mutex::new(max_per_second as f64),
            last_updated: std::sync::Mutex::new(Instant::now()),
        }
    }

    pub fn acquire(&self) -> bool {
        if self.max_per_second == 0 {
            return true;
        }

        let now = Instant::now();
        let mut last_updated = self.last_updated.lock().unwrap();
        let mut tokens = self.tokens.lock().unwrap();

        let elapsed_sec = now.duration_since(*last_updated).as_secs_f64();
        *tokens =
            (*tokens + elapsed_sec * self.max_per_second as f64).min(self.max_per_second as f64);
        *last_updated = now;

        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// JSON-RPC error codes
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_POLICY_VIOLATION: i64 = -32001;

/// Handle an incoming JSON-RPC request body.
/// Returns (response_json, should_kill).
pub async fn handle_jsonrpc(state: &ProxyState, body: &Value) -> (Value, bool) {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = body.get("params").cloned().unwrap_or(Value::Null);

    // Route by MCP method
    if method == "tools/list" || method.starts_with("notifications/") {
        // Transparent proxy — no policy evaluation
        return match forward::forward_request(&state.http_client, &state.upstream_url, body).await {
            Ok(resp) => (resp, false),
            Err(e) => (
                make_error(&id, -32603, &format!("Upstream error: {}", e)),
                false,
            ),
        };
    }

    if method.starts_with("resources/") || method.starts_with("prompts/") {
        // Reject — not supported in Phase 1
        let _ = state.audit_logger.write_entry(
            "tool_deny",
            method,
            None,
            Some("method_not_supported".to_string()),
            None,
        );
        logging::log_event(
            Level::Warn,
            "tool_deny",
            json!({"tool": method, "session": &state.session_id, "reason": "method_not_supported"}),
        );
        return (
            make_error(
                &id,
                JSONRPC_METHOD_NOT_FOUND,
                "Method not supported in Phase 1",
            ),
            false,
        );
    }

    if method != "tools/call" {
        // Unknown method — reject and log as DENY
        let _ = state.audit_logger.write_entry(
            "tool_deny",
            method,
            None,
            Some("unknown_method".to_string()),
            None,
        );
        logging::log_event(
            Level::Warn,
            "tool_deny",
            json!({"tool": method, "session": &state.session_id, "reason": "unknown_method"}),
        );
        return (
            make_error(&id, JSONRPC_METHOD_NOT_FOUND, "Method not found"),
            false,
        );
    }

    // tools/call — extract tool name and arguments
    let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let tool_params = params.get("arguments").cloned().unwrap_or(Value::Null);

    // Rate limit check (FR-107)
    if !state.rate_limiter.acquire() {
        let _ = state
            .audit_logger
            .write_entry("rate_limited", tool_name, None, None, None);
        logging::log_event(
            Level::Warn,
            "rate_limited",
            json!({
                "tool": tool_name,
                "session": &state.session_id,
                "limit_per_sec": state.rate_limiter.max_per_second
            }),
        );
        return (
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32029,
                    "message": "Rate limit exceeded",
                    "data": {
                        "session_id": &state.session_id,
                        "limit_per_sec": state.rate_limiter.max_per_second
                    }
                }
            }),
            false,
        );
    }

    // Policy evaluation
    let policy = match &state.policy {
        Some(p) => p,
        None => {
            if state.dry_run && !state.policy_loaded {
                // FR-113: No policy in dry-run mode — allow-all sentinel.
                // Log the call and forward it.
                let _ = state.audit_logger.write_entry(
                    "tool_allow",
                    tool_name,
                    Some(tool_params.clone()),
                    None,
                    Some(0.0),
                );
                logging::log_event(
                    Level::Info,
                    "tool_allow",
                    json!({"tool": tool_name, "session": &state.session_id, "latency_ms": 0.0, "note": "no_policy_dry_run"}),
                );

                return match forward::forward_request(&state.http_client, &state.upstream_url, body).await {
                    Ok(resp) => (resp, false),
                    Err(e) => (
                        make_error(&id, -32603, &format!("Upstream error: {}", e)),
                        false,
                    ),
                };
            }
            // No valid policy in enforcement mode — DENY all
            return handle_deny(state, &id, tool_name, "no_valid_policy_loaded").await;
        }
    };

    let start = Instant::now();
    let eval_result = policy.evaluate(tool_name, &tool_params);
    let eval_ms = start.elapsed().as_secs_f64() * 1000.0;

    match eval_result {
        EvalResult::Allow => {
            // ALLOW path: log → fsync → forward
            let log_result = state.audit_logger.write_entry(
                "tool_allow",
                tool_name,
                Some(tool_params.clone()),
                None,
                Some(eval_ms),
            );

            if let Err(e) = log_result {
                // fsync failed — follow DENY path (NFR-204)
                logging::log_event(
                    Level::Error,
                    "log_flush_failed",
                    json!({"reason": e.to_string(), "action": "deny_applied"}),
                );
                return handle_deny(state, &id, tool_name, "log_flush_failed").await;
            }

            logging::log_event(
                Level::Info,
                "tool_allow",
                json!({"tool": tool_name, "session": &state.session_id, "latency_ms": eval_ms}),
            );

            // Forward to MCP
            match forward::forward_request(&state.http_client, &state.upstream_url, body).await {
                Ok(resp) => (resp, false),
                Err(e) => (
                    make_error(&id, -32603, &format!("Upstream error: {}", e)),
                    false,
                ),
            }
        }
        EvalResult::Deny {
            reason_code,
            param_name,
            param_value,
            pattern,
        } => {
            let mut reason_parts = vec![format!("reason={}", reason_code)];
            if let Some(n) = &param_name {
                reason_parts.push(format!("param={}", n));
            }
            if let Some(v) = &param_value {
                reason_parts.push(format!("value={}", v));
            }
            if let Some(p) = &pattern {
                reason_parts.push(format!("pattern={}", p));
            }
            let reason = reason_parts.join(" ");

            if state.dry_run {
                // DRY_RUN_DENY: log but forward anyway, no kill
                let _ = state.audit_logger.write_entry(
                    "tool_dry_run_deny",
                    tool_name,
                    None,
                    Some(reason.clone()),
                    None,
                );
                logging::log_event(
                    Level::Warn,
                    "tool_dry_run_deny",
                    json!({"tool": tool_name, "session": &state.session_id, "reason": &reason}),
                );

                // Forward despite violation
                match forward::forward_request(&state.http_client, &state.upstream_url, body).await
                {
                    Ok(resp) => (resp, false),
                    Err(e) => (
                        make_error(&id, -32603, &format!("Upstream error: {}", e)),
                        false,
                    ),
                }
            } else {
                handle_deny(state, &id, tool_name, &reason).await
            }
        }
    }
}

/// Handle the DENY path: log → error response → kill
async fn handle_deny(
    state: &ProxyState,
    id: &Value,
    tool_name: &str,
    reason: &str,
) -> (Value, bool) {
    // Step 1: Write + fsync DENY log entry (params redacted)
    let log_result = state.audit_logger.write_entry(
        "tool_deny",
        tool_name,
        None,
        Some(reason.to_string()),
        None,
    );

    if let Err(e) = log_result {
        logging::log_event(
            Level::Error,
            "log_flush_failed",
            json!({"reason": e.to_string(), "action": "deny_applied"}),
        );
    }

    // Step 2: Log to stderr
    logging::log_event(
        Level::Warn,
        "tool_deny",
        json!({"tool": tool_name, "session": &state.session_id, "reason": reason}),
    );

    // Step 3: JSON-RPC error response
    let error_response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": JSONRPC_POLICY_VIOLATION,
            "message": format!("Policy violation: {}", reason),
            "data": {
                "session_id": &state.session_id,
                "kill_mode": state.kill_mode.as_str()
            }
        }
    });

    // Step 4: Kill will be executed by the server after sending response
    (error_response, true)
}

/// Create a JSON-RPC error response
fn make_error(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}
