//! JSON-RPC dispatch and method routing (FR-101)
//!
//! ## v6.1 Changes
//!
//! - Prometheus-compatible atomic counters added to `ProxyState` (Guidance #9).
//!   Exposed via `GET /metrics` on the gateway's listen address.
//! - `KillMode::Process` / `KillMode::Both` removed from the kill path (Guidance #2).

use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::audit::logger::AuditLogger;
use super::db::DbManager;
use crate::kill::KillMode;
use crate::logging::{self, Level};
use crate::policy::engine::{CompiledPolicy, EvalResult};
use crate::policy::schema::CycleAction;

/// FR-306: A fingerprint of a tool call for cycle detection.
/// Stores the tool name and a hash of the canonicalized arguments.
#[derive(Clone, PartialEq, Debug)]
pub struct ToolCallFingerprint {
    pub tool_name: String,
    pub args_hash: u64,
}

impl ToolCallFingerprint {
    pub fn new(tool_name: &str, args: &Value) -> Self {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        // Canonicalize: serialize to sorted JSON string for deterministic comparison.
        let canonical = canonical_json(args);
        let mut hasher = DefaultHasher::new();
        canonical.hash(&mut hasher);
        Self {
            tool_name: tool_name.to_string(),
            args_hash: hasher.finish(),
        }
    }
}

/// Produce a canonical JSON string with sorted object keys for deterministic hashing.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .iter()
                .map(|k| format!("{:?}:{}", k, canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        _ => value.to_string(),
    }
}

/// Shared proxy state
pub struct ProxyState {
    pub policy: std::sync::RwLock<Option<CompiledPolicy>>,
    pub audit_logger: Arc<AuditLogger>,
    pub session_id: String,
    pub kill_mode: KillMode,
    pub agent_pid: Option<u32>,
    pub upstream_url: String,
    pub dry_run: bool,
    pub shadow_mode: bool,
    /// FR-113: Whether a policy file was successfully loaded
    pub policy_loaded: std::sync::atomic::AtomicBool,
    pub rate_limiter: RateLimiter,
    pub http_client: reqwest::Client,
    pub safe_mode_scanner: Arc<crate::policy::safe_mode::SafeModeScanner>,
    pub ready: bool,
    pub db_manager: Arc<DbManager>,
    /// FR-303b: Response scanner for secret detection
    pub response_scanner: Arc<crate::policy::response_scanner::ResponseScanner>,
    /// FR-303b: Response scan configuration
    pub response_scan_config: std::sync::RwLock<crate::policy::response_scanner::ResponseScanConfig>,
    /// FR-306: Sliding window of recent tool call fingerprints (bounded to 5).
    pub tool_history: std::sync::Mutex<Vec<ToolCallFingerprint>>,
    
    /// FR-3: SSE broadcast channel for real-time dashboard streaming
    pub event_tx: tokio::sync::broadcast::Sender<String>,

    /// Dynamic sessions registry mapping validated client tokens/identities to isolated session contexts (FR-101)
    pub sessions: dashmap::DashMap<String, Arc<super::session::SessionContext>>,

    // ── Guidance #9: Prometheus-compatible atomic counters ─────────────────
    /// Total tool call requests evaluated (tools/call only).
    pub metrics_requests_total: Arc<AtomicU64>,
    /// Total tool calls that resulted in ALLOW.
    pub metrics_allow_total: Arc<AtomicU64>,
    /// Total tool calls that resulted in DENY (policy violation, safe mode, etc.).
    pub metrics_deny_total: Arc<AtomicU64>,
    /// Total requests dropped by the rate limiter.
    pub metrics_rate_limited_total: Arc<AtomicU64>,
    /// Total tool calls blocked by the agent firewall (cycle detection).
    pub metrics_firewall_cycle_total: Arc<AtomicU64>,

    // ── FR-104: SIEM export counters ─────────────────────────────────────
    /// Total audit entries successfully exported to the SIEM backend.
    pub metrics_siem_export_total: Arc<AtomicU64>,
    /// Total audit entries that failed SIEM export (fell back to local disk).
    pub metrics_siem_export_failed_total: Arc<AtomicU64>,
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
/// FR-306: Custom error code for firewall cycle detection.
const JSONRPC_FIREWALL_CYCLE: i64 = -32010;

/// FR-306: Max entries in the tool call history sliding window.
const TOOL_HISTORY_MAX: usize = 5;

pub enum ProxyAction {
    Forward,
    Respond(Value),
    RespondWithStatus(hyper::StatusCode, Value),
    KillAndRespond(Value),
    KillAndRespondWithStatus(hyper::StatusCode, Value),
}

/// Handle an incoming JSON-RPC request body to determine the proxy action.
/// Returns a `ProxyAction`. Evaluates against the dynamic, isolated `SessionContext`.
pub async fn evaluate_jsonrpc(
    state: &ProxyState,
    session: &Arc<super::session::SessionContext>,
    body: &Value,
) -> ProxyAction {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = body.get("params").cloned().unwrap_or(Value::Null);

    // Whitelist standard MCP lifecycle and discovery methods (FR-304)
    if method == "initialize" 
        || method == "notifications/initialized" 
        || method == "ping"
        || method == "tools/list" 
        || method.starts_with("notifications/")
        || method.starts_with("resources/")
        || method.starts_with("prompts/")
    {
        // Transparent proxy — no policy evaluation for lifecycle and discovery
        return ProxyAction::Forward;
    }

    if method != "tools/call" {
        // Unknown method — reject and log as DENY
        let _ = state.audit_logger.write_entry(
            &session.session_id,
            "tool_deny",
            method,
            None,
            Some("unknown_method".to_string()),
            None,
            session.identity_sub.clone(),
            session.identity_email.clone(),
            None,
            session.request_ip.clone(),
        );
        logging::log_event(
            Level::Warn,
            "tool_deny",
            json!({"tool": method, "session": &session.session_id, "reason": "unknown_method", "sub": &session.identity_sub}),
        );
        return ProxyAction::Respond(make_error(&id, JSONRPC_METHOD_NOT_FOUND, "Method not found"));
    }

    // tools/call — extract tool name and arguments
    let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let tool_params = params.get("arguments").cloned().unwrap_or(Value::Null);

    // Rate limit check (FR-107) — strictly isolated per session
    if !session.rate_limiter.acquire() {
        state.metrics_requests_total.fetch_add(1, Ordering::Relaxed);
        state.metrics_rate_limited_total.fetch_add(1, Ordering::Relaxed);
        let _ = state.audit_logger.write_entry(
            &session.session_id,
            "rate_limited",
            tool_name,
            None,
            None,
            None,
            session.identity_sub.clone(),
            session.identity_email.clone(),
            None,
            session.request_ip.clone(),
        );
        logging::log_event(
            Level::Warn,
            "rate_limited",
            json!({
                "tool": tool_name,
                "session": &session.session_id,
                "limit_per_sec": session.rate_limiter.max_per_second,
                "sub": &session.identity_sub,
            }),
        );
        return ProxyAction::Respond(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32029,
                "message": "Rate limit exceeded",
                "data": {
                    "session_id": &session.session_id,
                    "limit_per_sec": session.rate_limiter.max_per_second
                }
            }
        }));
    }

    // Increment total requests counter after rate limit pass
    state.metrics_requests_total.fetch_add(1, Ordering::Relaxed);

    // FR-306: Cycle Detection (Agent Firewall) — strictly isolated per session
    let cycle_action_to_take = {
        let firewall_cfg = session.policy.as_ref().and_then(|p| p.firewall.as_ref());
        let effective_cfg = firewall_cfg.cloned().unwrap_or_default();

        if effective_cfg.enabled {
            let fingerprint = ToolCallFingerprint::new(tool_name, &tool_params);
            let mut history = session.tool_history.lock().unwrap();

            // Append and bound the window
            history.push(fingerprint.clone());
            let len = history.len();
            if len > TOOL_HISTORY_MAX {
                history.drain(..len - TOOL_HISTORY_MAX);
            }

            let max_attempts = effective_cfg.cycle_detection.max_attempts as usize;
            if max_attempts > 0 && history.len() >= max_attempts {
                let tail = &history[history.len() - max_attempts..];
                let all_identical = tail.iter().all(|f| *f == fingerprint);

                if all_identical {
                    // Clear history so agent gets a fresh start or on developer override
                    history.clear();
                    state.metrics_firewall_cycle_total.fetch_add(1, Ordering::Relaxed);
                    Some((effective_cfg.cycle_detection.action, max_attempts))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    };

    if let Some((action, max_attempts)) = cycle_action_to_take {
        // Cycle detected
        let _ = state.audit_logger.write_entry(
            &session.session_id,
            "firewall_cycle_block",
            tool_name,
            None,
            Some(format!(
                "cycle_detected: {} consecutive identical calls (max_attempts={})",
                max_attempts, max_attempts
            )),
            None,
            session.identity_sub.clone(),
            session.identity_email.clone(),
            None,
            session.request_ip.clone(),
        );
        logging::log_event(
            Level::Warn,
            "firewall_cycle_block",
            json!({
                "tool": tool_name,
                "session": &session.session_id,
                "consecutive_calls": max_attempts,
                "action": format!("{:?}", action)
            }),
        );

        match action {
            CycleAction::PivotError => {
                return ProxyAction::Respond(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": JSONRPC_FIREWALL_CYCLE,
                        "message": format!(
                            "AgentWall: Cycle detected — tool '{}' called {} times with identical arguments. Try a different approach.",
                            tool_name, max_attempts
                        ),
                        "data": {
                            "session_id": &session.session_id,
                            "tool": tool_name,
                            "cycle_length": max_attempts
                        }
                    }
                }));
            }
            CycleAction::Block => {
                return handle_deny(
                    state, &session.session_id, &id, tool_name,
                    &format!("firewall_cycle_block: {} consecutive identical calls", max_attempts),
                    session.identity_sub.clone(), session.identity_email.clone(),
                    session.request_ip.clone(),
                    false, None, None,
                ).await;
            }
            CycleAction::PauseInteractive => {
                // In non-TTY environments, fall back to block.
                // Attempt console I/O via platform-specific paths.
                let user_allowed = try_interactive_pause(tool_name, max_attempts);
                if user_allowed {
                    let _ = state.audit_logger.write_entry(
                        &session.session_id,
                        "firewall_cycle_override",
                        tool_name,
                        None,
                        Some("developer_override".to_string()),
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                    );
                    logging::log_event(
                        Level::Warn,
                        "firewall_cycle_override",
                        json!({
                            "tool": tool_name,
                            "session": &session.session_id
                        }),
                    );
                    // Fall through to normal evaluation
                } else {
                    return handle_deny(
                        state, &session.session_id, &id, tool_name,
                        &format!("firewall_cycle_block: {} consecutive identical calls (interactive_denied)", max_attempts),
                        session.identity_sub.clone(), session.identity_email.clone(),
                        session.request_ip.clone(),
                        false, None, None,
                    ).await;
                }
            }
        }
    }

    // Safe Mode Evaluation (FR-303a) — tool-aware scanning
    let safe_mode_threat = state.safe_mode_scanner.scan_tool(tool_name, &tool_params);

    // Policy evaluation against frozen session-specific policy context
    let start = Instant::now();
    let eval_result = match &session.policy {
        Some(policy) => {
            Some(policy.evaluate(tool_name, &tool_params, session.identity_sub.as_deref()))
        }
        None => None,
    };
    let eval_ms = start.elapsed().as_secs_f64() * 1000.0;

    let final_eval = match (eval_result, safe_mode_threat) {
        (Some(EvalResult::Allow), Some(threat)) => {
            // Escape Hatch: User policy explicitly allowed this, overriding Safe Mode block.
            logging::log_event(
                Level::Warn,
                "safe_mode_override",
                json!({"tool": tool_name, "session": &session.session_id, "threat": threat.category.as_str(), "reason": "user_policy_override"}),
            );
            EvalResult::Allow
        }
        (Some(EvalResult::Allow), None) => EvalResult::Allow,
        (Some(EvalResult::Deny { .. }), Some(threat)) => {
            EvalResult::Deny {
                reason_code: "safe_mode_deny".to_string(),
                param_name: Some(threat.param_name.clone()),
                param_value: None,
                pattern: Some(threat.pattern_name.clone()),
                json_pointer: Some(format!("{} Edit policy: agentwall edit-policy", threat.reason)),
                validator_name: None,
            }
        }
        (Some(EvalResult::Deny { reason_code, param_name, param_value, pattern, json_pointer, validator_name }), None) => {
            EvalResult::Deny { reason_code, param_name, param_value, pattern, json_pointer, validator_name }
        }
        (None, Some(threat)) => {
            EvalResult::Deny {
                reason_code: "safe_mode_deny".to_string(),
                param_name: Some(threat.param_name.clone()),
                param_value: None,
                pattern: Some(threat.pattern_name.clone()),
                json_pointer: Some(format!("{} Edit policy: agentwall edit-policy", threat.reason)),
                validator_name: None,
            }
        }
        (None, None) => {
            if !state.policy_loaded.load(Ordering::Relaxed) {
                // Out-Of-The-Box Safe Mode: No policy loaded, Safe Mode is clean.
                EvalResult::Allow
            } else {
                // Policy was loaded but is missing/degraded
                EvalResult::Deny {
                    reason_code: "no_valid_policy_loaded".to_string(),
                    param_name: None,
                    param_value: None,
                    pattern: None,
                    json_pointer: None,
                    validator_name: None,
                }
            }
        }
    };

    // Identity claims were validated during dynamic session creation (OIDC cache)
    let identity_sub   = session.identity_sub.clone();
    let identity_email = session.identity_email.clone();

    match final_eval {
        EvalResult::Allow => {
            state.metrics_allow_total.fetch_add(1, Ordering::Relaxed);
            // ALLOW path: log → fsync → forward (NFR-204)
            let log_result = state.audit_logger.write_entry(
                &session.session_id,
                "tool_allow",
                tool_name,
                Some(tool_params.clone()),
                None,
                Some(eval_ms),
                identity_sub.clone(),
                identity_email.clone(),
                None,
                session.request_ip.clone(),
            );

            if let Err(e) = log_result {
                // fsync failed — follow DENY path (NFR-204)
                logging::log_event(
                    Level::Error,
                    "log_flush_failed",
                    json!({"reason": e.to_string(), "action": "deny_applied"}),
                );
                return handle_deny(
                    state, &session.session_id, &id, tool_name,
                    "log_flush_failed",
                    identity_sub, identity_email, session.request_ip.clone(),
                    false, None, None,
                ).await;
            }

            logging::log_event(
                Level::Info,
                "tool_allow",
                json!({
                    "tool":      tool_name,
                    "session":   &session.session_id,
                    "latency_ms": eval_ms,
                    "sub":       &identity_sub,
                    "email":     &identity_email,
                }),
            );

            ProxyAction::Forward
        }
        EvalResult::Deny {
            reason_code,
            param_name,
            param_value,
            pattern,
            json_pointer,
            validator_name,
        } => {
            state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
            let mut reason_parts = vec![format!("reason={}", reason_code)];
            if let Some(n) = &param_name  { reason_parts.push(format!("param={}", n)); }
            if let Some(v) = &param_value { reason_parts.push(format!("value={}", v)); }
            if let Some(p) = &pattern     { reason_parts.push(format!("pattern={}", p)); }
            if let Some(ptr) = &json_pointer { reason_parts.push(format!("pointer={}", ptr)); }
            if let Some(vn) = &validator_name { reason_parts.push(format!("validator={}", vn)); }
            let reason = reason_parts.join(" ");

            if state.dry_run {
                // DRY_RUN_DENY: log but forward anyway, no kill
                let _ = state.audit_logger.write_entry(
                    &session.session_id,
                    "tool_dry_run_deny",
                    tool_name,
                    None,
                    Some(reason.clone()),
                    None,
                    identity_sub.clone(),
                    identity_email.clone(),
                    None,
                    session.request_ip.clone(),
                );
                logging::log_event(
                    Level::Warn,
                    "tool_dry_run_deny",
                    json!({
                        "tool":    tool_name,
                        "session": &session.session_id,
                        "reason":  &reason,
                        "sub":     &identity_sub,
                        "email":   &identity_email,
                    }),
                );
                ProxyAction::Forward
            } else {
                let is_val_fail = reason_code == "validator_failed";
                handle_deny(
                    state, &session.session_id, &id, tool_name, &reason,
                    identity_sub, identity_email, session.request_ip.clone(),
                    is_val_fail, param_name, validator_name,
                ).await
            }
        }
    }
}

/// Handle the DENY path: write audit entry → send JSON-RPC error → signal kill.
///
/// The audit entry is written and fsync-confirmed before the error response is
/// constructed — satisfying NFR-204 (no forward without a durable log entry).
async fn handle_deny(
    state:             &ProxyState,
    session_id:        &str,
    id:                &Value,
    tool_name:         &str,
    reason:            &str,
    identity_sub:      Option<String>,
    identity_email:    Option<String>,
    request_ip:        Option<String>,
    is_validator_fail: bool,
    failing_param:     Option<String>,
    failing_validator: Option<String>,
) -> ProxyAction {
    let log_result = state.audit_logger.write_entry(
        session_id,
        "tool_deny",
        tool_name,
        None,
        Some(reason.to_string()),
        None,
        identity_sub.clone(),
        identity_email.clone(),
        None,
        request_ip.clone(),
    );

    if let Err(e) = log_result {
        logging::log_event(
            Level::Error,
            "log_flush_failed",
            json!({"reason": e.to_string(), "action": "deny_applied"}),
        );
    }

    logging::log_event(
        Level::Warn,
        "tool_deny",
        json!({
            "tool":    tool_name,
            "session": session_id,
            "reason":  reason,
            "sub":     &identity_sub,
            "email":   &identity_email,
        }),
    );

    let error_response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": if is_validator_fail { -32003 } else { JSONRPC_POLICY_VIOLATION },
            "message": format!("Policy violation: {}", reason),
            "data": {
                "session_id": session_id,
                "parameter":  failing_param,
                "validator":  failing_validator,
                "kill_mode":  state.kill_mode.as_str()
            }
        }
    });

    if is_validator_fail {
        ProxyAction::KillAndRespondWithStatus(hyper::StatusCode::BAD_REQUEST, error_response)
    } else {
        ProxyAction::KillAndRespond(error_response)
    }
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

/// FR-306: Attempt to pause and ask the developer via the system console.
/// Returns true if the user typed 'y' to allow the call through.
/// Returns false if the user denied, or if console I/O is not available (non-TTY).
fn try_interactive_pause(tool_name: &str, consecutive_calls: usize) -> bool {
    use std::io::{BufRead, Write};

    // Do not block when running under cargo tests/CI
    if std::env::var("CARGO_MANIFEST_DIR").is_ok() {
        return false;
    }

    // Try to open the system console directly (not stdin, which may be owned by JSON-RPC).
    #[cfg(target_os = "windows")]
    let console_result = {
        std::fs::OpenOptions::new()
            .read(true)
            .open("CONIN$")
            .and_then(|reader| {
                let mut stderr = std::io::stderr();
                writeln!(
                    stderr,
                    "\n⚠️  AgentWall Firewall: Cycle detected — tool '{}' called {} times with identical arguments.",
                    tool_name, consecutive_calls
                ).ok();
                writeln!(stderr, "   Allow this call? (y/N): ").ok();
                stderr.flush().ok();

                let mut line = String::new();
                let mut buf_reader = std::io::BufReader::new(reader);
                buf_reader.read_line(&mut line)?;
                Ok(line.trim().eq_ignore_ascii_case("y"))
            })
    };

    #[cfg(not(target_os = "windows"))]
    let console_result = {
        std::fs::OpenOptions::new()
            .read(true)
            .open("/dev/tty")
            .and_then(|reader| {
                let mut stderr = std::io::stderr();
                writeln!(
                    stderr,
                    "\n⚠️  AgentWall Firewall: Cycle detected — tool '{}' called {} times with identical arguments.",
                    tool_name, consecutive_calls
                ).ok();
                writeln!(stderr, "   Allow this call? (y/N): ").ok();
                stderr.flush().ok();

                let mut line = String::new();
                let mut buf_reader = std::io::BufReader::new(reader);
                buf_reader.read_line(&mut line)?;
                Ok(line.trim().eq_ignore_ascii_case("y"))
            })
    };

    match console_result {
        Ok(allowed) => allowed,
        Err(_) => {
            // Non-TTY environment — cannot interact. Log warning and fall back to block.
            eprintln!(
                "⚠️  AgentWall: pause_interactive requested but no TTY available. Falling back to block."
            );
            false
        }
    }
}
