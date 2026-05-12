//! Stdio bridge proxy for local MCP servers (FR-302, FR-303b)

use futures::{SinkExt, StreamExt};
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::kill::KillMode;
use crate::logging;
use crate::policy::response_scanner::ScanResult;
use crate::proxy::codec::JsonRpcCodec;
use crate::proxy::handler::{evaluate_jsonrpc, ProxyAction, ProxyState};

pub async fn run_stdio_bridge(
    state: Arc<ProxyState>,
    mut command: Command,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Configure stdio for the child process
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::inherit());

    let mut child = command.spawn()?;

    let child_stdin = child.stdin.take().expect("Failed to open stdin");
    let child_stdout = child.stdout.take().expect("Failed to open stdout");

    // We use FramedRead/Write to parse JSON objects from the streams
    let mut upstream_reader = FramedRead::new(child_stdout, JsonRpcCodec);
    let mut upstream_writer = FramedWrite::new(child_stdin, JsonRpcCodec);

    // Also wrap our own stdin/stdout to communicate with the local agent
    let agent_stdin = tokio::io::stdin();
    let agent_stdout = tokio::io::stdout();

    let mut agent_reader = FramedRead::new(agent_stdin, JsonRpcCodec);
    let mut agent_writer = FramedWrite::new(agent_stdout, JsonRpcCodec);

    // FR-303b: Track the last forwarded tool name for response correlation
    // MCP stdio is strictly sequential (one request → one response), so this is safe.
    let mut last_forwarded_tool: String = String::new();

    loop {
        tokio::select! {
            // Read from Agent (client)
            msg = agent_reader.next() => {
                match msg {
                    Some(Ok(json)) => {
                        // FR-303b: Extract tool name before forwarding
                        let tool_name = json.get("params")
                            .and_then(|p| p.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();

                        let action = evaluate_jsonrpc(&state, &json, None).await;
                        match action {
                            ProxyAction::Forward => {
                                // Track the tool name for response scanning
                                last_forwarded_tool = tool_name;
                                if let Err(e) = upstream_writer.send(json).await {
                                    eprintln!("Error sending to upstream: {}", e);
                                    break;
                                }
                            }
                            ProxyAction::Respond(resp) => {
                                if let Err(e) = agent_writer.send(resp).await {
                                    eprintln!("Error sending to agent: {}", e);
                                    break;
                                }
                            }
                            ProxyAction::KillAndRespond(resp) => {
                                let _ = agent_writer.send(resp).await;
                                if state.kill_mode == KillMode::Process || state.kill_mode == KillMode::Both {
                                    eprintln!("Violation: Killing process and exiting.");
                                    let _ = child.kill().await;
                                    break;
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        eprintln!("Error reading from agent: {}", e);
                        break;
                    }
                    None => {
                        eprintln!("Agent EOF: Closing session.");
                        break;
                    }
                }
            }

            // Read from Upstream (MCP Server)
            msg = upstream_reader.next() => {
                match msg {
                    Some(Ok(json)) => {
                        // FR-303b: Scan response for secrets before forwarding to agent
                        let processed = stdio_scan_response(&state, &json, &last_forwarded_tool);
                        if let Err(e) = agent_writer.send(processed).await {
                            eprintln!("Error sending to agent: {}", e);
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        eprintln!("Error reading from upstream: {}", e);
                        break;
                    }
                    None => {
                        eprintln!("Upstream EOF: Server process likely exited.");
                        break;
                    }
                }
            }

            // Subprocess exited
            status = child.wait() => {
                match status {
                    Ok(s) => eprintln!("Child process exited with status: {}", s),
                    Err(e) => eprintln!("Error waiting for child: {}", e),
                }
                break;
            }
        }
    }

    // Ensure child is dead
    let _ = child.kill().await;

    Ok(())
}

/// FR-303b: Scan a stdio response for secrets — mirrors the HTTP scan_and_process_response logic.
/// Fail-open: any scanner error passes the response through with audit log.
fn stdio_scan_response(
    state: &ProxyState,
    response: &serde_json::Value,
    tool_name: &str,
) -> serde_json::Value {
    let scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.response_scanner.scan_response(response, tool_name, &state.response_scan_config)
    }));

    let scan_result = match scan_result {
        Ok(result) => result,
        Err(_) => {
            let _ = state.audit_logger.write_entry(
                "SCANNER_FAILURE", tool_name, None,
                Some("Response scanner panicked — fail-open applied".to_string()),
                None, None,
            );
            logging::log_event(logging::Level::Error, "SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": &state.session_id, "reason": "scanner_panic"}));
            return response.clone();
        }
    };

    match scan_result {
        ScanResult::Pass | ScanResult::Clean => response.clone(),

        ScanResult::Skipped { reason } => {
            let _ = state.audit_logger.write_entry("response_scan_skipped", tool_name, None, Some(reason.clone()), None, None);
            logging::log_event(logging::Level::Warn, "response_scan_skipped",
                serde_json::json!({"tool": tool_name, "session": &state.session_id, "reason": &reason}));
            response.clone()
        }

        ScanResult::Redact { findings } => {
            if state.response_scan_config.dry_run {
                for f in &findings {
                    let _ = state.audit_logger.write_entry("response_scan_dry_run", tool_name, None,
                        Some(format!("Would redact {} at {}:{} preview={}", f.pattern_name, f.field_path, f.position, f.preview)), None, None);
                }
                logging::log_event(logging::Level::Warn, "response_scan_dry_run",
                    serde_json::json!({"tool": tool_name, "session": &state.session_id, "action": "redact", "count": findings.len()}));
                return response.clone();
            }
            for f in &findings {
                let _ = state.audit_logger.write_entry("response_secret_redacted", tool_name, None,
                    Some(format!("pattern={} field={} pos={} len={} preview={}", f.pattern_name, f.field_path, f.position, f.length, f.preview)), None, None);
            }
            logging::log_event(logging::Level::Warn, "response_secret_redacted",
                serde_json::json!({"tool": tool_name, "session": &state.session_id, "count": findings.len()}));
            state.response_scanner.redact_response(response, &state.response_scan_config)
        }

        ScanResult::Block { findings } => {
            if state.response_scan_config.dry_run {
                for f in &findings {
                    let _ = state.audit_logger.write_entry("response_scan_dry_run", tool_name, None,
                        Some(format!("Would block: {} preview={}", f.pattern_name, f.preview)), None, None);
                }
                logging::log_event(logging::Level::Warn, "response_scan_dry_run",
                    serde_json::json!({"tool": tool_name, "session": &state.session_id, "action": "block", "count": findings.len()}));
                return response.clone();
            }
            let f = &findings[0];
            let _ = state.audit_logger.write_entry("response_secret_blocked", tool_name, None,
                Some(format!("pattern={} field={} preview={}", f.pattern_name, f.field_path, f.preview)), None, None);
            logging::log_event(logging::Level::Warn, "response_secret_blocked",
                serde_json::json!({"tool": tool_name, "session": &state.session_id, "pattern": &f.pattern_name}));

            let id = response.get("id").cloned().unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32002,
                    "message": format!("Response blocked: secret detected ({}). Use --dry-run to preview, or adjust policy.", f.pattern_name),
                    "data": { "session_id": &state.session_id, "pattern": &f.pattern_name }
                }
            })
        }

        ScanResult::ScannerError { error } => {
            let _ = state.audit_logger.write_entry("SCANNER_FAILURE", tool_name, None,
                Some(format!("Scanner error: {} — fail-open applied", error)), None, None);
            logging::log_event(logging::Level::Error, "SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": &state.session_id, "error": &error}));
            response.clone()
        }
    }
}
