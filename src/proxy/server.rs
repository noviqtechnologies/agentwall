//! HTTP proxy server — listen, route, healthz/readyz (FR-101, §3.3, FR-303b)

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;

use super::handler::{self, ProxyState, ProxyAction};
use crate::kill::{self};
use crate::logging;
use crate::policy::response_scanner::ScanResult;
use super::forward;

/// Run the proxy server. Blocks until shutdown signal.
pub async fn run_server(
    state: Arc<ProxyState>,
    listen_addr: SocketAddr,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Enable SO_REUSEADDR to handle TIME_WAIT on Windows (FR-101)
    let domain = if listen_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    
    socket.set_reuse_address(true)?;
    // On Unix we'd use set_reuse_port(true) too, but on Windows reuse_address is enough
    
    socket.bind(&listen_addr.into())?;
    socket.listen(128)?;
    
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, _addr) = accept_result?;
                let io = TokioIo::new(stream);
                let state = state.clone();

                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let state = state.clone();
                        async move {
                            handle_request(req, &state).await
                        }
                    });

                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        // Connection errors are expected during kill
                        let _ = e;
                    }
                });
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Handle a single HTTP request
async fn handle_request(
    req: Request<Incoming>,
    state: &ProxyState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Health/readiness endpoints
    if method == hyper::Method::GET {
        match path.as_str() {
            "/healthz" => {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from("OK")))
                    .unwrap());
            }
            "/readyz" => {
                if state.ready {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from("OK")))
                        .unwrap());
                } else {
                    return Ok(Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(Full::new(Bytes::from("NOT READY")))
                        .unwrap());
                }
            }
            _ => {}
        }
    }

    // Only accept POST for JSON-RPC
    if method != hyper::Method::POST {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::from("Method Not Allowed")))
            .unwrap());
    }

    // Extract Authorization header (FR-202)
    let auth_header = req.headers().get(hyper::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Read body
    let body_bytes = match http_body_util::BodyExt::collect(req.into_body()).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("Bad Request")))
                .unwrap());
        }
    };

    // Parse JSON-RPC
    let body: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            let err = serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {"code": -32700, "message": "Parse error"}
            });
            return Ok(json_response(StatusCode::OK, &err));
        }
    };

    // Handle the JSON-RPC call
    let action = handler::evaluate_jsonrpc(state, &body, auth_header).await;

    // Extract tool name from original request for response scanning context
    let tool_name = body.get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("");

    let (response, should_kill) = match action {
        ProxyAction::Forward => {
            match forward::forward_request(&state.http_client, &state.upstream_url, &body).await {
                Ok(resp) => {
                    // FR-303b: Response scanning
                    let processed = scan_and_process_response(state, &resp, tool_name);
                    (processed, false)
                },
                Err(e) => (
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": body.get("id"),
                        "error": { "code": -32603, "message": format!("Upstream error: {}", e) }
                    }),
                    false,
                ),
            }
        }
        ProxyAction::Respond(resp) => (resp, false),
        ProxyAction::KillAndRespond(resp) => (resp, true),
    };

    // Send response first (before kill)
    let http_response = json_response(StatusCode::OK, &response);

    // Execute kill if needed (after response is constructed)
    if should_kill {
        kill::execute_kill(&state.kill_mode, &state.session_id, state.agent_pid);
    }

    Ok(http_response)
}

/// Build a JSON HTTP response
fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    let json_str = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json_str)))
        .unwrap()
}

/// FR-303b: Scan a response for secrets and apply redaction/blocking.
/// Fail-open: any scanner error passes the response through with audit log.
fn scan_and_process_response(
    state: &ProxyState,
    response: &serde_json::Value,
    tool_name: &str,
) -> serde_json::Value {
    // Catch panics — fail-open on any error
    let scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.response_scanner.scan_response(response, tool_name, &state.response_scan_config)
    }));

    let scan_result = match scan_result {
        Ok(result) => result,
        Err(_) => {
            // Scanner panicked — fail-open + loud audit log
            let _ = state.audit_logger.write_entry(
                "SCANNER_FAILURE",
                tool_name,
                None,
                Some("Response scanner panicked — fail-open applied".to_string()),
                None,
                None,
            );
            logging::log_event(
                logging::Level::Error,
                "SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": &state.session_id, "reason": "scanner_panic"}),
            );
            return response.clone();
        }
    };

    match scan_result {
        ScanResult::Pass | ScanResult::Clean => response.clone(),

        ScanResult::Skipped { reason } => {
            let _ = state.audit_logger.write_entry(
                "response_scan_skipped",
                tool_name,
                None,
                Some(reason.clone()),
                None,
                None,
            );
            logging::log_event(
                logging::Level::Warn,
                "response_scan_skipped",
                serde_json::json!({"tool": tool_name, "session": &state.session_id, "reason": &reason}),
            );
            response.clone()
        }

        ScanResult::Redact { findings } => {
            if state.response_scan_config.dry_run {
                // Dry-run: log what would be redacted but pass through
                for f in &findings {
                    let _ = state.audit_logger.write_entry(
                        "response_scan_dry_run",
                        tool_name,
                        None,
                        Some(format!("Would redact {} at {}:{} preview={}", f.pattern_name, f.field_path, f.position, f.preview)),
                        None,
                        None,
                    );
                }
                logging::log_event(
                    logging::Level::Warn,
                    "response_scan_dry_run",
                    serde_json::json!({
                        "tool": tool_name, 
                        "session": &state.session_id, 
                        "would_action": "redact", 
                        "pattern": findings.first().map(|f| f.pattern_name.clone()).unwrap_or_default(),
                        "count": findings.len()
                    }),
                );
                return response.clone();
            }

            // Log each finding (never the full secret)
            for f in &findings {
                let _ = state.audit_logger.write_entry(
                    "response_secret_redacted",
                    tool_name,
                    None,
                    Some(format!("pattern={} field={} pos={} len={} preview={}", f.pattern_name, f.field_path, f.position, f.length, f.preview)),
                    None,
                    None,
                );
            }
            logging::log_event(
                logging::Level::Warn,
                "response_secret_redacted",
                serde_json::json!({"tool": tool_name, "session": &state.session_id, "count": findings.len()}),
            );

            // Apply redaction
            state.response_scanner.redact_response(response, &state.response_scan_config)
        }

        ScanResult::Block { findings } => {
            if state.response_scan_config.dry_run {
                for f in &findings {
                    let _ = state.audit_logger.write_entry(
                        "response_scan_dry_run",
                        tool_name,
                        None,
                        Some(format!("Would block: {} preview={}", f.pattern_name, f.preview)),
                        None,
                        None,
                    );
                }
                logging::log_event(
                    logging::Level::Warn,
                    "response_scan_dry_run",
                    serde_json::json!({
                        "tool": tool_name, 
                        "session": &state.session_id, 
                        "would_action": "block", 
                        "pattern": findings.first().map(|f| f.pattern_name.clone()).unwrap_or_default(),
                        "count": findings.len()
                    }),
                );
                return response.clone();
            }

            let f = &findings[0];
            let _ = state.audit_logger.write_entry(
                "response_secret_blocked",
                tool_name,
                None,
                Some(format!("pattern={} field={} preview={}", f.pattern_name, f.field_path, f.preview)),
                None,
                None,
            );
            logging::log_event(
                logging::Level::Warn,
                "response_secret_blocked",
                serde_json::json!({"tool": tool_name, "session": &state.session_id, "pattern": &f.pattern_name}),
            );

            // Return JSON-RPC error instead of the response
            let id = response.get("id").cloned().unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32002,
                    "message": format!("Response blocked: secret detected ({}). Use --dry-run to preview, or adjust policy.", f.pattern_name),
                    "data": {
                        "session_id": &state.session_id,
                        "pattern": &f.pattern_name
                    }
                }
            })
        }

        ScanResult::ScannerError { error } => {
            // Fail-open + loud audit log
            let _ = state.audit_logger.write_entry(
                "SCANNER_FAILURE",
                tool_name,
                None,
                Some(format!("Scanner error: {} — fail-open applied", error)),
                None,
                None,
            );
            logging::log_event(
                logging::Level::Error,
                "SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": &state.session_id, "error": &error}),
            );
            response.clone()
        }
    }
}
