//! HTTP proxy server — listen, route, healthz/readyz, metrics (FR-101, §3.3, FR-303b)
//!
//! ## v6.1 Changes — Prometheus Metrics Phase 1 (Guidance #9)
//!
//! A Prometheus-compatible `GET /metrics` endpoint is now available from Phase 1.
//! Operations teams can scrape this endpoint with Prometheus and build Grafana dashboards
//! for real-time operational insights without waiting for a Phase 2 release.
//!
//! ### Exposed Metrics
//! | Metric | Description |
//! |--------|-------------|
//! | `agentwall_requests_total` | Total tool call requests evaluated |
//! | `agentwall_allow_total` | Allowed tool calls |
//! | `agentwall_deny_total` | Denied tool calls (policy violations) |
//! | `agentwall_rate_limited_total` | Rate-limited requests |
//! | `agentwall_firewall_cycle_total` | Firewall cycle detection triggers |

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
                let (stream, addr) = accept_result?;
                let client_ip = addr.ip().to_string();
                let io = TokioIo::new(stream);
                let state = state.clone();

                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let state = state.clone();
                        let client_ip = client_ip.clone();
                        async move {
                            if req.uri().path() == "/api/events/stream" && req.method() == hyper::Method::GET {
                                let (tx, rx) = tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(100);
                                let mut bcast_rx = state.event_tx.subscribe();
                                tokio::spawn(async move {
                                    while let Ok(msg) = bcast_rx.recv().await {
                                        let data = format!("data: {}\n\n", msg);
                                        if tx.send(Ok(hyper::body::Frame::data(Bytes::from(data)))).await.is_err() {
                                            break;
                                        }
                                    }
                                });
                                let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
                                use http_body_util::BodyExt;
                                let body = http_body_util::StreamBody::new(stream).boxed();
                                return Ok::<_, hyper::Error>(Response::builder()
                                    .status(StatusCode::OK)
                                    .header("Content-Type", "text/event-stream")
                                    .header("Cache-Control", "no-cache")
                                    .body(body)
                                    .unwrap());
                            }

                            let res = handle_request(req, state.clone(), &client_ip).await?;
                            use http_body_util::BodyExt;
                            Ok::<_, hyper::Error>(res.map(|b| b.map_err(|e| match e {}).boxed()))
                        }
                    });

                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
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

/// Evict sessions older than SESSION_TTL_SECS from the DashMap (Fix 3: session memory leak).
/// Called lazily on each new session creation so no background thread is required.
fn evict_expired_sessions(state: &ProxyState) {
    state.sessions.retain(|_, session| !session.is_expired());
}

/// Helper to resolve or create a SessionContext from the incoming request (FR-101)
async fn resolve_session(
    state: &ProxyState,
    auth_header: Option<&str>,
    credential_header: Option<&str>,
    client_ip: &str,
) -> Result<Arc<super::session::SessionContext>, (StatusCode, String)> {
    // Fix 5: Poison-safe RwLock read — if a prior writer panicked, log and deny rather
    // than crashing the entire proxy with an unwrap() panic. Wait for write locks normally.
    let identity_validator = {
        match state.policy.read() {
            Ok(guard) => guard.as_ref().and_then(|p| p.identity_validator.clone()),
            Err(_) => {
                crate::logging::log_event(
                    crate::logging::Level::Error,
                    "policy_lock_poisoned",
                    serde_json::json!({"remote_addr": client_ip, "action": "deny_applied"}),
                );
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Policy state is temporarily unavailable".to_string(),
                ));
            }
        }
    };

    if let Some(validator) = identity_validator {
        // OIDC is enabled! We require a Bearer token.
        let token = auth_header
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|t| t.trim());

        let t = match token {
            Some(t) if !t.is_empty() => t,
            _ => {
                // Fix 1: Write auth_failed to HMAC audit chain (not just stderr)
                let _ = state.audit_logger.write_entry(
                    &state.session_id,
                    "auth_failed",
                    "",
                    None,
                    Some(format!("identity_token_missing remote_addr={}", client_ip)),
                    None,
                    None,
                    None,
                    None,
                    Some(client_ip.to_string()),
                ).await;
                crate::logging::log_event(
                    crate::logging::Level::Warn,
                    "auth_failed",
                    serde_json::json!({
                        "reason": "identity_token_missing",
                        "remote_addr": client_ip,
                    }),
                );
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "Authorization Bearer token is missing".to_string(),
                ));
            }
        };

        // Compute SHA-256 hash of the token as session key to prevent credentials leak in map keys
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(t.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        // Check if session exists in dashmap
        if let Some(session) = state.sessions.get(&token_hash) {
            return Ok(session.clone());
        }

        // Fail-Closed: ensure keys are loaded
        if !validator.is_ready().await {
            // Fix 1: Write keys-not-ready failure to HMAC audit chain
            let _ = state.audit_logger.write_entry(
                &state.session_id,
                "auth_failed",
                "",
                None,
                Some(format!("identity_keys_not_ready remote_addr={}", client_ip)),
                None,
                None,
                None,
                None,
                Some(client_ip.to_string()),
            ).await;
            crate::logging::log_event(
                crate::logging::Level::Error,
                "auth_failed",
                serde_json::json!({
                    "reason": "identity_keys_not_ready",
                    "remote_addr": client_ip,
                }),
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "OIDC identity keys are not loaded/ready yet".to_string(),
            ));
        }

        // Validate token
        match validator.validate_token(t).await {
            Ok(sub) => {
                // Token valid! Create new isolated session context
                // Fix 5: Poison-safe policy read
                let current_policy = match state.policy.read() {
                    Ok(guard) => guard.clone(),
                    Err(_) => None,
                };
                let email = if sub.contains('@') { Some(sub.clone()) } else { None };
                let session = Arc::new(super::session::SessionContext::new(
                    Some(sub.clone()),
                    email,
                    current_policy,
                    Some(client_ip.to_string()),
                    credential_header.map(|s| s.to_string()),
                ));

                // Fix 3: Evict expired sessions before inserting new one
                evict_expired_sessions(state);
                state.sessions.insert(token_hash, session.clone());

                crate::logging::log_event(
                    crate::logging::Level::Info,
                    "session_start",
                    serde_json::json!({
                        "session": &session.session_id,
                        "identity": { "sub": &sub },
                        "policy_hash": "sha256:active"
                    }),
                );

                Ok(session)
            }
            Err(e) => {
                // Fix 1: Write invalid-token failure to HMAC audit chain
                let _ = state.audit_logger.write_entry(
                    &state.session_id,
                    "auth_failed",
                    "",
                    None,
                    Some(format!("invalid_token: {} remote_addr={}", e, client_ip)),
                    None,
                    None,
                    None,
                    None,
                    Some(client_ip.to_string()),
                ).await;
                crate::logging::log_event(
                    crate::logging::Level::Warn,
                    "auth_failed",
                    serde_json::json!({
                        "reason": format!("invalid_token: {}", e),
                        "remote_addr": client_ip,
                    }),
                );
                Err((
                    StatusCode::UNAUTHORIZED,
                    format!("OIDC Token validation failed: {}", e),
                ))
            }
        }
    } else {
        // OIDC is NOT configured. Fall back to local session tracking!
        // We use X-Session-ID header or Client IP as session key.
        let session_key = auth_header
            .unwrap_or(client_ip)
            .to_string();

        if let Some(session) = state.sessions.get(&session_key) {
            return Ok(session.clone());
        }

        // Fix 5: Poison-safe policy read
        let current_policy = match state.policy.read() {
            Ok(guard) => guard.clone(),
            Err(_) => {
                crate::logging::log_event(
                    crate::logging::Level::Error,
                    "policy_lock_poisoned",
                    serde_json::json!({"remote_addr": client_ip, "action": "deny_applied"}),
                );
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Policy state is temporarily unavailable".to_string(),
                ));
            }
        };

        let session = Arc::new(super::session::SessionContext::new(
            None,
            None,
            current_policy,
            Some(client_ip.to_string()),
            credential_header.map(|s| s.to_string()),
        ));

        // Fix 3: Evict expired sessions before inserting new one
        evict_expired_sessions(state);
        state.sessions.insert(session_key, session.clone());

        crate::logging::log_event(
            crate::logging::Level::Info,
            "session_start",
            serde_json::json!({
                "session": &session.session_id,
                "remote_addr": client_ip,
            }),
        );

        Ok(session)
    }
}

/// Handle a single HTTP request
async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    client_ip: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Determine if this is an egress proxy request (CONNECT, WebSocket upgrade, or absolute URI)
    let is_egress = method == hyper::Method::CONNECT
        || hyper_tungstenite::is_upgrade_request(&req)
        || req.uri().authority().is_some();

    if is_egress {
        // Resolve dynamic multi-tenant session context for egress
        let auth_header = req.headers().get(hyper::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        let credential_header = req.headers().get("X-AgentWall-Credential")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        
        let session = match resolve_session(&state, auth_header.as_deref(), credential_header.as_deref(), client_ip).await {
            Ok(s) => s,
            Err((status, err_msg)) => {
                let err = serde_json::json!({
                    "error": {"code": -32099, "message": err_msg}
                });
                return Ok(json_response(status, &err));
            }
        };

        return crate::proxy::egress::handle_egress(req, state, &session, client_ip).await;
    }

    // Health/readiness/metrics/dashboard endpoints
    if method == hyper::Method::GET {
        match path.as_str() {
            "/" => {
                let html = crate::dashboard::dashboard_html();
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(Full::new(Bytes::from(html)))
                    .unwrap());
            }
            "/api/stats" => {
                match state.db_manager.get_stats().await {
                    Ok(stats) => {
                        let json_val = serde_json::to_value(&stats).unwrap();
                        return Ok(json_response(StatusCode::OK, &json_val));
                    }
                    Err(e) => {
                        let err = serde_json::json!({
                            "error": format!("Database error: {}", e)
                        });
                        return Ok(json_response(StatusCode::INTERNAL_SERVER_ERROR, &err));
                    }
                }
            }
            "/api/events" => {
                let limit = req.uri().query()
                    .and_then(|q| {
                        q.split('&')
                            .find(|pair| pair.starts_with("limit="))
                            .and_then(|pair| pair.split('=').nth(1))
                            .and_then(|val| val.parse::<usize>().ok())
                    })
                    .unwrap_or(100)
                    .min(100);
                match state.db_manager.get_events(limit).await {
                    Ok(events) => {
                        let json_val = serde_json::to_value(&events).unwrap();
                        return Ok(json_response(StatusCode::OK, &json_val));
                    }
                    Err(e) => {
                        let err = serde_json::json!({
                            "error": format!("Database error: {}", e)
                        });
                        return Ok(json_response(StatusCode::INTERNAL_SERVER_ERROR, &err));
                    }
                }
            }
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
            "/metrics" => {
                return Ok(prometheus_metrics_response(&state));
            }
            "/api/self-healing/status" => {
                // Return dummy status for now based on recent events to satisfy dashboard
                match state.db_manager.get_events(500).await {
                    Ok(events) => {
                        let mut scorer = crate::self_healing::AnomalyScorer::new();
                        let mut tools_status = Vec::new();
                        
                        // Extract unique tools and latest timestamps
                        let mut tool_last_seen = std::collections::HashMap::new();
                        for e in &events {
                            if let Some(t) = &e.url_path {
                                let current = tool_last_seen.get(t).unwrap_or(&0i64);
                                if e.timestamp_ns > *current {
                                    tool_last_seen.insert(t.clone(), e.timestamp_ns);
                                }
                                
                                if let Some(body) = &e.request_body {
                                    if let Ok(params) = serde_json::from_str::<serde_json::Value>(body) {
                                        let mut flat = Vec::new();
                                        crate::generate_policy::flatten_json(&params, "", 0, 5, &mut flat);
                                        for (k, v) in flat {
                                            if let serde_json::Value::String(s) = v {
                                                scorer.observe(t, &k, &s);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        for (tool, last_seen) in tool_last_seen {
                            let decay = crate::self_healing::ConfidenceDecay::calculate(last_seen, 30);
                            tools_status.push(serde_json::json!({
                                "name": tool,
                                "confidence_decay": decay,
                                "last_seen": last_seen,
                                "stale": decay == 0.0
                            }));
                        }
                        
                        let suggestions = crate::self_healing::SuggestionEngine::generate_suggestions(&scorer, 0.9, &events);
                        
                        let status = serde_json::json!({
                            "enabled": true,
                            "decay_window_days": 30,
                            "tools": tools_status,
                            "pending_suggestions": suggestions
                        });
                        return Ok(json_response(StatusCode::OK, &status));
                    }
                    Err(e) => {
                        let err = serde_json::json!({"error": format!("Database error: {}", e)});
                        return Ok(json_response(StatusCode::INTERNAL_SERVER_ERROR, &err));
                    }
                }
            }
            // FR-5 v2.0: Gateway status endpoint — mode, uptime, policy, metrics
            "/gateway/status" => {
                use std::sync::atomic::Ordering;
                let uptime_secs = state.gateway_start_time.elapsed().as_secs();
                let policy_loaded = state.policy_loaded.load(Ordering::Relaxed);
                let mode = if state.shadow_mode {
                    "shadow"
                } else if state.dry_run {
                    "dry-run"
                } else {
                    "enforce"
                };
                let status = serde_json::json!({
                    "mode": mode,
                    "policy_loaded": policy_loaded,
                    "policy_path": state.policy_path,
                    "uptime_secs": uptime_secs,
                    "strict_credential_scope": state.credential_scope_validator.strict,
                    "metrics": {
                        "requests_total": state.metrics_requests_total.load(Ordering::Relaxed),
                        "allow_total": state.metrics_allow_total.load(Ordering::Relaxed),
                        "deny_total": state.metrics_deny_total.load(Ordering::Relaxed),
                        "rate_limited_total": state.metrics_rate_limited_total.load(Ordering::Relaxed),
                        "firewall_cycle_total": state.metrics_firewall_cycle_total.load(Ordering::Relaxed),
                        "siem_export_total": state.metrics_siem_export_total.load(Ordering::Relaxed),
                        "siem_export_failed_total": state.metrics_siem_export_failed_total.load(Ordering::Relaxed),
                    },
                    "upstream_url": &state.upstream_url,
                    "listen": "see --listen flag",
                    "fr22_integration_pending": true,
                    "note": "credential_scope validation is a stub — FR-22 Identity Platform integration pending"
                });
                return Ok(json_response(StatusCode::OK, &status));
            }
            _ => {}
        }
    }

    // FR-5 v2.0: Policy hot-reload endpoint (AC-5.6)
    // Reloads the policy YAML from the path originally passed at startup.
    // Existing connections are NOT dropped — the new policy takes effect for
    // the NEXT request through each session (Arc<RwLock> swap is atomic).
    if method == hyper::Method::POST && path == "/reload" {
        match &state.policy_path {
            None => {
                let err = serde_json::json!({
                    "error": "No policy path configured. Start the gateway with --policy <path> to enable hot-reload.",
                    "hint": "agentwall start --policy agentwall-policy.yaml"
                });
                return Ok(json_response(StatusCode::BAD_REQUEST, &err));
            }
            Some(policy_path_str) => {
                let path_clone = policy_path_str.clone();
                let reload_result = tokio::task::spawn_blocking(move || {
                    crate::policy::loader::load_policy(
                        std::path::Path::new(&path_clone),
                        None, // issuer override not re-applied on hot-reload
                    )
                }).await;

                match reload_result {
                    Ok(crate::policy::loader::PolicyLoadResult::Loaded { policy, raw_hash, warnings }) => {
                        // Atomically swap the policy — zero dropped connections
                        match state.policy.write() {
                            Ok(mut guard) => *guard = Some(policy),
                            Err(_) => {
                                let err = serde_json::json!({"error": "Policy lock poisoned during reload"});
                                return Ok(json_response(StatusCode::INTERNAL_SERVER_ERROR, &err));
                            }
                        }
                        state.policy_loaded.store(true, std::sync::atomic::Ordering::SeqCst);

                        crate::logging::log_event(
                            crate::logging::Level::Info,
                            "policy_reloaded",
                            serde_json::json!({
                                "path": &state.policy_path,
                                "hash": &raw_hash,
                                "warnings": &warnings,
                            }),
                        );

                        // Broadcast SSE event so the dashboard Gateway panel updates live
                        let sse_event = serde_json::json!({
                            "event": "gateway_reload",
                            "policy_hash": &raw_hash,
                            "warnings": &warnings,
                        });
                        if let Ok(s) = serde_json::to_string(&sse_event) {
                            let _ = state.event_tx.send(s);
                        }

                        return Ok(json_response(StatusCode::OK, &serde_json::json!({
                            "status": "reloaded",
                            "policy_hash": raw_hash,
                            "warnings": warnings,
                        })));
                    }
                    Ok(crate::policy::loader::PolicyLoadResult::Degraded { reason }) => {
                        let err = serde_json::json!({"error": format!("Policy degraded: {}", reason)});
                        return Ok(json_response(StatusCode::UNPROCESSABLE_ENTITY, &err));
                    }
                    Ok(crate::policy::loader::PolicyLoadResult::Fatal { error }) => {
                        let err = serde_json::json!({"error": format!("Policy fatal: {}", error)});
                        return Ok(json_response(StatusCode::UNPROCESSABLE_ENTITY, &err));
                    }
                    Err(e) => {
                        let err = serde_json::json!({"error": format!("Reload task failed: {}", e)});
                        return Ok(json_response(StatusCode::INTERNAL_SERVER_ERROR, &err));
                    }
                }
            }
        }
    }

    // Policy Generation endpoint
    if method == hyper::Method::POST && path == "/api/generate-policy" {
        // Fix AW-BUG-002: use get_all_events (ASC order, oldest first) to match
        // the CLI behavior in main.rs. generate_from_events() expects chronological
        // ordering for confidence decay, anomaly scoring, and first/last seen tracking.
        match state.db_manager.get_all_events(500).await {
            Ok(events) => {
                let yaml_str = crate::generate_policy::generate_from_events(&events, 30);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "text/yaml; charset=utf-8")
                    .body(Full::new(Bytes::from(yaml_str)))
                    .unwrap());
            }
            Err(e) => {
                let err = serde_json::json!({
                    "error": format!("Database error: {}", e)
                });
                return Ok(json_response(StatusCode::INTERNAL_SERVER_ERROR, &err));
            }
        }
    }

    // Self-healing suggestions trigger
    if method == hyper::Method::POST && path == "/api/self-healing/suggestions" {
        match state.db_manager.get_events(500).await {
            Ok(events) => {
                let mut scorer = crate::self_healing::AnomalyScorer::new();
                for e in &events {
                    if let Some(t) = &e.url_path {
                        if let Some(body) = &e.request_body {
                            if let Ok(params) = serde_json::from_str::<serde_json::Value>(body) {
                                let mut flat = Vec::new();
                                crate::generate_policy::flatten_json(&params, "", 0, 5, &mut flat);
                                for (k, v) in flat {
                                    if let serde_json::Value::String(s) = v {
                                        scorer.observe(t, &k, &s);
                                    }
                                }
                            }
                        }
                    }
                }
                let suggestions = crate::self_healing::SuggestionEngine::generate_suggestions(&scorer, 0.9, &events);
                
                // FR-4: Log to SIEM via StubGitOps
                let gitops = crate::self_healing::StubGitOps;
                use crate::self_healing::GitOpsPrPayload;
                for sug in &suggestions {
                    let _ = gitops.create_suggestion_pr(sug);
                }
                
                return Ok(json_response(StatusCode::OK, &serde_json::json!(suggestions)));
            }
            Err(e) => {
                let err = serde_json::json!({"error": format!("Database error: {}", e)});
                return Ok(json_response(StatusCode::INTERNAL_SERVER_ERROR, &err));
            }
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

    let credential_header = req.headers().get("X-AgentWall-Credential")
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

    let start_time = std::time::Instant::now();

    // Resolve dynamic multi-tenant session context (FR-101)
    let session = match resolve_session(&state, auth_header.as_deref(), credential_header.as_deref(), client_ip).await {
        Ok(s) => s,
        Err((status, err_msg)) => {
            let err = serde_json::json!({
                "jsonrpc": "2.0",
                "id": body.get("id").cloned().unwrap_or(serde_json::Value::Null),
                "error": {"code": -32099, "message": err_msg}
            });
            return Ok(json_response(status, &err));
        }
    };

    // Handle the JSON-RPC call against the dynamic session context
    let action = handler::evaluate_jsonrpc(&state, &session, &body).await;

    // Extract tool name from original request for response scanning context
    let tool_name = body.get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("");

    let mut dlp_findings_json = None;
    let mut injection_findings_json = None;

    let (response, should_kill, status_code) = match action {
        ProxyAction::Forward => {
            match forward::forward_request(&state.http_client, &state.upstream_url, &body).await {
                Ok(resp) => {
                    // FR-303b: Response scanning
                    let processed = scan_and_process_response(
                        &state,
                        &session,
                        &resp,
                        tool_name,
                        &mut dlp_findings_json,
                        &mut injection_findings_json,
                    ).await;
                    (processed, false, StatusCode::OK)
                },
                Err(e) => (
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": body.get("id"),
                        "error": { "code": -32603, "message": format!("Upstream error: {}", e) }
                    }),
                    false,
                    StatusCode::OK,
                ),
            }
        }
        ProxyAction::Respond(resp) => (resp, false, StatusCode::OK),
        ProxyAction::RespondWithStatus(status, resp) => (resp, false, status),
        ProxyAction::KillAndRespond(resp) => (resp, true, StatusCode::OK),
        ProxyAction::KillAndRespondWithStatus(status, resp) => (resp, true, status),
    };

    if body.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
        let tool_name = body.get("params")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        let parameters = body.get("params")
            .and_then(|p| p.get("arguments"))
            .map(|a| a.to_string())
            .unwrap_or_else(|| "{}".to_string());
        let response_str = response.to_string();
        let timestamp_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        
        let event = crate::proxy::db::EgressEvent {
            timestamp_ns,
            session_id: session.session_id.clone(),
            transport: "mcp".to_string(),
            method: Some("tools/call".to_string()),
            target_host: state.upstream_url.clone(),
            target_port: None,
            url_path: Some(tool_name),
            request_headers: None,
            request_body: Some(parameters),
            request_body_hash: None,
            response_status: Some(status_code.as_u16() as i64),
            response_body: Some(response_str),
            response_body_hash: None,
            dlp_findings: dlp_findings_json.clone(),
            injection_findings: injection_findings_json.clone(),
            latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
            verdict: Some(if should_kill || response.get("error").is_some() { "deny".to_string() } else { "allow".to_string() }),
            semantic_anomaly_score: None,
            identity_context: None,
        };
        let db = state.db_manager.clone();
        
        // Broadcast to SSE clients
        if let Ok(json_str) = serde_json::to_string(&event) {
            let _ = state.event_tx.send(json_str);
        }

        tokio::spawn(async move {
            let _ = db.insert(event).await;
            db.prune();
        });
    }

    // Send response first (before kill)
    let http_response = json_response(status_code, &response);

    // Execute kill if needed (after response is constructed)
    if should_kill {
        kill::execute_kill(&state.kill_mode, &session.session_id, state.agent_pid);
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

/// Guidance #9 + FR-104: Build a Prometheus text format response for GET /metrics.
///
/// Returns all operational counters in standard Prometheus exposition format
/// (text/plain; version=0.0.4). Counters are safe to scrape concurrently.
fn prometheus_metrics_response(state: &ProxyState) -> Response<Full<Bytes>> {
    use std::sync::atomic::Ordering;

    let requests    = state.metrics_requests_total.load(Ordering::Relaxed);
    let allowed     = state.metrics_allow_total.load(Ordering::Relaxed);
    let denied      = state.metrics_deny_total.load(Ordering::Relaxed);
    let rate_lim    = state.metrics_rate_limited_total.load(Ordering::Relaxed);
    let cycles      = state.metrics_firewall_cycle_total.load(Ordering::Relaxed);
    let siem_ok     = state.metrics_siem_export_total.load(Ordering::Relaxed);
    let siem_failed = state.metrics_siem_export_failed_total.load(Ordering::Relaxed);

    let body = format!(
        "# HELP agentwall_requests_total Total tool call requests evaluated by the gateway.\n\
         # TYPE agentwall_requests_total counter\n\
         agentwall_requests_total {requests}\n\
         # HELP agentwall_allow_total Tool calls allowed by policy evaluation.\n\
         # TYPE agentwall_allow_total counter\n\
         agentwall_allow_total {allowed}\n\
         # HELP agentwall_deny_total Tool calls denied (policy violation, DLP, safe mode).\n\
         # TYPE agentwall_deny_total counter\n\
         agentwall_deny_total {denied}\n\
         # HELP agentwall_rate_limited_total Requests dropped by the rate limiter.\n\
         # TYPE agentwall_rate_limited_total counter\n\
         agentwall_rate_limited_total {rate_lim}\n\
         # HELP agentwall_firewall_cycle_total Agent firewall cycle detection triggers.\n\
         # TYPE agentwall_firewall_cycle_total counter\n\
         agentwall_firewall_cycle_total {cycles}\n\
         # HELP agentwall_siem_export_total Audit entries successfully exported to SIEM backend.\n\
         # TYPE agentwall_siem_export_total counter\n\
         agentwall_siem_export_total {siem_ok}\n\
         # HELP agentwall_siem_export_failed_total Audit entries that failed SIEM export (local disk fallback applied).\n\
         # TYPE agentwall_siem_export_failed_total counter\n\
         agentwall_siem_export_failed_total {siem_failed}\n",
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// FR-303b: Scan a response for secrets and apply redaction/blocking.
/// Fail-open: any scanner error passes the response through with audit log.
async fn scan_and_process_response(
    state: &ProxyState,
    session: &super::session::SessionContext,
    response: &serde_json::Value,
    tool_name: &str,
    dlp_findings_json: &mut Option<String>,
    injection_findings_json: &mut Option<String>,
) -> serde_json::Value {
    let session_id = &session.session_id;

    // 1. Prompt Injection Scanning (FR-13)
    let enforce_mode = !state.shadow_mode;
    let inj_scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.injection_scanner.scan_response(response, tool_name, session_id, enforce_mode)
    }));

    match inj_scan_result {
        Ok(crate::policy::injection::ScanResult::Block { findings }) => {
            let f = &findings[0];
            let _ = state.audit_logger.write_entry(
                session_id,
                "injection_blocked",
                tool_name,
                None,
                Some(format!("pattern={} preview={}", f.pattern_name, f.preview)),
                None,
                session.identity_sub.clone(),
                session.identity_email.clone(),
                None,
                session.request_ip.clone(),
            ).await;
            logging::log_event(
                logging::Level::Warn,
                "injection_blocked",
                serde_json::json!({"tool": tool_name, "session": session_id, "pattern": &f.pattern_name}),
            );

            let findings_json = serde_json::json!({
                "findings": findings.iter().map(|f| format!("{}: {}", f.category.as_str(), f.preview)).collect::<Vec<_>>()
            });
            *injection_findings_json = Some(findings_json.to_string());

            let id = response.get("id").cloned().unwrap_or(serde_json::Value::Null);
            return serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32002,
                    "message": format!("Response blocked: prompt injection detected ({}).", f.pattern_name),
                    "data": {
                        "session_id": session_id,
                        "pattern": &f.pattern_name
                    }
                }
            });
        }
        Ok(crate::policy::injection::ScanResult::Timeout) => {
            if enforce_mode {
                let _ = state.audit_logger.write_entry(
                    session_id,
                    "injection_blocked_timeout",
                    tool_name,
                    None,
                    Some("Scanner timed out (potential ReDoS) — Blocked".to_string()),
                    None,
                    session.identity_sub.clone(),
                    session.identity_email.clone(),
                    None,
                    session.request_ip.clone(),
                ).await;
                logging::log_event(
                    logging::Level::Warn,
                    "injection_blocked_timeout",
                    serde_json::json!({"tool": tool_name, "session": session_id}),
                );

                let id = response.get("id").cloned().unwrap_or(serde_json::Value::Null);
                return serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32002,
                        "message": "Response blocked: injection scan timeout (potential ReDoS).",
                        "data": { "session_id": session_id }
                    }
                });
            } else {
                let _ = state.audit_logger.write_entry(
                    session_id,
                    "injection_warning_timeout",
                    tool_name,
                    None,
                    Some("Scanner timed out (potential ReDoS) — Warn (Shadow Mode)".to_string()),
                    None,
                    session.identity_sub.clone(),
                    session.identity_email.clone(),
                    None,
                    session.request_ip.clone(),
                ).await;
                logging::log_event(
                    logging::Level::Warn,
                    "injection_warning_timeout",
                    serde_json::json!({"tool": tool_name, "session": session_id}),
                );
            }
        }
        Ok(crate::policy::injection::ScanResult::Warn { findings }) => {
            let f = &findings[0];
            let _ = state.audit_logger.write_entry(
                session_id,
                "injection_warning",
                tool_name,
                None,
                Some(format!("pattern={} preview={}", f.pattern_name, f.preview)),
                None,
                session.identity_sub.clone(),
                session.identity_email.clone(),
                None,
                session.request_ip.clone(),
            ).await;
            logging::log_event(
                logging::Level::Warn,
                "injection_warning",
                serde_json::json!({"tool": tool_name, "session": session_id, "pattern": &f.pattern_name, "count": findings.len()}),
            );

            let findings_json = serde_json::json!({
                "findings": findings.iter().map(|f| format!("{}: {}", f.category.as_str(), f.preview)).collect::<Vec<_>>()
            });
            *injection_findings_json = Some(findings_json.to_string());
        }
        Ok(crate::policy::injection::ScanResult::ScannerError { error }) => {
            let _ = state.audit_logger.write_entry(
                session_id,
                "INJECTION_SCANNER_FAILURE",
                tool_name,
                None,
                Some(format!("Scanner error: {} — fail-open applied", error)),
                None,
                session.identity_sub.clone(),
                session.identity_email.clone(),
                None,
                session.request_ip.clone(),
            ).await;
            logging::log_event(
                logging::Level::Error,
                "INJECTION_SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": session_id, "error": &error}),
            );
        }
        Ok(crate::policy::injection::ScanResult::Clean) => {}
        Err(_) => {
            let _ = state.audit_logger.write_entry(
                session_id,
                "INJECTION_SCANNER_FAILURE",
                tool_name,
                None,
                Some("Injection scanner panicked — fail-open applied".to_string()),
                None,
                session.identity_sub.clone(),
                session.identity_email.clone(),
                None,
                session.request_ip.clone(),
            ).await;
            logging::log_event(
                logging::Level::Error,
                "INJECTION_SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": session_id, "reason": "scanner_panic"}),
            );
        }
    }

    // 2. DLP/Secrets Scanning
    let scan_config = match state.response_scan_config.read() {
        Ok(guard) => guard.clone(),
        Err(_) => crate::policy::response_scanner::ResponseScanConfig::default(),
    };
    // Catch panics — fail-open on any error
    let scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.response_scanner.scan_response(response, tool_name, &scan_config)
    }));

    let scan_result = match scan_result {
        Ok(result) => result,
        Err(_) => {
            // Scanner panicked — fail-open + loud audit log
            let _ = state.audit_logger.write_entry(
                session_id,
                "SCANNER_FAILURE",
                tool_name,
                None,
                Some("Response scanner panicked — fail-open applied".to_string()),
                None,
                session.identity_sub.clone(),
                session.identity_email.clone(),
                None,
                session.request_ip.clone(),
            ).await;
            logging::log_event(
                logging::Level::Error,
                "SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": session_id, "reason": "scanner_panic"}),
            );
            return response.clone();
        }
    };

    match scan_result {
        ScanResult::Pass | ScanResult::Clean => response.clone(),

        ScanResult::Skipped { reason } => {
            let _ = state.audit_logger.write_entry(
                session_id,
                "response_scan_skipped",
                tool_name,
                None,
                Some(reason.clone()),
                None,
                session.identity_sub.clone(),
                session.identity_email.clone(),
                None,
                session.request_ip.clone(),
            ).await;
            logging::log_event(
                logging::Level::Warn,
                "response_scan_skipped",
                serde_json::json!({"tool": tool_name, "session": session_id, "reason": &reason}),
            );
            response.clone()
        }

        ScanResult::Redact { findings } => {
            let findings_json = serde_json::json!({
                "findings": findings.iter().map(|f| format!("{}: redact preview={}", f.pattern_name, f.preview)).collect::<Vec<_>>()
            });
            *dlp_findings_json = Some(findings_json.to_string());

            if scan_config.dry_run {
                // Dry-run: log what would be redacted but pass through
                for f in &findings {
                    let _ = state.audit_logger.write_entry(
                        session_id,
                        "response_scan_dry_run",
                        tool_name,
                        None,
                        Some(format!("Would redact {} at {}:{} preview={}", f.pattern_name, f.field_path, f.position, f.preview)),
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                    ).await;
                }
                logging::log_event(
                    logging::Level::Warn,
                    "response_scan_dry_run",
                    serde_json::json!({
                        "tool": tool_name, 
                        "session": session_id, 
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
                    session_id,
                    "response_secret_redacted",
                    tool_name,
                    None,
                    Some(format!("pattern={} field={} pos={} len={} preview={}", f.pattern_name, f.field_path, f.position, f.length, f.preview)),
                    None,
                    session.identity_sub.clone(),
                    session.identity_email.clone(),
                    None,
                    session.request_ip.clone(),
                ).await;
            }
            logging::log_event(
                logging::Level::Warn,
                "response_secret_redacted",
                serde_json::json!({"tool": tool_name, "session": session_id, "count": findings.len()}),
            );

            // Apply redaction
            state.response_scanner.redact_response(response, &scan_config)
        }

        ScanResult::Block { findings } => {
            let findings_json = serde_json::json!({
                "findings": findings.iter().map(|f| format!("{}: block preview={}", f.pattern_name, f.preview)).collect::<Vec<_>>()
            });
            *dlp_findings_json = Some(findings_json.to_string());

            if scan_config.dry_run {
                for f in &findings {
                    let _ = state.audit_logger.write_entry(
                        session_id,
                        "response_scan_dry_run",
                        tool_name,
                        None,
                        Some(format!("Would block: {} preview={}", f.pattern_name, f.preview)),
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                    ).await;
                }
                logging::log_event(
                    logging::Level::Warn,
                    "response_scan_dry_run",
                    serde_json::json!({
                        "tool": tool_name, 
                        "session": session_id, 
                        "would_action": "block", 
                        "pattern": findings.first().map(|f| f.pattern_name.clone()).unwrap_or_default(),
                        "count": findings.len()
                    }),
                );
                return response.clone();
            }

            let f = &findings[0];
            let _ = state.audit_logger.write_entry(
                session_id,
                "response_secret_blocked",
                tool_name,
                None,
                Some(format!("pattern={} field={} preview={}", f.pattern_name, f.field_path, f.preview)),
                None,
                session.identity_sub.clone(),
                session.identity_email.clone(),
                None,
                session.request_ip.clone(),
            ).await;
            logging::log_event(
                logging::Level::Warn,
                "response_secret_blocked",
                serde_json::json!({"tool": tool_name, "session": session_id, "pattern": &f.pattern_name}),
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
                        "session_id": session_id,
                        "pattern": &f.pattern_name
                    }
                }
            })
        }

        ScanResult::ScannerError { error } => {
            // Fail-open + loud audit log
            let _ = state.audit_logger.write_entry(
                session_id,
                "SCANNER_FAILURE",
                tool_name,
                None,
                Some(format!("Scanner error: {} — fail-open applied", error)),
                None,
                session.identity_sub.clone(),
                session.identity_email.clone(),
                None,
                session.request_ip.clone(),
            ).await;
            logging::log_event(
                logging::Level::Error,
                "SCANNER_FAILURE",
                serde_json::json!({"tool": tool_name, "session": session_id, "error": &error}),
            );
            response.clone()
        }
    }
}
