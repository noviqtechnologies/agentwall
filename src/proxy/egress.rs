use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;

use crate::proxy::handler::ProxyState;
use crate::proxy::db::EgressEvent;
use crate::proxy::session::SessionContext;

pub async fn handle_egress(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    session: &SessionContext,
    _client_ip: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    // 1. CONNECT proxying
    if method == hyper::Method::CONNECT {
        let target_host = uri.authority().map(|a| a.host().to_string()).unwrap_or_default();
        let target_port = uri.authority().and_then(|a| a.port_u16()).unwrap_or(443);
        
        let target_url = format!("{}:{}", target_host, target_port);
        let session_id = session.session_id.clone();
        let state_clone = state.clone();
        let timestamp_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let start_time = std::time::Instant::now();

        tokio::task::spawn(async move {
            // Fix AW-BUG-004: track actual connection outcome for accurate audit logging.
            // Default to failure (502/deny); only set success (200/allow) when TCP connect succeeds.
            let mut final_status: i64 = 502;
            let mut final_verdict = "deny".to_string();

            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
                    match tokio::net::TcpStream::connect(&target_url).await {
                        Ok(mut server) => {
                            final_status = 200;
                            final_verdict = "allow".to_string();
                            let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await;
                        }
                        Err(e) => {
                            eprintln!("Tunnel connection failed to {}: {}", target_url, e);
                        }
                    }
                }
                Err(e) => eprintln!("upgrade error: {}", e),
            }
            
            // Log egress event after tunnel closes
            let event = EgressEvent {
                timestamp_ns,
                session_id,
                transport: "http_connect".to_string(),
                method: Some("CONNECT".to_string()),
                target_host,
                target_port: Some(target_port as i64),
                url_path: None,
                request_headers: None,
                request_body: None,
                request_body_hash: None,
                response_status: Some(final_status),
                response_body: None,
                response_body_hash: None,
                dlp_findings: None,
                injection_findings: None,
                latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
                verdict: Some(final_verdict),
                semantic_anomaly_score: None,
                identity_context: None,
            };
            if let Ok(json_str) = serde_json::to_string(&event) {
                let _ = state_clone.event_tx.send(json_str);
            }
            let _ = state_clone.db_manager.insert(event).await;
        });
        
        return Ok(Response::new(Full::new(Bytes::new())));
    }
    
    // 2. WebSockets proxying
    if hyper_tungstenite::is_upgrade_request(&req) {
        let target_host = uri.authority().map(|a| a.host().to_string()).unwrap_or_default();
        let target_port = uri.authority().and_then(|a| a.port_u16()).unwrap_or(80);
        let url_path = uri.path_and_query().map(|pq| pq.as_str().to_string()).unwrap_or_default();
        let target_url_str = if target_port == 443 {
            format!("wss://{}{}", target_host, url_path)
        } else {
            format!("ws://{}:{}{}", target_host, target_port, url_path)
        };
        
        // Fix AW-BUG-003: handle malformed WebSocket upgrade gracefully instead
        // of panicking. Missing Sec-WebSocket-Key or invalid headers now return
        // 400 Bad Request with an audit log entry, instead of crashing the handler.
        let (response, websocket) = match hyper_tungstenite::upgrade(req, None) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("WebSocket upgrade failed: {}", e);
                let event = EgressEvent {
                    timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    session_id: session.session_id.clone(),
                    transport: "websocket".to_string(),
                    method: Some("websocket_upgrade_failed".to_string()),
                    target_host: target_host.clone(),
                    target_port: Some(target_port as i64),
                    url_path: Some(url_path.clone()),
                    request_headers: None,
                    request_body: None,
                    request_body_hash: None,
                    response_status: Some(400),
                    response_body: None,
                    response_body_hash: None,
                    dlp_findings: None,
                    injection_findings: None,
                    latency_ms: None,
                    verdict: Some("deny".to_string()),
                    semantic_anomaly_score: None,
                    identity_context: None,
                };
                let _ = state.db_manager.insert(event).await;
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from(format!("WebSocket upgrade failed: {}", e))))
                    .unwrap());
            }
        };
        let session_id = session.session_id.clone();
        let state_clone = state.clone();
        let timestamp_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let start_time = std::time::Instant::now();

        tokio::task::spawn(async move {
            match websocket.await {
                Ok(client_ws) => {
                    // Connect to target WebSocket server
                    let target_ws = tokio_tungstenite::connect_async(&target_url_str).await;
                    match target_ws {
                        Ok((server_ws, _)) => {
                            use futures_util::{StreamExt, SinkExt};
                            let (mut client_tx, mut client_rx) = client_ws.split();
                            let (mut server_tx, mut server_rx) = server_ws.split();
                            
                            let c2s = async move {
                                while let Some(msg) = client_rx.next().await {
                                    if let Ok(m) = msg {
                                        if server_tx.send(m).await.is_err() { break; }
                                    } else { break; }
                                }
                            };
                            let s2c = async move {
                                while let Some(msg) = server_rx.next().await {
                                    if let Ok(m) = msg {
                                        if client_tx.send(m).await.is_err() { break; }
                                    } else { break; }
                                }
                            };
                            tokio::join!(c2s, s2c);
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to target WS {}: {}", target_url_str, e);
                        }
                    }
                }
                Err(e) => eprintln!("WebSocket upgrade error: {}", e),
            }
            
            // Log egress event
            let event = EgressEvent {
                timestamp_ns,
                session_id,
                transport: "websocket".to_string(),
                method: Some("websocket_upgrade".to_string()),
                target_host,
                target_port: Some(target_port as i64),
                url_path: Some(url_path),
                request_headers: None,
                request_body: None,
                request_body_hash: None,
                response_status: Some(101),
                response_body: None,
                response_body_hash: None,
                dlp_findings: None,
                injection_findings: None,
                latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
                verdict: Some("allow".to_string()),
                semantic_anomaly_score: None,
                identity_context: None,
            };
            if let Ok(json_str) = serde_json::to_string(&event) {
                let _ = state_clone.event_tx.send(json_str);
            }
            let _ = state_clone.db_manager.insert(event).await;
        });
        
        let mut res = Response::builder().status(response.status());
        for (k, v) in response.headers() {
            res = res.header(k, v);
        }
        return Ok(res.body(Full::new(Bytes::new())).unwrap());
    }
    
    // 3. Standard fetch proxying
    let target_host = uri.authority().map(|a| a.host().to_string()).unwrap_or_default();
    let target_port = uri.authority().and_then(|a| a.port_u16()).unwrap_or(80);
    let url_path = uri.path_and_query().map(|pq| pq.as_str().to_string()).unwrap_or_default();
    let method_str = method.to_string();
    
    let timestamp_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let start_time = std::time::Instant::now();
    let session_id = session.session_id.clone();
    
    // Parse request body
    let mut req_headers = reqwest::header::HeaderMap::new();
    for (k, v) in req.headers() {
        req_headers.insert(k.clone(), v.clone());
    }
    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => Bytes::new(),
    };
    
    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap();

    // FR-12: Content-Aware DLP & Secret Detection on outbound egress requests
    let body_str = String::from_utf8_lossy(&body_bytes);
    let combined_content = format!("{} {}", uri, body_str);
    let dlp_findings = state.dlp_scanner.scan_content(&combined_content);

    let mut verdict = "allow".to_string();
    let mut dlp_findings_json = None;

    if !dlp_findings.is_empty() {
        let findings_json = serde_json::json!({
            "findings": dlp_findings.iter().map(|f| format!("{}: {}", f.category.as_str(), f.preview)).collect::<Vec<_>>()
        });
        dlp_findings_json = Some(findings_json.to_string());

        if state.shadow_mode {
            crate::logging::log_event(
                crate::logging::Level::Warn,
                "egress_dlp_finding",
                serde_json::json!({
                    "transport": "fetch",
                    "session": &session.session_id,
                    "target_host": &target_host,
                    "findings": &findings_json["findings"]
                }),
            );
        } else {
            let critical = dlp_findings.iter().any(|f| f.category != crate::policy::dlp::SecretCategory::EnvVar);
            if critical {
                verdict = "deny".to_string();
                let err_res = Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("X-AgentWall-Block-Reason", format!("dlp:{}", dlp_findings[0].pattern_name))
                    .body(Full::new(Bytes::from("AgentWall Blocked: Secret DLP Violation")))
                    .unwrap();

                // Log egress event for blocked request
                let event = EgressEvent {
                    timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    session_id,
                    transport: "fetch".to_string(),
                    method: Some(method_str),
                    target_host,
                    target_port: Some(target_port as i64),
                    url_path: Some(url_path),
                    request_headers: None,
                    request_body: None,
                    request_body_hash: None,
                    response_status: Some(403),
                    response_body: None,
                    response_body_hash: None,
                    dlp_findings: dlp_findings_json,
                    injection_findings: None,
                    latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
                    verdict: Some(verdict),
                    semantic_anomaly_score: None,
                    identity_context: None,
                };
                if let Ok(json_str) = serde_json::to_string(&event) {
                    let _ = state.event_tx.send(json_str);
                }
                let _ = state.db_manager.insert(event).await;

                return Ok(err_res);
            }
        }
    }

    let req_builder = state.http_client.request(
        reqwest_method,
        uri.to_string()
    )
    .headers(req_headers)
    .body(body_bytes);
    
    let mut response_status = 502;
    
    let mut injection_findings_json = None;

    let final_res = match req_builder.send().await {
        Ok(upstream_res) => {
            response_status = upstream_res.status().as_u16();
            let mut builder = Response::builder().status(upstream_res.status());
            for (k, v) in upstream_res.headers() {
                builder = builder.header(k, v);
            }
            if let Ok(bytes) = upstream_res.bytes().await {
                let body_str = String::from_utf8_lossy(&bytes);
                // Scan for Prompt Injection
                let enforce_mode = !state.shadow_mode;
                let scan_val = serde_json::json!({ "content": body_str.to_string() });
                let inj_scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    state.injection_scanner.scan_response(&scan_val, "http_fetch", &session_id, enforce_mode)
                }));
                
                let mut is_blocked = false;
                match inj_scan_result {
                    Ok(crate::policy::injection::ScanResult::Block { findings }) => {
                        let f = &findings[0];
                        let findings_json = serde_json::json!({
                            "findings": findings.iter().map(|f| format!("{}: {}", f.category.as_str(), f.preview)).collect::<Vec<_>>()
                        });
                        injection_findings_json = Some(findings_json.to_string());
                        verdict = "deny".to_string();
                        response_status = 403;
                        is_blocked = true;
                        
                        let _ = state.audit_logger.write_entry(&session_id, "injection_blocked", "http_fetch", None,
                            Some(format!("pattern={} preview={}", f.pattern_name, f.preview)), None, None, None, None, None).await;
                    }
                    Ok(crate::policy::injection::ScanResult::Timeout) => {
                        if enforce_mode {
                            verdict = "deny".to_string();
                            response_status = 403;
                            is_blocked = true;
                            
                            let _ = state.audit_logger.write_entry(&session_id, "injection_blocked_timeout", "http_fetch", None,
                                Some("Scanner timed out (potential ReDoS) — Blocked".to_string()), None, None, None, None, None).await;
                        } else {
                            let _ = state.audit_logger.write_entry(&session_id, "injection_warning_timeout", "http_fetch", None,
                                Some("Scanner timed out (potential ReDoS) — Warn".to_string()), None, None, None, None, None).await;
                        }
                    }
                    Ok(crate::policy::injection::ScanResult::Warn { findings }) => {
                        let findings_json = serde_json::json!({
                            "findings": findings.iter().map(|f| format!("{}: {}", f.category.as_str(), f.preview)).collect::<Vec<_>>()
                        });
                        injection_findings_json = Some(findings_json.to_string());
                    }
                    _ => {}
                }

                if is_blocked {
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("X-AgentWall-Block-Reason", "injection_detected")
                        .body(Full::new(Bytes::from("AgentWall Blocked: Prompt Injection Detected")))
                        .unwrap()
                } else {
                    builder.body(Full::new(bytes)).unwrap_or_default()
                }
            } else {
                builder.body(Full::new(Bytes::new())).unwrap_or_default()
            }
        }
        Err(e) => {
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("Bad Gateway: {}", e))))
                .unwrap()
        }
    };
    
    // Log egress event
    let event = EgressEvent {
        timestamp_ns,
        session_id,
        transport: "fetch".to_string(),
        method: Some(method_str),
        target_host,
        target_port: Some(target_port as i64),
        url_path: Some(url_path),
        request_headers: None,
        request_body: None,
        request_body_hash: None,
        response_status: Some(response_status as i64),
        response_body: None,
        response_body_hash: None,
        dlp_findings: dlp_findings_json,
        injection_findings: injection_findings_json,
        latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
        verdict: Some(verdict),
        semantic_anomaly_score: None,
        identity_context: None,
    };
    if let Ok(json_str) = serde_json::to_string(&event) {
        let _ = state.event_tx.send(json_str);
    }
    let _ = state.db_manager.insert(event).await;
    
    Ok(final_res)
}
