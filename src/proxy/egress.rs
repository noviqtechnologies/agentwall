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
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
                    match tokio::net::TcpStream::connect(&target_url).await {
                        Ok(mut server) => {
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
                response_status: Some(200),
                response_body: None,
                response_body_hash: None,
                dlp_findings: None,
                injection_findings: None,
                latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
                verdict: Some("allow".to_string()),
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
        
        let (response, websocket) = hyper_tungstenite::upgrade(req, None).unwrap();
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
                    response_status: Some(403),
                    response_body: None,
                    response_body_hash: None,
                    dlp_findings: dlp_findings_json,
                    injection_findings: None,
                    latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
                    verdict: Some(verdict),
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
    
    let final_res = match req_builder.send().await {
        Ok(upstream_res) => {
            response_status = upstream_res.status().as_u16();
            let mut builder = Response::builder().status(upstream_res.status());
            for (k, v) in upstream_res.headers() {
                builder = builder.header(k, v);
            }
            if let Ok(bytes) = upstream_res.bytes().await {
                builder.body(Full::new(bytes)).unwrap_or_default()
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
        injection_findings: None,
        latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
        verdict: Some(verdict),
    };
    if let Ok(json_str) = serde_json::to_string(&event) {
        let _ = state.event_tx.send(json_str);
    }
    let _ = state.db_manager.insert(event).await;
    
    Ok(final_res)
}
