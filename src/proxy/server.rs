//! HTTP proxy server — listen, route, healthz/readyz (FR-101, §3.3)

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;

use super::handler::{self, ProxyState};
use crate::kill::{self};

/// Run the proxy server. Blocks until shutdown signal.
pub async fn run_server(
    state: Arc<ProxyState>,
    listen_addr: SocketAddr,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(listen_addr).await?;

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
    let (response, should_kill) = handler::handle_jsonrpc(state, &body).await;

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
