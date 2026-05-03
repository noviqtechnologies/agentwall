use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[derive(Clone, Serialize, Deserialize)]
struct CallRecord {
    tool: String,
    params: Value,
}

#[derive(Default)]
struct ServerState {
    calls: Mutex<Vec<CallRecord>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = "127.0.0.1:3000".parse()?;
    let listener = TcpListener::bind(addr).await?;
    println!("Mock MCP Server listening on http://{}", addr);

    let state = Arc::new(ServerState::default());

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| handle(req, state.clone()));
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                eprintln!("Error serving connection: {:?}", e);
            }
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<ServerState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if method == Method::GET && path == "/calls" {
        let calls = state.calls.lock().unwrap().clone();
        return Ok(json_response(StatusCode::OK, &json!(calls)));
    }

    if method == Method::GET && path == "/reset" {
        state.calls.lock().unwrap().clear();
        return Ok(json_response(StatusCode::OK, &json!({"status": "cleared"})));
    }

    if method == Method::POST {
        let body_bytes = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Ok(json_response(StatusCode::BAD_REQUEST, &json!({"error": "Bad request"}))),
        };

        let body: Value = match serde_json::from_slice(&body_bytes) {
            Ok(v) => v,
            Err(_) => return Ok(json_response(StatusCode::BAD_REQUEST, &json!({"error": "Invalid JSON"}))),
        };

        let req_method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let req_id = body.get("id").cloned().unwrap_or(Value::Null);

        if req_method == "tools/call" {
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let tool_args = params.get("arguments").cloned().unwrap_or(Value::Null);

            state.calls.lock().unwrap().push(CallRecord {
                tool: tool_name.clone(),
                params: tool_args.clone(),
            });

            let resp = json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tool": tool_name,
                    "status": "success"
                }
            });
            return Ok(json_response(StatusCode::OK, &resp));
        }

        // Just echo back other methods as success for mock
        let resp = json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": "ok"
        });
        return Ok(json_response(StatusCode::OK, &resp));
    }

    Ok(json_response(StatusCode::NOT_FOUND, &json!({"error": "Not found"})))
}

fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let json_str = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json_str)))
        .unwrap()
}
