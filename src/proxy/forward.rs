//! MCP forwarding — proxy requests to the upstream MCP server

use reqwest::Client;
use serde_json::Value;

/// Forward a JSON-RPC request to the upstream MCP server.
/// Returns the raw response body.
pub async fn forward_request(
    client: &Client,
    upstream_url: &str,
    body: &Value,
) -> Result<Value, ForwardError> {
    let resp = client
        .post(upstream_url)
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| ForwardError::Network(e.to_string()))?;

    let _status = resp.status();
    let body_bytes = resp
        .bytes()
        .await
        .map_err(|e| ForwardError::Network(e.to_string()))?;

    let response: Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| ForwardError::InvalidResponse(e.to_string()))?;

    Ok(response)
}

#[derive(Debug)]
pub enum ForwardError {
    Network(String),
    InvalidResponse(String),
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "Network error: {}", e),
            Self::InvalidResponse(e) => write!(f, "Invalid MCP response: {}", e),
        }
    }
}
