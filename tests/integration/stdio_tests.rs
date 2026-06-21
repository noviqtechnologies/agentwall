use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::sleep;

#[tokio::test]
async fn test_stdio_bridge() {
    let bin = env!("CARGO_BIN_EXE_agentwall");

    // Spawn agentwall in stdio mode
    let mut child = Command::new(bin)
        .args([
            "dev",
            "--stdio",
            "--mcp-url",
            "http://127.0.0.1:3000",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start agentwall stdio proxy");

    // Give it a moment to initialize
    sleep(Duration::from_millis(500)).await;

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let mut stdout = child.stdout.take().expect("Failed to open stdout");

    // Send a JSON-RPC 'ping' request
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "ping",
        "id": 1
    });
    let req_str = format!("{}\n", serde_json::to_string(&req).unwrap());

    stdin.write_all(req_str.as_bytes()).await.expect("Failed to write to stdin");
    stdin.flush().await.expect("Failed to flush stdin");

    // Read the response from stdout
    let mut buf = vec![0; 4096];
    
    // We use a small timeout to read the response to avoid hanging if the bridge is broken
    let n = tokio::time::timeout(Duration::from_secs(5), stdout.read(&mut buf))
        .await
        .expect("Timeout waiting for stdout read")
        .expect("Failed to read from stdout");

    let res_str = String::from_utf8_lossy(&buf[..n]);

    // The proxy should respond to ping automatically or forward it. 
    // Either way, we expect a valid JSON-RPC message containing jsonrpc: 2.0
    assert!(
        res_str.contains(r#""jsonrpc":"2.0""#) || res_str.contains(r#""jsonrpc": "2.0""#),
        "Expected JSON-RPC format in stdout, got: {}",
        res_str
    );

    // Clean up
    child.kill().await.ok();
}
