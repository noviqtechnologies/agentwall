use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
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
    let stdout = child.stdout.take().expect("Failed to open stdout");

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
    
    // We use a small timeout to read the response to avoid hanging if the bridge is broken
    let mut res_str = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let mut reader = tokio::io::BufReader::new(stdout);
        loop {
            let mut line = String::new();
            use tokio::io::AsyncBufReadExt;
            if reader.read_line(&mut line).await.unwrap() == 0 { break; }
            res_str.push_str(&line);
            if line.contains("jsonrpc") { break; }
        }
    }).await;

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
