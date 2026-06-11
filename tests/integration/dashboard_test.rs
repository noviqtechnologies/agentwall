use reqwest::Client;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_dashboard_api_endpoints() {
    let listen_addr = "127.0.0.1:8085";
    
    // Spawn proxy server in shadow mode for testing
    let bin = env!("CARGO_BIN_EXE_agentwall");
    let mut cmd = tokio::process::Command::new(bin)
        .arg("dev")
        .arg("--listen")
        .arg(listen_addr)
        .arg("--mcp-url")
        .arg("http://127.0.0.1:3000") // Dummy
        .arg("--no-browser")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start agentwall proxy");
        
    // Wait for server to start
    sleep(Duration::from_secs(2)).await;

    let client = Client::new();
    
    // 1. Test GET / (HTML Dashboard)
    let res = client.get(format!("http://{}", listen_addr))
        .send()
        .await
        .expect("Failed to GET /");
        
    assert_eq!(res.status(), 200);
    let html = res.text().await.unwrap();
    assert!(html.contains("<!DOCTYPE html>"));
    
    // 2. Test GET /api/stats
    let res = client.get(format!("http://{}/api/stats", listen_addr))
        .send()
        .await
        .expect("Failed to GET /api/stats");
        
    assert_eq!(res.status(), 200);
    let json: serde_json::Value = res.json().await.unwrap();
    assert!(json.get("total_events").is_some());
    assert!(json.get("unique_tools").is_some());
    
    // 3. Test POST /api/generate-policy
    let res = client.post(format!("http://{}/api/generate-policy", listen_addr))
        .send()
        .await
        .expect("Failed to POST /api/generate-policy");
        
    assert_eq!(res.status(), 200);
    let yaml = res.text().await.unwrap();
    assert!(yaml.contains("tools:"));

    // Cleanup
    cmd.kill().await.unwrap();
}
