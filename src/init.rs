//! FR-20: agentwall init — IDE discovery & sidecar generation
use colored::*;
use std::path::Path;

use crate::cli::InitTarget;
use crate::wrap::config_path::*;

pub fn run_init(target: &Option<InitTarget>) -> i32 {
    if let Some(t) = target {
        match t {
            InitTarget::Sidecar { mcp_upstream } => return run_init_sidecar(mcp_upstream),
        }
    }

    println!("{}", "VEXA AgentWall — IDE Discovery (FR-20)".bold().cyan());
    println!("Scanning for known agent and IDE configurations...\n");

    let mut found_any = false;

    // Detect Claude
    if let Ok(path) = claude_config_path() {
        if Path::new(&path).exists() {
            println!("{} {}", "✓".green(), "Claude Desktop detected".bold());
            println!("  To integrate: {}", "agentwall wrap claude".cyan());
            found_any = true;
        }
    }

    // Detect Cursor
    if let Ok(path) = cursor_config_path() {
        if Path::new(&path).exists() {
            println!("{} {}", "✓".green(), "Cursor IDE detected".bold());
            println!("  To integrate: {}", "agentwall wrap cursor".cyan());
            found_any = true;
        }
    }

    // Detect VS Code
    if let Ok(path) = vscode_config_path() {
        if Path::new(&path).exists() {
            println!("{} {}", "✓".green(), "VS Code detected".bold());
            println!("  To integrate: {}", "agentwall wrap vscode".cyan());
            found_any = true;
        }
    }

    // Detect JetBrains
    if let Ok(path) = jetbrains_config_path() {
        if Path::new(&path).exists() {
            println!("{} {}", "✓".green(), "JetBrains IDE detected".bold());
            println!("  To integrate: {}", "agentwall wrap jetbrains".cyan());
            found_any = true;
        }
    }

    // Detect Zed
    if let Ok(path) = zed_config_path() {
        if Path::new(&path).exists() {
            println!("{} {}", "✓".green(), "Zed Editor detected".bold());
            println!("  To integrate: {}", "agentwall wrap zed".cyan());
            found_any = true;
        }
    }

    // Detect Cline
    if let Ok(path) = cline_config_path() {
        if Path::new(&path).exists() {
            println!("{} {}", "✓".green(), "Cline Extension detected".bold());
            println!("  To integrate: {}", "agentwall wrap cline".cyan());
            found_any = true;
        }
    }

    // Detect OpenCode
    if let Ok(path) = opencode_config_path() {
        if Path::new(&path).exists() {
            println!("{} {}", "✓".green(), "OpenCode detected".bold());
            println!("  To integrate: {}", "agentwall wrap opencode".cyan());
            found_any = true;
        }
    }

    // Detect Antigravity
    if let Ok(path) = antigravity_config_path() {
        if Path::new(&path).exists() {
            println!("{} {}", "✓".green(), "Antigravity IDE detected".bold());
            println!("  To integrate: {}", "agentwall wrap antigravity".cyan());
            found_any = true;
        }
    }

    println!();
    if !found_any {
        println!("{}", "No supported IDE configs were detected in standard locations.".yellow());
    } else {
        println!("{}", "Run the integration commands above to wrap your MCP servers with AgentWall.".dimmed());
    }

    0
}

fn run_init_sidecar(mcp_upstream: &str) -> i32 {
    let yaml = format!(
r#"---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentwall-proxy
  labels:
    app: agentwall
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agentwall
  template:
    metadata:
      labels:
        app: agentwall
    spec:
      containers:
        - name: agentwall
          image: vexa/agentwall:latest
          command: ["agentwall", "start"]
          args:
            - "--mcp-url"
            - "{mcp_upstream}"
            - "--listen"
            - "0.0.0.0:8080"
          ports:
            - containerPort: 8080
              name: proxy
          volumeMounts:
            - name: config
              mountPath: /etc/agentwall
      volumes:
        - name: config
          configMap:
            name: agentwall-policy
---
apiVersion: v1
kind: Service
metadata:
  name: agentwall-service
spec:
  selector:
    app: agentwall
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
"#);
    println!("{}", yaml);
    0
}
