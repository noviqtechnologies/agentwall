# 🚀 VEXA AgentWall — Universal Demo Setup Guide

This guide provides step-by-step instructions to get the AgentWall Security Dashboard running on **Windows**, **macOS**, and **Linux**.

---

## 📋 Prerequisites

Before starting, ensure you have the following installed on your system:

| Tool | version | Purpose |
|---|---|---|
| **Rust / Cargo** | 1.70+ | To compile the `agentwall` binary |
| **Python** | 3.8+ | To run the Bridge Server |
| **pip** | Latest | To install Python dependencies |
| **Modern Browser** | Latest | To view the Dashboard (Chrome, Edge, Firefox) |

---

## 🛠️ Step 1: Build the Binary

Open your terminal (PowerShell on Windows, Terminal on macOS/Linux) and run:

### Windows
```powershell
cargo build --release
cp target\release\agentwall.exe .\agentwall.exe -Force
```

### macOS / Linux
```bash
cargo build --release
cp target/release/agentwall ./agentwall
chmod +x ./agentwall
```

---

## 🐍 Step 2: Setup Python Bridge

Install the required Python packages for the bridge server:

```bash
pip install flask flask-cors
```

---

## 🚀 Step 3: Launch the Demo

Navigate to the `demo-ui` folder and start the bridge server.

### Windows
```powershell
cd demo-ui
python bridge.py --vexa-bin ..\agentwall.exe
```

### macOS / Linux
```bash
cd demo-ui
python3 bridge.py --vexa-bin ../agentwall
```

---

## 🌐 Step 4: Open the Dashboard

1.  Locate the file `demo-ui/index.html`.
2.  **Double-click** it to open it in your browser.
3.  Ensure the top-left status bar shows **BRIDGE CONNECTED**.

---

## 🧪 Quick Test Scenarios (v4.3 Features)

Once the dashboard is open, try these scenarios to explore the latest security features:

### 1. Nested Validation (FR-201)
*   Go to **Monitor & Auth**.
*   Click **Start Proxy**.
*   Click **Valid Nested** preset → Result: `ALLOWED`.
*   Click **Invalid Nested (Limit)** preset → Result: `DENIED` (Schema violation).

### 2. Identity Binding (FR-202)
*   Go to **Policy Editor**.
*   Uncomment the `identity:` block in the YAML.
*   Click **Save Policy** and **Restart Proxy**.
*   Simulate a call without a token to see the identity enforcement in action.

### 3. Production Promotion (FR-204)
*   Go to the **Policy Promotion** tab.
*   Click **Run Promotion Check**.
*   Observe the risk score validation and the **Ed25519 Cryptographic Signature** generated for your policy.

---

## ❓ Troubleshooting

| Issue | Solution |
|---|---|
| **"Binary not found"** | Ensure the `--vexa-bin` path correctly points to the `agentwall` file. |
| **"Permission Denied"** (Linux/macOS) | Run `chmod +x ../agentwall` to make the binary executable. |
| **"Bridge Disconnected"** | Check if another process is using port `5173`. Run `python bridge.py --port 5174` and update `index.html` if needed. |
| **"Invalid JSON" in Report** | Ensure you are using the latest compiled binary (v1.0.5+). |

---

© 2026 NoviqTech — Vexa AgentWall Governance Platform
