# VEXA AgentWall — Demo UI

A **local-first, zero-build** interactive dashboard for exploring VEXA AgentWall. It connects to the `agentwall` binary running on your machine via a lightweight Python bridge server, giving you a full GUI to edit policies, start/stop the proxy, simulate tool calls, and inspect the audit trail — all without touching the command line after the initial setup.

---

## Contents

```
demo-ui/
├── index.html      # Single-page dashboard — open directly in your browser
├── bridge.py       # Python bridge server (Flask + flask-cors)
├── demo_setup.md   # Universal Setup Guide (Windows, macOS, Linux)
├── policy.example.yaml # Default demo policy template (copied to policy.yaml on first run)
└── README.md       # This file
```

---

## How It Works

```
Browser (index.html)
       │  fetch() / EventSource
       ▼
bridge.py  ← Flask HTTP server on localhost:5173
       │  subprocess.run() / subprocess.Popen()
       ▼
agentwall.exe  ← the compiled Rust binary
       │  HMAC-chained JSON audit log
       ▼
audit.log
```

- `index.html` is a pure HTML + Vanilla JS SPA. It makes REST calls to the bridge on `http://127.0.0.1:5173`.
- `bridge.py` wraps `agentwall` subcommands, manages the proxy process lifetime, tails the audit log, and streams new entries to the browser via **Server-Sent Events (SSE)**.
- No npm, no build step, no bundler. Open `index.html` directly.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.8+** | Verify with `python --version` |
| **agentwall binary** | Build from root: `cargo build --release` → `target\release\agentwall.exe` |
| **Flask & flask-cors** | Install once: `pip install flask flask-cors` |
| **Modern browser** | Chrome, Edge, or Firefox (Safari works but SSE reconnect may vary) |

---

## Setup & Installation

### 1. Build the Binary

From the repository root:

```powershell
cargo build --release
```

The binary will be at `target\release\agentwall.exe`.

### 2. Install Python Dependencies

```powershell
pip install flask flask-cors
```

---

## Running the Demo

### Step 1 — Start the Bridge Server

Navigate to the `demo-ui` folder and start the bridge, pointing `--vexa-bin` at your compiled binary:

```powershell
cd demo-ui
python bridge.py --vexa-bin ..\target\release\agentwall.exe
```

You should see:

```
============================================================
 VEXA AGENTWALL - BRIDGE SERVER
 Status:        RUNNING
 Bridge URL:   http://127.0.0.1:5173
 Vexa Binary:  ..\target\release\agentwall.exe
 Policy File:  C:\...\demo-ui\policy.yaml
------------------------------------------------------------
 Press Ctrl+C to shutdown.
============================================================
```

#### All Bridge Options

| Flag | Default | Description |
|---|---|---|
| `--vexa-bin` | `./vexa` | Path to the `agentwall` / `vexa` binary |
| `--policy` | `./policy.yaml` | Default policy YAML file used by the proxy and editor |
| `--log-path` | `./audit.log` | Audit log file to write and tail |
| `--listen` | `127.0.0.1:8080` | Address the proxy will listen on |
| `--report-path` | `./session-report.json` | Where the proxy writes the session report on shutdown |
| `--port` | `5173` | Port the bridge HTTP server listens on |

**Example with custom paths:**

```powershell
python bridge.py `
  --vexa-bin   ..\target\release\agentwall.exe `
  --policy     .\my-policy.yaml `
  --log-path   .\my-session.log `
  --listen     127.0.0.1:9090 `
  --port       5173
```

### Step 2 — Open the UI

Simply double-click `index.html` in File Explorer, or drag it into your browser. It will automatically connect to the bridge on `http://127.0.0.1:5173`.

> **Bridge Banner:** If a red warning banner appears at the top ("Bridge server disconnected"), the bridge is not running or is on a different port. Check your terminal.

---

## UI Panels

### 01 — Policy Editor

Edit your YAML security policy live in the browser.

| Action | What Happens |
|---|---|
| **Edit the YAML** | Modify the policy live. Support for **Schema v2** is active. |
| **Save Policy** | Writes the YAML to the `--policy` file on disk via `POST /policy/save` |
| **Run Policy Check** | Runs `agentwall test` (FR-204) against a built-in set of sample tool calls and shows a pass/fail table |

The built-in check fixtures test:
- `read_file` with a safe path → **ALLOW**
- `read_file` with a secrets path → **DENY**
- `write_file` to the output dir → **ALLOW**
- `exec_shell` with an allowed command → **ALLOW**
- `exec_shell` with `rm -rf /` → **DENY**

> **Tip:** Edit the policy, save it, then re-run **Policy Check** to immediately see how your changes affect enforcement — without starting the proxy.

---

### 02 — Session Monitor

Start and stop the `agentwall` proxy and watch it enforce policy in real time.

#### Proxy Controls

| Field | Description |
|---|---|
| **Listen Address** | The `host:port` the proxy binds to (e.g., `127.0.0.1:8080`) |
| **Kill Mode** | `both` (default), `connection`, or `process` — action taken on a policy violation |
| **Start Proxy** | Calls `POST /proxy/start` → spawns `agentwall start` as a subprocess |
| **Stop Proxy** | Calls `POST /proxy/stop` → gracefully terminates the process |

#### NEW: Stdio Wrap Mode (FR-302)

AgentWall now supports **Bidirectional MCP Interception** for agents that communicate with tools via `stdin`/`stdout`.

1.  Toggle the mode in the **Session Monitor** to **Stdio Wrap**.
2.  Enter the command you want to wrap (e.g., `python test-tools/mock-stdio-server.py`).
3.  Click **Start Proxy** → AgentWall spawns the command and intercepts its pipes.
4.  Use **Simulate Tool Call** → The bridge sends the call to AgentWall's `stdin`, AgentWall evaluates it, forwards to the mock server, and returns the result.

This mode allows AgentWall to be used as a transparent "wrapper" around any MCP server, providing governance without requiring network configuration.

The sidebar status dot and badge update every 2 seconds to reflect the current proxy state (`STOPPED` / `RUNNING` / `READY` / `INITIALIZING`).

#### Live Log Stream

The bridge tails `audit.log` and pushes new entries to the browser via **Server-Sent Events**. The SSE indicator in the top-right of the card shows `● CONNECTED` when the stream is live.

Each row shows:
- **Time** — HH:MM:SS from the log entry timestamp
- **Event** — e.g., `TOOL_ALLOW`, `TOOL_DENY`, `RATE_LIMIT_DENY`, `DRY_RUN_DENY`
- **Tool** — the MCP tool name
- **Message** — the reason or parameter snapshot

#### Simulate Tool Call

Send a JSON-RPC tool call directly to the running proxy to see it be allowed or denied in real time.

**Quick-fill presets:**

| Button | Tool | Path/Command | Feature |
|---|---|---|---|
| **Valid Nested** | `query_database` | `{"options": {...}}` | **FR-201** (JSON Schema) |
| **Invalid Nested**| `query_database` | `limit: 200` | **FR-201** (Violation) |
| **Safe Read** | `read_file` | `/workspace/src/main.py` | Basic Regex |
| **Blocked Path** | `read_file` | `/etc/passwd` | Path Restriction |

Or enter any tool name and JSON parameters manually and click **Send**. The result card animates green for `ALLOWED` and red for `DENIED`.

---

### 03 — Audit History

A historical view of the entire `audit.log` file, refreshed on demand.

**Stats bar** (top of panel):

| Stat | Source |
|---|---|
| Total Calls | Count of all log entries |
| Allowed | Entries with `event: tool_allow` |
| Denied | Entries with `event: tool_deny` or `rate_limit_deny` |
| p95 Latency | 95th percentile of `latency_ms` across all entries |

**Actions:**
- **Refresh Logs** — reloads up to the last 100 entries from `GET /log/entries?limit=100`
- **Run AgentWall verify-log** — calls `agentwall verify-log` on the current log file and displays whether the HMAC chain is intact (`✓ Chain intact`) or broken (`✗ Tampered`)

---

### 04 — Session Report

Generates a high-level analytics report from the audit log using `agentwall report`.

Displays:
- **Session ID**, **Started**, **Ended** timestamps
- **Total / Allowed / Denied** call counts
- **Blocked Incidents** table — tool name, time, and denial reason for every blocked call
- **Tool Usage** table — per-tool call counts across the session

Click **Refresh Report** to re-run the report command against the current log.

---

### 05 — Policy Promotion (FR-204)

Verify that your policy is ready for production and generate a cryptographic signature.

| Check | Requirement |
|---|---|
| **Risk Scores** | Every tool in the policy must have a `risk` level (`low`, `medium`, `high`) |
| **Identity Config**| Production policies must define an OIDC `issuer` (HTTPS) and `audience` |
| **Signing** | Generates an Ed25519 signature of the policy content for tamper-evidence |

Click **Run Promotion Check** to see the readiness report and public key.

---

## Bridge API Reference

The bridge exposes a simple REST API on `http://127.0.0.1:5173`:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | Bridge health check — returns `{"bridge": "ok"}` |
| `POST` | `/proxy/start` | Spawn the `agentwall start` subprocess |
| `POST` | `/proxy/stop` | Terminate the running proxy |
| `GET` | `/proxy/status` | Returns `{"running": bool, "pid": int\|null}` |
| `GET` | `/proxy/readyz` | Polls the proxy's `/readyz` endpoint |
| `POST` | `/proxy/call` | Forward a simulated tool call to the running proxy |
| `POST` | `/check` | Run `agentwall check` with a policy string and fixture array |
| `POST` | `/policy/save` | Write policy content to the configured policy file |
| `POST` | `/verify-log` | Run `agentwall verify-log` on the audit log |
| `POST` | `/report` | Run `agentwall report --format json` and return the parsed result |
| `GET` | `/log/entries` | Return last N log entries from the audit log (query: `?limit=N`) |
| `GET` | `/log/stream` | Server-Sent Events stream of new log lines as they are written |

---

## Troubleshooting

### "Bridge server disconnected" banner

- The bridge is not running, or it's on a different port.
- Check your terminal for errors.
- Make sure you started `bridge.py` before opening `index.html`.

### "Binary not found" error on Start Proxy

- The `--vexa-bin` path is wrong.
- Build first: `cargo build --release` from the repo root.
- Use the full path if needed: `--vexa-bin C:\path\to\agentwall.exe`

### Proxy fails to start with stderr output

- Another process may already be listening on the same port. Change `--listen` or kill the other process.
- Check that the policy file path is correct and readable.

### SSE shows "○ DISCONNECTED"

- The bridge is running but SSE failed. This can happen if the browser blocked the connection.
- Try refreshing the page. The bridge auto-reconnects SSE clients.

### Log stream shows no entries

- Start the proxy first (Session Monitor panel), then simulate a tool call.
- The log tailer starts from the *end* of the file on first open, so pre-existing entries won't be streamed — use the **Audit History** panel to view those.

### Verify-log shows "Tampered"

- The audit log was modified externally (e.g., edited in a text editor, truncated).
- This is expected if you manually edited `audit.log`. Delete it and start a fresh session to get a clean chain.

---

## Resetting a Session

To start fresh:

```powershell
# Stop the bridge (Ctrl+C in its terminal), then:
Remove-Item .\audit.log -ErrorAction SilentlyContinue
Remove-Item .\session-report.json -ErrorAction SilentlyContinue

# Restart the bridge
python bridge.py --vexa-bin ..\target\release\agentwall.exe
```

---

## License

Apache-2.0 © NoviqTech — see [LICENSE](../LICENSE) for details.
