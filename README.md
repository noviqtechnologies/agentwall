# VEXA AgentWall

> **Local-first sidecar proxy enforcing deterministic security policies for autonomous AI agents over MCP.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.5-brightgreen.svg)]()
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)]()

VEXA AgentWall sits between an AI agent runtime and its MCP (Model Context Protocol) tool servers. It intercepts every JSON-RPC tool call, evaluates it against a YAML-defined policy, and either allows or denies the call — while writing a cryptographically chained, tamper-evident audit log of every decision.

---

## Table of Contents

- [Why AgentWall?](#why-agentwall)
- [Key Benefits](#key-benefits)
- [Official Landing Page](#official-landing-page)
- [Architecture & Enforcement Flow](#architecture--enforcement-flow)
- [Demo UI](#demo-ui)
- [Quickstart](#quickstart)
- [Policy Reference](#policy-reference)
- [CLI Reference](#cli-reference)
- [Key Features](#key-features)
- [Security & Limitations](#security--limitations)
- [Building from Source](#building-from-source)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)

---

## Why AgentWall?

Autonomous AI agents can call tools with real-world consequences — writing files, executing shell commands, making network requests. Without an enforcement layer, a hallucinated tool call or a compromised agent can cause irreversible damage.

AgentWall provides a **zero-trust enforcement boundary** with zero changes required to your agent code.

---

## Key Benefits

| Benefit | Description |
|---|---|
| 🛡️ **Zero-Trust by Default** | Explicit allow-list policy. Everything not permitted is denied. |
| 🔐 **Cryptographic Auditability** | Every decision is HMAC-SHA256 chained — tamper-evident and compliance-ready. |
| 🔌 **Agent-Agnostic** | Works as a transparent sidecar; no agent code changes required. |
| ⚡ **Ultra-Lightweight** | Single Rust binary, zero external runtime dependencies, <10ms latency overhead. |
| 🔄 **Operational Resilience** | Token-bucket rate limiting prevents runaway loops and API flooding. |
| 🧪 **Frictionless Development** | Dry-run mode and a pre-flight `check` tool let you iterate safely. |

---

## Key Features

| Feature | Description |
|---|---|
| **Nested Validation** | Full JSON Schema validation for nested parameters with depth limiting. |
| **Identity Binding** | OIDC-bound JWT validation for tool calls with background JWK rotation. |
| **Promotion Suite** | `agentwall promote` for production readiness checks and cryptographic signing. |
| **Durable Audit** | Every decision is HMAC-SHA256 chained — tamper-evident and compliance-ready. |
| **Rate Limiting** | Token-bucket rate limiting per session and per tool. |
| **Dry-Run Mode** | Policy enforcement simulation for safe development and onboarding. |
| **Policy Generation** | `agentwall init` scaffolds a policy from observed tool calls. |
| **Zero-Dependency UI** | A local dashboard for real-time monitoring and policy testing. |
| **Bidirectional MCP Interception** | HTTP proxy + stdio wrap for full‑duplex tool calls (FR‑302). |
| **Safe Mode** | Sensible out-of-the-box protection against high-risk paths and exfiltration (FR-303a). |

---

## Official Landing Page

For more information, product tours, and demo requests, visit:
[https://vexasec.io/agentwall.html](https://vexasec.io/agentwall.html)

---

## Architecture & Enforcement Flow

```
┌─────────────────────────────────────────────────────────┐
│                     AI Agent Runtime                    │
│            (any framework: LangChain, AutoGPT, …)       │
└──────────────────────┬──────────────────────────────────┘
                       │  JSON-RPC over HTTP or Stdio (Wrap mode)
                       ▼
┌─────────────────────────────────────────────────────────┐
│               VEXA AgentWall Proxy                      │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Policy Eval │  │  Safe Mode   │  │  Audit Logger │  │
│  │  (YAML)     │  │ (Global Reg) │  │(HMAC-SHA256)  │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │  Allowed calls forwarded
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  MCP Tool Servers                       │
│        (filesystem, shell, search, database, …)         │
└─────────────────────────────────────────────────────────┘
```

### Transport Modes
AgentWall supports two distinct interception modes:
1. **HTTP Proxy Mode** (`agentwall start`): Intercepts MCP calls over HTTP.
2. **Stdio Wrap Mode** (`agentwall wrap`): Wraps the agent executable, intercepting its standard input/output streams directly. This is ideal for CLI agents that don't support configuring a proxy URL.


### Key Design Decisions
- **Deny-by-default** — only explicitly permitted tools/parameters pass through.
- **Safe Mode Protection** — out-of-the-box global rules blocking high-risk paths, exfiltration, and SSRF attempts even with no policy file.
- **Regex-anchored patterns** — all string parameters are validated against anchored regex (`^(?:...)$`) to prevent partial-match bypasses.
- **Chained audit log** — each entry's HMAC includes the previous entry's hash, forming a tamper-evident chain.
- **Kill modes** — on violation, the proxy can close the connection, SIGKILL the agent process, or both.

### Operational Flow (Step-by-Step)

VEXA AgentWall acts as a mandatory enforcement layer between your AI agent and its tools.

```text
    AI AGENT             VEXA AGENTWALL             TOOL SERVER
       │                        │                        │
       │  (1) Tool Call Request │                        │
       ├───────────────────────>│                        │
       │  (HTTP or Stdio)       │                        │
       │                        │                        │
       │                        │──┐ [Evaluation Phase]  │
       │                        │  │ Identity Check      │
       │                        │  │ Rate Limiting       │
       │                        │  │ Global Safe Mode    │
       │                        │  │ Param Validation    │
       │                        │<─┘                     │
       │                        │                        │
       │                        │──┐ [Durable Logging]   │
       │                        │  │ Chained HMAC        │
       │                        │  │ fsync to Disk       │
       │                        │<─┘                     │
       │                        │                        │
       │       [IF ALLOWED]     │                        │
       │                        │ (2) Forward Call       │
       │                        ├───────────────────────>│
       │                        │                        │
       │                        │ (3) Return Result      │
       │                        │<───────────────────────┤
       │     (4) Tool Result    │                        │
       │<───────────────────────┤                        │
       │                        │                        │
       │       [IF DENIED]      │                        │
       │                        │                        │
       │  (2) Policy Error      │                        │
       │<───────────────────────┤                        │
       │                        │──┐ [Enforcement]       │
       │                        │  │ Trigger --kill-mode │
       │                        │<─┘                     │
       │                        │                        │
```


1. **Deployment & Interception**:
   - **HTTP Mode**: You set `AGENTWALL_PROXY_URL` (e.g., `http://127.0.0.1:8080`). The AI agent's MCP SDK redirects JSON-RPC traffic to the proxy listener.
   - **Stdio Mode**: You launch your agent via `agentwall wrap --command "agent-exec"`. The proxy spawns the agent as a child process and intercepts its standard input/output streams.
2. **Evaluation**: For every intercepted tool call, the policy engine evaluates the request against `policy.yaml`. This includes **Identity Binding** (JWT check), **Rate Limiting**, and **Nested Parameter Validation** (JSON Schema).
3. **Durable Logging**: The decision (`allow` or `deny`) is written to the audit log. The entry is cryptographically chained (HMAC-SHA256) and **immediately flushed to disk** (`fsync`) before any action is taken.
4. **Enforcement**:
   - **On Success**: The call is forwarded to the upstream MCP server.
   - **On Violation**: The call is blocked. The proxy returns a JSON-RPC error to the agent and, depending on the configured `--kill-mode`, may immediately terminate the agent process to prevent further unauthorized attempts.

> [!IMPORTANT]
> **Why the agent has no choice but to use the proxy:**
> 1. **SDK-Level Resolution:** Most MCP SDKs resolve the server URL from `AGENTWALL_PROXY_URL` at import time.
> 2. **Stdio Pipe Ownership:** In `wrap` mode, the proxy owns the agent's input/output pipes; the agent has no direct way to communicate with tools except through these supervised channels.
> 3. **Network Egress Control:** Direct MCP access should be blocked at the OS or network level (e.g., `iptables` or K8s `NetworkPolicy`). Even if an agent tries to ignore environment variables, it cannot reach the MCP server any other way.

---

## Demo UI

AgentWall ships with a **local-first demo dashboard** for exploring its features interactively without writing any code.

The demo UI is a zero-dependency single-page app (no npm, no build step) backed by a lightweight Python bridge server that relays commands to the `agentwall` binary.

```
demo-ui/
├── index.html      # Single-page dashboard (open directly in browser)
├── bridge.py       # Python bridge server (Flask) — relays API calls to the binary
├── policy.example.yaml # Default demo policy template
└── README.md       # Demo-specific setup guide
```

### Demo UI Features

| Panel | Key | What It Does |
|---|---|---|
| **Policy Editor** | `01` | Live YAML editor with one-click pre-flight validation against built-in sample calls |
| **Monitor & Auth** | `02` | Start/stop the proxy, watch real-time log stream via SSE, and simulate identity-bound calls |
| **Policy Promotion** | `03` | Verify policy integrity, risk scores, and cryptographic signatures for production readiness |
| **Audit History** | `04` | Browse all log entries with stats (total / allowed / denied / p95 latency) |
| **Session Report** | `05` | Generate and view a session analytics report with blocked incidents and tool usage |

### Quick Launch (macOS/Linux)

```bash
# 1. Install Python dependencies (one-time)
pip install flask flask-cors

# 2. Start the bridge server (from demo-ui folder)
cd demo-ui
python3 bridge.py --vexa-bin ../agentwall

# 3. Open the UI — open index.html in your browser
#    (e.g. 'open index.html' on macOS)
```

### Quick Launch (Windows)

```powershell
# 1. Install Python dependencies (one-time)
pip install flask flask-cors

# 2. Start the bridge server (from demo-ui folder)
cd demo-ui
python bridge.py --vexa-bin ..\agentwall.exe

# 3. Open the UI — just double-click index.html in File Explorer
#    or navigate to it in your browser
```

> See [`demo-ui/README.md`](demo-ui/README.md) for the full setup guide including all bridge server options.

---

## Quickstart

The recommended path starts locally in dry-run mode — no CI/CD, no DevOps, no pipeline changes. 

### Prerequisites

- **Rust Toolchain**: `cargo` and `rustc` (v1.75+). Install from [rustup.rs](https://rustup.rs/).
- **Python 3.8+**: Required for running the included simulation scripts and the Demo UI bridge.
- **Git**: To clone and manage the repository.

**Step 1 — Clone the repository**

```bash
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall
```

**Step 2 — Build the binary**

Before you start, build the project and move the binary to the root for easier access:

*macOS/Linux (Bash):*
```bash
cargo build --release
cp target/release/agentwall .
```

*Windows (PowerShell):*
```powershell
cargo build
copy target\debug\agentwall.exe .
```

**Step 3 — Start in dry-run mode without a policy**

Open a terminal and start the proxy.

*Bash:*
```bash
./agentwall start --dry-run --listen 127.0.0.1:8080 --log-path audit.log &
# Wait for proxy
until curl -sf http://127.0.0.1:8080/healthz; do sleep 0.1; done
```

*PowerShell:*
```powershell
Start-Process -FilePath ".\agentwall.exe" -ArgumentList "start", "--dry-run", "--listen", "127.0.0.1:8080", "--log-path", "audit.log"
```

**Step 4 — Point your agent at the proxy (or simulate a call)**

To test the proxy immediately, you can use the provided quickstart agent script.

*Bash:*
```bash
# Set environment variable
export AGENTWALL_PROXY_URL=http://127.0.0.1:8080

# Simulate a tool call
curl -X POST http://127.0.0.1:8080 -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "test.txt"}}, "id": 1}'
```

*PowerShell (Windows):*
```powershell
# Set the environment variable for your session
$env:AGENTWALL_PROXY_URL="http://127.0.0.1:8080"

# Run the simulated agent
python quickstart_agent.py
```

Once you are ready, you can run the provided quickstart agent:
`python quickstart_agent.py`

**Step 5 — See what your agent actually did**
```bash
# macOS/Linux (Bash):
./agentwall report audit.log --format text

# Windows (PowerShell):
.\agentwall.exe report audit.log --format text
```

**Step 6 — Generate a starter policy**
```bash
# macOS/Linux (Bash):
./agentwall init --from-log audit.log

# Windows (PowerShell):
.\agentwall.exe init --from-log audit.log
```

**Step 7 — Tune the generated policy and re-run with enforcement**

Edit `policy.yaml` — tighten regexes, remove tools your agent shouldn't need. Then pre-flight validate using the security test suite:

```bash
# macOS/Linux:
./agentwall test --policy policy.yaml audit.log
```

```powershell
# Windows:
.\agentwall.exe test --policy policy.yaml audit.log
```

Finally, run with enforcement enabled (no `--dry-run`):

*macOS/Linux (Bash):*
```bash
# Adding & at the end runs it in the background
./agentwall start --policy policy.yaml --listen 127.0.0.1:8080 --log-path audit.log --kill-mode both &
```

*Windows (PowerShell):*
```powershell
# Start-Process ensures the proxy runs in a separate window so it doesn't block your terminal
Start-Process -FilePath ".\agentwall.exe" -ArgumentList "start", "--policy", "policy.yaml", "--listen", "127.0.0.1:8080", "--log-path", "audit.log", "--kill-mode", "both"
```

**Step 8 — Verify the log**

*Note: If you didn't run the proxy in the background in the previous step, you must open a **new terminal window** to run this command.*

```bash
# macOS/Linux (Bash):
./agentwall verify-log audit.log

# Windows (PowerShell):
.\agentwall.exe verify-log audit.log
```

### Path B — CI/CD Integration (Graduation Path)

Once you have a working local policy and at least one session report, you can deploy the proxy to your CI/CD pipeline or cluster, enforcing the same `policy.yaml`.

---

## Policy Reference

A policy file is a YAML document with the following structure:

```yaml
version: "2"                    # Schema version (FR-201/202 support)
default_action: deny            # "allow" or "deny" for unconfigured tools

identity:                       # FR-202: Identity Binding
  issuer: "https://auth.com"    # OIDC issuer URL
  audience: "agentwall-proxy"   # Expected audience in JWT

session:
  max_calls_per_second: 10      # Optional: rate limit across all tools

tools:
  - name: "query_database"      # FR-201: Nested Validation Engine
    action: allow
    risk: high                  # Required for FR-204 promotion
    parameters:
      - name: "options"
        type: object
        schema:                 # Recursive JSON Schema validation
          type: object
          properties:
            query: { type: string, pattern: "^SELECT.*" }
            limit: { type: integer, maximum: 100 }
          required: ["query"]
```

### Pattern Auto-Anchoring

All regex patterns are automatically wrapped in `^(?:...)$` to prevent partial-match bypasses. For example:

```yaml
pattern: "/workspace/.*"
# Becomes: ^(?:/workspace/.*)$
```

> **⚠ Footgun Warning:** If you use alternation like `foo|bar/.*`, the non-capturing group ensures it evaluates as `^(?:foo|bar/.*)$`, not `(^foo)|(bar/.*$)`. Do not disable anchoring in production.

---

## CLI Reference

```
agentwall <SUBCOMMAND>

SUBCOMMANDS:
  start        Start the proxy server (HTTP mode)
  wrap         Wrap an agent executable, intercepting its stdio (Stdio mode)
  test         Execute security unit tests against a fixture file (FR-204)
  promote      Validate and sign a policy for production (FR-204)
  verify-log   Verify cryptographic integrity of an audit log
  report       Generate a session analytics report from an audit log
  init         Generate a starter policy from a dry-run audit log

OPTIONS FOR 'start':
  --policy <PATH>          Path to policy YAML file
  --listen <ADDR>          Listen address (default: 127.0.0.1:8080)
  --mcp-url <URL>          Upstream MCP server URL (default: http://127.0.0.1:3000)
  --log-path <PATH>        Path for the audit log file
  --kill-mode <MODE>       Action on policy violation: connection | process | both (default: connection)
  --dry-run                Log violations but do not enforce them
  --oidc-issuer <URL>      Override OIDC issuer for identity binding (FR-202)
  --report-path <PATH>     Path to write the session report JSON on shutdown

OPTIONS FOR 'wrap':
  --command <CMD>          The full command to execute and wrap (e.g., 'python agent.py')
  --policy <PATH>          Path to policy YAML file
  --log-path <PATH>        Path for the audit log file
  --kill-mode <MODE>       Action on policy violation: connection | process | both (default: connection)

OPTIONS FOR 'test':
  --policy <PATH>          Policy YAML file to validate against
  <FIXTURE>                JSON file containing an array of tool calls to test

OPTIONS FOR 'promote':
  --policy <PATH>          Policy YAML file to promote
  --key <PATH>             Path to Ed25519 private key (optional: generates temp key if absent)

OPTIONS FOR 'report':
  <LOG_PATH>               Path to audit log file
  --format <FORMAT>        Output format: json | text (default: json)
  --report-include-params  Include raw parameters in the report (WARNING: sensitive data)

OPTIONS FOR 'init':
  --from-log <PATH>        Audit log to derive policy from
  --output <PATH>          Output policy file path (default: policy.yaml)
```


---

## Security & Limitations

### What AgentWall Cannot Prevent

1. **Direct Bypass**: The proxy cannot stop an agent from calling MCP servers directly if the network allows it. You **must** block direct MCP egress at the OS/container level (e.g., Kubernetes `NetworkPolicy`, `iptables`) and force all traffic through the proxy.

2. **SIGKILL Rollback**: When a violation triggers a kill, the proxy terminates the connection and/or process. It **cannot** roll back side effects already committed by the MCP server before termination.

### `--kill-mode` Reference

| Mode | Behaviour | When to Use |
|---|---|---|
| `connection` | Closes the TCP socket immediately | Default — K8s without `shareProcessNamespace` |
| `process` | Sends `SIGKILL` to the agent's PID | Single-host deployments |
| `both` | Closes socket **and** sends `SIGKILL`; falls back to connection-only if kill fails | Maximum enforcement |

> **Kubernetes Note:** PID namespaces are not shared by default. Set `shareProcessNamespace: true` in your pod spec if you want `process` or `both` kill mode to work.

### Dry-Run Security Implications

Starting the proxy with `--dry-run` (or `VEXA_DRY_RUN=true`) logs violations as `DRY_RUN_DENY` but **forwards the call to the MCP server anyway**. The agent is never killed.

> **⚠ WARNING:** Dry-run disables enforcement. It is for policy development only. A `dry_run_active` security event is logged at startup, and the final session report will explicitly mark `"dry_run": true`. **Never use in production.**

---

## Building from Source

**Prerequisites:** Rust toolchain 1.75+

```bash
# Debug build (faster compilation, larger binary)
cargo build

# Release build (optimized, recommended for benchmarking)
cargo build --release

# Run the test suite
cargo test

# Run benchmarks
cargo bench
```

The compiled binary is `agentwall` (or `agentwall.exe` on Windows).

---

## Contributing

We welcome contributions! Whether it's reporting a bug, improving documentation, or submitting a Pull Request, please check our [GitHub Issues](https://github.com/noviqtechnologies/agentwall/issues) to get started.

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m 'Add some amazing feature'`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Open a Pull Request.

## Support

- **Documentation**: coming soon
- **Email Support**: [support@vexasec.io](mailto:support@vexasec.io)
- **Issues**: [GitHub Issues](https://github.com/noviqtechnologies/agentwall/issues)

## Security Policy

If you discover a security vulnerability within VEXA AgentWall, please send an e-mail to [security@vexasec.io](mailto:support@vexasec.io). All security vulnerabilities will be promptly addressed.

---

## License

Apache-2.0 © NoviqTech — see [LICENSE](LICENSE) for details.
