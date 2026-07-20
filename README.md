# AgentWall

AgentWall is an egress proxy and security gateway for AI agents operating over the Model Context Protocol (MCP), HTTP, HTTPS, and WebSocket connections. It intercepts, audits, and blocks unauthorized agent tool calls based on YAML-defined policies. 

MCP (Model Context Protocol) is an open standard that allows AI models to securely connect to local and remote data sources and tools. AgentWall acts as a firewall specifically designed for these MCP tool calls.

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/version-1.0.14-green.svg" alt="Version"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.89%2B-orange.svg" alt="Rust"></a>
</p>

---

## Deployment Modes

AgentWall consists of three separate components depending on your role:

1. **Local Developer Proxy (`agentwall dev`)** — A proxy in shadow mode meant to run locally on a developer's machine. It intercepts outbound traffic from your agent, surfaces patterns in a local dashboard, and generates a YAML security policy draft based on observed behavior.
2. **Centralized Enforcement Gateway (`agentwall start`)** — A hardened gateway deployment that actively enforces security policies in a production or staging environment.
3. **Agent Identity Platform (`agentwall identity`)** *(Preview)* — A CLI tool for provisioning short-lived, scoped credentials for agents.

---

## Core Capabilities

### Observation & Routing (Local Proxy)
* **Unified Egress Proxy:** Intercepts MCP, HTTP CONNECT, WebSocket, and plain HTTP traffic.
* **Ecosystem Integrations:** Modifies configuration for Claude Desktop, Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, and Antigravity to route through AgentWall.
* **Local Web Dashboard:** Single-page event log stored locally via SQLite.
* **Auto-Policy Generation:** Drafts YAML security policies (`agentwall-policy.yaml`) from observed traffic patterns.

### Enforcement (Centralized Gateway)
* **Enforcement Pipeline:** Sequential validation including Identity, Credential Scope, Policy Engine, DLP, Injection, Response Scan, and Audit Logging.
* **Policy Engine:** Strict tool allowlisting with schema validation and bounds checking.
* **Zero-Downtime Policy Hot-Reload:** Dynamically reload `agentwall-policy.yaml` via API or `SIGHUP` without dropping connections.
* **Fail-Closed Mode:** A global panic hook that immediately aborts all active connections if any task fails.
* **TLS Support:** Built-in TLS listener using `rustls` for secure deployments.

### Data Loss Prevention (DLP)
* **DLP Scanner:** 21 regex patterns detecting AWS Keys, GitHub Tokens, API Keys, Stripe Keys, SSH Private Keys, Azure Storage Keys, GCP API Keys, Slack Tokens, SendGrid Keys, PostgreSQL/MongoDB/Redis URIs, Credit Card Numbers, UAE Emirates ID, US SSN, and environment variable references.
* **Community Rules:** Extensible YAML configuration for loading custom regex rules on startup.

### Injection Defense
* **Injection Detection:** 6-pass normalizer and 16-pattern injection scanner that blocks inbound tool responses and external payloads.
* **Safe Mode Rules:** 15 high-signal rules detecting sensitive file access (SSH keys, .env, Kubeconfig, Docker socket), exfiltration pipes, Netcat listeners, destructive operations (`rm -rf /`), and cloud metadata SSRF.

### Compliance & Auditing
* **HMAC Audit Logger:** Chained, append-only audit logs.
* **SIEM Integration:** Direct export to Splunk, Datadog, OpenSearch, or local files.
* **OIDC Identity Binding:** Validates JWTs to bind agent requests to specific policy profiles.

### Agent Identity & Credential Governance
* **Credential Provisioning:** Provision short-lived, scoped credentials for agents to prevent long-lived secret sprawl.

### SaaS Dashboard — Fleet Visibility
* **Fleet Dashboard:** Optional, self-hosted web dashboard for fleet-wide visibility into agent activity and DLP alerts.

### Cloud Native
* **Kubernetes Operator:** Helm chart included with a Kubernetes operator that automatically generates egress-deny `NetworkPolicy` rules.

---

## Prerequisites & Installation

### System Requirements
* **Operating System:** Linux is strongly recommended for production enforcement (required for netns isolation). macOS and Windows are supported for local development.
* **Rust:** Version 1.89+ (if building from source).
* **Dependencies:** `pkg-config` and `libssl-dev` (Linux) or equivalent.

### One-Command Install

```bash
curl -fsSL https://vexasec.io/install.sh | sh
```
Downloads a statically-linked binary to `~/.local/bin/agentwall`.

### Build from Source
```bash
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall
cargo build --release
# Binary at: ./target/release/agentwall
```

---

## Quick Start — Local Development

### 1. Start the Shadow Proxy
**HTTP MCP Agent:**
```bash
agentwall dev
```
**Stdio MCP Agent (Claude Desktop, Cursor):**
```bash
agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

### 2. Route Agent Traffic
Set standard proxy variables so your agent routes traffic through AgentWall:
```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export AGENTWALL_PROXY_URL=http://localhost:8080
python my_agent.py
```

### 3. Generate a Policy Draft
Generate a policy draft based on observed local traffic.
```bash
agentwall generate-policy --decay-window 30d
```

### 4. Lint & Submit
Validate the policy file:
```bash
agentwall lint agentwall-policy.yaml
```

Validate the policy against a deployed gateway instance:
```bash
agentwall test --policy agentwall-policy.yaml --gateway http://localhost:8080 --oidc-token "$TOKEN" ./fixtures.json
```

---

## Full End-to-End Test with Docker Stack

The repo includes a Docker Compose stack with a mock OIDC server (port 8081) and mock MCP server (port 3000).

```bash
# Start the full stack
docker compose up -d --build

# In a separate terminal, start the shadow proxy
agentwall dev

# Obtain a development JWT from the mock OIDC server
TOKEN=$(curl -fsS "http://localhost:8081/token?sub=dev&aud=agentwall" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

# Send an allowed tool call
curl -fsS -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{"example":"hello"}}}'

# Shut down
docker compose down -v
```

---

## Ecosystem Integrations (IDEs)

AgentWall can modify your local IDE configuration to route traffic through the proxy.

| Target IDE | Wrap Command | Unwrap Command |
|---|---|---|
| **Claude Desktop** | `agentwall wrap claude` | `agentwall unwrap claude` |
| **Cursor** | `agentwall wrap cursor` | `agentwall unwrap cursor` |
| **VS Code** | `agentwall wrap vscode` | `agentwall unwrap vscode` |
| **JetBrains** | `agentwall wrap jetbrains` | `agentwall unwrap jetbrains` |
| **Zed Editor** | `agentwall wrap zed` | `agentwall unwrap zed` |
| **Cline** | `agentwall wrap cline` | `agentwall unwrap cline` |
| **OpenCode** | `agentwall wrap opencode` | `agentwall unwrap opencode` |
| **Antigravity** | `agentwall wrap antigravity` | `agentwall unwrap antigravity` |

---

## Centralized Enforcement Gateway

### Deployment Options

**1. Standalone Binary**
```bash
./agentwall start \
  --policy policy.yaml \
  --listen 0.0.0.0:8080 \
  --log-path audit.log \
  --oidc-issuer https://your-idp.example.com \
  --siem-backend splunk \
  --siem-endpoint https://splunk.example.com:8088/services/collector/event \
  --siem-token "$SPLUNK_HEC_TOKEN"
```

**2. Docker Compose**
```yaml
services:
  agentwall:
    image: ghcr.io/noviqtechnologies/agentwall:v1.0.14
    volumes:
      - ./policy.yaml:/etc/agentwall/policy.yaml:ro
      - ./audit.log:/var/log/agentwall/audit.log
    command: ["start", "--policy", "/etc/agentwall/policy.yaml", "--listen", "0.0.0.0:8080"]
    ports:
      - "8080:8080"
```

**3. With TLS**
```bash
./agentwall start \
  --policy policy.yaml \
  --listen 0.0.0.0:8443 \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem
```

**4. Helm Chart**
```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=my-gateway-tls
```

### Zero-Downtime Policy Hot-Reload
You can dynamically reload `agentwall-policy.yaml`.
- **API Call:** `curl -X POST http://localhost:8080/reload`
- **Signal (Linux):** `kill -SIGHUP $(pidof agentwall)`

### Architecture & Security Guarantees
- **Bypass Prevention (Requires Operator Configuration):** AgentWall relies on external networking controls to prevent bypass. Operators **must** configure OS-level network namespaces (`netns`) and firewall rules (`iptables` / `nftables`) to drop outbound packets from the agent that do not route to the gateway.
- **Fail-Closed Mode:** The gateway installs a global panic hook — if any task panics, active connections are aborted via `JoinSet::abort_all()`.
- **TLS Listener:** Uses `rustls`.
- **K8s NetworkPolicy:** The operator generates an egress-deny `NetworkPolicy` when `spec.networkPolicy.enforced: true` is set.

---

## Agent Identity & Credential Governance

AgentWall introduces per-agent credential governance. Agents request short-lived, scoped credentials at runtime instead of holding long-lived secrets.

```bash
# Provision a scoped credential for an agent (1-hour TTL)
agentwall identity create --agent my-agent --scope read-only --ttl 1h

# Rotate credentials
agentwall identity rotate --agent my-agent

# Audit credential history
agentwall identity audit --agent my-agent --verify

# Set per-tool-call credential scoping
agentwall identity scope --agent my-agent --tool execute_shell --deny

# Inspect a specific credential binding
agentwall identity inspect --credential <credential-id>
```

---

## SaaS Dashboard — Fleet Visibility

AgentWall includes an optional, self-hosted dashboard for fleet-wide visibility into agent activity.

**Components:**
| Component | Language | Purpose |
|-----------|----------|---------|
| `dashboard/proto` | Rust | Wire types shared between gateway and dashboard-api. |
| `dashboard/api` | Go | Backend API — ingests redacted events from the gateway. |
| `dashboard/frontend` | React/TS | Single-page app. |
| `src/dashboard` | Rust | Gateway-side integration. |

**Deployment:**
```bash
# Helm
helm install agentwall ./chart \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true \
  --set dashboardApi.oidc.issuer=https://your-idp.example.com \
  --set dashboardApi.oidc.clientId=agentwall-dashboard

# Local dev (Docker Compose)
cd dashboard && docker compose up -d --build
```

---

## Policy Reference

Policies are Schema v2 YAML files. `default_action: deny` is required. Object parameters require an inline `schema` block.

```yaml
version: "2"
default_action: deny

self_healing:
  enabled: true
  decay_window: 30d
  auto_suggest: true
  suggest_threshold: 0.9
  approval_required: true

auth:
  provider: okta
  jwks_uri: https://your-org.okta.com/oauth2/default/v1/keys
  audience: agentwall
  issuer: https://your-org.okta.com

identity:
  provider: oidc
  issuer: https://your-org.okta.com
  agents:
    - id: my-agent
      description: "Data analysis agent"
      allowed_tools: ["read_file", "execute_query"]

session:
  max_calls_per_second: 10

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        max_length: 512
        validators:
          - path_traversal
          - regex: "^/allowed/.*"
```

---

## CLI Command Reference

| Command | Description |
|---------|-------------|
| `agentwall dev` | Start full egress proxy in shadow mode. |
| `agentwall start` | Run the enforcement gateway (requires `--policy`). |
| `agentwall generate-policy` | Generate a YAML policy draft from observed traffic. |
| `agentwall lint <policy>` | Validate policy YAML (schema + security warnings). |
| `agentwall test` | Validate policy against a deployed gateway in CI/CD. |
| `agentwall verify-log <log>` | Verify HMAC chain integrity of an audit log. |
| `agentwall report <log>` | Generate a session report from an audit log. |
| `agentwall validate` | Single-payload policy check for authors. |
| `agentwall promote` | Production readiness checks and Ed25519 signing. |
| `agentwall identity create` | Provision a new scoped, short-lived credential for an agent. |
| `agentwall identity rotate` | Rotate active credential. |
| `agentwall identity inspect` | Display the active credential details and expiration. |
| `agentwall identity audit` | Dump the HMAC-chained identity event log. |
| `agentwall identity scope` | Set per-tool-call allow/deny scoping. |
| `agentwall wrap <target>` | Patch IDE configs to route via AgentWall. |
| `agentwall unwrap <target>` | Restore IDE configurations to their original state. |

---

## Environment Variables

| Variable | Command | Description |
|----------|---------|-------------|
| `HTTP_PROXY` / `HTTPS_PROXY` | `dev` | Route all traffic through AgentWall |
| `AGENTWALL_POLICY_PATH` | `start` | Path to policy YAML |
| `AGENTWALL_LISTEN` | `start`, `dev` | Listen address (default `127.0.0.1:8080`) |
| `AGENTWALL_MCP_URL` | `start`, `dev` | Upstream MCP server URL |
| `AGENTWALL_LOG_PATH` | `start` | Audit log file path |
| `AGENTWALL_OIDC_ISSUER` | `start` | OIDC issuer URL |
| `AGENTWALL_SIEM_BACKEND` | `start` | `splunk`, `datadog`, `opensearch`, or `local` |
| `AGENTWALL_SIEM_ENDPOINT` | `start` | SIEM ingestion endpoint URL |
| `AGENTWALL_SIEM_TOKEN` | `start` | SIEM authentication token |
| `AGENTWALL_SIEM_TIMEOUT` | `start` | SIEM export timeout in seconds (default: 2) |
| `AGENTWALL_INCLUDE_PARAMS` | `start` | `true` to include raw parameters in audit logs |
| `AGENTWALL_SHADOW_MODE` | `start` | `true` to enable shadow mode on `start` |
| `AGENTWALL_DRY_RUN` | `start` | Log violations but forward all calls |
| `AGENTWALL_STRICT_CREDENTIAL_SCOPE` | `start` | `true` to upgrade credential scope mismatches from WARN to DENY |
| `AGENTWALL_REPORT_PATH` | `start` | File path to write a session report on shutdown |
| `ALLOW_WILDCARD_IDENTITY` | `start`, `loader` | `true` to allow wildcard identity (`*`) in tool policies |
| `VEXA_GATEWAY_URL` | `test` | Gateway endpoint URL for test command validation |
| `AGENTWALL_OIDC_TOKEN` | `test` | OIDC Bearer token for gateway authentication during test |
| `AGENTWALL_TLS_CERT` | `start` | Path to TLS certificate PEM file for HTTPS listener |
| `AGENTWALL_TLS_KEY` | `start` | Path to TLS private key PEM file for HTTPS listener |

---

## Current Limitations / Known Issues

* **Semantic scanner has no embedded model:** The current implementation is a heuristic stub. Live semantic inference is not implemented.
* **`agentwall test` without `--gateway` is deprecated:** File-only fixture validation does not exercise DLP or OIDC validation code paths.
* **`type: object` parameters require schemas:** Without an inline `schema:` block, these cause a fatal startup error.
* **`pause_interactive` falls back to `block`:** In non-TTY environments, this cycle-detection action behaves as `block`.
* **Audit log rotation truncates without archiving:** When the log file exceeds `--log-max-bytes`, the previous file is not archived or compressed.
* **Separate build for dashboard:** The `dashboard/` directory is not compiled by `cargo build`.
* **SIEM export failures are not retried:** Failed exports are discarded.

---

## Troubleshooting

* **Traffic is bypassing the proxy locally:** Ensure the IDE or agent process properly honors `HTTP_PROXY` and `HTTPS_PROXY` variables. For complex routing, use the `agentwall wrap` command to rewrite configuration files natively.
* **Gateway crashes on startup:** Double-check your YAML policy for invalid syntax, specifically missing `schema` definitions on `object` and `array` properties, which cause fatal errors.
* **Network namespace isolation failing:** AgentWall does not automatically configure your `iptables`/firewall. Ensure your iptables rules explicitly drop packets that bypass the proxy container's IP/port.

---

## Contributing

1. Open an issue for significant changes.
2. Fork the repository and create a feature branch.
3. Run `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test`.
4. Submit a PR.

---

## License

Copyright © [NoviqTech](https://vexasec.io). Licensed under the [Apache License 2.0](LICENSE).
