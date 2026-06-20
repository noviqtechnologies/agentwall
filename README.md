# Vexa AgentWall

<p align="center">
  <b>Full egress proxy and security gateway for AI agents — MCP, HTTP, HTTPS, and WebSocket.</b>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/version-1.0.10-green.svg" alt="Version"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.75%2B-orange.svg" alt="Rust"></a>
</p>

<p align="center">
  <a href="https://vexasec.io/">Website</a> · <a href="https://github.com/noviqtechnologies/agentwall/issues">Issues</a> · <a href="mailto:security@vexasec.io">Security</a>
</p>

---

## The Two-Engine Model

AgentWall operates as two distinct tools with a clean separation of concerns:

1. **Local Developer CLI (`agentwall dev`)** — A zero-friction full egress proxy in shadow mode. It intercepts and records all outbound traffic from your agent: MCP JSON-RPC tool calls, direct HTTP/HTTPS fetches, CONNECT tunnels, and WebSocket connections. It surfaces risk patterns in a local dashboard and generates a YAML security policy draft. **No enforcement, no cloud, no signup.**
2. **Centralized Enforcement Gateway** — A team/org deployment that enforces reviewed policies for all production agents. It is operated by the platform or security team—not the developer—ensuring compliance and true security control.

> **Why two separate tools?** A security control operated by the same person it constrains is not a security control. Local enforcement on a developer's machine can be bypassed. The centralized gateway breaks that conflict of interest by acting as a hardened infrastructure bottleneck.

---

## Core Capabilities

AgentWall is built to provide deterministic, tamper-proof control over what agents are allowed to do.

### 🔍 Unparalleled Observation & Routing
* **Unified Egress Proxy:** Intercepts MCP, HTTP CONNECT, WebSocket, and plain HTTP traffic.
* **Ecosystem Integrations:** Automatic discovery and patching for Claude Desktop, Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, and Antigravity.
* **Local Web Dashboard:** Real-time visibility into tool inventories, session timelines, parameter exploration, and risk flags—all stored locally via SQLite.
* **Auto-Policy Generation:** Automatically drafts robust YAML security policies (`agentwall-policy.yaml`) from observed traffic patterns.

### 🛡️ Enterprise-Grade Enforcement
* **Default-Deny Policy Engine:** Strict tool allowlisting with deep schema validation, bounds checking, and parameter enum enforcement.
* **Process Sandbox:** OS-level containment using Landlock LSM + seccomp + netns on Linux and `sandbox-exec` on macOS to force all agent traffic through the proxy.
* **Tool Call Chain Detector:** Analyzes call trajectories to detect and block recursive runaway loops and anomalous behavioral sequences.
* **Adaptive Enforcement & Baselines:** Computes threat scores, escalates from warning to blocking dynamically, and builds behavioral contracts.
* **Emergency Kill Switch:** Immediate session termination via SIGUSR1, sentinel file, or remote API without tearing down the underlying proxy.

### 🔐 Data Loss Prevention (DLP) & Secret Detection
* **Content-Aware DLP:** 62 built-in regex patterns detecting AWS Keys, GitHub Tokens, Stripe Keys, SSH Private Keys, DB URIs, and PII (SSNs, Emirates IDs).
* **Deep Scanning:** Supports Base64 recursive decoding (up to 3 layers deep), Shannon entropy analysis for cryptographic material, and BIP-39 validation for crypto seed phrases.
* **Canary Token Subsystem:** Generates, injects, and detects canary tokens to identify data exfiltration attempts.

### 🛑 Injection & Poisoning Defense
* **Deterministic Injection Detection:** 6-pass normalizer and 29-pattern injection scanner that blocks inbound tool responses and external payloads from compromising your agent. *(Note: AgentWall focuses on deterministic pattern matching, not semantic LLM evaluation).*
* **Risk Flags:** Auto-detects path traversal (`../`), shell injection metacharacters, external URLs, unbounded strings, and destructive operation names.

### 📋 Compliance & Auditing
* **HMAC Audit Logger:** Tamper-evident, offline-verifiable audit logs.
* **SIEM Integration:** Direct export to Splunk, Datadog, OpenSearch, or local files.
* **OIDC Identity Binding:** Validates JWTs to bind agent requests to specific policy profiles.

---

## Installation

### One-Command Install (macOS, Linux, Windows via bash)

```bash
curl -fsSL https://vexasec.io/install.sh | sh
```
Downloads a statically-linked binary to `~/.local/bin/agentwall`. No Docker, no Kubernetes, no runtime dependencies.

### Build from Source
Requires Rust 1.75+.
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
All events appear in `~/.agentwall/events.db` and the local dashboard at `http://127.0.0.1:8080`.

### 3. Generate a Policy Draft
```bash
agentwall generate-policy
# Output: ./agentwall-policy.yaml
```

### 4. Validate & Submit
```bash
agentwall lint agentwall-policy.yaml
```
Commit `agentwall-policy.yaml` and submit it to your security team for deployment.

---

## Full End-to-End Test with Docker Stack

The repo includes a Docker Compose stack with a mock OIDC server (port 8081) and mock MCP server (port 3000) for integration testing.

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

## Ecosystem Integrations (IDEs & Sidecar)

AgentWall can automatically discover and patch your local IDE to route traffic securely through the proxy. Use `--dry-run` to preview changes safely.

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

### Cloud & Kubernetes (Sidecar)
```bash
agentwall init sidecar --mcp-upstream http://my-upstream-mcp:3000 > sidecar.yaml
kubectl apply -f sidecar.yaml
```

---

## Centralized Enforcement Gateway

The centralized gateway evaluates policies, enforces DLP, logs audits, and protects your production environment. 

### Run as a Standalone Binary
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

### Verify the Audit Log
```bash
agentwall verify-log audit.log
agentwall report audit.log --format text
```

---

## Policy Reference

Policies are Schema v2 YAML files. `default_action: deny` is required. Object parameters require an inline `schema` block.

```yaml
version: "2"
default_action: deny

auth:
  provider: okta
  jwks_uri: https://your-org.okta.com/oauth2/default/v1/keys
  audience: agentwall
  issuer: https://your-org.okta.com

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
| `agentwall sandbox` | Execute agent in an OS-level sandbox (`--best-effort`). |
| `agentwall generate-policy` | Generate a YAML policy draft from observed traffic. |
| `agentwall lint <policy>` | Validate policy YAML (schema + security warnings). |
| `agentwall test` | Validate policy against a deployed gateway (CI/CD). |
| `agentwall verify-log <log>` | Verify HMAC chain integrity of an audit log. |
| `agentwall report <log>` | Generate a session report from an audit log. |
| `agentwall validate` | Single-payload policy check for authors. |
| `agentwall promote` | Production readiness checks and Ed25519 signing. |
| `agentwall init sidecar` | Generate K8s sidecar proxy manifests. |
| `agentwall wrap <target>` | Patch IDE configs to route via AgentWall. |

---

## Environment Variables

| Variable | Command | Description |
|----------|---------|-------------|
| `HTTP_PROXY` / `HTTPS_PROXY` | `dev` | Route all traffic through AgentWall (client-side) |
| `AGENTWALL_POLICY_PATH` | `start` | Path to policy YAML |
| `AGENTWALL_LISTEN` | `start`, `dev` | Listen address (default `127.0.0.1:8080`) |
| `AGENTWALL_MCP_URL` | `start`, `dev` | Upstream MCP server URL |
| `AGENTWALL_LOG_PATH` | `start` | Audit log file path |
| `AGENTWALL_OIDC_ISSUER` | `start` | OIDC issuer URL |
| `AGENTWALL_SIEM_BACKEND` | `start` | `splunk`, `datadog`, `opensearch`, or `local` |
| `AGENTWALL_SHADOW_MODE` | `start` | `true` to enable shadow mode on `start` |
| `AGENTWALL_DRY_RUN` | `start` | Log violations but forward all calls |

*(Run `agentwall start --help` for the full list of flags).*

---

## Security Model

**Enforced Guarantees:**
- Default-deny architecture for unlisted tools.
- Strict parameter schema validation (JSON Schema, URL schemes, regex, path traversal).
- Cryptographic binding of identity (OIDC) to decisions.
- Fail-closed operational posture.

**Out of Scope:**
- Semantic prompt-injection detection (we focus on deterministic string normalizers).
- Remote OS-level process termination (we sever connections).
- Cloud-hosted dashboards (everything is local or BYO-SIEM).

---

## Contributing

1. Open an issue for significant changes.
2. Fork the repository and create a feature branch.
3. Run `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test`.
4. Submit a PR.

---

## License

Copyright © [NoviqTech](https://vexasec.io). Licensed under the [Apache License 2.0](LICENSE).
