# Vexa AgentWall

Vexa AgentWall is a full egress proxy and security gateway for AI agents operating over MCP, HTTP, HTTPS, and WebSocket connections. It provides organizations with a default-deny control plane to intercept, sandbox, audit, and actively block unauthorized agent tool calls and data exfiltration attempts.

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/version-1.0.12-green.svg" alt="Version"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.89%2B-orange.svg" alt="Rust"></a>
</p>

<p align="center">
  <a href="https://vexasec.io/">Website</a> · <a href="https://github.com/noviqtechnologies/agentwall/issues">Issues</a> · <a href="mailto:security@vexasec.io">Security</a>
</p>

---

## The Three-Engine Model

AgentWall v2.0 operates as three distinct, complementary layers:

1. **Local Developer CLI (`agentwall dev`)** — A zero-friction full egress proxy in shadow mode. It intercepts and records all outbound traffic from your agent: MCP JSON-RPC tool calls, direct HTTP/HTTPS fetches, CONNECT tunnels, and WebSocket connections. It surfaces risk patterns in a local dashboard and generates a YAML security policy draft. **No enforcement, no cloud, no signup.**
2. **Centralized Enforcement Gateway** — A team/org deployment that enforces reviewed policies for all production agents. It is operated by the platform or security team—not the developer—ensuring compliance and true security control.
3. **Agent Identity Platform** *(Preview / Phase 2)* — Per-agent credential provisioning, short-lived credential brokering, secret rotation, and audit trails. CLI commands are available as an early preview; vault integrations (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) are in active development.

> **Why separate engines?** A security control operated by the same person it constrains is not a security control. Local enforcement on a developer's machine can be bypassed. The centralized gateway breaks that conflict of interest by acting as a hardened infrastructure bottleneck.

---

## Core Capabilities

AgentWall is built to provide deterministic, tamper-proof control over what agents are allowed to do.

### 🔍 Unparalleled Observation & Routing
* **Unified Egress Proxy:** Intercepts MCP, HTTP CONNECT, WebSocket, and plain HTTP traffic.
* **Ecosystem Integrations:** Automatic discovery and patching for Claude Desktop, Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, and Antigravity.
* **Local Web Dashboard:** Minimal single-page event log with real-time tool call visibility, filter, and CSV/JSON export — all stored locally via SQLite.
* **Auto-Policy Generation:** Automatically drafts robust YAML security policies (`agentwall-policy.yaml`) from observed traffic patterns with self-healing confidence decay.

### 🛡️ Enterprise-Grade Enforcement (v2.0)
* **9-Step Enforcement Pipeline:** Rigorous sequential validation including Identity, Credential Scope, Policy Engine, DLP, Injection, Semantic (Stub), A2A, Response Scan, and Audit Logging.
* **Default-Deny Policy Engine:** Strict tool allowlisting with deep schema validation, bounds checking, and parameter enum enforcement.
* **Process Sandbox:** OS-level containment using Landlock LSM + seccomp + netns on Linux. *(Note: macOS `sandbox-exec` is deprecated by Apple and deferred; Linux covers production deployments.)*
* **Adaptive Enforcement & Baselines:** *(Deferred to Phase 3)* Threat scoring and escalation from warning to blocking.
* **Tool Call Chain Detector:** *(Deferred to Phase 3)* Detection of recursive runaway loops.
* **Emergency Kill Switch:** *(Deferred to Phase 3)* Session termination via SIGUSR1, sentinel file, or remote API.

### 🔐 Hybrid Data Loss Prevention (DLP) & Secret Detection
* **Deterministic DLP:** 21 built-in regex patterns detecting AWS Keys, GitHub Tokens, OpenAI/Anthropic API Keys, Stripe Keys, SSH Private Keys, Azure Storage Keys, GCP API Keys, Slack Tokens, SendGrid Keys, PostgreSQL/MongoDB/Redis URIs, Credit Card Numbers (Luhn validated), UAE Emirates ID, US SSN, and environment variable references.
* **Community Rules:** Extensible YAML configuration for loading custom team or community-curated secret detection patterns on startup.
* **Semantic Scanner (FR-12B) — Stub:** Heuristic anomaly detection stub that scores payloads for semantic exfiltration and instruction manipulation. The full quantized 3B model (Phi-4-Mini) is in active development; the current stub provides a scoring interface without live model inference.
* **Deep Scanning:** Supports Base64 recursive decoding (up to 3 layers deep), Shannon entropy analysis (> 4.5 bits/char, length > 32) for cryptographic material, and BIP-39 validation for crypto seed phrases.
* **Canary Token Subsystem:** *(Deferred to Phase 3)*

### 🛑 Injection & Poisoning Defense
* **Deterministic Injection Detection:** 6-pass normalizer (NFKC, zero-width stripping, Cyrillic homoglyphs, URL decode, Base64 decode, leetspeak, case-fold) and 16-pattern injection scanner that blocks inbound tool responses and external payloads from compromising your agent. *(AgentWall focuses on deterministic pattern matching; the semantic scanner supplements this for sophisticated attacks that patterns miss.)*
* **Risk Flags:** Auto-detects path traversal (`../`), shell injection metacharacters, external URLs, unbounded strings, and destructive operation names.
* **Tool Poisoning Detection:** Detects mid-session `tools/list` response mutations (hash-based).

### 📋 Compliance & Auditing
* **HMAC Audit Logger:** Tamper-evident, offline-verifiable audit logs (`agentwall verify-log`).
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
Requires Rust 1.89+ (tested on Rust 1.89).
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

### 3. Generate a Policy Draft & Self-Healing
Generate a robust policy draft with self-healing behavioral insights. The `--decay-window` flag specifies how long to retain confidence in observed tools (default: 30d).

```bash
agentwall generate-policy --decay-window 30d
# Output: ./agentwall-policy.yaml
```
The generated policy includes confidence decay metadata and anomaly review suggestions.

### 4. Lint & Submit
Validate the policy file before submitting to your security team:
```bash
agentwall lint agentwall-policy.yaml
```
Validate the policy against a deployed gateway instance (file-only local validation is deprecated):
```bash
agentwall test --policy agentwall-policy.yaml --gateway http://localhost:8080 --oidc-token "$TOKEN" ./fixtures.json
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

> [!WARNING]
> **Deprecated:** The `agentwall init` command is deprecated in v6.1 in favor of a GitOps-driven deployment workflow.

```bash
agentwall init sidecar --mcp-upstream http://my-upstream-mcp:3000 > sidecar.yaml
kubectl apply -f sidecar.yaml
```

---

## Centralized Enforcement Gateway (v2.0)

The centralized gateway evaluates policies, enforces DLP, logs audits, and protects your production environment using a robust 9-step enforcement pipeline.

### 9-Step Enforcement Pipeline
| Phase | Action | Description |
|-------|--------|-------------|
| 1 | **Identity Validation** | Validates OIDC JWTs and extracts claims. |
| 2 | **Credential Scope** | Validates identity scopes against policy requirements (FR-5). |
| 3 | **Policy Engine** | Checks tool against default-deny allowlist and JSON schema. |
| 4 | **DLP Scan** | Content-aware scan for secrets and PII (21 built-in patterns + community rules). |
| 5 | **Injection Scan** | Checks payloads against 16 prompt injection signatures via 6-pass normalizer. |
| 6 | **Semantic Anomaly** | (Stub) Heuristic intent scoring — full LLM model in active development. |
| 7 | **A2A Scan** | *(Planned — Phase 2)* Validates inter-agent protocol messages. |
| 8 | **Response Scan** | Analyzes tool output to prevent data exfiltration. |
| 9 | **Audit Log** | Writes a durable, tamper-evident HMAC audit record. |

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
    image: ghcr.io/noviqtechnologies/agentwall:v1.0.12
    volumes:
      - ./policy.yaml:/etc/agentwall/policy.yaml:ro
      - ./audit.log:/var/log/agentwall/audit.log
    command: ["start", "--policy", "/etc/agentwall/policy.yaml", "--listen", "0.0.0.0:8080"]
    ports:
      - "8080:8080"
```

**3. Kubernetes Sidecar (Recommended)**
*(Using GitOps rather than deprecated `agentwall init sidecar`)*
Inject the `agentwall` container alongside your MCP server Pod, bound to localhost.

### Configuration (`agentwall-policy.yaml`)
A typical production policy includes `credential_scope` constraints:
```yaml
version: "2"
default_action: deny

tools:
  - name: execute_query
    action: allow
    credential_scope: ["db:read", "db:write"] # FR-5 v2.0
    parameters:
      - name: query
        type: string
        required: true
```

### Zero-Downtime Policy Hot-Reload
You can dynamically reload `agentwall-policy.yaml` without dropping connections.
- **API Call:** `curl -X POST http://localhost:8080/reload`
- **Signal:** `kill -SIGHUP $(pidof agentwall)`

### Architecture & Security Guarantees
- **Bypass Prevention:** Use OS-level network namespaces (`netns`) and firewall rules to drop outbound packets from the agent that do not route to the gateway.
- **Fail-Closed Supervisor:** Ensure the agent process terminates if AgentWall crashes. Use process groups or a supervisor like `systemd` with `BindsTo=agentwall.service`.

### Acceptance Criteria Checklist (FR-5)
- [x] **AC-5.1:** HTTP 403 JSON-RPC error mapping
- [x] **AC-5.2:** P99 overhead < 5ms
- [x] **AC-5.3:** Concurrency & rate-limiting lock-free structures
- [x] **AC-5.4:** Non-blocking SIEM exporter
- [x] **AC-5.5:** Fail-closed policy parse/hash validation
- [x] **AC-5.6:** Zero-downtime hot-reloads
- [x] **AC-5.7:** Parse v2.0 `ToolRule` schema extensions
- [x] **AC-5.8:** Credential scope validation
- [x] **AC-5.9:** Integration test suite

### Verify the Audit Log
```bash
agentwall verify-log audit.log
agentwall report audit.log --format text
```

---

## Agent Identity & Credential Governance (Preview)

> [!NOTE]
> The Agent Identity Platform (`agentwall identity`) is available as a **CLI preview**. Full vault backend integrations (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) are in active development (Phase 2).

AgentWall v2.0 introduces per-agent credential governance — the system that provisions, scopes, rotates, and audits agent credentials. Agents request short-lived, scoped credentials at runtime instead of holding long-lived secrets in environment variables.

```bash
# Provision a scoped credential for an agent (1-hour TTL)
agentwall identity create --agent my-agent --scope read-only --ttl 1h

# Rotate credentials with zero downtime (old credential valid for 30s drain period)
agentwall identity rotate --agent my-agent

# Audit credential history (HMAC-chained)
agentwall identity audit --agent my-agent --verify

# Set per-tool-call credential scoping
agentwall identity scope --agent my-agent --tool execute_shell --deny

# Inspect a specific credential binding
agentwall identity inspect --credential <credential-id>
```

---

## Policy Reference

Policies are Schema v2 YAML files. `default_action: deny` is required. Object parameters require an inline `schema` block. The policy can also house a `self_healing` configuration directive to govern behavioral learning parameters.

```yaml
version: "2"
default_action: deny

# FR-4 Self-Healing Configuration
self_healing:
  enabled: true
  decay_window: 30d             # Period of time before inactive tools are marked stale
  auto_suggest: true            # Propose schema suggestions for deviations
  suggest_threshold: 0.9        # Anomaly scoring threshold to log to SIEM / Suggestions
  approval_required: true       # Require explicit developer approval in Dashboard

auth:
  provider: okta
  jwks_uri: https://your-org.okta.com/oauth2/default/v1/keys
  audience: agentwall
  issuer: https://your-org.okta.com

# FR-22 Agent Identity Configuration
identity:
  provider: oidc
  issuer: https://your-org.okta.com
  agents:
    - id: my-agent
      description: "Data analysis agent"
      allowed_tools: ["read_file", "execute_query"]
    - id: deploy-agent
      description: "Deployment agent"
      allowed_tools: ["*"]

session:
  max_calls_per_second: 10

tools:
  - name: read_file
    action: allow
    # Self-healing metadata generated dynamically:
    # risk_tier: TIER_3  confidence: high  (145 observations)
    # confidence_decay: 1.00  last_seen: 2026-06-22T12:00:00Z  stale: false
    parameters:
      - name: path
        type: string
        required: true
        max_length: 512
        validators:
          - path_traversal
          - regex: "^/allowed/.*"

# ── Anomalies (review required) ────────────────────────────────────────
# - read_file.path: observed anomalous value "/etc/passwd" (anomaly_score: 0.98)
#   → Is this expected? Review before enabling enforcement.
```

---

## CLI Command Reference

| Command | Description |
|---------|-------------|
| `agentwall dev` | Start full egress proxy in shadow mode. |
| `agentwall start` | Run the enforcement gateway (requires `--policy`). |
| `agentwall generate-policy` | Generate a YAML policy draft from observed traffic. |
| `agentwall lint <policy>` | Validate policy YAML (schema + security warnings). |
| `agentwall test` | Validate policy against a deployed gateway in CI/CD (local file-only mode is deprecated). |
| `agentwall verify-log <log>` | Verify HMAC chain integrity of an audit log. |
| `agentwall report <log>` | Generate a session report from an audit log. |
| `agentwall validate` | Single-payload policy check for authors. |
| `agentwall promote` | Production readiness checks and Ed25519 signing. |
| `agentwall identity create` | Provision a new scoped, short-lived credential for an agent. |
| `agentwall identity rotate` | Rotate active credential with zero-downtime drain period. |
| `agentwall identity inspect` | Display the active credential details and expiration. |
| `agentwall identity audit` | Dump the HMAC-chained identity event log for forensics. |
| `agentwall identity scope` | Set per-tool-call allow/deny scoping for an agent's credential. |
| `agentwall init sidecar` | (Deprecated in v6.1) Generate K8s sidecar proxy manifests. |
| `agentwall wrap <target>` | Patch IDE configs to route via AgentWall. |
| `agentwall unwrap <target>` | Restore IDE configurations to their original state. |

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
| `AGENTWALL_SIEM_ENDPOINT` | `start` | SIEM ingestion endpoint URL |
| `AGENTWALL_SIEM_TOKEN` | `start` | SIEM authentication token |
| `AGENTWALL_SIEM_TIMEOUT` | `start` | SIEM export timeout in seconds (default: 2) |
| `AGENTWALL_INCLUDE_PARAMS` | `start` | `true` to include raw parameters in audit logs |
| `AGENTWALL_SHADOW_MODE` | `start` | `true` to enable shadow mode on `start` |
| `AGENTWALL_DRY_RUN` | `start` | Log violations but forward all calls |
| `AGENTWALL_STRICT_CREDENTIAL_SCOPE` | `start` | `true` to upgrade credential scope mismatches from WARN to DENY (FR-5 v2.0) |
| `AGENTWALL_REPORT_PATH` | `start` | File path to write a session report on shutdown |
| `ALLOW_WILDCARD_IDENTITY` | `start`, `loader` | `true` to allow wildcard identity (`*`) in tool policies |
| `VEXA_GATEWAY_URL` | `test` | Gateway endpoint URL for test command validation |
| `AGENTWALL_OIDC_TOKEN` | `test` | OIDC Bearer token for gateway authentication during test |
| `AGENTWALL_SEMANTIC_SCANNING` | `start` | `true` to enable heuristic semantic anomaly scanning |
| `AGENTWALL_SEMANTIC_THRESHOLD` | `start` | Threshold for semantic anomaly findings (default: 0.85) |

*(Run `agentwall start --help` for the full list of flags).*

---

## Roadmap

| Feature | Status | Phase |
|---------|--------|-------|
| Unified Egress Proxy (MCP, HTTP, WebSocket) | ✅ Built | Phase 1 |
| Shadow Mode & Local Event Store (SQLite) | ✅ Built | Phase 1 |
| Minimal Local Dashboard | ✅ Built | Phase 1 |
| Auto-Policy Generation with Self-Healing | ✅ Built | Phase 1 |
| Deterministic DLP (21 patterns) | ✅ Built | Phase 1 |
| Injection Detection (16 patterns, 6-pass normalizer) | ✅ Built | Phase 1 |
| HMAC Audit Logger + SIEM Export | ✅ Built | Phase 1 |
| Enforcement Gateway (Policy Engine, FR-5) | ✅ Built | Phase 1 |
| OIDC Identity Binding | ✅ Built | Phase 1 |
| Ecosystem Integrations (8 IDEs) | ✅ Built | Phase 1 |
| Agent Identity CLI (Preview) | ✅ Preview | Phase 1 |
| Semantic Scanner (Full 3B Model) | 🔨 In Development | Phase 2 |
| Linux Process Sandbox (Landlock + seccomp) | 🔨 In Development | Phase 2 |
| A2A Protocol Scanner | 🗓 Planned | Phase 2 |
| Full Identity Platform (Vault/AWS SM/Azure KV) | 🗓 Planned | Phase 2 |
| SaaS Dashboard | 🗓 Planned | Phase 2–3 |
| Tool Call Chain Detection | 🗓 Planned | Phase 3 |
| Emergency Kill Switch | 🗓 Planned | Phase 3 |
| Adaptive Enforcement & Behavioral Baseline | 🗓 Planned | Phase 3 |
| Canary Token Subsystem | 🗓 Planned | Phase 3 |
| Compliance-as-Code Engine (NIST, SOC 2, ISO 27001) | 🗓 Planned | Phase 3 |

---

## Security Model

**Enforced Guarantees:**
- Default-deny architecture for unlisted tools.
- Strict parameter schema validation (JSON Schema, URL schemes, regex, path traversal).
- Cryptographic binding of identity (OIDC) to decisions, including mandatory Credential Scopes (FR-5).
- Fail-closed operational posture across network and process levels.

**Current Limitations / Out of Scope:**
- Semantic prompt-injection detection via live LLM is a stub — deterministic string normalizers cover 16 known attack patterns today.
- Remote OS-level process termination (connections are severed, not processes killed).
- Cloud-hosted dashboards (everything is local or BYO-SIEM in Phase 1).
- macOS `sandbox-exec` process isolation (deprecated by Apple; deferred indefinitely).

---

## Contributing

1. Open an issue for significant changes.
2. Fork the repository and create a feature branch.
3. Run `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test`.
4. Submit a PR.

---

## License

Copyright © [NoviqTech](https://vexasec.io). Licensed under the [Apache License 2.0](LICENSE).
