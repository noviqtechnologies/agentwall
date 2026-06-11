# Vexa AgentWall

**Enterprise security gateway for AI agent tool calls over MCP.**

Vexa AgentWall is a self-hosted, **centrally deployed** enforcement layer for the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). Every JSON-RPC tool call is authenticated with OIDC, evaluated against a version-controlled allowlist policy, and recorded in a tamper-evident audit trail with real-time export to your SIEM.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.6-green.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

[Website](https://vexasec.io/agentwall.html) · [Report an issue](https://github.com/noviqtechnologies/agentwall/issues) · [Security](mailto:security@vexasec.io)

---

## Table of contents

- [Why AgentWall](#why-agentwall)
- [Features](#features)
- [Architecture](#architecture)
- [Shadow Mode](#shadow-mode-fr-2)
- [Quick start](#quick-start)
- [Deployment](#deployment)
- [Policy management](#policy-management)
- [Command-line interface](#command-line-interface)
- [Operations](#operations)
- [Security model](#security-model)
- [Contributing](#contributing)
- [License](#license)

---

## Why Vexa AgentWall

AI agents that invoke tools can read sensitive data, execute commands, and reach internal services. General API gateways and prompt-layer controls do not provide a dedicated **tool-call enforcement boundary** with identity-bound audit trails.

Vexa AgentWall is built for platform and security teams deploying agents at scale:

| Capability | What you get |
|------------|----------------|
| **Centralized enforcement** | One organizational gateway (Kubernetes or Docker Compose)—not a per-process sidecar. |
| **Identity** | Every session requires a valid OIDC JWT (Okta, Microsoft Entra ID, or any JWKS provider). |
| **Policy** | Deny-by-default YAML allowlists with JSON Schema for nested parameters—no blind object pass-through. |
| **Audit** | HMAC-chained logs, offline verification, and export to Splunk, Datadog, or OpenSearch. |
| **Operations** | Health probes and Prometheus metrics from day one. |

> **Two-layer Architecture:** AgentWall solves this at two distinct layers. First, the developer runs `agentwall dev` locally — a zero‑friction observation tool that records every tool call, surfaces risk patterns, and auto‑generates a security policy draft. No cloud accounts, no YAML hand‑authoring, no Docker. Second, the platform or security team deploys the **AgentWall Centralized Enforcement Gateway** — a hardened Rust service that all production agents route through, enforcing the reviewed and approved policy under the security team's control. The developer cannot bypass it, modify it, or disable it.

> **Network prerequisite:** Route all agent egress through the gateway (for example, Kubernetes `NetworkPolicy`) and block direct access to MCP servers. The gateway enforces only the traffic it sees.

---

## Features

### Gateway (multi-tenant)

- **HTTP MCP proxy** — JSON-RPC 2.0; concurrent agent sessions with per-session isolation.
- **Policy engine** — Schema v2 YAML; typed parameters; auto-anchored regex; **required** inline JSON Schema for `object` parameters.
- **Default-deny** — Invalid or permissive policy configurations fail at startup; unlisted tools are blocked.
- **Connection-level enforcement** — On violation, the gateway returns a JSON-RPC error and terminates the MCP session (no remote process kill).
- **Shadow Mode (FR-2)** — Observation-only proxy: all tool calls are forwarded unconditionally, logged to a local SQLite database, and exposed via a REST events API. No policy evaluation, no blocking. Ideal for baselining traffic before enforcement.

### Security

- **OIDC authentication** — RS256/ES256 JWT validation with JWKS caching and background key rotation.
- **Structural validators** — Opt-in `path_traversal`, `url_scheme_allowlist`, `sql_injection_basic`, `shell_injection_basic`, and custom `regex` per parameter.
- **Response scanning** — Optional secret detection and redaction in tool outputs (`--scan-responses`).

### Observability

- **Probes** — `GET /healthz`, `GET /readyz`
- **Metrics** — Prometheus-compatible `GET /metrics`
- **SIEM export** — Splunk HEC, Datadog Logs, OpenSearch, or local-only fallback
- **Events API** — `GET /api/events` returns the most recent tool-call events from the local SQLite database (shadow mode)

---

## Architecture

```
  AI Agent A ──┐
  AI Agent B ──┼──►  Vexa AgentWall          ──►  MCP Tool Servers
  AI Agent C ──┘     (central gateway)            (GitHub, DB, FS, …)
                     OIDC · Policy · Audit
                              │
                              ▼
                         Enterprise SIEM
```

**Enforcement flow:** OIDC validation → rate limiting → policy + structural validators → durable audit write → forward to upstream MCP → optional response scan.

**Shadow Mode flow:** forward (unconditionally) → SQLite event log → `GET /api/events`.

Configure agents with your gateway endpoint and OIDC bearer tokens—for example, `AGENTWALL_PROXY_URL` or your ingress URL.

---

## Shadow Mode

Shadow Mode is an **observation-only proxy** — every MCP tool call is forwarded to the upstream server without any policy evaluation or enforcement. All events are persisted locally in SQLite (`~/.agentwall/events.db`) and queryable via a REST API.

Use shadow mode to:
- **Baseline** all tool calls before writing a policy.
- **Monitor** agent behaviour in development without blocking anything.
- **Audit** traffic without deploying enforcement.

### Enabling Shadow Mode

```bash
# Dedicated dev command — always shadow mode:
agentwall dev \
  --listen 127.0.0.1:8080 \
  --mcp-url http://127.0.0.1:3000

# Or use the start command with the explicit flag:
agentwall start \
  --shadow-mode \
  --listen 127.0.0.1:8080 \
  --mcp-url http://127.0.0.1:3000

# Via environment variable:
AGENTWALL_SHADOW_MODE=true agentwall start ...
```

When active, the startup banner shows:

```
👁 Mode: SHADOW (Observation Only — no enforcement)
ℹ  All tool calls forwarded and logged. Enforcement is OFF.
```

### Events API

Query recently observed tool-call events:

```bash
# Fetch the most recent 50 events (default):
curl http://127.0.0.1:8080/api/events

# Fetch up to 100 events (maximum):
curl "http://127.0.0.1:8080/api/events?limit=100"
```

Each event object in the response array contains:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string (ISO 8601) | When the call was received |
| `tool_name` | string | MCP tool name (e.g. `read_file`) |
| `parameters` | string (JSON) | Serialised tool arguments |
| `response` | string (JSON) | Upstream server response |
| `upstream_endpoint` | string | MCP server URL |
| `session_id` | string | Agent session identifier |
| `latency_ms` | number | Round-trip latency to upstream |

### Storage & Retention

- **Database path:** `~/.agentwall/events.db` (SQLite, created automatically).
- **Pruning:** The oldest 1 000 rows are deleted automatically when the database file exceeds **500 MiB**.
- **Stdio proxy:** When `shadow_mode` is active in the stdio bridge, traffic is piped directly without JSON-RPC parsing (zero overhead).

> ⚠️ **Production note:** Shadow Mode disables all enforcement. Never run `--shadow-mode` or `AGENTWALL_SHADOW_MODE=true` in a production enforcement environment.

---

# Local Web Dashboard

When running the gateway in `dev` mode (`cargo run -- dev`), AgentWall automatically serves a rich, real‑time web dashboard directly from the binary. **In shadow mode the proxy skips policy evaluation**, so the dashboard works without a JWT. To see policy enforcement (allowed/denied calls) you must run the full Docker‑Compose stack, which provides the mock OIDC server and upstream MCP.

#### Features
- **Live Event Stream**: Real‑time SSE updates as agents make tool calls.
- **Inventory & Parameters**: View observed tools, upstream endpoints, and call arguments.
- **Risk Trends**: Visualize request distribution and tool latency.
- **Policy Drafts**: Instantly generate starter policy YAMLs from observed activity.

#### How to test manually (full end‑to‑end)
1. **Start the full development stack** (includes mock OIDC at port 8081 and mock MCP at port 3000):
   ```bash
   docker compose up -d --build
   ```
2. **Run the local shadow proxy** (the dashboard UI will open):
   ```bash
   cargo run -- dev
   ```
3. **Obtain a development JWT** from the mock OIDC server:
   ```powershell
   $token = (Invoke-RestMethod "http://localhost:8081/token?sub=dev&aud=agentwall").access_token
   $headers = @{ Authorization = "Bearer $token" }
   ```
4. **Send an allowed tool call** (passes policy):
   ```powershell
   $allowedBody = @{
       jsonrpc = "2.0"
       method  = "tools/call"
       params  = @{
           name      = "safe_tool"
           arguments = @{ example = "hello" }
       }
       id = 1
   } | ConvertTo-Json -Depth 10
   Invoke-RestMethod "http://localhost:8080/" -Method Post -Headers $headers -ContentType "application/json" -Body $allowedBody
   ```
5. **Send a denied tool call** (blocked by policy):
   ```powershell
   $deniedBody = @{
       jsonrpc = "2.0"
       method  = "tools/call"
       params  = @{
           name      = "leak_secret"
           arguments = @{}
       }
       id = 2
   } | ConvertTo-Json -Depth 10
   Invoke-RestMethod "http://localhost:8080/" -Method Post -Headers $headers -ContentType "application/json" -Body $deniedBody
   ```
6. **Watch the dashboard** – the live event stream will show both calls in real time.

If you only need to preview the UI without policy enforcement, you can skip steps 1‑3; run `cargo run -- dev` and the dashboard will display events (all calls are treated as allowed).


---

### Quick start

#### 1️⃣ Local development (no Docker)

```bash
# Run the shadow proxy with built‑in dashboard (no policy enforcement, no JWT required)
cargo run -- dev
```

- The UI opens automatically at `http://127.0.0.1:8080`.
- All tool calls are logged and shown in real time, but **no policy checks** are performed.

#### 2️⃣ Full end‑to‑end testing (Docker stack)

```bash
# Start the complete development environment (gateway, mock OIDC, mock MCP)
docker compose up -d --build

# In a separate terminal, run the dev proxy to serve the dashboard
cargo run -- dev
```

- The mock OIDC server on `localhost:8081` issues development JWTs.
- The mock MCP server on `localhost:3000` receives forwarded tool calls.
- Use the JWT flow described in the **Local Web Dashboard (FR‑3)** section to test allowed and denied calls.

#### 3️⃣ Clean up

```bash
# Stop and remove containers
docker compose down -v
```

---

### Prerequisites

- [Docker Desktop](https://docs.docker.com/get-docker/) with `docker compose`
- A local HTTP client:
  - **Windows**: PowerShell `Invoke-RestMethod` (built-in)
  - **macOS/Linux**: `curl`

> Note: The local stack builds a small Rust-based mock MCP server container. You do **not** need Rust installed locally; Docker builds it with a recent Rust toolchain.

### Docker Compose

```bash
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall
docker compose up -d --build
```

### Validate the gateway (recommended)

1) Confirm the local services are up:

- Gateway health: `GET http://localhost:8080/healthz`
- Mock OIDC health: `GET http://localhost:8081/health`
- Metrics: `GET http://localhost:8080/metrics`

#### PowerShell (Windows) — quick health checks

```powershell
Invoke-RestMethod "http://localhost:8080/healthz"
Invoke-RestMethod "http://localhost:8081/health"
Invoke-RestMethod "http://localhost:8080/metrics" | Select-Object -First 20
```

#### bash (macOS/Linux) — quick health checks

```bash
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8081/health
curl -fsS http://localhost:8080/metrics | head -n 20
```

2) Obtain a development JWT from the local mock OIDC provider.

#### PowerShell (Windows)

```powershell
$token = (Invoke-RestMethod "http://localhost:8081/token?sub=agent-dev&aud=agentwall").access_token
$headers = @{ Authorization = "Bearer $token" }

# Allowed call (passes policy; upstream records the call)
$allowedBody = @{
  jsonrpc = "2.0"
  method  = "tools/call"
  params  = @{
    name      = "safe_tool"
    arguments = @{ example = "hello" }
  }
  id      = 1
} | ConvertTo-Json -Depth 10

Invoke-RestMethod "http://localhost:8080/" -Method Post -Headers $headers -ContentType "application/json" -Body $allowedBody

# Denied call (not in allowlist → gateway returns a JSON-RPC error)
$deniedBody = @{
  jsonrpc = "2.0"
  method  = "tools/call"
  params  = @{
    name      = "leak_secret"
    arguments = @{ }
  }
  id      = 2
} | ConvertTo-Json -Depth 10

try {
  Invoke-RestMethod "http://localhost:8080/" -Method Post -Headers $headers -ContentType "application/json" -Body $deniedBody
} catch {
  $_.Exception.Message
}
```

#### bash (macOS/Linux)

```bash
TOKEN="$(curl -fsS "http://localhost:8081/token?sub=agent-dev&aud=agentwall" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"

curl -fsS -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "safe_tool",
      "arguments": { "example": "hello" }
    },
    "id": 1
  }'

# Denied call (not in allowlist → gateway returns a JSON-RPC error)
curl -s -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "leak_secret",
      "arguments": {}
    },
    "id": 2
  }' | cat
```

3) Inspect what reached the upstream mock MCP server:

- `GET http://localhost:3000/calls` — shows calls that were forwarded (allowed calls only).

4) Shut down cleanly when done:

```bash
docker compose down -v
```

See [`docker-compose.yml`](docker-compose.yml) for service definitions and environment defaults. The Compose stack mounts a local development policy at `./test-tools/test-policy.yaml`.

### Build from source

```bash
cargo build --release

./target/release/agentwall lint policy.example.yaml

./target/release/agentwall start \
  --policy policy.example.yaml \
  --listen 0.0.0.0:8080 \
  --log-path audit.log \
  --oidc-issuer https://your-idp.example.com \
  --siem-backend splunk \
  --siem-endpoint https://splunk.example.com:8088/services/collector/event \
  --siem-token "$SPLUNK_HEC_TOKEN"
```

Verify the audit chain:

```bash
./target/release/agentwall verify-log audit.log
./target/release/agentwall report audit.log --format text
```

---

## Deployment

### Production

1. Deploy the gateway as a **cluster Service** (Kubernetes recommended) or managed Docker Compose stack.
2. Store policies in a **GitOps** repository; apply via CI/CD (ConfigMap, volume mount, or equivalent).
3. Configure **OIDC** (`--oidc-issuer`, audience, JWKS) so every agent presents a corporate JWT.
4. Export audit events to your **SIEM** (`--siem-backend`, `--siem-endpoint`, `--siem-token`).
5. Enforce **network egress** so agents cannot reach MCP servers except through the gateway.

### Environment variables

| Variable | Description |
|----------|-------------|
| `AGENTWALL_POLICY_PATH` | Path to policy YAML |
| `AGENTWALL_LISTEN` | Listen address (default `127.0.0.1:8080`) |
| `AGENTWALL_MCP_URL` | Upstream MCP server URL |
| `AGENTWALL_LOG_PATH` | Audit log file path |
| `AGENTWALL_OIDC_ISSUER` | OIDC issuer URL (required for production) |
| `AGENTWALL_SIEM_BACKEND` | `splunk`, `datadog`, `opensearch`, or `local` |
| `AGENTWALL_SIEM_ENDPOINT` | SIEM ingestion URL |
| `AGENTWALL_SIEM_TOKEN` | SIEM authentication token |
| `AGENTWALL_SIEM_TIMEOUT` | Export timeout in seconds (default `2`) |
| `AGENTWALL_REPORT_PATH` | Optional session report path on shutdown |
| `AGENTWALL_DRY_RUN` | Development only: log denials but still forward requests |
| `AGENTWALL_SHADOW_MODE` | Enable Shadow Mode — observe all traffic without enforcement (FR-2) |
| `AGENTWALL_INCLUDE_PARAMS` | Store raw tool parameters in audit log (default: hashed only) |
| `VEXA_GATEWAY_URL` | Target gateway for `agentwall test --gateway` in CI |

Run `agentwall start --help` for all flags.

### Kubernetes

Expose AgentWall behind a Service or Ingress. Apply a `NetworkPolicy` that allows agent pods to reach only the gateway—not upstream MCP endpoints directly.

---

## Policy management

Policies are **schema v2** YAML files managed in version control (`default_action: deny` is required). Object parameters must include an inline `schema` block—omitting it causes a startup error.

```yaml
version: "2"
default_action: deny

auth:
  provider: okta
  jwks_uri: https://your-org.okta.com/oauth2/default/v1/keys
  audience: agentwall
  issuer: https://your-org.okta.com
  cache_ttl_minutes: 15

session:
  max_calls_per_second: 10

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        validators:
          - path_traversal
          - regex: "^/allowed/paths/.*"
```

**Workflow**

1. Author or change policy in Git with pull request review.
2. Run `agentwall lint` for schema and permissive-pattern warnings.
3. Run `agentwall test --gateway <test-gateway-url> --oidc-token <token> --policy policy.yaml fixtures.json` in CI before merge.
4. Deploy to the gateway via your GitOps pipeline.

Reference policy: [`policy.example.yaml`](policy.example.yaml).

---

## Command-line interface

| Command | Purpose |
|---------|---------|
| `agentwall start` | Run the central HTTP MCP gateway |
| `agentwall start --shadow-mode` | Run the gateway in shadow (observation-only) mode — no enforcement (FR-2) |
| `agentwall dev` | Start a local shadow proxy with a built-in dashboard endpoint (FR-2) |
| `agentwall lint` | Validate policy YAML locally (schema + warnings) |
| `agentwall test` | Validate policy against a **deployed** test gateway and fixture file (CI/CD) |
| `agentwall verify-log` | Verify HMAC integrity of an audit log |
| `agentwall report` | Build a session report from an audit log file |
| `agentwall promote` | Production readiness checks and Ed25519 policy signing |
| `agentwall validate` | Single-payload policy check for policy authors |

**Notes**

- **`lint`** — Local policy checks. Exit codes: `0` clean, `1` errors, `2` warnings only.
- **`test`** — Production validation path: requires `--gateway` and `--oidc-token` to exercise the live gateway. Fixture format: `[{ "tool": "name", "params": { ... } }, ...]`.
- **`promote`** — Validates schema v2 requirements (including identity configuration) before signing.
- **`dev`** — Equivalent to `start --shadow-mode`; sets `shadow_mode = true`, skips policy loading, and serves the local Web Dashboard (FR-3). Automatically opens your browser. Intended for local development baselining.
- **`start --shadow-mode`** — Same behaviour as `dev` but within the `start` command, allowing environment variable control via `AGENTWALL_SHADOW_MODE`.

Local single-payload checks for policy authors: `agentwall validate --policy policy.yaml --tool read_file --payload call.json`.

---

## Operations

### HTTP endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | `GET` | Local Web Dashboard UI (FR-3) |
| `/` | `POST` | MCP JSON-RPC proxy |
| `/healthz` | `GET` | Liveness |
| `/readyz` | `GET` | Readiness |
| `/metrics` | `GET` | Prometheus-compatible counters |
| `/api/events` | `GET` | Most recent tool-call events from SQLite (shadow mode, FR-2). Optional `?limit=N` (max 100). |
| `/api/events/stream` | `GET` | Live SSE stream of tool execution events (FR-3) |
| `/api/stats` | `GET` | Dashboard real-time statistics (FR-3) |
| `/api/generate-policy` | `POST` | Generate policy YAML draft (FR-3) |

### Repository layout

```
agentwall/
├── src/
│   ├── proxy/
│   │   ├── server.rs    # HTTP gateway, routing, /api/events endpoint
│   │   ├── handler.rs   # ProxyState, policy evaluation, shadow_mode bypass
│   │   ├── stdio.rs     # Stdio bridge + transparent shadow pipe
│   │   ├── db.rs        # SQLite event engine (FR-2)
│   │   └── session.rs   # Per-session isolation
│   ├── policy/          # Schema, engine, OIDC identity
│   └── audit/           # HMAC logger, SIEM export
├── tests/               # Unit and integration tests
├── test-tools/          # Local mocks (OIDC, SIEM, fixtures)
├── docker-compose.yml   # Local stack aligned with production
├── Dockerfile
└── policy.example.yaml
```

### Development

```bash
cargo build --release
cargo test
cargo bench
cargo fmt --check
cargo clippy -- -D warnings
```

Use the Docker Compose stack and SIEM integration for local testing. **Production observability is through your SIEM and Prometheus**—not a bundled product dashboard.

---

## Security model

**Provided by the gateway**

- Deny-by-default enforcement for routed traffic
- OIDC-bound identity on audited decisions
- Full JSON Schema validation for object parameters
- Tamper-evident audit logs with offline verification
- Session termination on policy violation (connection boundary)

**Required from operators**

- Network policies that prevent MCP bypass
- GitOps-managed policies with CI validation against a test gateway
- OIDC for all production agent sessions
- No `--dry-run`, `AGENTWALL_DRY_RUN`, `--shadow-mode`, or `AGENTWALL_SHADOW_MODE` in production environments

**Not in scope**

- Semantic DLP or prompt-injection detection (use complementary controls)
- Remote process termination (`--kill-mode process` / `both` are not supported)
- Local sidecar or desktop wrap installers
- Policy generation from runtime logs (`agentwall init` is deprecated)

**Responsible disclosure:** [contact@vexasec.io](mailto:contact@vexasec.io)

---

## Contributing

We welcome issues, documentation improvements, and pull requests.

1. [Open an issue](https://github.com/noviqtechnologies/agentwall/issues) for significant changes.
2. Fork the repository and create a feature branch.
3. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` pass.
4. Submit a pull request with a clear description and test plan.

---

## Support

| Channel | Link |
|---------|------|
| GitHub Issues | [github.com/noviqtechnologies/agentwall/issues](https://github.com/noviqtechnologies/agentwall/issues) |
| Product | [vexasec.io/agentwall](https://vexasec.io/agentwall.html) |
| Email | [contact@vexasec.io](mailto:contact@vexasec.io) |

---

## License

Copyright © [NoviqTech](https://vexasec.io). Licensed under the [Apache License 2.0](LICENSE).
