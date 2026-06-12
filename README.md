# Vexa AgentWall

**MCP security proxy for AI agent tool calls.**

AgentWall operates as two distinct tools with a clean separation of concerns:

1. **Local Developer CLI** — shadow-mode observation proxy. Records every MCP tool call the agent makes, surfaces risk patterns in a local dashboard, and generates a YAML security policy draft. No enforcement, no cloud, no signup.
2. **Centralized Enforcement Gateway** — team/org deployment. Enforces reviewed policies for all production agents. Operated by the platform or security team — not the developer.

> **Why two separate tools?** A security control operated by the same person it constrains is not a security control. Local enforcement on a developer's machine can be disabled by that developer. The centralized gateway breaks that conflict of interest.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.10-green.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

[Website](https://vexasec.io/) · [Issues](https://github.com/noviqtechnologies/agentwall/issues) · [Security](mailto:security@vexasec.io)

---

## Table of Contents

- [What This Is (and Is Not)](#what-this-is-and-is-not)
- [Installation](#installation)
- [Quick Start — Local Development](#quick-start--local-development)
- [Local Web Dashboard](#local-web-dashboard)
- [Auto-Policy Generation](#auto-policy-generation)
- [Centralized Enforcement Gateway](#centralized-enforcement-gateway)
- [Policy Reference](#policy-reference)
- [CLI Reference](#cli-reference)
- [Environment Variables](#environment-variables)
- [HTTP Endpoints](#http-endpoints)
- [Security Model](#security-model)
- [Repository Layout](#repository-layout)
- [Contributing](#contributing)
- [License](#license)

---

## What This Is (and Is Not)

**This IS:**
- A locally-installed CLI (`agentwall dev`) for observation, policy generation, and linting.
- A transparent local MCP proxy (shadow mode only) that records agent behaviour without blocking.
- A local web dashboard served on `localhost` for visualizing agent tool calls in real time.
- An auto-policy generator that drafts YAML security policies from observed traffic.
- A centralized enforcement gateway for team/org deployment — enforces reviewed policies, operated by the security team.
- A policy linter (`agentwall lint`) and audit log verifier (`agentwall verify-log`).

**This is NOT:**
- A SaaS platform, cloud backend, or hosted web application.
- A local enforcement tool. There is no `--enforce` flag on the developer CLI. Enforcement is centralized infrastructure.
- An SDK or library that patches LangChain, OpenAI, or Anthropic.
- A prompt injection detection tool (use Lakera or similar).
- An LLM observability platform (use LangSmith, AgentOps).
- A general API gateway (use Kong, Cloudflare).

---

## Installation

### One-command install (macOS, Linux, Windows via bash)

```bash
curl -fsSL https://vexasec.io/install.sh | sh
```

The script downloads a statically-linked binary from [GitHub Releases](https://github.com/noviqtechnologies/agentwall/releases), installs it to `~/.local/bin/agentwall`, and prints PATH instructions if needed. No Docker, no Kubernetes, no runtime dependencies.

**Supported platforms:**

| OS | Architecture | Binary type |
|----|---|---|
| macOS 12+ | x86_64, aarch64 | Universal |
| Linux (glibc 2.31+ / Ubuntu 20.04+) | x86_64, aarch64 | Static (musl) |
| Windows 10 21H2+ | x86_64 | Native |

**Verify the install:**

```bash
agentwall --version
# agentwall 1.0.8
```

### Build from source

Requires Rust 1.75+.

```bash
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall
cargo build --release
# Binary at: ./target/release/agentwall
```

---

## Quick Start — Local Development

Shadow mode records every MCP tool call without blocking or modifying any traffic. It writes events to a local SQLite database and serves a real-time web dashboard.

### Prerequisites

- AgentWall CLI installed (see above).
- An MCP-compatible agent or tool server running locally (optional — the proxy forwards to `localhost:3000` by default).

### Step 1 — Start the shadow proxy

**HTTP MCP agent:**

```bash
agentwall dev
# Listening on: 127.0.0.1:8080
# Upstream: http://127.0.0.1:3000
# Dashboard: http://127.0.0.1:8080
```

Configure your agent to route MCP traffic through `http://localhost:8080` instead of directly to your MCP server.

**Stdio MCP agent (Claude Desktop, Cursor):**

```bash
agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

This wraps the downstream MCP process. Update your `claude_desktop_config.json` to use `agentwall dev --stdio --` as the command prefix.

### Step 2 — Run your agent

Route MCP traffic through the proxy. The proxy adds no enforcement — all calls pass through unchanged.

```bash
# Example: point an HTTP MCP client at the proxy
export AGENTWALL_PROXY_URL=http://localhost:8080
python my_agent.py
```

Events appear in `~/.agentwall/events.db` within one second of each tool call.

### Step 3 — Generate a policy draft

```bash
agentwall generate-policy
# Output: ./agentwall-policy.yaml
```

### Step 4 — Validate the policy

```bash
agentwall lint agentwall-policy.yaml
# Exit 0: clean
# Exit 1: schema or security errors
# Exit 2: malformed YAML
```

### Step 5 — Submit for security review

Commit `agentwall-policy.yaml` to version control and submit it to your platform or security team for deployment to the centralized enforcement gateway. The developer's job ends here — policy enforcement is not a developer-side concern.

### Full end-to-end test with Docker stack

The repo includes a Docker Compose stack with a mock OIDC server (port 8081) and mock MCP server (port 3000) for integration testing.

```bash
# Start the full stack
docker compose up -d --build

# In a separate terminal, start the shadow proxy
agentwall dev

# Obtain a development JWT from the mock OIDC server
# PowerShell (Windows):
$token = (Invoke-RestMethod "http://localhost:8081/token?sub=dev&aud=agentwall").access_token
$headers = @{ Authorization = "Bearer $token" }

# bash (macOS/Linux):
TOKEN=$(curl -fsS "http://localhost:8081/token?sub=dev&aud=agentwall" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
```

**Send an allowed tool call (passes policy):**

```powershell
# PowerShell
$body = @{
    jsonrpc = "2.0"; id = 1; method = "tools/call"
    params  = @{ name = "safe_tool"; arguments = @{ example = "hello" } }
} | ConvertTo-Json -Depth 10

Invoke-RestMethod "http://localhost:8080/" -Method Post -Headers $headers `
    -ContentType "application/json" -Body $body
```

```bash
# bash
curl -fsS -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{"example":"hello"}}}'
```

**Send a denied tool call (not in policy allowlist):**

```powershell
# PowerShell
$body = @{
    jsonrpc = "2.0"; id = 2; method = "tools/call"
    params  = @{ name = "leak_secret"; arguments = @{} }
} | ConvertTo-Json -Depth 10

try {
    Invoke-RestMethod "http://localhost:8080/" -Method Post -Headers $headers `
        -ContentType "application/json" -Body $body
} catch { $_.Exception.Message }
```

```bash
# bash
curl -s -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"leak_secret","arguments":{}}}'
```

**Check calls that reached the upstream mock MCP server:**

```bash
curl http://localhost:3000/calls
```

**Shut down:**

```bash
docker compose down -v
```

---

## Local Web Dashboard

When `agentwall dev` starts, it automatically opens `http://127.0.0.1:8080` in the default browser. Use `--no-browser` to suppress this.

The dashboard is served by the same binary — no separate Node.js process, no cloud dependency.

**What the dashboard shows:**

| View | Description |
|------|-------------|
| **Tool Inventory** | All observed tools: call count, last seen, risk tier (TIER_1 / TIER_2 / TIER_3). |
| **Session Timeline** | Chronological list of tool calls with timestamp, parameters (collapsed), response status, and latency. Click to expand full JSON. |
| **Parameter Explorer** | Per-tool view of observed parameter values, inferred types, bounds, and detected patterns (file paths, URLs, SQL, shell commands). |
| **Risk Flags** | Auto-detected: path traversal (`../`), shell injection metacharacters, external URLs, unbounded strings, destructive operation names. |
| **Generate Policy** | Button that calls `agentwall generate-policy` and displays the resulting YAML in-browser with a download option. |

**Live event streaming:** New tool calls appear in the timeline within 500ms via Server-Sent Events (`/api/events/stream`).

**Storage:** Events are stored in `~/.agentwall/events.db` (SQLite). Automatic pruning kicks in when the file exceeds 500 MiB.

> The dashboard is a developer diagnostic tool. It has no login, no user accounts, and no multi-user collaboration. All data stays on the local machine.

---

## Auto-Policy Generation

`agentwall generate-policy` reads all events from the local SQLite store and produces a `agentwall-policy.yaml` draft.

```bash
agentwall generate-policy
# Reading observed tool calls from event store...
# Analysing N events across M unique tools...
# Policy written to agentwall-policy.yaml
```

**What the generator produces per tool:**

- Tool name allowlist entry.
- Per-parameter schema: inferred type, `max_length` (observed max + 20% headroom), enum values if ≤ 10 unique values observed.
- `risk_tier`: `TIER_1` (destructive/shell), `TIER_2` (data access/mutation), `TIER_3` (read-only).
- `confidence`: `high` (≥ 50 observations), `medium` (10–49), `low` (< 10).
- Path-like string parameters automatically receive the `path_traversal` validator.
- `anomalies` section flagging parameter values that appear exactly once — requires human review before enabling enforcement.

**Example output:**

```yaml
# Auto-generated by AgentWall from 847 observed tool calls
# Observation window: 2026-06-01 to 2026-06-07
# Review this policy carefully before enabling enforcement.

version: "2"
default_action: deny

tools:
  - name: read_file
    action: allow
    risk_tier: TIER_3
    confidence: high         # 312 observations
    parameters:
      - name: path
        type: string
        required: true
        max_length: 256
        validators:
          - path_traversal
        observed_pattern: "^/workspace/.*$"  # informational

  - name: execute_query
    action: allow
    risk_tier: TIER_1        # CAUTION: destructive potential
    confidence: medium       # 28 observations
    parameters:
      - name: query
        type: string
        required: true
        max_length: 2048
      - name: database
        type: string
        required: true
        enum: ["analytics", "staging"]

# ── Anomalies (review required) ─────────────────────────────
# - execute_query.query: observed value containing "DROP TABLE" (1 occurrence)
#   → Likely a test. Confirm before enabling enforcement.
```

Validate the generated policy before submitting it:

```bash
agentwall lint agentwall-policy.yaml
```

---

## Centralized Enforcement Gateway

> **This is Phase 2 infrastructure.** The policy engine (`src/policy/`) is built and production-ready. Centralized gateway packaging and deployment tooling are under active development.

The centralized gateway is the only component that enforces policy. It is deployed and operated by the platform or security team — separate from the developer's local machine. All production agents route MCP traffic through it.

**Enforcement flow:** OIDC validation → rate limiting → policy evaluation → structural validators → audit write → forward to upstream MCP → optional response scan.

**Default-deny:** Unlisted tools are blocked. An invalid or permissive policy configuration fails at startup.

**Fail-closed:** If the gateway crashes, all active agent MCP connections drop. There is no silent pass-through.

### Run with Docker Compose (for integration testing)

```bash
docker compose up -d --build
```

See [`docker-compose.yml`](docker-compose.yml) for service definitions. The stack mounts `./test-tools/test-policy.yaml` as the enforcement policy.

### Run as a standalone binary

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

### Verify the audit log

```bash
agentwall verify-log audit.log
agentwall report audit.log --format text
```

---

## Policy Reference

Policies are Schema v2 YAML files. `default_action: deny` is required. Object parameters require an inline `schema` block — omitting it causes a startup error.

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
        max_length: 512
        validators:
          - path_traversal
          - regex: "^/allowed/.*"

  - name: query_db
    action: allow
    parameters:
      - name: filters
        type: object
        required: true
        schema:
          type: object
          properties:
            table:
              type: string
            limit:
              type: integer
```

**Supported parameter validators:**

| Validator | Description |
|-----------|-------------|
| `path_traversal` | Blocks `../` sequences. |
| `url_scheme_allowlist` | Blocks disallowed URL schemes. |
| `sql_injection_basic` | Flags basic SQL injection patterns. |
| `shell_injection_basic` | Flags shell metacharacters. |
| `regex: "..."` | Validates against a pattern. All patterns are auto-anchored (`^...$`). |

**Policy workflow:**

1. Author or modify policy in a Git branch with peer review.
2. Run `agentwall lint policy.yaml` locally.
3. Run `agentwall test --gateway <url> --oidc-token <token> --policy policy.yaml fixtures.json` in CI.
4. Deploy to the centralized gateway via your GitOps pipeline.

Reference: [`policy.example.yaml`](policy.example.yaml).

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `agentwall dev` | Start local shadow proxy (observation only, no enforcement). Opens dashboard. |
| `agentwall dev --stdio -- <cmd>` | Stdio proxy mode — wraps a downstream MCP process. |
| `agentwall dev --no-browser` | Start shadow proxy without opening the browser. |
| `agentwall start` | Run the enforcement gateway (requires `--policy`). |
| `agentwall start --shadow-mode` | Run the gateway in shadow mode via `start` command. |
| `agentwall generate-policy` | Generate a YAML policy draft from observed shadow-mode traffic. |
| `agentwall lint <policy.yaml>` | Validate policy YAML (schema + security warnings). |
| `agentwall test` | Validate policy against a deployed gateway with fixture calls (CI/CD). |
| `agentwall verify-log <log>` | Verify HMAC chain integrity of an audit log. |
| `agentwall report <log>` | Generate a session report from an audit log. |
| `agentwall validate` | Single-payload policy check for policy authors. |
| `agentwall promote` | Production readiness checks and Ed25519 policy signing. |
| `agentwall wrap claude` | Patch Claude Desktop config to route MCP through AgentWall. |
| `agentwall unwrap claude` | Restore Claude Desktop config from the AgentWall backup. |

**`agentwall lint` exit codes:** `0` = clean, `1` = errors, `2` = malformed YAML.

**`agentwall test`** requires `--gateway <url>` and `--oidc-token <token>` to exercise a live gateway. Fixture format: `[{ "tool": "name", "params": { ... } }, ...]`.

---

## Environment Variables

| Variable | Command | Description |
|----------|---------|-------------|
| `AGENTWALL_POLICY_PATH` | `start` | Path to policy YAML |
| `AGENTWALL_LISTEN` | `start` | Listen address (default `127.0.0.1:8080`) |
| `AGENTWALL_MCP_URL` | `start`, `dev` | Upstream MCP server URL |
| `AGENTWALL_LOG_PATH` | `start` | Audit log file path |
| `AGENTWALL_OIDC_ISSUER` | `start` | OIDC issuer URL |
| `AGENTWALL_SIEM_BACKEND` | `start` | `splunk`, `datadog`, `opensearch`, or `local` |
| `AGENTWALL_SIEM_ENDPOINT` | `start` | SIEM ingestion URL |
| `AGENTWALL_SIEM_TOKEN` | `start` | SIEM authentication token |
| `AGENTWALL_SIEM_TIMEOUT` | `start` | Export timeout in seconds (default `2`) |
| `AGENTWALL_SHADOW_MODE` | `start` | `true` to enable shadow mode on `start` |
| `AGENTWALL_DRY_RUN` | `start` | Log violations but forward all calls |
| `AGENTWALL_INCLUDE_PARAMS` | `start` | Store raw parameters in audit log (default: hashed) |
| `AGENTWALL_REPORT_PATH` | `start` | Session report path on shutdown |
| `VEXA_GATEWAY_URL` | `test` | Target gateway for `agentwall test` in CI |

Run `agentwall start --help` for all flags.

---

## HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | `GET` | Local web dashboard |
| `/` | `POST` | MCP JSON-RPC 2.0 proxy |
| `/healthz` | `GET` | Liveness probe |
| `/readyz` | `GET` | Readiness probe |
| `/metrics` | `GET` | Prometheus-compatible counters |
| `/api/events` | `GET` | Recent tool-call events from SQLite. `?limit=N` (max 100, default 50). |
| `/api/events/stream` | `GET` | Live SSE stream of tool-call events |
| `/api/stats` | `GET` | Real-time event statistics |
| `/api/generate-policy` | `POST` | Trigger policy generation, returns YAML |

---

## Security Model

**What the gateway enforces:**

- Default-deny: unlisted tools are blocked.
- OIDC-bound identity on all audited decisions.
- Full JSON Schema validation for object parameters.
- Tamper-evident HMAC-chained audit logs with offline verifiability.
- Session termination on policy violation (connection boundary only — no remote process kill).

**What you must provide:**

- Network policies (K8s `NetworkPolicy`, VPC egress rules, firewall) that prevent agents from routing around the gateway.
- GitOps-managed policies with CI validation against a test gateway.
- OIDC for all production agent sessions.
- Never run `--shadow-mode`, `AGENTWALL_SHADOW_MODE`, or `AGENTWALL_DRY_RUN` in a production enforcement environment.

**Out of scope:**

- Semantic DLP or prompt-injection detection.
- Remote process termination (`--kill-mode process` / `both` are removed as of v6.1).
- SaaS dashboard or cloud-hosted log storage.
- Legal compliance certifications.

**Responsible disclosure:** [security@vexasec.io](mailto:security@vexasec.io)

---

## Repository Layout

```
agentwall/
├── src/
│   ├── main.rs              # Entry point, command dispatch
│   ├── cli.rs               # Clap CLI definitions
│   ├── proxy/
│   │   ├── handler.rs       # ProxyState, policy evaluation, shadow-mode bypass
│   │   ├── server.rs        # HTTP gateway, routing, /api/* endpoints
│   │   ├── db.rs            # SQLite event store (FR-2)
│   │   ├── stdio.rs         # Stdio bridge and transparent shadow pipe
│   │   └── session.rs       # Per-session isolation
│   ├── dashboard/
│   │   ├── mod.rs           # Dashboard module
│   │   └── dashboard.html   # Embedded dashboard UI (FR-3)
│   ├── policy/              # Schema, engine, OIDC identity, response scanner
│   ├── audit/               # HMAC logger, SIEM export
│   ├── generate_policy.rs   # Auto-policy generator (FR-4)
│   └── lint.rs              # Policy linter
├── tests/
│   └── unit/                # Unit tests (68+ passing)
├── test-tools/              # Mock OIDC server, mock MCP server, test fixtures
├── docs/
│   └── VexaAgentWall-PRD-FINAL.md
├── docker-compose.yml       # Local development stack
├── Dockerfile
├── policy.example.yaml
└── install.sh               # One-command installer (FR-1)
```

### Development

```bash
cargo build
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

---

## Contributing

1. [Open an issue](https://github.com/noviqtechnologies/agentwall/issues) for significant changes.
2. Fork the repository and create a feature branch.
3. Ensure `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` all pass.
4. Submit a pull request with a description and test plan.

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
