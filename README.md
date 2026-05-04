# VEXA AgentWall

> **Local-first sidecar proxy enforcing deterministic security policies for autonomous AI agents over MCP.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen.svg)]()
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)]()

VEXA AgentWall sits between an AI agent runtime and its MCP (Model Context Protocol) tool servers. It intercepts every JSON-RPC tool call, evaluates it against a YAML-defined policy, and either allows or denies the call — while writing a cryptographically chained, tamper-evident audit log of every decision.

---

## Table of Contents

- [Why AgentWall?](#why-agentwall)
- [Key Benefits](#key-benefits)
- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [Policy Reference](#policy-reference)
- [CLI Reference](#cli-reference)
- [Features (Phase 1 MVP)](#features-phase-1-mvp)
- [Demo UI](#demo-ui)
- [Security Guarantees & Known Limitations](#security-guarantees--known-limitations)
- [Building from Source](#building-from-source)
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

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     AI Agent Runtime                    │
│            (any framework: LangChain, AutoGPT, …)       │
└──────────────────────┬──────────────────────────────────┘
                       │  JSON-RPC over HTTP
                       ▼
┌─────────────────────────────────────────────────────────┐
│               VEXA AgentWall Proxy                      │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Policy Eval │  │ Rate Limiter │  │  Audit Logger │  │
│  │  (YAML)     │  │(Token Bucket)│  │(HMAC-SHA256)  │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │  Allowed calls forwarded
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  MCP Tool Servers                       │
│        (filesystem, shell, search, database, …)         │
└─────────────────────────────────────────────────────────┘
```

**Key design decisions:**
- **Deny-by-default** — only explicitly permitted tools/parameters pass through.
- **Regex-anchored patterns** — all string parameters are validated against anchored regex (`^(?:...)$`) to prevent partial-match bypasses.
- **Chained audit log** — each entry's HMAC includes the previous entry's hash, forming a tamper-evident chain.
- **Kill modes** — on violation, the proxy can close the connection, SIGKILL the agent process, or both.

---

## Quickstart

### Step 1 — Build the Binary

```bash
cargo build --release
# Binary will be at: target/release/agentwall (Linux/macOS) or target\release\agentwall.exe (Windows)
```

> Pre-built binaries for Windows are available in `agentwall-windows.zip`.

### Step 2 — Write a Policy

```yaml
version: "1"
default_action: deny
session:
  max_calls_per_second: 5

tools:
  - name: "read_file"
    action: allow
    parameters:
      - name: "path"
        type: string
        pattern: "/workspace/.*"
        required: true
```

### Step 3 — Pre-flight Validation

Test your policy against a fixture file *before* running a real agent:

```bash
agentwall check --policy policy.yaml fixture.json
# Exit 0 = all calls allowed
# Exit 1 = one or more denied
# Exit 2 = error (bad policy / bad fixture)
```

### Step 4 — Start the Proxy

```bash
agentwall start \
  --policy policy.yaml \
  --listen 127.0.0.1:8080 \
  --log-path audit.log \
  --kill-mode both &

# Wait for proxy to be ready
until curl -sf http://127.0.0.1:8080/healthz; do sleep 0.1; done

# Point your agent at the proxy
VEXA_PROXY_URL=http://127.0.0.1:8080 python your_agent.py
```

### Step 5 — Verify and Report

```bash
# Verify cryptographic chain integrity
agentwall verify-log audit.log
# Exit 0 = chain intact, Exit 1 = tampered

# Generate a session report
agentwall report audit.log --format text   # human-readable summary
agentwall report audit.log --format json   # machine-readable JSON
```

---

## Policy Reference

A policy file is a YAML document with the following structure:

```yaml
version: "1"                    # Schema version (always "1" for Phase 1)
default_action: deny            # "allow" or "deny" for unconfigured tools

session:
  max_calls_per_second: 10      # Optional: rate limit across all tools

tools:
  - name: "tool_name"           # Exact MCP tool name to match
    action: allow               # "allow" or "deny"
    parameters:
      - name: "param_name"      # Parameter key in the tool's arguments
        type: string            # "string", "number", "boolean", "object", "array"
        pattern: "^/safe/.*$"   # Regex pattern (for string types only)
        required: true          # If true, call is denied if param is missing
        unanchored: false       # Set true to disable auto ^(?:...)$ wrapping (not recommended)
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
  start        Start the proxy server
  check        Pre-flight validate a policy against a fixture file
  verify-log   Verify cryptographic integrity of an audit log
  report       Generate a session analytics report from an audit log

OPTIONS FOR 'start':
  --policy <PATH>          Path to policy YAML file
  --listen <ADDR>          Listen address (default: 127.0.0.1:8080)
  --log-path <PATH>        Path for the audit log file
  --kill-mode <MODE>       Action on policy violation: connection | process | both
  --dry-run                Log violations but do not enforce them
  --log-max-bytes <N>      Rotate log when it exceeds N bytes
  --rate-limit <N>         Calls-per-second limit (overrides policy file)
  --report-path <PATH>     Path to write the session report JSON on shutdown

OPTIONS FOR 'check':
  --policy <PATH>          Policy YAML file to validate against
  <FIXTURE>                JSON file containing an array of tool calls to test

OPTIONS FOR 'report':
  <LOG_PATH>               Path to audit log file
  --format <FORMAT>        Output format: json | text (default: text)
```

---

## Features (Phase 1 MVP)

| Feature | Reference | Description |
|---|---|---|
| Policy Config | FR-106 | Configurable policy paths with world-writable permission checks |
| Rate Limiting | FR-107 | Token-bucket rate limiting per session (`--rate-limit`) |
| Pre-flight Validation | FR-108 | `agentwall check` with fixture validation and exact `ALLOW/DENY` output |
| Log Rotation | FR-109 | `fsync`-based rotation archiving to `.bak` files when `--log-max-bytes` is exceeded |
| Dry-Run Mode | FR-110 | Policy enforcement simulation; violations logged as `DRY_RUN_DENY` but not blocked |
| Session Report | FR-111 | `agentwall report` tool for post-session analytics in JSON or text formats |

---

## Demo UI

AgentWall ships with a **local-first demo dashboard** for exploring its features interactively without writing any code.

The demo UI is a zero-dependency single-page app (no npm, no build step) backed by a lightweight Python bridge server that relays commands to the `agentwall` binary.

```
demo-ui/
├── index.html      # Single-page dashboard (open directly in browser)
├── bridge.py       # Python bridge server (Flask) — relays API calls to the binary
├── policy.yaml     # Default demo policy — edit live in the UI
└── README.md       # Demo-specific setup guide
```

### Demo UI Features

| Panel | Key | What It Does |
|---|---|---|
| **Policy Editor** | `01` | Live YAML editor with one-click pre-flight validation against built-in sample calls |
| **Session Monitor** | `02` | Start/stop the proxy, watch real-time log stream via SSE, simulate tool calls |
| **Audit History** | `03` | Browse all log entries with stats (total / allowed / denied / p95 latency) |
| **Session Report** | `04` | Generate and view a session analytics report with blocked incidents and tool usage |

### Quick Launch (Windows)

```powershell
# 1. Install Python dependencies (one-time)
pip install flask flask-cors

# 2. Start the bridge server (from demo-ui folder)
cd demo-ui
python bridge.py --vexa-bin ..\target\release\agentwall.exe

# 3. Open the UI — just double-click index.html in File Explorer
#    or navigate to it in your browser
```

> See [`demo-ui/README.md`](demo-ui/README.md) for the full setup guide including all bridge server options.

---

## Security Guarantees & Known Limitations

### What AgentWall Cannot Prevent

1. **Direct Bypass**: The proxy cannot stop an agent from calling MCP servers directly if the network allows it. You **must** block direct MCP egress at the OS/container level (e.g., Kubernetes `NetworkPolicy`, `iptables`) and force all traffic through the proxy.

2. **Nested Object Content**: Phase 1 treats `type: object` and `type: array` parameters as opaque. It checks for their *presence* if `required: true`, but does **not** validate their *contents*. An agent could exfiltrate data through nested fields of an otherwise-allowed tool.

3. **SIGKILL Rollback**: When a violation triggers a kill, the proxy terminates the connection and/or process. It **cannot** roll back side effects already committed by the MCP server before termination.

### `--kill-mode` Reference

| Mode | Behaviour | When to Use |
|---|---|---|
| `connection` | Closes the TCP socket immediately | K8s without `shareProcessNamespace` |
| `process` | Sends `SIGKILL` to the agent's PID | Single-host deployments |
| `both` | Closes socket **and** sends `SIGKILL`; falls back to connection-only if kill fails | Default — maximum enforcement |

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

## License

Apache-2.0 © NoviqTech — see [LICENSE](LICENSE) for details.
