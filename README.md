# VEXA AgentWall

VEXA AgentWall is a local-first sidecar proxy that enforces deterministic security policies for autonomous AI agents communicating over the MCP (Model Context Protocol). It sits between an agent runtime and its MCP tool servers, intercepting every JSON-RPC call, evaluating it against a policy schema, and allowing or denying the call while writing a signed audit log.

## Key Benefits

*   **Zero-Trust by Default**: Protect your sensitive systems by replacing implicit trust with strict, explicit policy evaluations. Vexa AgentWall ensures agents can only execute exactly what has been pre-authorized.
*   **Cryptographic Auditability**: Gain unshakeable confidence in your compliance reporting. Every action—whether allowed or denied—is logged into an append-only, HMAC-SHA256 chained audit file, guaranteeing tamper-evident operations.
*   **Agent-Agnostic Integration**: Secure your infrastructure without modifying a single line of your AI agent's code. Vexa AgentWall acts as a transparent sidecar proxy, allowing developers to focus on intelligence while the proxy handles enforcement.
*   **Operational Resilience**: Protect downstream tool servers from runaway loops or hallucinated API flooding through configurable, per-session token-bucket rate limiting.
*   **Frictionless Development**: Safely iterate on security policies using Dry-Run mode to observe potential violations without breaking live agent workflows, and validate rules beforehand using the built-in pre-flight `check` tool.
*   **Ultra-Lightweight**: Shipped as a standalone Rust binary with zero external runtime dependencies, ensuring single-digit millisecond latency overhead.

## Quickstart

**Step 1 — Install**
(Binaries will be available in future releases. For now, build from source using `cargo build --release`).

**Step 2 — Write a minimal policy**
```yaml
version: "1"
default_action: deny
tools:
  - name: "read_file"
    action: allow
    parameters:
      - name: "path"
        type: string
        pattern: "/workspace/.*"
        required: true
```

**Step 3 — Test your policy before running**
```bash
agentwall check --policy policy.yaml fixture.json
# Exit 0 = all calls allowed. Exit 1 = any denied. Exit 2 = error.
```

**Step 4 — Start the proxy, then the agent**
```bash
agentwall start --policy policy.yaml --listen 127.0.0.1:8080 --log-path audit.log --kill-mode both &
until curl -sf http://127.0.0.1:8080/healthz; do sleep 0.1; done
VEXA_PROXY_URL=http://127.0.0.1:8080 python your_agent.py
```

**Step 5 — Verify the audit log and generate a session report**
```bash
agentwall verify-log audit.log               # Exit 0 = chain intact
agentwall report audit.log        # JSON session report
agentwall report audit.log --format text # Text session report
```

## Features Supported (Phase 1 MVP)

* **FR-106 (Policy Config):** Configurable policy paths with world-writable permission checks.
* **FR-107 (Rate Limiting):** Token-bucket rate limiting for MCP tool calls (`--rate-limit`).
* **FR-108 (Pre-flight Validation):** `agentwall check` subcommand with fixture validation and exact `ALLOW/DENY` output.
* **FR-109 (Log Rotation):** `fsync`-based log rotation archiving to `.bak` files when `--log-max-bytes` is exceeded.
* **FR-110 (Dry-Run Mode):** Policy enforcement simulation with `tool_dry_run_deny` logging (`--dry-run`).
* **FR-111 (Session Report):** `agentwall report` tool for post-session analytics in JSON or human-readable text formats.

## Security Guarantees & Known Limitations

### What AgentWall Cannot Prevent

1. **Direct Bypass**: The proxy alone cannot prevent an agent from bypassing it if the network allows direct access to the MCP server. You MUST block direct MCP egress at the OS/container level (e.g., using Kubernetes NetworkPolicy or iptables) and force traffic through the proxy.
2. **Nested Object Content Validation**: In Phase 1, `type: object` and `type: array` parameters are blind pass-throughs. The proxy ensures they are present if required, but it does NOT validate their content. An agent could exfiltrate data through nested fields of allowed tools.
3. **SIGKILL Rollback**: When a policy violation triggers a kill, the proxy terminates the connection and the process (if configured). However, it cannot roll back any side effects that were already committed by the MCP server before the termination.

### `--kill-mode` Guidance

- `connection` (Default for K8s): Closes the socket immediately. The agent can no longer communicate over this MCP session. Use this in Kubernetes environments without `shareProcessNamespace`.
- `process`: Sends a `SIGKILL` to the agent's PID.
- `both`: Closes the connection and sends a `SIGKILL`. If `SIGKILL` fails, it falls back to connection closing. Note: Kubernetes pods do not share PID namespaces by default; you must set `shareProcessNamespace: true` if you want to use process killing.

### Auto-Anchoring Behavior & Alternation

By default, the proxy wraps string regex patterns in `^(?:...)$`. This prevents partial matches from leaking access.

**Footgun Warning**: If your pattern uses alternation like `foo|bar/.*`, naive anchoring would produce `^foo|bar/.*$`, which means `(^foo)` OR `(bar/.*$)`. The proxy's non-capturing group `^(?:foo|bar/.*)$` ensures the entire pattern is evaluated securely.

To disable auto-anchoring (not recommended), set `unanchored: true` on the parameter. This will log a security warning at startup.

### Dry-Run Security Implications

You can start the proxy with `--dry-run` or `VEXA_DRY_RUN=true`. In this mode, policy violations are logged as `DRY_RUN_DENY`, but the tool call is forwarded to the MCP server anyway, and the agent is NOT killed.

**WARNING**: Dry-run disables enforcement. It should ONLY be used for policy development. Any production run with dry-run active will log a critical `dry_run_active` security event at startup, and the final session report will explicitly mark `"dry_run": true`.

## Nested Object Limitation

As mentioned, Phase 1 cannot validate inside `type: object` or `type: array` parameters. This exists because adding full JSON Schema validation is complex and would delay shipping the core proxy functionality. Treat any tool that accepts `object` parameters as higher-risk. Future versions (Phase 2) will introduce proper JSON Schema validation for nested types.
