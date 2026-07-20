# Configuration & Policies

AgentWall's core enforcement logic is driven by Schema v2 YAML policy files. 

## Policy Structure

A policy file strictly defines the allowed actions, tools, and identity providers. The `default_action: deny` directive is required to ensure a fail-safe posture.

Here is an example `agentwall-policy.yaml`:

```yaml
version: "2"
default_action: deny

# Controls local shadow proxy behavior
self_healing:
  enabled: true
  decay_window: 30d
  auto_suggest: true
  suggest_threshold: 0.9
  approval_required: true

# External authentication provider (for dashboard/users)
auth:
  provider: okta
  jwks_uri: https://your-org.okta.com/oauth2/default/v1/keys
  audience: agentwall
  issuer: https://your-org.okta.com

# Identity provider for binding Agents to specific rules
identity:
  provider: oidc
  issuer: https://your-org.okta.com
  agents:
    - id: my-agent
      description: "Data analysis agent"
      allowed_tools: ["read_file", "execute_query"]

# Rate limiting
session:
  max_calls_per_second: 10

# Explicit Tool Allowlisting
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

## Zero-Downtime Policy Reloading

AgentWall supports hot-reloading its configuration without dropping active connections. This is critical for centralized enforcement gateways.

- **Via API:** `curl -X POST http://localhost:8080/reload`
- **Via Signal (Linux):** `kill -SIGHUP $(pidof agentwall)`

## Data Loss Prevention (DLP)

AgentWall includes a DLP engine that scans outbound requests and inbound responses for sensitive data. 
It supports 21 built-in regex patterns, detecting:
- AWS, Azure, and GCP Keys
- GitHub and Slack Tokens
- Stripe and SendGrid Keys
- Credit Card Numbers, US SSNs
- `.env` variable references

## Agent Identity & Credential Governance

AgentWall introduces per-agent credential governance. Instead of hardcoding long-lived secrets into your AI Agents, you can provision short-lived, scoped credentials at runtime.

```bash
# Provision a scoped credential for an agent (1-hour TTL)
agentwall identity create --agent my-agent --scope read-only --ttl 1h

# Rotate credentials
agentwall identity rotate --agent my-agent

# Set per-tool-call credential scoping
agentwall identity scope --agent my-agent --tool execute_shell --deny
```
