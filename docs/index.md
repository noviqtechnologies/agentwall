# AgentWall Documentation

Welcome to the AgentWall technical documentation. 

AgentWall is an egress proxy and security gateway for AI agents operating over the Model Context Protocol (MCP), HTTP, HTTPS, and WebSocket connections. It intercepts, audits, and blocks unauthorized agent tool calls based on YAML-defined policies.

## What is AgentWall?

MCP (Model Context Protocol) is an open standard that allows AI models to securely connect to local and remote data sources and tools. As AI agents increasingly autonomously invoke tools, a robust security boundary is necessary. AgentWall acts as a firewall specifically designed for these MCP tool calls.

AgentWall intercepts outbound traffic from your agent, surfacing patterns in a local dashboard, and generates a YAML security policy draft based on observed behavior.

## Core Capabilities

- **Observation & Routing:** Intercepts MCP, HTTP CONNECT, WebSocket, and plain HTTP traffic.
- **Enforcement:** Strict tool allowlisting with schema validation and bounds checking.
- **Data Loss Prevention (DLP):** 21 regex patterns detecting API keys, secrets, and PII.
- **Injection Defense:** 6-pass normalizer and 16-pattern injection scanner that blocks inbound tool responses and external payloads.
- **Compliance & Auditing:** HMAC-chained audit logs with direct export to SIEMs like Splunk and Datadog.

## Architecture

AgentWall is deployed in distinct modes depending on your operational needs:

1. **Local Developer Proxy (`agentwall dev`)** 
   A shadow proxy meant to run locally on a developer's machine. It observes traffic, provides a local SQLite-backed web dashboard, and generates initial policy drafts automatically.

2. **Centralized Enforcement Gateway (`agentwall start`)**
   A hardened gateway deployment that actively enforces security policies in a production or staging environment. It supports TLS and Zero-Downtime policy hot-reloading.

3. **Agent Identity Platform (`agentwall identity`)**
   A tool for provisioning short-lived, scoped credentials for agents to eliminate long-lived secret sprawl.

## Documentation Index

- [Deployment & Installation](deployment.md)
- [Quickstart Guide](quickstart.md)
- [Comprehensive Functional Scenarios Guide](comprehensive_guide.md)
- [Configuration & Policies](configuration.md)
- [Ecosystem Integrations](integrations.md)
