# agentwall
VEXA AgentWall is a local-first sidecar proxy that enforces deterministic security policies for autonomous AI agents communicating over the MCP protocol. It sits between an agent runtime and its MCP tool servers, intercepting every JSON-RPC call, evaluating it against a policy schema.
