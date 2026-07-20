# IDE & Ecosystem Integrations

AgentWall provides seamless integrations with the most popular AI-powered IDEs and coding assistants. 

Instead of manually setting up environment variables, you can use the `agentwall wrap` command to automatically patch your local IDE configurations to route traffic through the AgentWall proxy.

## Supported Targets

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

## How it works

When you run `agentwall wrap <target>`, the CLI edits the application's native configuration files (e.g., `settings.json`, `config.yaml`, or extension preferences) to point outbound HTTP and MCP connections to your local AgentWall proxy. 

To restore your configuration to its original state, run `agentwall unwrap <target>`.
