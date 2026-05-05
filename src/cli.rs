//! CLI definitions — clap derive (§5.3)

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agentwall", version, about = "VEXA AgentWall — MCP security proxy")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run the proxy server
    Start {
        /// YAML policy file path
        #[arg(long, env = "AGENTWALL_POLICY_PATH")]
        policy: Option<String>,

        /// Proxy listen address
        #[arg(long, env = "AGENTWALL_LISTEN", default_value = "127.0.0.1:8080")]
        listen: String,

        /// Audit log output path
        #[arg(long, env = "AGENTWALL_LOG_PATH", default_value = "audit.log")]
        log_path: String,

        /// Upstream MCP server URL
        #[arg(long, env = "AGENTWALL_MCP_URL", default_value = "http://127.0.0.1:3000")]
        mcp_url: String,

        /// Agent PID for kill switch
        #[arg(long, env = "AGENTWALL_AGENT_PID")]
        agent_pid: Option<u32>,

        /// Read agent PID from file
        #[arg(long, env = "AGENTWALL_AGENT_PID_FILE")]
        agent_pid_file: Option<String>,

        /// Kill mode: connection, process, both
        /// Kill mode
        #[arg(long, default_value = "connection")]
        kill_mode: String,

        /// Maximum log size in bytes before rotation (default 100MB)
        #[arg(long, default_value_t = 104857600)]
        log_max_bytes: u64,

        /// Dry-run mode: log violations but allow calls
        #[arg(long, env = "AGENTWALL_DRY_RUN", default_value_t = false)]
        dry_run: bool,

        /// Max tool calls per second (overrides policy)
        #[arg(long)]
        rate_limit: Option<u32>,

        /// Write session report on shutdown
        #[arg(long, env = "AGENTWALL_REPORT_PATH")]
        report_path: Option<String>,
    },

    /// Pre-flight policy check against a fixture
    Check {
        /// YAML policy file path
        #[arg(long)]
        policy: String,

        /// Show DENY verdicts but exit 0 (for review without blocking CI)
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// JSON fixture file
        fixture: String,
    },

    /// Verify HMAC chain integrity of an audit log
    VerifyLog {
        /// Audit log file path
        log_path: String,
    },

    /// Generate a session report from a completed audit log
    Report {
        /// Audit log file path
        log_path: String,

        /// Output file
        #[arg(long)]
        output: Option<String>,

        /// Report format (json|text)
        #[arg(long, default_value = "json")]
        format: String,

        /// Include raw params in report (WARNING: may leak PII/secrets)
        #[arg(long, default_value_t = false)]
        report_include_params: bool,
    },

    /// Generate a starter policy from a dry-run audit log (FR-112)
    Init {
        /// Audit log to derive policy from
        #[arg(long)]
        from_log: String,

        /// Output policy file path
        #[arg(long, default_value = "policy.yaml")]
        output: String,
    },
}
