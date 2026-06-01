//! CLI definitions — clap derive (§5.3)
//!
//! ## v6.1 Deprecation Changes
//!
//! - `--kill-mode process` / `--kill-mode both` removed from `start` and `wrap`.
//! - `agentwall init` is deprecated. Use a GitOps workflow instead.
//! - `agentwall test` now accepts `--gateway` and `--oidc-token` for CI/CD integration.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agentwall",
    version,
    about = "VEXA AgentWall — centralized enterprise security gateway for AI agent tool calls over MCP"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run the gateway server
    Start {
        /// YAML policy file path
        #[arg(long, env = "AGENTWALL_POLICY_PATH")]
        policy: Option<String>,

        /// Gateway listen address
        #[arg(long, env = "AGENTWALL_LISTEN", default_value = "127.0.0.1:8080")]
        listen: String,

        /// Audit log output path
        #[arg(long, env = "AGENTWALL_LOG_PATH", default_value = "audit.log")]
        log_path: String,

        /// Upstream MCP server URL
        #[arg(long, env = "AGENTWALL_MCP_URL", default_value = "http://127.0.0.1:3000")]
        mcp_url: String,

        /// Agent PID (ignored in v6.1 — process kill is removed)
        #[arg(long, env = "AGENTWALL_AGENT_PID", hide = true)]
        agent_pid: Option<u32>,

        /// Read agent PID from file (ignored in v6.1 — process kill is removed)
        #[arg(long, env = "AGENTWALL_AGENT_PID_FILE", hide = true)]
        agent_pid_file: Option<String>,

        /// Kill mode [DEPRECATED in v6.1 — only 'connection' is supported]
        ///
        /// 'process' and 'both' have been removed. The gateway enforces security at
        /// the MCP connection boundary. Remove this flag; 'connection' is the default.
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

        /// OIDC issuer URL for identity binding (FR-202). Required for enterprise deployments.
        #[arg(long, env = "AGENTWALL_OIDC_ISSUER")]
        oidc_issuer: Option<String>,

        /// Write session report on shutdown
        #[arg(long, env = "AGENTWALL_REPORT_PATH")]
        report_path: Option<String>,

        /// Enable balanced security profile (placeholder for future graduated security)
        #[arg(long, default_value_t = false)]
        balanced: bool,

        /// Enable strict security profile (placeholder for future graduated security)
        #[arg(long, default_value_t = false)]
        strict: bool,

        /// Enable response scanning for secret detection (FR-303b)
        #[arg(long, default_value_t = false)]
        scan_responses: bool,

        /// Block entire response on secret detection instead of redacting (FR-303b)
        #[arg(long, default_value_t = false)]
        block_on_secrets: bool,

        /// Maximum response size to scan in bytes (FR-303b, default: 1MB)
        #[arg(long, default_value_t = 1048576)]
        max_scan_bytes: usize,

        // ── FR-104: SIEM Export ────────────────────────────────────────────

        /// SIEM backend to export audit events to (FR-104).
        /// Supported values: splunk | datadog | opensearch | local
        /// Use 'local' (default) for disk-only operation without network export.
        #[arg(long, env = "AGENTWALL_SIEM_BACKEND", default_value = "local")]
        siem_backend: String,

        /// SIEM ingestion endpoint URL (FR-104).
        /// Splunk:     https://splunk.corp.com:8088/services/collector/event
        /// Datadog:    https://http-intake.logs.datadoghq.com/api/v2/logs
        /// OpenSearch: https://opensearch.corp.com/agentwall-logs/_doc
        #[arg(long, env = "AGENTWALL_SIEM_ENDPOINT", default_value = "")]
        siem_endpoint: String,

        /// SIEM authentication token (FR-104).
        /// Splunk: HEC token. Datadog: API key. OpenSearch: 'user:password' or Bearer token.
        #[arg(long, env = "AGENTWALL_SIEM_TOKEN", default_value = "")]
        siem_token: String,

        /// SIEM export per-request timeout in seconds (FR-104, default: 2).
        /// Tool calls are not blocked beyond this timeout; SIEM failures fall back to local disk.
        #[arg(long, env = "AGENTWALL_SIEM_TIMEOUT", default_value_t = 2)]
        siem_timeout_secs: u64,

        /// Include raw tool call parameters in the audit log (FR-104).
        /// WARNING: may expose PII or secrets. Only enable in dedicated secure logging environments.
        /// Default: params are hashed (SHA-256) rather than stored in plaintext.
        #[arg(long, env = "AGENTWALL_INCLUDE_PARAMS", default_value_t = false)]
        include_params: bool,
    },

    /// Validate a policy against a gateway instance using fixture test calls (FR-204)
    ///
    /// ## v6.1 Behavior
    ///
    /// File-only validation (without --gateway) is DEPRECATED. Policies must be validated
    /// against a deployed gateway instance in CI/CD pipelines to accurately simulate
    /// runtime DLP, cycle detection, and OIDC validation behavior.
    ///
    /// Use --gateway to point to a test gateway and --oidc-token for authentication.
    Test {
        /// YAML policy file path
        #[arg(long)]
        policy: String,

        /// Show DENY verdicts but exit 0 (for review without blocking CI)
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// JSON fixture file
        fixture: String,

        /// Gateway endpoint URL for v6.1 gateway-mode validation (recommended)
        ///
        /// Example: --gateway https://agentwall.internal.corp/
        #[arg(long, env = "VEXA_GATEWAY_URL")]
        gateway: Option<String>,

        /// OIDC Bearer token for authenticating with the gateway
        #[arg(long, env = "AGENTWALL_OIDC_TOKEN")]
        oidc_token: Option<String>,
    },

    /// Validate and sign a policy for production (FR-204)
    Promote {
        /// YAML policy file to promote
        #[arg(long)]
        policy: String,

        /// Path to the Ed25519 private key (PEM or raw bytes)
        /// If not provided, a temporary key will be generated for demo purposes.
        #[arg(long)]
        key: Option<String>,
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

    /// [DEPRECATED v6.1] Generate a starter policy from a dry-run audit log
    ///
    /// ## Removed in v6.1
    ///
    /// `agentwall init` encouraged ad-hoc policy creation outside of version control.
    /// Enterprise security policies require GitOps workflows with peer review, automated
    /// validation, and CI/CD deployment.
    ///
    /// ## Migration
    ///
    /// 1. Author policy YAML files directly in your GitOps repository.
    /// 2. Use provided policy templates as a starting point.
    /// 3. Validate with: `agentwall test --gateway <URL> --policy policy.yaml fixture.json`
    /// 4. Deploy via CI/CD pipeline with `--gateway` pointing to your test environment.
    Init {
        /// Audit log to derive policy from
        #[arg(long)]
        from_log: String,

        /// Output policy file path
        #[arg(long, default_value = "policy.yaml")]
        output: String,
    },

    /// Automatically wrap an existing agent command with AgentWall (FR-301, FR-302)
    Wrap {
        /// The command to wrap (e.g. "npx @modelcontextprotocol/server-memory")
        #[arg(long)]
        command: Option<String>,

        /// Automatically detect and wrap known agents
        #[arg(long, default_value_t = false)]
        auto_detect: bool,

        /// YAML policy file path
        #[arg(long)]
        policy: Option<String>,

        /// Dry-run mode: log violations but allow calls
        #[arg(long, env = "AGENTWALL_DRY_RUN", default_value_t = false)]
        dry_run: bool,

        /// Kill mode [DEPRECATED in v6.1 — only 'connection' is supported]
        ///
        /// 'process' and 'both' have been removed. Remove this flag from your configuration.
        #[arg(long, default_value = "connection")]
        kill_mode: String,

        /// Audit log output path
        #[arg(long, env = "AGENTWALL_LOG_PATH", default_value = "audit.log")]
        log_path: String,

        /// Enable balanced security profile (placeholder for future graduated security)
        #[arg(long, default_value_t = false)]
        balanced: bool,

        /// Enable strict security profile (placeholder for future graduated security)
        #[arg(long, default_value_t = false)]
        strict: bool,

        /// Enable response scanning for secret detection (FR-303b)
        #[arg(long, default_value_t = false)]
        scan_responses: bool,

        /// Block entire response on secret detection instead of redacting (FR-303b)
        #[arg(long, default_value_t = false)]
        block_on_secrets: bool,

        /// Maximum response size to scan in bytes (FR-303b, default: 1MB)
        #[arg(long, default_value_t = 1048576)]
        max_scan_bytes: usize,

        /// Target to wrap (e.g. claude)
        #[command(subcommand)]
        target: Option<WrapTarget>,
    },

    /// Restore AgentWall wrappers
    Unwrap {
        /// Target to unwrap (e.g. claude)
        #[command(subcommand)]
        target: UnwrapTarget,
    },



    /// Internal command used by Claude Desktop to proxy tool calls (FR-304)
    #[command(name = "stdio-proxy", hide = true)]
    StdioProxy {
        /// Trailing arguments: -- <command> <args...>
        #[arg(last = true)]
        args: Vec<String>,

        /// Enable response scanning for secret detection
        #[arg(long, default_value_t = false)]
        scan_responses: bool,

        /// Block entire response on secret detection instead of redacting
        #[arg(long, default_value_t = false)]
        block_on_secrets: bool,

        /// Maximum response size to scan in bytes
        #[arg(long, default_value_t = 1048576)]
        max_scan_bytes: usize,
    },

    /// Validate a tool call payload against a policy file locally (FR-202)
    Validate {
        /// YAML policy file path
        #[arg(long)]
        policy: String,

        /// Name of the tool to evaluate
        #[arg(long)]
        tool: String,

        /// Path to JSON file containing the parameters payload
        #[arg(long)]
        payload: String,
    },

    /// Lint a policy YAML file for schema and security warnings (FR-203)
    Lint {
        /// YAML policy file path
        policy: String,
    },
}

#[derive(Subcommand)]
pub enum WrapTarget {
    /// Wrap Claude Desktop MCP servers with AgentWall (FR-304)
    Claude {
        /// Preview what would change without writing (safe)
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Enable response scanning for secret detection (FR-303b)
        #[arg(long, default_value_t = false)]
        scan_responses: bool,

        /// Block entire response on secret detection instead of redacting
        #[arg(long, default_value_t = false)]
        block_on_secrets: bool,
    },
}

#[derive(Subcommand)]
pub enum UnwrapTarget {
    /// Restore Claude Desktop config from the most recent AgentWall backup (FR-304)
    Claude {
        /// Restore even if backup is missing — prints manual cleanup instructions
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}
