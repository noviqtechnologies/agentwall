//! Kill switch — connection termination only (v6.1)
//!
//! ## v6.1 Deprecation Notice
//!
//! `--kill-mode process` and `--kill-mode both` have been **removed** in v6.1.
//!
//! **Reason:** The central gateway cannot reliably send SIGKILL signals to remote
//! agent processes across network boundaries. The enforcement boundary for the
//! gateway is the MCP connection itself. Connection termination (`--kill-mode connection`)
//! is the only supported enforcement mechanism.
//!
//! **Migration:** Remove `--kill-mode` from your startup configuration. Connection
//! termination is now the default and only mode. Design agents to handle JSON-RPC
//! connection errors gracefully per the v6.1 agent design guidance.

use crate::logging::{self, Level};

/// Kill mode — v6.1: only `Connection` is supported.
///
/// `Process` and `Both` are retained as enum variants for internal deserialization
/// compatibility but are rejected by `from_str` at the CLI boundary.
#[derive(Debug, Clone, PartialEq)]
pub enum KillMode {
    /// Terminate the MCP connection (default and only supported mode in v6.1).
    Connection,
    /// DEPRECATED in v6.1. Use `Connection` instead.
    #[deprecated(
        since = "6.1.0",
        note = "process kill mode is removed in v6.1. The gateway cannot reliably send SIGKILL to remote processes across network boundaries. Connection termination is the enforcement boundary."
    )]
    Process,
    /// DEPRECATED in v6.1. Use `Connection` instead.
    #[deprecated(
        since = "6.1.0",
        note = "both kill mode is removed in v6.1. Use connection termination only."
    )]
    Both,
}

impl KillMode {
    /// Parse a kill mode string from the CLI.
    ///
    /// In v6.1, only `"connection"` is accepted. `"process"` and `"both"` return
    /// an error with a migration message.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "connection" => Ok(KillMode::Connection),
            "process" => Err(
                "--kill-mode process is removed in v6.1. \
                The gateway cannot reliably send SIGKILL to remote agent processes across \
                network boundaries. Connection termination is the security enforcement boundary. \
                Remove --kill-mode from your configuration (connection is now the default).".to_string()
            ),
            "both" => Err(
                "--kill-mode both is removed in v6.1. \
                Connection termination is the only supported enforcement mechanism. \
                Remove --kill-mode from your configuration (connection is now the default).".to_string()
            ),
            other => Err(format!(
                "Invalid kill mode: \"{}\". The only supported value in v6.1 is: connection",
                other
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            KillMode::Connection => "connection",
            #[allow(deprecated)]
            KillMode::Process => "process",
            #[allow(deprecated)]
            KillMode::Both => "both",
        }
    }
}

/// Execute the kill switch after a DENY verdict.
///
/// In v6.1, this always performs connection termination. The connection close
/// is handled by the caller (server layer) dropping the response stream.
pub fn execute_kill(mode: &KillMode, session_id: &str, _agent_pid: Option<u32>) -> bool {
    // v6.1: All modes resolve to connection termination.
    // Process-level kill is not supported across network boundaries.
    logging::log_event(
        Level::Warn,
        "kill_connection",
        serde_json::json!({"session": session_id, "mode": mode.as_str()}),
    );
    true // connection close is handled by the caller dropping the response
}

/// Read agent PID from a PID file.
///
/// Retained for backward compatibility but agent_pid is ignored in v6.1.
pub fn read_pid_file(path: &str) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}
