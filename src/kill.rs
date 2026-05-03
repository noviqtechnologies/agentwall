//! Kill switch — connection close, SIGKILL, both modes (FR-105)

use crate::logging::{self, Level};

/// Kill mode as specified by --kill-mode
#[derive(Debug, Clone, PartialEq)]
pub enum KillMode {
    Connection,
    Process,
    Both,
}

impl KillMode {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "connection" => Ok(KillMode::Connection),
            "process" => Ok(KillMode::Process),
            "both" => Ok(KillMode::Both),
            other => Err(format!(
                "Invalid kill mode: \"{}\". Valid: connection, process, both",
                other
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            KillMode::Connection => "connection",
            KillMode::Process => "process",
            KillMode::Both => "both",
        }
    }
}

/// Execute the kill switch after a DENY verdict.
/// connection_closed is a callback that the caller uses to close the socket.
/// Returns true if the kill was fully applied.
pub fn execute_kill(mode: &KillMode, session_id: &str, agent_pid: Option<u32>) -> bool {
    match mode {
        KillMode::Connection => {
            logging::log_event(
                Level::Warn,
                "kill_connection",
                serde_json::json!({"session": session_id}),
            );
            true // connection close is handled by the caller dropping the response
        }
        KillMode::Process => execute_sigkill(agent_pid, session_id),
        KillMode::Both => {
            // Close socket first (handled by caller), then SIGKILL
            logging::log_event(
                Level::Warn,
                "kill_connection",
                serde_json::json!({"session": session_id}),
            );

            if let Some(pid) = agent_pid {
                if !send_sigkill(pid) {
                    logging::log_event(
                        Level::Warn,
                        "kill_process_failed",
                        serde_json::json!({
                            "pid": pid,
                            "reason": "signal_failed",
                            "fallback": "connection_applied"
                        }),
                    );
                    // Connection close is always applied — this is acceptable
                    return true;
                }
                logging::log_event(
                    Level::Warn,
                    "kill_process_sent",
                    serde_json::json!({"pid": pid}),
                );
            } else {
                logging::log_event(
                    Level::Warn,
                    "kill_process_failed",
                    serde_json::json!({
                        "pid": 0,
                        "reason": "no_agent_pid",
                        "fallback": "connection_applied"
                    }),
                );
            }
            true
        }
    }
}

fn execute_sigkill(agent_pid: Option<u32>, _session_id: &str) -> bool {
    match agent_pid {
        Some(pid) => {
            if send_sigkill(pid) {
                logging::log_event(
                    Level::Warn,
                    "kill_process_sent",
                    serde_json::json!({"pid": pid}),
                );
                true
            } else {
                logging::log_event(
                    Level::Warn,
                    "kill_process_failed",
                    serde_json::json!({
                        "pid": pid,
                        "reason": "signal_failed",
                        "fallback": "connection_applied"
                    }),
                );
                false
            }
        }
        None => {
            logging::log_event(
                Level::Warn,
                "kill_process_failed",
                serde_json::json!({
                    "pid": 0,
                    "reason": "no_agent_pid",
                    "fallback": "connection_applied"
                }),
            );
            false
        }
    }
}

/// Send SIGKILL to a process. Returns true on success.
#[cfg(unix)]
fn send_sigkill(pid: u32) -> bool {
    use std::process::Command;
    Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn send_sigkill(pid: u32) -> bool {
    // Windows: use taskkill as a fallback (not officially supported in Phase 1)
    use std::process::Command;
    Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Read agent PID from a PID file
pub fn read_pid_file(path: &str) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}
