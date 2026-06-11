//! FR-3: Local Web Dashboard — embedded HTML module.
//!
//! The dashboard HTML is embedded at compile time via `include_str!()`.
//! It is served by the proxy server at `GET /` when `agentwall dev` is running.
//! No external files or Node.js are required — the entire UI ships inside the binary.

/// Returns the embedded dashboard HTML for the local developer web UI.
pub fn dashboard_html() -> &'static str {
    include_str!("dashboard.html")
}
