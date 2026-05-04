//! Session report generation (FR-111)

use chrono::Utc;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Session report matching PRD §6.5
#[derive(Debug, Serialize)]
pub struct SessionReport {
    pub schema_version: String,
    pub proxy_version: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub session_id: String,
    pub dry_run: bool,
    pub started_at: String,
    pub ended_at: String,
    pub kill_mode: String,
    pub summary: ReportSummary,
    pub denied_calls: Vec<DeniedCall>,
    pub tools_used: Vec<ToolUsed>,
    pub object_param_blind_passthrough: bool,
    pub object_param_tools: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReportSummary {
    pub total_calls: u64,
    pub allowed: u64,
    pub denied: u64,
    pub dry_run_denied: u64,
    pub rate_limited: u64,
}

#[derive(Debug, Serialize)]
pub struct DeniedCall {
    pub ts: String,
    pub tool: String,
    pub reason: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub params_redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ToolUsed {
    pub name: String,
    pub call_count: u64,
    pub first_called: String,
}

/// Generate a session report from an audit log file.
pub fn generate_report(
    log_path: &Path,
    include_params: bool,
    policy_hash: &str,
    kill_mode: &str,
    dry_run: bool,
    object_param_tools: Vec<String>,
) -> Result<SessionReport, String> {
    let file = std::fs::File::open(log_path).map_err(|e| format!("Cannot open log: {}", e))?;

    let reader = BufReader::new(file);
    let mut raw_lines = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Read error at line {}: {}", i + 1, e))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        
        // Use from_str but catch trailing characters by allowing partial parse if needed
        // though normally serde_json::from_str is strict.
        let entry: crate::audit::logger::AuditEntry = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(_) => {
                // Fallback: Try to parse just the first object in case of trailing junk
                let mut stream = serde_json::Deserializer::from_str(trimmed).into_iter::<crate::audit::logger::AuditEntry>();
                if let Some(Ok(e)) = stream.next() {
                    e
                } else {
                    return Err(format!("Invalid JSON at line {}: {}", i + 1, line));
                }
            }
        };
        raw_lines.push(entry);
    }

    let mut allowed = 0u64;
    let mut denied = 0u64;
    let mut dry_run_denied = 0u64;
    let mut rate_limited = 0u64;
    let mut denied_calls = Vec::new();
    let mut session_id = String::new();
    let mut started_at = String::new();
    let mut session_dry_run = dry_run;
    let mut tools_map: HashMap<String, ToolUsed> = HashMap::new();

    for entry in &raw_lines {
        if session_id.is_empty() && !entry.session_id.is_empty() {
            session_id = entry.session_id.clone();
            started_at = entry.ts.clone();
        }
        match entry.event.as_str() {
            "dry_run_active" => {
                session_dry_run = true;
            }
            "tool_allow" => {
                allowed += 1;
                let t_name = entry.tool_name.clone().unwrap_or_default();
                let tool_stats = tools_map.entry(t_name.clone()).or_insert_with(|| ToolUsed {
                    name: t_name,
                    call_count: 0,
                    first_called: entry.ts.clone(),
                });
                tool_stats.call_count += 1;
            }
            "tool_deny" => {
                denied += 1;
                denied_calls.push(DeniedCall {
                    ts: entry.ts.clone(),
                    tool: entry.tool_name.clone().unwrap_or_default(),
                    reason: entry.reason.clone().unwrap_or_default(),
                    params_redacted: !include_params,
                    params: if include_params {
                        entry.params.clone()
                    } else {
                        None
                    },
                });
            }
            "tool_dry_run_deny" => {
                dry_run_denied += 1;
                denied_calls.push(DeniedCall {
                    ts: entry.ts.clone(),
                    tool: entry.tool_name.clone().unwrap_or_default(),
                    reason: entry.reason.clone().unwrap_or_default(),
                    params_redacted: !include_params,
                    params: if include_params {
                        entry.params.clone()
                    } else {
                        None
                    },
                });
            }
            "rate_limited" => {
                rate_limited += 1;
            }
            _ => {}
        }
    }

    let total = allowed + denied + dry_run_denied + rate_limited;

    let mut tools_used: Vec<ToolUsed> = tools_map.into_values().collect();
    tools_used.sort_by(|a, b| b.call_count.cmp(&a.call_count)); // sort by frequency

    Ok(SessionReport {
        schema_version: "1".to_string(),
        proxy_version: env!("CARGO_PKG_VERSION").to_string(),
        policy_version: "1".to_string(),
        policy_hash: policy_hash.to_string(),
        session_id,
        dry_run: session_dry_run,
        started_at,
        ended_at: Utc::now().to_rfc3339(),
        kill_mode: kill_mode.to_string(),
        summary: ReportSummary {
            total_calls: total,
            allowed,
            denied,
            dry_run_denied,
            rate_limited,
        },
        denied_calls,
        tools_used,
        object_param_blind_passthrough: !object_param_tools.is_empty(),
        object_param_tools,
    })
}

pub fn format_text_report(report: &SessionReport) -> String {
    let mut out = String::new();
    out.push_str("AgentWall Session Report\n");
    out.push_str("──────────────────────────────\n");
    out.push_str(&format!("Session:     {}\n", report.session_id));
    let hash_disp = if report.policy_hash.len() > 19 {
        &report.policy_hash[0..19]
    } else {
        &report.policy_hash
    };
    out.push_str(&format!("Policy:      {}...\n", hash_disp));
    out.push_str(&format!(
        "Dry-run:     {}\n",
        if report.dry_run { "YES" } else { "NO" }
    ));
    out.push_str(&format!(
        "Duration:    {} → {}\n\n",
        report.started_at, report.ended_at
    ));

    out.push_str(&format!("Calls:  {} total  |  {} allowed  |  {} denied  |  {} dry-run-denied  |  {} rate-limited\n\n",
        report.summary.total_calls, report.summary.allowed, report.summary.denied, report.summary.dry_run_denied, report.summary.rate_limited));

    out.push_str("Denied Calls:\n");
    for call in &report.denied_calls {
        out.push_str(&format!(
            "  [{}] {}  reason={}\n",
            call.ts, call.tool, call.reason
        ));
    }
    if report.denied_calls.is_empty() {
        out.push_str("  (None)\n");
    }
    out.push_str("\nTools Used:\n");
    for t in &report.tools_used {
        out.push_str(&format!(
            "  {}   {} calls  (first: {})\n",
            t.name, t.call_count, t.first_called
        ));
    }
    if report.tools_used.is_empty() {
        out.push_str("  (None)\n");
    }

    if report.object_param_blind_passthrough {
        out.push_str("\n  ⚠ OBJECT PARAM WARNING: The following tools use type:object or type:array parameters\n");
        out.push_str(
            "    whose content was NOT validated in this session (Phase 1 limitation):\n    ",
        );
        out.push_str(&report.object_param_tools.join(", "));
        out.push_str("\n");
    }

    out
}
