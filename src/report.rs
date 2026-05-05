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
    pub policy_version: Option<String>,
    pub policy_hash: Option<String>,
    pub policy: Option<String>,
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
    policy_loaded: bool,
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
        policy_version: if policy_loaded { Some("1".to_string()) } else { None },
        policy_hash: if policy_loaded { Some(policy_hash.to_string()) } else { None },
        policy: None,
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
    use colored::*;
    let mut out = String::new();
    
    let title = " AgentWall Session Report ".bold().white().on_cyan();
    out.push_str(&format!("\n{}\n", title));
    out.push_str(&format!("{}\n", "─".repeat(60).cyan()));
    
    out.push_str(&format!("  {:<12} {}\n", "Session:".bold(), report.session_id.cyan()));
    
    if let Some(hash) = &report.policy_hash {
        let hash_disp = if hash.len() > 19 {
            &hash[0..19]
        } else {
            hash
        };
        out.push_str(&format!("  {:<12} {}...\n", "Policy:".bold(), hash_disp.yellow()));
    } else {
        out.push_str(&format!("  {:<12} {}\n", "Policy:".bold(), "None (Allow-all sentinel)".red()));
    }
    
    let mode_str = if report.dry_run { 
        "DRY-RUN (Logging Only)".yellow().bold() 
    } else { 
        "ENFORCEMENT (Active Blocking)".green().bold() 
    };
    out.push_str(&format!("  {:<12} {}\n", "Mode:".bold(), mode_str));
    
    out.push_str(&format!(
        "  {:<12} {} → {}\n",
        "Duration:".bold(),
        report.started_at.dimmed(),
        report.ended_at.dimmed()
    ));
    out.push_str(&format!("{}\n\n", "─".repeat(60).cyan()));

    // Summary Box
    out.push_str(&format!("  {}   {} total calls\n", "📊".blue(), report.summary.total_calls.to_string().bold()));
    out.push_str(&format!("  {}   {} allowed\n", "✅".green(), report.summary.allowed.to_string().green()));
    
    if report.dry_run {
        out.push_str(&format!("  {}   {} dry-run violations\n", "⚠ ".yellow(), report.summary.dry_run_denied.to_string().yellow()));
    } else {
        out.push_str(&format!("  {}   {} blocked\n", "🚫".red(), report.summary.denied.to_string().red()));
    }
    
    if report.summary.rate_limited > 0 {
        out.push_str(&format!("  {}   {} rate limited\n", "⏳".blue(), report.summary.rate_limited.to_string().blue()));
    }
    out.push_str("\n");

    // Tools Table
    out.push_str(&format!("  {}\n", "Tools Observed:".bold().underline()));
    if report.tools_used.is_empty() {
        out.push_str("    (None recorded)\n");
    } else {
        for t in &report.tools_used {
            out.push_str(&format!(
                "    {:<20} {:>4} calls   ({})\n",
                t.name.cyan(),
                t.call_count.to_string().bold(),
                format!("first: {}", t.first_called).dimmed()
            ));
        }
    }
    out.push_str("\n");

    // Violations List
    if !report.denied_calls.is_empty() {
        let violation_title = if report.dry_run {
            "Policy Violations (Dry-Run):".bold().yellow().underline()
        } else {
            "Denied Calls:".bold().red().underline()
        };
        out.push_str(&format!("  {}\n", violation_title));
        
        for call in &report.denied_calls {
            let mut params_str = String::new();
            if !call.params_redacted {
                if let Some(p) = &call.params {
                    params_str = format!("  params={}", p).dimmed().to_string();
                }
            }
            out.push_str(&format!(
                "    [{}] {:<18}  reason={}{}\n",
                call.ts.dimmed(),
                call.tool.bold(),
                call.reason.yellow(),
                params_str
            ));
        }
        out.push_str("\n");
    }

    // Warnings
    if report.object_param_blind_passthrough {
        out.push_str(&format!("  {} {}\n", "⚠".yellow(), "OBJECT PARAM WARNING:".bold().yellow()));
        out.push_str("    The following tools use complex objects/arrays which were NOT validated:\n");
        out.push_str(&format!("    {}\n\n", report.object_param_tools.join(", ").dimmed()));
    }

    if report.policy_hash.is_none() {
        out.push_str(&format!("  {} {}\n\n", "⚠".red(), "CRITICAL: No policy loaded during this session.".bold().red()));
    }

    // Footer / Next Steps
    out.push_str(&format!("{}\n", "─".repeat(60).cyan()));
    out.push_str(&format!("  {}\n", "Next Steps:".bold()));
    if report.policy_hash.is_none() || report.dry_run {
        out.push_str(&format!("    Run `{}` to generate your rules.\n", "agentwall init --from-log audit.log".cyan()));
    } else {
        out.push_str("    Review denied calls and refine your policy regex patterns.\n");
    }
    out.push_str(&format!("{}\n", "─".repeat(60).cyan()));

    out
}
