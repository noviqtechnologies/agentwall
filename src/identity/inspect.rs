//! FR-22: `agentwall identity inspect` command
//!
//! Inspects a specific credential binding by ID.
//!
//! # Usage
//! ```bash
//! agentwall identity inspect --credential <id>
//! ```

use colored::*;

use crate::identity::{audit_log::IdentityAuditLogger, credential::AgentCredential};

/// Execute `agentwall identity inspect`.
///
/// # Returns
/// Exit code: 0 = success, 1 = error
pub fn run_identity_inspect(credential_id: &str) -> i32 {
    println!(
        "{} Inspecting credential '{}'...",
        "🔍".yellow(),
        credential_id.cyan()
    );

    // Find the credential by scanning all credentials in the directory
    // (In production, this would query Vault or a database)
    let creds_dir = AgentCredential::credentials_dir();
    let mut found_cred: Option<AgentCredential> = None;

    if let Ok(entries) = std::fs::read_dir(creds_dir) {
        for entry in entries.flatten() {
            if entry.path().extension().is_some_and(|e| e == "json") {
                if let Ok(json) = std::fs::read_to_string(entry.path()) {
                    if let Ok(cred) = serde_json::from_str::<AgentCredential>(&json) {
                        if cred.credential_id == credential_id {
                            found_cred = Some(cred);
                            break;
                        }
                    }
                }
            }
        }
    }

    let cred = match found_cred {
        Some(c) => c,
        None => {
            eprintln!(
                "{} Credential '{}' not found locally.",
                "✖".red(),
                credential_id
            );
            return 1;
        }
    };

    println!("{}", "─".repeat(60).cyan());
    println!("{} Credential Details", "📄".blue().bold());
    println!("{}", "─".repeat(60).cyan());
    println!("  {} {}", "Agent ID:".bold(), cred.agent_id.cyan());
    println!("  {} {}", "Credential ID:".bold(), cred.credential_id.cyan());
    println!("  {} {}", "Type:".bold(), cred.credential_type.to_string().yellow());
    println!("  {} {}", "Status:".bold(), cred.status.to_string().magenta());
    println!("  {} {}", "Scope:".bold(), cred.scope.green());
    println!(
        "  {} {}",
        "Issued At:".bold(),
        cred.issued_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().yellow()
    );
    println!(
        "  {} {}",
        "Expires At:".bold(),
        cred.expires_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().yellow()
    );
    println!("  {} {}", "Backend:".bold(), cred.vault_backend.cyan());
    println!("  {} {}", "Authorized By:".bold(), cred.authorized_by.dimmed());
    println!("  {} {}", "Binding Hash:".bold(), cred.binding_hash.dimmed());

    if !cred.tool_scopes.is_empty() {
        println!("{}", "─".repeat(60).cyan());
        println!("  {} Tool Scope Overrides:", "🛠".blue().bold());
        for scope in &cred.tool_scopes {
            let action = if scope.allow { "ALLOW".green() } else { "DENY".red() };
            println!("    - {}: {}", scope.tool.cyan(), action);
        }
    }

    println!("{}", "─".repeat(60).cyan());

    // Look up usage history from the audit log
    println!("  {} Usage History:", "📜".blue().bold());
    let audit_logger = IdentityAuditLogger::new();
    if let Ok(entries) = audit_logger.read_for_agent(&cred.agent_id) {
        let cred_entries: Vec<_> = entries
            .into_iter()
            .filter(|e| e.credential_id == credential_id || e.new_credential_id.as_deref() == Some(credential_id))
            .collect();

        if cred_entries.is_empty() {
            println!("    {}", "No audit history found for this credential.".dimmed());
        } else {
            for entry in cred_entries {
                let event = entry.event_type.to_string();
                let event_colored = match event.as_str() {
                    "ISSUED" => event.green(),
                    "ROTATED" => event.yellow(),
                    "REVOKED" => event.red(),
                    _ => event.normal(),
                };
                let ts_short = &entry.timestamp[..19];
                println!(
                    "    {} {} {}",
                    ts_short.dimmed(),
                    event_colored,
                    entry.description.dimmed()
                );
            }
        }
    } else {
        println!("    {}", "Cannot read audit history.".red());
    }

    println!("{}", "─".repeat(60).cyan());

    0
}
