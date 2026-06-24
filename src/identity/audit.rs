//! FR-22: `agentwall identity audit` command
//!
//! Displays the full HMAC-chained credential history for an agent.
//! Verifies chain integrity before display and reports any tampering.
//!
//! # Usage
//! ```bash
//! agentwall identity audit --agent my-agent
//! agentwall identity audit --agent my-agent --verify  # verify chain integrity
//! ```
//!
//! # AC-22.5
//! `identity audit` returns a complete history of credential issuance,
//! rotation, and revocation events, all HMAC-chained.

use colored::*;

use crate::identity::audit_log::{IdentityAuditLogger, IdentityEventType};

/// Execute `agentwall identity audit`.
///
/// # Arguments
/// - `agent_id`: Agent to display audit history for
/// - `verify`: If true, verify the HMAC chain before display
///
/// # Returns
/// Exit code: 0 = success, 1 = tampering detected or read error, 2 = no entries
pub fn run_identity_audit(agent_id: &str, verify: bool) -> i32 {
    let logger = IdentityAuditLogger::new();

    // 1. Optionally verify chain integrity first
    if verify {
        print!("{} Verifying HMAC chain integrity... ", "ℹ".blue());
        match logger.verify_chain() {
            Ok(count) => {
                println!(
                    "{} ({} entries verified)",
                    "VALID".green().bold(),
                    count.to_string().cyan()
                );
            }
            Err(e) => {
                println!("{}", "CHAIN BROKEN".red().bold());
                eprintln!("{} {}", "✖".red(), e);
                eprintln!(
                    "{}",
                    "  ⚠  Identity audit log has been tampered with. Evidence may be inadmissible."
                        .red()
                );
                return 1;
            }
        }
    }

    // 2. Read entries for the agent
    let entries = match logger.read_for_agent(agent_id) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} Cannot read identity audit log: {}", "✖".red(), e);
            return 1;
        }
    };

    if entries.is_empty() {
        println!(
            "{} No identity audit entries found for agent '{}'.",
            "ℹ".blue(),
            agent_id.cyan()
        );
        println!(
            "{}",
            "  Hint: Run 'agentwall identity create --agent <name>' to provision a credential."
                .yellow()
        );
        return 2;
    }

    // 3. Print header
    println!("{}", "─".repeat(70).cyan());
    println!(
        "{}  Identity Audit History — {}",
        "🔍".blue(),
        agent_id.cyan().bold()
    );
    println!("{}", "─".repeat(70).cyan());
    println!(
        "  {:<5} {:<20} {:<15} {:<15} {}",
        "#".bold(),
        "Timestamp".bold(),
        "Event".bold(),
        "Credential".bold(),
        "Description".bold()
    );
    println!("{}", "─".repeat(70).cyan());

    // 4. Print each entry
    for entry in &entries {
        let event_colored = match entry.event_type {
            IdentityEventType::Issued => "ISSUED".green().bold(),
            IdentityEventType::Rotated => "ROTATED".yellow().bold(),
            IdentityEventType::Revoked => "REVOKED".red().bold(),
            IdentityEventType::Expired => "EXPIRED".red().dimmed(),
            IdentityEventType::ScopeChanged => "SCOPE_CHG".cyan().bold(),
            IdentityEventType::ValidationFailed => "FAIL".red().bold(),
            IdentityEventType::Used => "USED".dimmed(),
        };

        // Truncate credential ID for display
        let cred_short = if entry.credential_id.len() > 12 {
            format!("{}...", &entry.credential_id[..12])
        } else {
            entry.credential_id.clone()
        };

        // Format timestamp as short readable form
        let ts_short = &entry.timestamp[..19]; // "2026-06-22T21:00:00"

        // Truncate description
        let desc_truncated = if entry.description.len() > 30 {
            format!("{}...", &entry.description[..30])
        } else {
            entry.description.clone()
        };

        println!(
            "  {:<5} {:<20} {:<15} {:<15} {}",
            entry.index.to_string().dimmed(),
            ts_short.dimmed(),
            event_colored,
            cred_short.cyan(),
            desc_truncated.dimmed()
        );

        // Show new_credential_id for ROTATED events
        if let Some(ref new_cred_id) = entry.new_credential_id {
            let new_short = if new_cred_id.len() > 12 {
                format!("{}...", &new_cred_id[..12])
            } else {
                new_cred_id.clone()
            };
            println!(
                "  {:<5} {:<20} {:<15} {} {}",
                "",
                "",
                "  → new:".dimmed(),
                new_short.green(),
                "(rotated to)".dimmed()
            );
        }
    }

    println!("{}", "─".repeat(70).cyan());
    println!(
        "  Total: {} events | Authorized by: {} | Backend: {}",
        entries.len().to_string().cyan(),
        entries
            .first()
            .map(|e| e.authorized_by.as_str())
            .unwrap_or("unknown")
            .yellow(),
        entries
            .first()
            .map(|e| e.vault_backend.as_str())
            .unwrap_or("unknown")
            .cyan()
    );
    println!("{}", "─".repeat(70).cyan());

    // 5. Show chain verification hint if not already done
    if !verify {
        println!(
            "  {} Run with {} to verify HMAC chain integrity.",
            "ℹ".blue(),
            "--verify".yellow()
        );
    }

    0
}
