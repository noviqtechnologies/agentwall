//! FR-22: `agentwall identity scope` command
//!
//! Modifies the per-tool-call credential scope rules for an agent.
//!
//! ## Behavior
//! This command updates the local `AgentCredential` binding file.
//! In production (Phase 2/3), it will also update the policy YAML or Vault policy.
//!
//! # Usage
//! ```bash
//! agentwall identity scope --agent my-agent --tool execute_shell --deny
//! agentwall identity scope --agent my-agent --tool read_file --allow
//! ```

use colored::*;

use crate::identity::{
    audit_log::{IdentityAuditEntryBuilder, IdentityAuditLogger, IdentityEventType},
    credential::{AgentCredential, ToolScope},
};

/// Execute `agentwall identity scope`.
///
/// # Returns
/// Exit code: 0 = success, 1 = error
pub fn run_identity_scope(agent_id: &str, tool_name: &str, allow: bool, _policy_path: &str) -> i32 {
    let action_str = if allow { "allow".green() } else { "deny".red() };
    println!(
        "{} Updating credential scope for agent '{}' → tool '{}': {}",
        "⚙".yellow(),
        agent_id.cyan(),
        tool_name.cyan(),
        action_str
    );

    // 1. Load the existing credential binding
    let mut cred = match AgentCredential::load(agent_id) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {}", "✖".red(), e);
            eprintln!(
                "{}",
                "  Hint: Run 'agentwall identity create' first to provision a credential.".yellow()
            );
            return 1;
        }
    };

    // 2. Update or insert the tool scope constraint
    let mut updated = false;
    for scope in &mut cred.tool_scopes {
        if scope.tool == tool_name {
            scope.allow = allow;
            updated = true;
            break;
        }
    }

    if !updated {
        cred.tool_scopes.push(ToolScope {
            tool: tool_name.to_string(),
            paths: vec![],
            databases: vec![],
            allow,
        });
    }

    // 3. Save the updated credential binding
    if let Err(e) = cred.save() {
        eprintln!("{} Cannot save updated credential binding: {}", "✖".red(), e);
        return 1;
    }

    // 4. Log the SCOPE_CHANGED event to the identity audit chain
    let operator = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "agentwall-cli".to_string());

    let audit_logger = IdentityAuditLogger::new();
    let mut audit_entry = IdentityAuditEntryBuilder::new(
        IdentityEventType::ScopeChanged,
        agent_id,
        &cred.credential_id,
        &cred.scope,
        &operator,
        &cred.vault_backend,
        &format!(
            "Credential scope updated: tool '{}' set to {}",
            tool_name,
            if allow { "ALLOW" } else { "DENY" }
        ),
    );
    audit_entry.tool_name = Some(tool_name.to_string());

    if let Err(e) = audit_logger.append(audit_entry) {
        eprintln!("{} Warning: Cannot write scope audit entry: {}", "⚠".yellow(), e);
    }

    // 5. Print result
    println!("{}", "─".repeat(60).cyan());
    println!("{} Scope updated successfully", "✓".green().bold());
    println!("{}", "─".repeat(60).cyan());
    println!("  {} {}", "Agent:".bold(), agent_id.cyan());
    println!("  {} {}", "Tool:".bold(), tool_name.cyan());
    println!("  {} {}", "Action:".bold(), action_str);
    println!("  {} {}", "Credential ID:".bold(), cred.credential_id.dimmed());
    println!("{}", "─".repeat(60).cyan());

    0
}
