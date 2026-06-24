//! FR-22: `agentwall identity rotate` command
//!
//! Rotates agent credentials with zero downtime.
//!
//! ## Zero-Downtime Rotation (AC-22.3)
//!
//! 1. Issues a NEW credential with the same scope and TTL as the current one.
//! 2. Marks the OLD credential as `Draining` — valid for `drain_secs` after rotation.
//! 3. After the drain period, explicitly revokes the old credential in Vault.
//! 4. Appends a `ROTATED` event to the HMAC identity audit chain.
//!
//! # Usage
//! ```bash
//! agentwall identity rotate --agent my-agent
//! agentwall identity rotate --agent my-agent --drain-secs 60
//! ```

use std::thread;
use std::time::Duration;

use colored::*;

use crate::identity::{
    audit_log::{IdentityAuditEntryBuilder, IdentityAuditLogger, IdentityEventType},
    credential::{AgentCredential, CredentialStatus},
    vault::VaultConfig,
};
use crate::logging::{self, Level};

/// Execute `agentwall identity rotate`.
///
/// # Arguments
/// - `agent_id`: Agent to rotate credentials for
/// - `drain_secs`: How long the old credential remains valid after rotation
///
/// # Returns
/// Exit code: 0 = success, 1 = error
pub fn run_identity_rotate(agent_id: &str, drain_secs: u64) -> i32 {
    println!(
        "{} Rotating credentials for agent '{}' (drain: {}s)...",
        "🔄".yellow(),
        agent_id.cyan(),
        drain_secs.to_string().yellow()
    );

    // 1. Load the existing credential binding
    let mut old_cred = match AgentCredential::load(agent_id) {
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

    if !old_cred.is_valid() {
        eprintln!(
            "{} Existing credential for '{}' is {} (status: {}).",
            "⚠".yellow(),
            agent_id,
            "already expired or revoked".red(),
            old_cred.status
        );
        println!(
            "{}",
            "  → Issuing a fresh credential instead of rotating.".yellow()
        );
    }

    let old_credential_id = old_cred.credential_id.clone();
    let old_vault_cred_id = old_cred.jwt_id.clone().unwrap_or_default();

    // 2. Issue a new credential with the same scope
    let vault_config = VaultConfig::from_env("vault", None);
    let adapter = vault_config.build_adapter();

    let ttl_seconds = crate::identity::credential::parse_ttl(&old_cred.ttl).num_seconds() as u64;

    let issued = match adapter.issue(agent_id, &old_cred.scope, ttl_seconds) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Cannot issue new credential: {}", "✖".red(), e);
            return 1;
        }
    };

    // 3. Build the new credential binding
    let operator = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "agentwall-cli".to_string());

    let mut new_cred = AgentCredential::new(
        agent_id,
        &old_cred.agent_sub,
        &old_cred.scope,
        old_cred.tool_scopes.clone(),
        old_cred.credential_type.clone(),
        adapter.backend_name(),
        &old_cred.ttl,
        drain_secs,
        &operator,
    );
    new_cred.jwt_id = Some(issued.vault_credential_id.clone());

    // 4. Mark old credential as Draining
    old_cred.status = CredentialStatus::Draining;

    // 5. Save the NEW credential binding (overwrites the file)
    if let Err(e) = new_cred.save() {
        eprintln!("{} Cannot save new credential binding: {}", "✖".red(), e);
        return 1;
    }

    // 6. Log the ROTATED event to the identity audit chain
    let audit_logger = IdentityAuditLogger::new();
    let mut audit_entry = IdentityAuditEntryBuilder::new(
        IdentityEventType::Rotated,
        agent_id,
        &old_credential_id,
        &old_cred.scope,
        &operator,
        adapter.backend_name(),
        &format!(
            "Credential rotated for agent '{}'. Old: {} → New: {} (drain: {}s)",
            agent_id, old_credential_id, new_cred.credential_id, drain_secs
        ),
    );
    audit_entry.new_credential_id = Some(new_cred.credential_id.clone());

    if let Err(e) = audit_logger.append(audit_entry) {
        eprintln!("{} Warning: Cannot write rotation audit entry: {}", "⚠".yellow(), e);
    }

    logging::log_event(
        Level::Info,
        "identity_credential_rotated",
        serde_json::json!({
            "agent_id": agent_id,
            "old_credential_id": old_credential_id,
            "new_credential_id": new_cred.credential_id,
            "scope": old_cred.scope,
            "drain_secs": drain_secs,
        }),
    );

    // 7. Print result
    println!("{}", "─".repeat(60).cyan());
    println!("{} Credential rotated successfully", "✓".green().bold());
    println!("{}", "─".repeat(60).cyan());
    println!("  {} {}", "Agent:".bold(), agent_id.cyan());
    println!("  {} {}", "Old Credential ID:".bold(), old_credential_id.dimmed());
    println!("  {} {}", "New Credential ID:".bold(), new_cred.credential_id.cyan());
    println!("  {} {}", "Scope:".bold(), old_cred.scope.green());
    println!(
        "  {} {}",
        "New expires at:".bold(),
        new_cred.expires_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().yellow()
    );
    println!(
        "  {} Old credential valid for {}s (draining)",
        "⏱".yellow(),
        drain_secs.to_string().yellow()
    );
    println!("{}", "─".repeat(60).cyan());
    println!(
        "{} {}",
        "🔑 New Token:".bold().yellow(),
        issued.credential_value.dimmed()
    );
    println!("{}", "─".repeat(60).cyan());
    println!(
        "{}",
        "  ⚠  Update your agent runtime with the new token immediately.".yellow()
    );

    // 8. Schedule old credential revocation after drain period
    // This runs in a background thread so the CLI returns immediately.
    // In production (K8s operator), the operator handles this via a TTL-based watcher.
    if !old_vault_cred_id.is_empty() && drain_secs > 0 {
        let vault_config_clone = VaultConfig::from_env("vault", None);
        let old_id = old_vault_cred_id.clone();
        let agent_id_clone = agent_id.to_string();
        let old_cred_id_clone = old_credential_id.clone();

        thread::spawn(move || {
            thread::sleep(Duration::from_secs(drain_secs));
            let adapter = vault_config_clone.build_adapter();
            match adapter.revoke(&old_id) {
                Ok(()) => {
                    logging::log_event(
                        Level::Info,
                        "identity_credential_revoked_after_drain",
                        serde_json::json!({
                            "agent_id": agent_id_clone,
                            "old_credential_id": old_cred_id_clone,
                            "vault_credential_id": old_id,
                            "drain_secs": drain_secs,
                        }),
                    );
                }
                Err(e) => {
                    logging::log_event(
                        Level::Warn,
                        "identity_credential_revocation_failed",
                        serde_json::json!({
                            "agent_id": agent_id_clone,
                            "vault_credential_id": old_id,
                            "error": e.to_string(),
                        }),
                    );
                }
            }
        });

        println!(
            "  {} Old credential will be revoked after {}s drain period.",
            "ℹ".blue(),
            drain_secs
        );
    }

    0
}
