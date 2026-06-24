//! FR-22: `agentwall identity create` command
//!
//! Provisions a new scoped, short-lived credential for an agent.
//! The credential is issued from the configured vault backend (HashiCorp Vault,
//! AWS Secrets Manager, or Azure Key Vault) and the binding metadata is stored
//! locally at `~/.agentwall/credentials/<agent_name>.json`.
//!
//! # Usage
//! ```bash
//! agentwall identity create --agent my-agent --scope read-only --ttl 1h
//! ```
//!
//! # AC-22.1
//! Credential issuance must complete within 200ms p95 (includes vault round-trip).

use colored::*;

use crate::identity::{
    audit_log::{IdentityAuditEntryBuilder, IdentityAuditLogger, IdentityEventType},
    credential::{AgentCredential, CredentialType},
    vault::{VaultConfig, VaultError},
};
use crate::logging::{self, Level};

/// Execute `agentwall identity create`.
///
/// # Arguments
/// - `agent_id`: The agent name (matches `agents[].id` in policy YAML)
/// - `scope`: The requested credential scope (e.g., "read-only", "analytics")
/// - `ttl`: Time-to-live string (e.g., "1h", "30m")
/// - `rotation_policy`: Optional rotation policy ("daily", "weekly", etc.)
///
/// # Returns
/// Exit code: 0 = success, 1 = error, 2 = configuration error
pub fn run_identity_create(
    agent_id: &str,
    scope: &str,
    ttl: &str,
    rotation_policy: Option<&str>,
) -> i32 {
    println!(
        "{} Provisioning credential for agent '{}' with scope '{}' (TTL: {})...",
        "🔑".yellow(),
        agent_id.cyan(),
        scope.green(),
        ttl.yellow()
    );

    // 1. Load vault configuration from environment
    let vault_config = VaultConfig::from_env("vault", None);
    let adapter = vault_config.build_adapter();

    // 2. Validate inputs
    if agent_id.is_empty() {
        eprintln!("{} Agent ID cannot be empty.", "✖".red());
        return 2;
    }
    if scope.is_empty() {
        eprintln!("{} Scope cannot be empty. Use e.g.: --scope read-only", "✖".red());
        return 2;
    }

    // 3. Validate TTL
    let ttl_duration = crate::identity::credential::parse_ttl(ttl);
    let ttl_seconds = ttl_duration.num_seconds() as u64;
    if ttl_seconds == 0 {
        eprintln!("{} Invalid TTL '{}'. Use format: 1h, 30m, 3600s.", "✖".red(), ttl);
        return 2;
    }

    // 4. Issue credential from vault backend
    let start = std::time::Instant::now();
    let issued = match adapter.issue(agent_id, scope, ttl_seconds) {
        Ok(c) => c,
        Err(VaultError::Unreachable(msg)) => {
            eprintln!(
                "{} {} is unreachable: {}",
                "✖".red(),
                adapter.backend_name(),
                msg
            );
            eprintln!(
                "{}",
                "  Hint: Start a local vault dev server with: vault server -dev".yellow()
            );
            eprintln!(
                "{}",
                "  Or set AGENTWALL_IDENTITY_BACKEND=aws-secrets-manager to use AWS SM.".yellow()
            );
            return 1;
        }
        Err(VaultError::AuthFailed(msg)) => {
            eprintln!("{} Vault authentication failed: {}", "✖".red(), msg);
            eprintln!("{}", "  Hint: Set VAULT_TOKEN for dev mode, or VAULT_ROLE_ID + VAULT_SECRET_ID for production.".yellow());
            return 1;
        }
        Err(VaultError::Configuration(msg)) => {
            eprintln!("{} Vault configuration error: {}", "✖".red(), msg);
            return 2;
        }
        Err(e) => {
            eprintln!("{} Credential issuance failed: {}", "✖".red(), e);
            return 1;
        }
    };
    let elapsed_ms = start.elapsed().as_millis();

    // 5. Build credential binding record
    let operator = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "agentwall-cli".to_string());

    let mut cred = AgentCredential::new(
        agent_id,
        &format!("{}@agentwall.local", agent_id), // sub claim — in production, from OIDC token
        scope,
        vec![],                // tool_scopes — set via `identity scope` command
        CredentialType::Jwt,
        adapter.backend_name(),
        ttl,
        30, // drain_secs default
        &operator,
    );
    cred.jwt_id = Some(issued.vault_credential_id.clone());

    // 6. Save binding to disk
    if let Err(e) = cred.save() {
        eprintln!("{} Cannot save credential binding: {}", "✖".red(), e);
        return 1;
    }

    // 7. Append to identity audit log
    let audit_logger = IdentityAuditLogger::new();
    let audit_entry = IdentityAuditEntryBuilder::new(
        IdentityEventType::Issued,
        agent_id,
        &cred.credential_id,
        scope,
        &operator,
        adapter.backend_name(),
        &format!(
            "Credential issued for agent '{}' with scope '{}' (TTL: {}, backend: {})",
            agent_id, scope, ttl, adapter.backend_name()
        ),
    );

    match audit_logger.append(audit_entry) {
        Ok(entry) => {
            logging::log_event(
                Level::Info,
                "identity_credential_issued",
                serde_json::json!({
                    "agent_id": agent_id,
                    "credential_id": cred.credential_id,
                    "scope": scope,
                    "ttl": ttl,
                    "backend": adapter.backend_name(),
                    "audit_index": entry.index,
                    "elapsed_ms": elapsed_ms,
                }),
            );
        }
        Err(e) => {
            eprintln!("{} Warning: Cannot write identity audit log: {}", "⚠".yellow(), e);
            // Non-fatal — credential was issued, just audit write failed
        }
    }

    // 8. Print result
    println!("{}", "─".repeat(60).cyan());
    println!("{} Credential provisioned successfully", "✓".green().bold());
    println!("{}", "─".repeat(60).cyan());
    println!("  {} {}", "Agent:".bold(), agent_id.cyan());
    println!("  {} {}", "Credential ID:".bold(), cred.credential_id.cyan());
    println!("  {} {}", "Scope:".bold(), scope.green());
    println!("  {} {}", "TTL:".bold(), ttl.yellow());
    println!(
        "  {} {}",
        "Expires at:".bold(),
        cred.expires_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().yellow()
    );
    println!("  {} {}", "Backend:".bold(), adapter.backend_name().cyan());
    println!("  {} {} ms", "Issued in:".bold(), elapsed_ms.to_string().green());

    if let Some(policy) = rotation_policy {
        println!("  {} {}", "Rotation Policy:".bold(), policy.yellow());
    }

    println!("{}", "─".repeat(60).cyan());
    println!(
        "{} {}",
        "🔑 Token:".bold().yellow(),
        issued.credential_value.dimmed()
    );
    println!("{}", "─".repeat(60).cyan());
    println!(
        "{}",
        "  ⚠  Store this token securely. It will not be shown again.".yellow()
    );
    println!(
        "  {}",
        "  Credential binding saved to ~/.agentwall/credentials/<agent>.json".dimmed()
    );
    println!(
        "  {}",
        "  Inject as: export AGENTWALL_AGENT_TOKEN=\"<token>\"".dimmed()
    );
    println!("{}", "─".repeat(60).cyan());

    // Warn if issuance took > 200ms (AC-22.1 threshold)
    if elapsed_ms > 200 {
        println!(
            "{} Credential issuance took {}ms (threshold: 200ms). Check vault latency.",
            "⚠".yellow(),
            elapsed_ms
        );
    }

    0
}
