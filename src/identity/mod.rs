//! FR-22: Agent Identity & Credential Governance Platform
//!
//! This module is the **product redefinition** of AgentWall v2.0.
//!
//! AgentWall is no longer just an agent firewall — it is the system that
//! provisions, scopes, rotates, and audits agent credentials. Every enterprise
//! deploying AI agents needs this. No dominant open-source player owns this
//! space. **This is the enterprise lock.**
//!
//! ## The Core Problem Solved
//!
//! Agents currently hold long-lived credentials in environment variables.
//! These credentials are over-permissioned, manually rotated (or never rotated),
//! and represent a persistent attack surface.
//!
//! AgentWall v2.0 becomes the broker: agents request short-lived, scoped
//! credentials at runtime. AgentWall issues them from the configured vault
//! (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault). The agent never
//! holds a long-lived credential.
//!
//! ## CLI Commands
//!
//! ```bash
//! agentwall identity create --agent <name> --scope <scope> --ttl <ttl>
//! agentwall identity rotate --agent <name>
//! agentwall identity audit  --agent <name>
//! agentwall identity scope  --agent <name> --tool <tool> --allow|--deny
//! agentwall identity inspect --credential <id>
//! ```
//!
//! ## Architecture
//!
//! ```text
//! Agent Runtime
//!      │
//!      │ 1. "I need credentials for read_file"
//!      ▼
//! AgentWall Identity Platform (this module)
//!      │ 2. Validate agent identity (OIDC)
//!      │ 3. Check scope policy
//!      │ 4. Request dynamic secret from Vault / AWS SM / Azure KV
//!      │ 5. Issue short-lived JWT (1h TTL)
//!      │ 6. Bind credential to agent sub claim
//!      │ 7. Log to HMAC audit chain
//!      │
//!      │ 8. Return scoped credential
//!      ▼
//! Agent Runtime
//!      │ 9. Use credential for tool call
//!      ▼
//! AgentWall Enforcement Gateway
//!      │ 10. Validate JWT + credential scope before policy eval
//! ```

pub mod audit;
pub mod audit_log;
pub mod create;
pub mod credential;
pub mod inspect;
pub mod rotate;
pub mod scope;
pub mod scope_validator;
pub mod vault;

pub use credential::AgentCredential;
pub use scope_validator::{CredentialScopeCheckResult, IdentityScopeValidator};

/// FR-22: Identity subcommand routing
#[derive(Debug)]
pub enum IdentityCommand {
    /// Provision a new scoped, short-lived credential for an agent
    Create {
        agent: String,
        scope: String,
        ttl: String,
        rotation_policy: Option<String>,
    },
    /// Rotate agent credentials with zero downtime
    Rotate {
        agent: String,
        drain_secs: u64,
    },
    /// Display the full HMAC-chained credential audit history
    Audit {
        agent: String,
        verify: bool,
    },
    /// Set per-tool-call credential scoping rules
    Scope {
        agent: String,
        tool: String,
        allow: bool,
        policy_path: String,
    },
    /// Inspect a specific credential binding
    Inspect {
        credential_id: String,
    },
}

/// Execute an identity subcommand.
///
/// Returns an exit code (0 = success, 1 = error, 2 = validation failure).
pub fn run_identity(cmd: IdentityCommand) -> i32 {
    match cmd {
        IdentityCommand::Create {
            agent,
            scope,
            ttl,
            rotation_policy,
        } => create::run_identity_create(&agent, &scope, &ttl, rotation_policy.as_deref()),
        IdentityCommand::Rotate { agent, drain_secs } => {
            rotate::run_identity_rotate(&agent, drain_secs)
        }
        IdentityCommand::Audit { agent, verify } => {
            audit::run_identity_audit(&agent, verify)
        }
        IdentityCommand::Scope {
            agent,
            tool,
            allow,
            policy_path,
        } => scope::run_identity_scope(&agent, &tool, allow, &policy_path),
        IdentityCommand::Inspect { credential_id } => {
            inspect::run_identity_inspect(&credential_id)
        }
    }
}
