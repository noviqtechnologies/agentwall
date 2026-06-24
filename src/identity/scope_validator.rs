//! FR-22: Enforcement Gateway Credential Scope Validator
//!
//! Enforces AC-22.10 (per-tool-call scoping). Validates the credential bound to the
//! current tool call request against the credential scope defined in the policy and
//! the local credential binding file.

use crate::identity::credential::AgentCredential;
use crate::logging::{self, Level};
use serde_json::json;

/// Result of identity scope validation
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialScopeCheckResult {
    /// Permitted — credential allows this tool call
    Allowed,
    /// Insufficient — credential lacks required scope or explicitly denies this tool
    Insufficient(String),
    /// Expired — credential TTL elapsed
    Expired,
    /// Invalid — credential not found or malformed
    Invalid(String),
}

/// Scope validator for the Enforcement Gateway.
/// Replaces the stub in `src/policy/credential_scope.rs`.
pub struct IdentityScopeValidator;

impl IdentityScopeValidator {
    /// Validates an agent's credential for a specific tool call.
    ///
    /// # Arguments
    /// - `agent_id`: The agent making the call (verified via OIDC token)
    /// - `tool_name`: The tool being requested
    /// - `credential_id`: The ID of the credential presented in the request header
    pub fn validate(
        agent_id: &str,
        tool_name: &str,
        credential_id: &str,
    ) -> CredentialScopeCheckResult {
        // 1. Load the credential binding
        let cred = match AgentCredential::load(agent_id) {
            Ok(c) => c,
            Err(_) => {
                return CredentialScopeCheckResult::Invalid(format!(
                    "No valid credential binding found for agent '{}'",
                    agent_id
                ));
            }
        };

        // 2. Verify credential ID matches
        if cred.credential_id != credential_id {
            // Check if it's the draining credential (rotation in progress)
            // (In a full implementation, we'd lookup by credential_id, but here
            // we just load the agent's active credential for simplicity).
            return CredentialScopeCheckResult::Invalid(format!(
                "Presented credential '{}' does not match active credential '{}'",
                credential_id, cred.credential_id
            ));
        }

        // 3. Verify TTL
        if !cred.is_valid() {
            return CredentialScopeCheckResult::Expired;
        }

        // 4. Check per-tool scope (AC-22.10)
        if !cred.permits_tool(tool_name) {
            let msg = format!(
                "Credential '{}' (scope: '{}') does not permit tool '{}'",
                credential_id, cred.scope, tool_name
            );

            logging::log_event(
                Level::Warn,
                "credential_scope_insufficient",
                json!({
                    "agent_id": agent_id,
                    "credential_id": credential_id,
                    "scope": cred.scope,
                    "tool": tool_name,
                    "action": "deny",
                }),
            );

            return CredentialScopeCheckResult::Insufficient(msg);
        }

        CredentialScopeCheckResult::Allowed
    }
}
