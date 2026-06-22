//! FR-5: Credential Scope Validator (stub — FR-22 Identity Platform integration pending)
//!
//! Reads `credential_scope` arrays from policy tool blocks and validates them against
//! the `X-AgentWall-Credential-Scope` HTTP header sent by identity-aware agents.
//!
//! ## Behavior (v2.0 stub)
//!
//! | Mode                      | On mismatch                              |
//! |---------------------------|------------------------------------------|
//! | Default                   | WARN — log and continue                  |
//! | `--strict-credential-scope` | DENY — return 403 Credential Scope Insufficient |
//!
//! Full integration with HashiCorp Vault / AWS Secrets Manager / Azure Key Vault
//! is deferred until FR-22 (Agent Identity Platform) is implemented.

use crate::logging::{self, Level};
use serde_json::json;

/// Result of credential scope validation.
#[derive(Debug, Clone, PartialEq)]
pub enum CredentialScopeResult {
    /// Scope is permitted (or no scope configured for this tool).
    Permitted,
    /// Scope is insufficient — returns reason string.
    Insufficient { reason: String },
    /// No credential scope configured for this tool — always permitted.
    NotConfigured,
}

/// Validates agent credential scopes against per-tool policy rules.
///
/// This is a local stub implementation. When FR-22 (Agent Identity Platform) is
/// available, this will integrate with the identity platform's credential broker.
pub struct CredentialScopeValidator {
    /// When true, scope mismatches result in DENY rather than WARN.
    pub strict: bool,
}

impl CredentialScopeValidator {
    /// Create a new validator.
    ///
    /// # Arguments
    /// * `strict` — if `true`, scope mismatches cause a hard DENY (`--strict-credential-scope`).
    ///   if `false`, scope mismatches emit a WARN and continue (default).
    pub fn new(strict: bool) -> Self {
        Self { strict }
    }

    /// Validate the agent's declared credential scope against the tool's required scopes.
    ///
    /// # Arguments
    /// * `tool_name` — name of the tool being called.
    /// * `required_scopes` — scopes required by the policy for this tool (from `credential_scope:`).
    /// * `agent_scope_header` — value of the `X-AgentWall-Credential-Scope` header, if present.
    /// * `session_id` — for audit logging.
    pub fn validate(
        &self,
        tool_name: &str,
        required_scopes: &[String],
        agent_scope_header: Option<&str>,
        session_id: &str,
    ) -> CredentialScopeResult {
        // If no scopes are required for this tool, always permit.
        if required_scopes.is_empty() {
            return CredentialScopeResult::NotConfigured;
        }

        // Parse the agent's declared scopes from the header.
        let agent_scopes: Vec<&str> = match agent_scope_header {
            Some(header) if !header.trim().is_empty() => {
                header.split(',').map(|s| s.trim()).collect()
            }
            _ => {
                // No scope header present — agent is not scope-aware.
                // In stub mode, emit a WARN and permit.
                logging::log_event(
                    Level::Warn,
                    "credential_scope_missing_header",
                    json!({
                        "tool": tool_name,
                        "session": session_id,
                        "required_scopes": required_scopes,
                        "note": "Agent sent no X-AgentWall-Credential-Scope header. FR-22 Identity Platform integration pending.",
                        "strict": self.strict,
                    }),
                );

                if self.strict {
                    return CredentialScopeResult::Insufficient {
                        reason: format!(
                            "Tool '{}' requires credential scope {:?} but agent sent no X-AgentWall-Credential-Scope header. \
                             Use --strict-credential-scope=false to warn instead of deny.",
                            tool_name, required_scopes
                        ),
                    };
                }
                // WARN mode: permit and continue.
                return CredentialScopeResult::Permitted;
            }
        };

        // Check that the agent holds at least one of the required scopes.
        let has_required = required_scopes.iter().any(|req| {
            agent_scopes.contains(&req.as_str())
                || agent_scopes.contains(&"*") // wildcard scope grants all
        });

        if has_required {
            CredentialScopeResult::Permitted
        } else {
            let reason = format!(
                "Tool '{}' requires one of {:?} but agent declared scopes {:?}",
                tool_name, required_scopes, agent_scopes
            );

            logging::log_event(
                Level::Warn,
                "credential_scope_insufficient",
                json!({
                    "tool": tool_name,
                    "session": session_id,
                    "required_scopes": required_scopes,
                    "agent_scopes": agent_scopes,
                    "strict": self.strict,
                    "action": if self.strict { "deny" } else { "warn" },
                    "note": "FR-22 Identity Platform integration pending. Stub validator active.",
                }),
            );

            if self.strict {
                CredentialScopeResult::Insufficient { reason }
            } else {
                // WARN mode — log but permit.
                CredentialScopeResult::Permitted
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scopes(s: &[&str]) -> Vec<String> {
        s.iter().map(|&x| x.to_string()).collect()
    }

    #[test]
    fn test_not_configured_when_no_scopes_required() {
        let v = CredentialScopeValidator::new(false);
        assert_eq!(
            v.validate("read_file", &[], None, "sess-1"),
            CredentialScopeResult::NotConfigured
        );
    }

    #[test]
    fn test_warn_mode_permits_when_no_header() {
        let v = CredentialScopeValidator::new(false);
        let result = v.validate("read_file", &make_scopes(&["read-only"]), None, "sess-1");
        // WARN mode: permit even when header is missing
        assert_eq!(result, CredentialScopeResult::Permitted);
    }

    #[test]
    fn test_strict_mode_denies_when_no_header() {
        let v = CredentialScopeValidator::new(true);
        let result = v.validate("read_file", &make_scopes(&["read-only"]), None, "sess-1");
        assert!(matches!(result, CredentialScopeResult::Insufficient { .. }));
    }

    #[test]
    fn test_permitted_when_scope_matches() {
        let v = CredentialScopeValidator::new(true);
        let result = v.validate(
            "read_file",
            &make_scopes(&["read-only", "read-write"]),
            Some("read-only, audit"),
            "sess-1",
        );
        assert_eq!(result, CredentialScopeResult::Permitted);
    }

    #[test]
    fn test_insufficient_when_scope_mismatch_strict() {
        let v = CredentialScopeValidator::new(true);
        let result = v.validate(
            "delete_file",
            &make_scopes(&["admin"]),
            Some("read-only"),
            "sess-1",
        );
        assert!(matches!(result, CredentialScopeResult::Insufficient { .. }));
    }

    #[test]
    fn test_warn_mode_permits_on_mismatch() {
        let v = CredentialScopeValidator::new(false);
        let result = v.validate(
            "delete_file",
            &make_scopes(&["admin"]),
            Some("read-only"),
            "sess-1",
        );
        // WARN mode: log but permit
        assert_eq!(result, CredentialScopeResult::Permitted);
    }

    #[test]
    fn test_wildcard_scope_permits_all() {
        let v = CredentialScopeValidator::new(true);
        let result = v.validate(
            "any_tool",
            &make_scopes(&["admin", "write"]),
            Some("*"),
            "sess-1",
        );
        assert_eq!(result, CredentialScopeResult::Permitted);
    }
}
