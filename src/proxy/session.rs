//! Multi-tenant agent session context and isolation manager (FR-101)

use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

use crate::policy::engine::CompiledPolicy;
use crate::proxy::handler::{RateLimiter, ToolCallFingerprint};

/// A completely isolated context for a single active AI agent session.
/// Enforces absolute isolation of rate limiting, cycle detection, policy contexts, and logs (FR-101).
pub struct SessionContext {
    /// Unique session UUID generated dynamically by the gateway
    pub session_id: String,
    
    /// Optional authenticated subject identity from Okta/Entra ID OIDC claim
    pub identity_sub: Option<String>,
    
    /// Optional authenticated email identity from Okta/Entra ID OIDC claim
    pub identity_email: Option<String>,
    
    /// The frozen compiled policy context active at the moment of session initiation.
    /// This ensures that policy hot-reloads do not disrupt in-flight sessions (FR-106).
    pub policy: Option<CompiledPolicy>,
    
    /// Isolated token-bucket rate limiter for this specific session context
    pub rate_limiter: RateLimiter,
    
    /// Isolated sliding window of tool call fingerprints for cycle detection / loop prevention
    pub tool_history: Mutex<Vec<ToolCallFingerprint>>,
    
    /// The precise timestamp when this session was initialized
    pub start_time: Instant,

    /// Isolated client remote IP address (FR-201)
    pub request_ip: Option<String>,
}

impl SessionContext {
    /// Create a new isolated session context bound to a validated OIDC identity or client token.
    /// Freezes the active policy rules at session startup to protect in-flight workflows (FR-106).
    pub fn new(
        identity_sub: Option<String>,
        identity_email: Option<String>,
        active_policy: Option<CompiledPolicy>,
        request_ip: Option<String>,
    ) -> Self {
        let session_id = Uuid::new_v4().to_string();
        let start_time = Instant::now();

        // Resolve rate limit. Check if policy specifies a default session rate limit
        let limit = active_policy
            .as_ref()
            .map(|p| p.max_calls_per_second)
            .unwrap_or(0);

        Self {
            session_id,
            identity_sub,
            identity_email,
            policy: active_policy,
            rate_limiter: RateLimiter::new(limit),
            tool_history: Mutex::new(Vec::new()),
            start_time,
            request_ip,
        }
    }
}
