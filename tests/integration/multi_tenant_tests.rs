use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use serde_json::json;
use agentwall::proxy::handler::{evaluate_jsonrpc, ProxyAction, ProxyState, RateLimiter};
use agentwall::policy::engine::CompiledPolicy;
use agentwall::policy::schema::{FirewallConfig, CycleDetectionConfig, CycleAction};
use agentwall::audit::logger::{AuditLogger, AuditLoggerConfig};
use agentwall::kill::KillMode;
use agentwall::policy::safe_mode::SafeModeScanner;
use agentwall::policy::response_scanner::{ResponseScanner, ResponseScanConfig};
use agentwall::proxy::session::SessionContext;

fn create_mock_proxy_state(policy: Option<CompiledPolicy>) -> Arc<ProxyState> {
    let log_path = std::env::temp_dir().join(format!("multi_tenant_test_{}.log", uuid::Uuid::new_v4()));
    let config = AuditLoggerConfig {
        log_path,
        session_id: "multi-tenant-test-session".to_string(),
        session_secret: b"secret-12345678901234567890123456789012".to_vec(),
        max_bytes: 100000,
        siem_exporter: None,
        include_params: true,
    };
    let audit_logger = Arc::new(AuditLogger::new(config).unwrap());

    let db_manager = Arc::new(agentwall::proxy::db::DbManager::init());

    Arc::new(ProxyState {
        policy: std::sync::RwLock::new(policy),
        policy_path: None,
        gateway_start_time: std::time::Instant::now(),
        credential_scope_validator: Arc::new(agentwall::policy::credential_scope::CredentialScopeValidator::new(false)),
        audit_logger,
        session_id: "multi-tenant-test-session".to_string(),
        kill_mode: KillMode::Connection,
        agent_pid: None,
        upstream_url: "".to_string(),
        dry_run: false,
        shadow_mode: false,
        policy_loaded: AtomicBool::new(true),
        rate_limiter: RateLimiter::new(0),
        http_client: reqwest::Client::new(),
        safe_mode_scanner: Arc::new(SafeModeScanner::new().unwrap()),
        ready: true,
        db_manager,
        response_scanner: Arc::new(ResponseScanner::new().unwrap()),
        response_scan_config: std::sync::RwLock::new(ResponseScanConfig::default()),
        dlp_scanner: std::sync::Arc::new(agentwall::policy::dlp::DlpScanner::new(None).unwrap()),
        semantic_scanner: std::sync::Arc::new(agentwall::policy::semantic::SemanticScanner::new(agentwall::policy::semantic::SemanticConfig::default())),
        injection_scanner: Arc::new(agentwall::policy::injection::InjectionScanner::default()),
        tool_history: std::sync::Mutex::new(Vec::new()),
        sessions: dashmap::DashMap::new(),
        metrics_requests_total: Arc::new(AtomicU64::new(0)),
        metrics_allow_total: Arc::new(AtomicU64::new(0)),
        metrics_deny_total: Arc::new(AtomicU64::new(0)),
        metrics_rate_limited_total: Arc::new(AtomicU64::new(0)),
        metrics_firewall_cycle_total: Arc::new(AtomicU64::new(0)),
        metrics_siem_export_total: Arc::new(AtomicU64::new(0)),
        metrics_siem_export_failed_total: Arc::new(AtomicU64::new(0)),
        event_tx: tokio::sync::broadcast::channel(256).0,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn test_concurrency_and_isolation_100_sessions() {
    let policy = CompiledPolicy {
        max_calls_per_second: 0,
        tools: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
    };

    let state = create_mock_proxy_state(Some(policy.clone()));

    // Create 100 concurrent agent tasks
    let mut handles = vec![];
    for idx in 0..100 {
        let state_clone = state.clone();
        let policy_clone = policy.clone();
        let session_token = format!("bearer-token-{}", idx);
        
        let handle = tokio::spawn(async move {
            // Resolve session context
            let session = Arc::new(SessionContext::new(
                Some(format!("agent-{}", idx)),
                Some(format!("agent-{}@enterprise.com", idx)),
                Some(policy_clone),
                None,
                None,
            ));
            
            state_clone.sessions.insert(session_token, session.clone());

            // Make a tool call and evaluate it
            let req = json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": { "path": format!("/workspace/file-{}.txt", idx) }
                },
                "id": idx
            });

            let action = evaluate_jsonrpc(&state_clone, &session, &req).await;
            (session.session_id.clone(), action)
        });
        handles.push(handle);
    }

    let mut session_ids = std::collections::HashSet::new();
    for handle in handles {
        let (session_id, action) = handle.await.unwrap();
        
        // Assert that each session ID is unique
        assert!(session_ids.insert(session_id), "Each session context must have a unique UUID");

        // Since the policy tools list is empty, default action is deny (policy violation)
        match action {
            ProxyAction::KillAndRespond(val) => {
                assert_eq!(val["error"]["code"], -32001, "Should deny tool call as policy violation");
            }
            _ => panic!("Expected tool call to be denied"),
        }
    }

    assert_eq!(state.sessions.len(), 100, "Should have successfully registered exactly 100 sessions in the registry");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_rate_limiting_isolation() {
    // Session context rate limiting specifies 2 calls per second
    let policy = CompiledPolicy {
        max_calls_per_second: 2,
        tools: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
    };

    let state = create_mock_proxy_state(Some(policy.clone()));

    // Create session A
    let session_a = Arc::new(SessionContext::new(
        Some("agent-a".to_string()),
        None,
        Some(policy.clone()),
        None,
        None,
    ));
    state.sessions.insert("token-a".to_string(), session_a.clone());

    // Create session B
    let session_b = Arc::new(SessionContext::new(
        Some("agent-b".to_string()),
        None,
        Some(policy.clone()),
        None,
        None,
    ));
    state.sessions.insert("token-b".to_string(), session_b.clone());

    let req_a = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "/workspace/a.txt" }
        },
        "id": 1
    });

    let req_b = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "/workspace/b.txt" }
        },
        "id": 2
    });

    // Make 2 quick calls on Session A (within rate limit burst)
    let action_a1 = evaluate_jsonrpc(&state, &session_a, &req_a).await;
    let action_a2 = evaluate_jsonrpc(&state, &session_a, &req_a).await;

    // Both should be denied by policy, not rate-limited
    match action_a1 {
        ProxyAction::KillAndRespond(val) => assert_eq!(val["error"]["code"], -32001),
        _ => panic!("Expected policy deny"),
    }
    match action_a2 {
        ProxyAction::KillAndRespond(val) => assert_eq!(val["error"]["code"], -32001),
        _ => panic!("Expected policy deny"),
    }

    // 3rd call on Session A should be rate-limited
    let action_a3 = evaluate_jsonrpc(&state, &session_a, &req_a).await;
    match action_a3 {
        ProxyAction::Respond(val) => {
            assert_eq!(val["error"]["code"], -32029, "3rd call of Session A must be rate-limited");
            assert!(val["error"]["message"].as_str().unwrap().contains("Rate limit exceeded"));
        }
        _ => panic!("Expected rate limit respond action"),
    }

    // Check Session B at the exact same moment
    let action_b1 = evaluate_jsonrpc(&state, &session_b, &req_b).await;
    // Session B should NOT be rate-limited! (should get policy deny -32001)
    match action_b1 {
        ProxyAction::KillAndRespond(val) => {
            assert_eq!(val["error"]["code"], -32001, "Session B must NOT be affected by Session A's rate limit");
        }
        _ => panic!("Expected Session B call to pass through rate limiter and get policy deny"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cycle_detection_isolation() {
    let policy = CompiledPolicy {
        max_calls_per_second: 0,
        tools: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: Some(FirewallConfig {
            enabled: true,
            cycle_detection: CycleDetectionConfig {
                max_attempts: 3,
                action: CycleAction::PivotError,
            },
        }),
    };

    let state = create_mock_proxy_state(Some(policy.clone()));

    // Create session A
    let session_a = Arc::new(SessionContext::new(
        Some("agent-a".to_string()),
        None,
        Some(policy.clone()),
        None,
        None,
    ));
    state.sessions.insert("token-a".to_string(), session_a.clone());

    // Create session B
    let session_b = Arc::new(SessionContext::new(
        Some("agent-b".to_string()),
        None,
        Some(policy.clone()),
        None,
        None,
    ));
    state.sessions.insert("token-b".to_string(), session_b.clone());

    let req = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "dangerous_tool",
            "arguments": { "cmd": "rm -rf" }
        },
        "id": 1
    });

    // Make 3 consecutive identical calls on Session A
    let _ = evaluate_jsonrpc(&state, &session_a, &req).await;
    let _ = evaluate_jsonrpc(&state, &session_a, &req).await;
    let action_a3 = evaluate_jsonrpc(&state, &session_a, &req).await;

    // Session A's 3rd call should trigger a cycle block
    match action_a3 {
        ProxyAction::Respond(val) => {
            assert_eq!(val["error"]["code"], -32010, "Session A must be blocked by cycle detection on the 3rd attempt");
            assert!(val["error"]["message"].as_str().unwrap().contains("Cycle detected"));
        }
        _ => panic!("Expected cycle detection block for Session A"),
    }

    // Session B makes the exact same call for the first time
    let action_b1 = evaluate_jsonrpc(&state, &session_b, &req).await;

    // Session B must NOT trigger a cycle block! It should get regular policy deny
    match action_b1 {
        ProxyAction::KillAndRespond(val) => {
            assert_eq!(val["error"]["code"], -32001, "Session B must have clean history and NOT be blocked by Session A's tool cycle");
        }
        _ => panic!("Expected Session B call to get regular policy deny, not cycle block"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_hot_reload_policy_isolation() {
    // Policy 1 (Allows 'read_file')
    let policy_v1 = CompiledPolicy {
        max_calls_per_second: 0,
        tools: vec![
            agentwall::policy::engine::CompiledTool {
                name: "read_file".to_string(),
                action: "allow".to_string(),
                risk: None,
                parameters: vec![],
                identity: None,
                credential_scope: vec![],
                semantic_anomaly_threshold: None,
                a2a_trust_level: None,
            }
        ],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
    };

    // Policy 2 (Denies everything)
    let policy_v2 = CompiledPolicy {
        max_calls_per_second: 0,
        tools: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
    };

    let state = create_mock_proxy_state(Some(policy_v1.clone()));

    // Initiate Session A under Policy 1 (freezes Policy 1 in its context)
    let session_a = Arc::new(SessionContext::new(
        Some("agent-a".to_string()),
        None,
        state.policy.read().unwrap().clone(),
        None,
        None,
    ));
    state.sessions.insert("token-a".to_string(), session_a.clone());

    // Perform Hot-Reload on the Gateway state (Swap active policy to Policy 2)
    {
        let mut policy_write = state.policy.write().unwrap();
        *policy_write = Some(policy_v2.clone());
    }

    // Initiate Session B AFTER hot-reload (freezes Policy 2 in its context)
    let session_b = Arc::new(SessionContext::new(
        Some("agent-b".to_string()),
        None,
        state.policy.read().unwrap().clone(),
        None,
        None,
    ));
    state.sessions.insert("token-b".to_string(), session_b.clone());

    let req = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "/workspace/data.json" }
        },
        "id": 1
    });

    // Evaluate tool call on Session A (in-flight session)
    let action_a = evaluate_jsonrpc(&state, &session_a, &req).await;
    // Session A should follow frozen Policy 1 and ALLOW the tool call (which triggers forward)
    match action_a {
        ProxyAction::Forward => {}
        _ => panic!("In-flight Session A must be allowed to execute under its frozen policy context"),
    }

    // Evaluate tool call on Session B (new session)
    let action_b = evaluate_jsonrpc(&state, &session_b, &req).await;
    // Session B should follow the hot-reloaded Policy 2 and DENY the tool call
    match action_b {
        ProxyAction::KillAndRespond(val) => {
            assert_eq!(val["error"]["code"], -32001, "New Session B must enforce the hot-reloaded policy rules immediately");
        }
        _ => panic!("Expected Session B call to be denied under new policy"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dynamic_tool_history_max() {
    let policy = CompiledPolicy {
        max_calls_per_second: 0,
        tools: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: Some(FirewallConfig {
            enabled: true,
            cycle_detection: CycleDetectionConfig {
                max_attempts: 7, // > TOOL_HISTORY_MIN (5)
                action: CycleAction::PivotError,
            },
        }),
    };

    let state = create_mock_proxy_state(Some(policy.clone()));
    let session = Arc::new(SessionContext::new(
        Some("agent-test".to_string()),
        None,
        Some(policy.clone()),
        None,
        None,
    ));

    let req = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "dangerous_tool",
            "arguments": { "cmd": "rm -rf" }
        },
        "id": 1
    });

    // Make 6 consecutive identical calls
    for _ in 0..6 {
        let _ = evaluate_jsonrpc(&state, &session, &req).await;
    }

    // 7th call should trigger cycle block
    let action = evaluate_jsonrpc(&state, &session, &req).await;

    match action {
        ProxyAction::Respond(val) => {
            assert_eq!(val["error"]["code"], -32010, "Cycle detection must work for max_attempts > 5");
        }
        _ => panic!("Expected cycle detection block on 7th attempt"),
    }
}

#[tokio::test]
async fn test_session_ttl_expiry() {
    let policy = CompiledPolicy {
        max_calls_per_second: 0,
        tools: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
    };

    let session = SessionContext::new(
        Some("agent-test".to_string()),
        None,
        Some(policy),
        None,
        None,
    );

    // Fresh session should not be expired
    assert!(!session.is_expired(), "Fresh session should not be expired");

    // We can't mock Instant easily without a crate like `mock_instant`, but we can verify the constant is 4 hours
    assert_eq!(agentwall::proxy::session::SESSION_TTL_SECS, 4 * 60 * 60, "TTL must be 4 hours");
}
