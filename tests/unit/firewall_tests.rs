use std::sync::Arc;
use serde_json::json;
use agentwall::proxy::handler::{evaluate_jsonrpc, ProxyAction, ProxyState, RateLimiter, ToolCallFingerprint};
use agentwall::policy::engine::CompiledPolicy;
use agentwall::policy::schema::{FirewallConfig, CycleDetectionConfig, CycleAction};
use agentwall::audit::logger::AuditLogger;
use agentwall::kill::KillMode;
use agentwall::policy::safe_mode::SafeModeScanner;
use agentwall::policy::response_scanner::{ResponseScanner, ResponseScanConfig};
use std::sync::atomic::{AtomicU64, AtomicBool};

#[test]
fn test_canonical_json_hashing() {
    let args1 = json!({
        "key1": "value1",
        "key2": 42,
        "nested": {
            "b": true,
            "a": "hello"
        }
    });

    let args2 = json!({
        "key2": 42,
        "key1": "value1",
        "nested": {
            "a": "hello",
            "b": true
        }
    });

    let fp1 = ToolCallFingerprint::new("my_tool", &args1);
    let fp2 = ToolCallFingerprint::new("my_tool", &args2);

    assert_eq!(fp1, fp2, "Fingerprints must be identical regardless of parameter order");
}

#[test]
fn test_tool_history_memory_bounding() {
    let log_path = std::env::temp_dir().join(format!("vexa_test_fw_mem_{}.log", uuid::Uuid::new_v4()));
    let audit_logger = Arc::new(AuditLogger::new(agentwall::audit::logger::AuditLoggerConfig {
        log_path,
        session_id: "session-fw-mem".to_string(),
        session_secret: b"secret-12345678901234567890123456789012".to_vec(),
        max_bytes: 100000,
        siem_exporter: None,
        include_params: false,
    }).unwrap());

    let db_manager = Arc::new(agentwall::proxy::db::DbManager::init());
    let state = ProxyState {
        policy: std::sync::RwLock::new(Some(CompiledPolicy {
            max_calls_per_second: 0,
            tools: vec![],
            identity_validator: None,
            scannable_tools: vec![],
            safe_tools: vec![],
            firewall: None, // Will fallback to default (enabled=true, max_attempts=3)
        })),
        audit_logger,
        session_id: "session-fw-mem".to_string(),
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
    };

    let rt = tokio::runtime::Runtime::new().unwrap();

    let local_policy = state.policy.read().unwrap().clone();
    let session = Arc::new(agentwall::proxy::session::SessionContext::new(
        None,
        None,
        local_policy,
        None,
    ));

    // Call 10 times with different parameters so cycle detection isn't triggered,
    // but history is populated.
    for i in 0..10 {
        let req = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "some_tool",
                "arguments": { "val": i }
            },
            "id": i
        });
        
        let _ = rt.block_on(async {
            evaluate_jsonrpc(&state, &session, &req).await
        });
    }

    let history = session.tool_history.lock().unwrap();
    assert_eq!(history.len(), 5, "History size must be capped at TOOL_HISTORY_MAX (5)");
}

#[test]
fn test_cycle_detection_blocking() {
    let log_path = std::env::temp_dir().join(format!("vexa_test_fw_block_{}.log", uuid::Uuid::new_v4()));
    let audit_logger = Arc::new(AuditLogger::new(agentwall::audit::logger::AuditLoggerConfig {
        log_path,
        session_id: "session-fw-block".to_string(),
        session_secret: b"secret-12345678901234567890123456789012".to_vec(),
        max_bytes: 100000,
        siem_exporter: None,
        include_params: false,
    }).unwrap());

    let db_manager = Arc::new(agentwall::proxy::db::DbManager::init());
    let state = ProxyState {
        policy: std::sync::RwLock::new(Some(CompiledPolicy {
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
        })),
        audit_logger,
        session_id: "session-fw-block".to_string(),
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
    };

    let req = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "allowed_tool",
            "arguments": { "foo": "bar" }
        },
        "id": 1
    });

    let rt = tokio::runtime::Runtime::new().unwrap();

    let local_policy = state.policy.read().unwrap().clone();
    let session = Arc::new(agentwall::proxy::session::SessionContext::new(
        None,
        None,
        local_policy,
        None,
    ));
    let res1 = rt.block_on(evaluate_jsonrpc(&state, &session, &req));
    let res2 = rt.block_on(evaluate_jsonrpc(&state, &session, &req));
    let res3 = rt.block_on(evaluate_jsonrpc(&state, &session, &req));

    match res1 {
        ProxyAction::KillAndRespond(val) => {
            assert_eq!(val["error"]["code"], -32001, "First call should fail with policy violation");
        }
        _ => panic!("Expected KillAndRespond for first call"),
    }

    match res2 {
        ProxyAction::KillAndRespond(val) => {
            assert_eq!(val["error"]["code"], -32001, "Second call should fail with policy violation");
        }
        _ => panic!("Expected KillAndRespond for second call"),
    }

    match res3 {
        ProxyAction::Respond(val) => {
            assert_eq!(val["error"]["code"], -32010, "Third call should fail with JSONRPC_FIREWALL_CYCLE");
            assert!(val["error"]["message"].as_str().unwrap().contains("Cycle detected"), "Error message should mention cycle detection");
        }
        _ => panic!("Expected Respond with cycle block for third call"),
    }
}

#[test]
fn test_pause_interactive_fallback_in_non_tty() {
    let log_path = std::env::temp_dir().join(format!("vexa_test_fw_tty_{}.log", uuid::Uuid::new_v4()));
    let audit_logger = Arc::new(AuditLogger::new(agentwall::audit::logger::AuditLoggerConfig {
        log_path,
        session_id: "session-fw-tty".to_string(),
        session_secret: b"secret-12345678901234567890123456789012".to_vec(),
        max_bytes: 100000,
        siem_exporter: None,
        include_params: false,
    }).unwrap());

    let db_manager = Arc::new(agentwall::proxy::db::DbManager::init());
    let state = ProxyState {
        policy: std::sync::RwLock::new(Some(CompiledPolicy {
            max_calls_per_second: 0,
            tools: vec![],
            identity_validator: None,
            scannable_tools: vec![],
            safe_tools: vec![],
            firewall: Some(FirewallConfig {
                enabled: true,
                cycle_detection: CycleDetectionConfig {
                    max_attempts: 2,
                    action: CycleAction::PauseInteractive,
                },
            }),
        })),
        audit_logger,
        session_id: "session-fw-tty".to_string(),
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
    };

    let req = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "allowed_tool",
            "arguments": { "foo": "bar" }
        },
        "id": 1
    });

    let rt = tokio::runtime::Runtime::new().unwrap();

    let local_policy = state.policy.read().unwrap().clone();
    let session = Arc::new(agentwall::proxy::session::SessionContext::new(
        None,
        None,
        local_policy,
        None,
    ));

    let _res1 = rt.block_on(evaluate_jsonrpc(&state, &session, &req));
    let res2 = rt.block_on(evaluate_jsonrpc(&state, &session, &req));

    match res2 {
        ProxyAction::KillAndRespond(val) => {
            assert_eq!(val["error"]["code"], -32001, "PauseInteractive fallback should fail with policy violation");
        }
        _ => panic!("Expected KillAndRespond for blocked call"),
    }
}
