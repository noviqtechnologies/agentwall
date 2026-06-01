use agentwall::audit::logger::{AuditLogger, AuditLoggerConfig};
use agentwall::audit::verifier::{verify_chain_with_secret, VerifyResult};
use agentwall::report::generate_report;
use serde_json::json;
use std::fs;
use std::sync::Arc;
use std::thread;
use tempfile::tempdir;

#[test]
fn test_integration_full_pipeline_and_report() {
    let dir = tempdir().unwrap();
    let config = AuditLoggerConfig {
        log_path: dir.path().join("audit.log"),
        session_id: "integration-session".to_string(),
        session_secret: vec![0x99; 32],
        max_bytes: 1024 * 1024,
        siem_exporter: None,
        include_params: true,
    };
    let log_path = config.log_path.clone();
    let secret = config.session_secret.clone();
    let logger = AuditLogger::new(config).unwrap();

    // 1. Write several entries
    logger.write_entry(
        "integration-session",
        "tool_allow",
        "calculator",
        Some(json!({"val": 42})),
        None,
        Some(0.1),
        Some("user-123".to_string()),
        Some("user-123@corp.com".to_string()),
        Some("policy-sha-abc".to_string()),
        None,
    ).unwrap();

    logger.write_entry(
        "integration-session",
        "tool_deny",
        "bash",
        Some(json!({"cmd": "rm -rf"})),
        Some("unauthorized tool".to_string()),
        Some(1.2),
        Some("user-123".to_string()),
        Some("user-123@corp.com".to_string()),
        Some("policy-sha-abc".to_string()),
        None,
    ).unwrap();

    // Drop logger to flush background writer
    drop(logger);
    thread::sleep(std::time::Duration::from_millis(200));

    // 2. Verify chain with secret
    match verify_chain_with_secret(&log_path, &secret) {
        VerifyResult::Valid { entry_count } => {
            assert_eq!(entry_count, 2);
        }
        other => panic!("Chain verification failed: {:?}", other),
    }

    // 3. Generate session report
    let report = generate_report(
        &log_path,
        true, // include_params
        "policy-sha-abc",
        true, // policy_loaded
        "both",
        false, // dry_run
        vec![],
    ).unwrap();

    assert_eq!(report.session_id, "integration-session");
    assert_eq!(report.summary.allowed, 1);
    assert_eq!(report.summary.denied, 1);
    assert_eq!(report.summary.total_calls, 2);
    assert_eq!(report.policy_hash, Some("policy-sha-abc".to_string()));
}

#[test]
fn test_integration_concurrent_sessions() {
    let dir = tempdir().unwrap();
    let config = AuditLoggerConfig {
        log_path: dir.path().join("audit.log"),
        session_id: "shared-session-id".to_string(),
        session_secret: vec![0xCC; 32],
        max_bytes: 1024 * 1024,
        siem_exporter: None,
        include_params: true,
    };
    let log_path = config.log_path.clone();
    let secret = config.session_secret.clone();
    let logger = Arc::new(AuditLogger::new(config).unwrap());

    // Spawn 8 threads writing concurrently
    let mut handles = vec![];
    for t_idx in 0..8 {
        let logger_clone = logger.clone();
        let handle = thread::spawn(move || {
            for i in 0..10 {
                logger_clone.write_entry(
                    "shared-session-id",
                    "tool_allow",
                    &format!("tool_{}_{}", t_idx, i),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Drop logger to flush
    drop(logger);
    thread::sleep(std::time::Duration::from_millis(200));

    // Verify all 80 entries are chained correctly
    match verify_chain_with_secret(&log_path, &secret) {
        VerifyResult::Valid { entry_count } => {
            assert_eq!(entry_count, 80);
        }
        other => panic!("Chain verification failed for concurrent logs: {:?}", other),
    }
}

#[test]
fn test_integration_rotation_under_load() {
    let dir = tempdir().unwrap();
    // Use very small max_bytes so that log rotates frequently under load
    let config = AuditLoggerConfig {
        log_path: dir.path().join("audit.log"),
        session_id: "rotation-session".to_string(),
        session_secret: vec![0xEE; 32],
        max_bytes: 1000,
        siem_exporter: None,
        include_params: true,
    };
    let log_path = config.log_path.clone();
    let secret = config.session_secret.clone();
    let logger = Arc::new(AuditLogger::new(config).unwrap());

    // Write 50 entries to force multiple rotations
    let mut handles = vec![];
    for t_idx in 0..5 {
        let logger_clone = logger.clone();
        let handle = thread::spawn(move || {
            for i in 0..10 {
                logger_clone.write_entry(
                    "rotation-session",
                    "tool_allow",
                    &format!("tool_{}_{}", t_idx, i),
                    Some(json!({"long_parameter_to_consume_bytes": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"})),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ).unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    drop(logger);
    thread::sleep(std::time::Duration::from_millis(200));

    // Check that multiple rotated files exist
    let files: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|res| res.unwrap().path())
        .collect();
    assert!(files.len() > 1, "Should have rotated files");

    // Check active log verifies cleanly
    match verify_chain_with_secret(&log_path, &secret) {
        VerifyResult::Valid { .. } => {}
        other => panic!("Active log verification failed: {:?}", other),
    }
}
