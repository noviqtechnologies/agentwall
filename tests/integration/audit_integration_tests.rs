use agentwall::audit::logger::{AuditLogger, AuditLoggerConfig};
use agentwall::audit::verifier::{verify_chain_with_secret, VerifyResult};
use agentwall::report::generate_report;
use serde_json::json;
use std::fs;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_integration_full_pipeline_and_report() {
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
    ).await.unwrap();

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
    ).await.unwrap();

    // Drop logger to flush background writer
    drop(logger);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_integration_concurrent_sessions() {
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

    // Spawn 8 tokio tasks writing concurrently
    let mut handles = vec![];
    for t_idx in 0..8 {
        let logger_clone = logger.clone();
        let handle = tokio::spawn(async move {
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
                ).await.unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    // Drop logger to flush
    drop(logger);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Verify all 80 entries are chained correctly
    match verify_chain_with_secret(&log_path, &secret) {
        VerifyResult::Valid { entry_count } => {
            assert_eq!(entry_count, 80);
        }
        other => panic!("Chain verification failed for concurrent logs: {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_integration_rotation_under_load() {
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
        let handle = tokio::spawn(async move {
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
                ).await.unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    drop(logger);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

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

#[tokio::test]
async fn test_integration_auth_failed_in_chain() {
    let dir = tempdir().unwrap();
    let config = AuditLoggerConfig {
        log_path: dir.path().join("audit.log"),
        session_id: "auth-test-session".to_string(),
        session_secret: vec![0x11; 32],
        max_bytes: 1024 * 1024,
        siem_exporter: None,
        include_params: true,
    };
    let log_path = config.log_path.clone();
    let secret = config.session_secret.clone();
    let logger = AuditLogger::new(config).unwrap();

    // Fix 1: Write an auth_failed event
    logger.write_entry(
        "auth-test-session",
        "auth_failed",
        "",
        None,
        Some("identity_token_missing remote_addr=127.0.0.1".to_string()),
        None,
        None,
        None,
        None,
        Some("127.0.0.1".to_string()),
    ).await.unwrap();

    drop(logger);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    match verify_chain_with_secret(&log_path, &secret) {
        VerifyResult::Valid { entry_count } => {
            assert_eq!(entry_count, 1);
        }
        other => panic!("Chain verification failed for auth_failed: {:?}", other),
    }
}

#[tokio::test]
async fn test_integration_tampered_log() {
    let dir = tempdir().unwrap();
    let config = AuditLoggerConfig {
        log_path: dir.path().join("audit.log"),
        session_id: "tamper-session".to_string(),
        session_secret: vec![0x22; 32],
        max_bytes: 1024 * 1024,
        siem_exporter: None,
        include_params: true,
    };
    let log_path = config.log_path.clone();
    let secret = config.session_secret.clone();
    let logger = AuditLogger::new(config).unwrap();

    // Write a couple of entries
    logger.write_entry(
        "tamper-session",
        "tool_allow",
        "read_file",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ).await.unwrap();

    logger.write_entry(
        "tamper-session",
        "tool_allow",
        "write_file",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ).await.unwrap();

    drop(logger);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Read the log file, find an entry and tamper with it
    let mut contents = fs::read_to_string(&log_path).unwrap();
    // Replace "read_file" with "root_shell"
    contents = contents.replace("read_file", "root_shell");
    fs::write(&log_path, contents).unwrap();

    // Verify it fails
    match verify_chain_with_secret(&log_path, &secret) {
        VerifyResult::Invalid { entry_index, .. } => {
            // Expected hash mismatch or chain break at index 0 because read_file was the first entry
            assert_eq!(entry_index, 0);
        }
        VerifyResult::Error(_e) => {
            // This could also happen if replace messes up json, but we just replaced tool name
        }
        other => panic!("Expected Invalid or Error, got: {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_siem_export_failure_fallback_logs_locally() {
    let dir = tempdir().unwrap();
    let config = AuditLoggerConfig {
        log_path: dir.path().join("audit.log"),
        session_id: "siem-fail-session".to_string(),
        session_secret: vec![0x33; 32],
        max_bytes: 1024 * 1024,
        siem_exporter: Some(agentwall::audit::siem::SiemExporter::new(
            agentwall::audit::siem::SiemBackend::Splunk,
            "http://192.0.2.1:8088/services/collector/event".to_string(),
            "dummy_token".to_string(),
            1, // 1s timeout
        )),
        include_params: true,
    };
    let log_path = config.log_path.clone();
    let secret = config.session_secret.clone();
    let logger = AuditLogger::new(config).unwrap();

    logger.write_entry(
        "siem-fail-session",
        "tool_allow",
        "read_file",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ).await.unwrap();

    drop(logger);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Verify it is written locally
    match verify_chain_with_secret(&log_path, &secret) {
        VerifyResult::Valid { entry_count } => {
            assert_eq!(entry_count, 1);
        }
        other => panic!("Chain verification failed: {:?}", other),
    }
}
