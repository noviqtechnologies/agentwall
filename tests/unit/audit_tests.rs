use agentwall::audit::logger::{AuditLogger, AuditLoggerConfig, ZERO_HMAC};
use agentwall::audit::verifier::{verify_chain, verify_chain_with_secret, VerifyResult};
use serde_json::json;
use std::fs;
use tempfile::tempdir;

fn create_temp_config(dir: &std::path::Path, max_bytes: u64) -> AuditLoggerConfig {
    AuditLoggerConfig {
        log_path: dir.join("audit.log"),
        session_id: "test-session-123".to_string(),
        session_secret: vec![0x42; 32], // deterministic for tests
        max_bytes,
        siem_exporter: None,
        include_params: true,
    }
}

#[tokio::test]
async fn test_audit_sync_write_and_chain() {
    let dir = tempdir().unwrap();
    let config = create_temp_config(dir.path(), 1024 * 1024);
    let logger = AuditLogger::new(config).expect("failed to create logger");

    // Write first entry
    let e1 = logger
        .write_entry(
            "test-session-123",
            "tool_allow",
            "calculator",
            Some(json!({"op": "add"})),
            None,
            Some(1.5),
            Some("user-1".to_string()),
            Some("user1@corp.com".to_string()),
            Some("sha256:abc".to_string()),
            None,
        )
        .await
        .expect("write failed");

    assert_eq!(e1.entry_index, 0);
    assert_eq!(e1.prev_hmac, ZERO_HMAC);
    assert!(e1.hmac.is_some());
    assert_eq!(e1.identity_email, Some("user1@corp.com".to_string()));
    assert_eq!(e1.policy_hash, Some("sha256:abc".to_string()));
    assert!(e1.params_hash.is_some()); // Should be hashed
    assert_eq!(e1.params, Some(json!({"op": "add"}))); // Should be stored plaintext because include_params = true

    // Write second entry
    let e2 = logger
        .write_entry(
            "test-session-123",
            "tool_deny",
            "bash",
            None,
            Some("policy_violation".to_string()),
            None,
            Some("user-1".to_string()),
            Some("user1@corp.com".to_string()),
            Some("sha256:abc".to_string()),
            None,
        )
        .await
        .expect("write failed");

    assert_eq!(e2.entry_index, 1);
    assert_eq!(e2.prev_hmac, e1.hmac.unwrap()); // Chain is intact
    assert!(e2.hmac.is_some());
    
    // Verify the log offline
    let verify_res = verify_chain(&dir.path().join("audit.log"));
    if let VerifyResult::Valid { entry_count } = verify_res {
        assert_eq!(entry_count, 2);
    } else {
        panic!("Chain verification failed: {:?}", verify_res);
    }
}

#[tokio::test]
async fn test_audit_log_rotation() {
    let dir = tempdir().unwrap();
    // Tiny max_bytes to force rapid rotation
    let config = create_temp_config(dir.path(), 500);
    let logger = AuditLogger::new(config).expect("failed to create logger");

    for i in 0..10 {
        logger
            .write_entry(
                "test-session-123",
                "test_event",
                &format!("tool_{}", i),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
    }

    // On Windows (and in general) the logger sends the ack BEFORE doing rotation.
    // Write TWO extra sentinel entries after the loop so that by the time the SECOND
    // ack arrives the background thread has definitely finished any rotation triggered
    // by the FIRST sentinel — i.e. the active audit.log is stable and non-empty.
    for sentinel in &["tool_flush_1", "tool_flush_2"] {
        logger
            .write_entry(
                "test-session-123",
                "test_event",
                sentinel,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
    }

    // Since max_bytes was tiny, it should have rotated a few times.
    let files: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|res| res.unwrap().path())
        .collect();
    
    assert!(files.len() > 1, "Log file should have been rotated");

    // The active file should verify cleanly (starts with rotation_seed)
    let verify_res = verify_chain(&dir.path().join("audit.log"));
    match verify_res {
        VerifyResult::Valid { .. } => {}
        _ => panic!("Active file verification failed: {:?}", verify_res),
    }
}

#[tokio::test]
async fn test_verify_chain_with_secret_tamper_detection() {
    let dir = tempdir().unwrap();
    let config = create_temp_config(dir.path(), 1024 * 1024);
    let session_secret = config.session_secret.clone();
    let log_path = config.log_path.clone();
    
    let logger = AuditLogger::new(config).expect("failed to create logger");

    logger.write_entry(
        "sess-1", "test_event", "tool_1", None, None, None, None, None, None, None
    ).await.unwrap();
    logger.write_entry(
        "sess-1", "test_event", "tool_2", None, None, None, None, None, None, None
    ).await.unwrap();

    // Initial verify is clean
    match verify_chain_with_secret(&log_path, &session_secret) {
        VerifyResult::Valid { entry_count: 2 } => {}
        other => panic!("Expected valid chain, got {:?}", other),
    }

    // Tamper with the file!
    let mut contents = fs::read_to_string(&log_path).unwrap();
    contents = contents.replace("tool_1", "hacked_tool");
    fs::write(&log_path, contents).unwrap();

    // Verify again - should detect tampering
    match verify_chain_with_secret(&log_path, &session_secret) {
        VerifyResult::Invalid { entry_index, reason } => {
            assert_eq!(entry_index, 0);
            assert!(reason.contains("HMAC mismatch"));
        }
        other => panic!("Expected invalid chain, got {:?}", other),
    }
}
