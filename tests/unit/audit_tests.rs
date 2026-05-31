use std::io::Write;
use tempfile::NamedTempFile;
use agentwall::audit::logger::AuditLogger;
use agentwall::audit::verifier::{verify_chain, verify_chain_with_secret, VerifyResult};

#[test]
fn test_hmac_chain() {
    let temp_file = NamedTempFile::new().unwrap();
    let log_path = temp_file.path().to_path_buf();

    let secret = b"my_super_secret_key_12345678901".to_vec();
    let session_id = "session-123".to_string();
    let logger = AuditLogger::new(log_path.clone(), session_id, secret.clone(), 0).unwrap();

    // Write first entry
    logger
        .write_entry("tool_allow", "read_file", None, None, Some(1.2), None)
        .unwrap();

    // Write second entry
    logger
        .write_entry(
            "tool_deny",
            "exec_shell",
            None,
            Some("not_allowed".to_string()),
            None,
            None,
        )
        .unwrap();

    // Drop the logger to ensure the background thread finishes flushing
    drop(logger);

    // Give the background thread a moment to complete writes
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Verify chain consistency (without secret)
    match verify_chain(&log_path) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 2),
        other => panic!("Chain should be valid, got: {:?}", other),
    }

    // Verify full HMAC (with secret)
    match verify_chain_with_secret(&log_path, &secret) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 2),
        other => panic!("Full HMAC verification should pass, got: {:?}", other),
    }

    // Tamper with the log file
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(&log_path)
        .unwrap();
    writeln!(file, r#"{{"ts":"2026-05-03T12:00:00Z","session_id":"session-123","event":"tool_allow","tool_name":"bad_tool","entry_index":2,"prev_hmac":"tampered","hmac":"fake"}}"#).unwrap();

    // Verify again — should detect tampering
    match verify_chain(&log_path) {
        VerifyResult::Invalid { entry_index, .. } => assert_eq!(entry_index, 2),
        other => panic!("Expected invalid chain due to tampering, got: {:?}", other),
    }
}
