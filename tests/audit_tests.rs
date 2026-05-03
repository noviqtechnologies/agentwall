use std::io::Write;
use tempfile::NamedTempFile;
use vexa::audit::logger::{AuditLogger, ZERO_HMAC};
use vexa::audit::verifier::{verify_chain, verify_chain_with_secret, VerifyResult};

#[test]
fn test_hmac_chain() {
    let temp_file = NamedTempFile::new().unwrap();
    let log_path = temp_file.path().to_path_buf();

    let secret = b"my_super_secret_key_12345678901".to_vec();
    let session_id = "session-123".to_string();
    let logger = AuditLogger::new(log_path.clone(), session_id, secret.clone(), 0).unwrap();

    // Write first entry
    let e1 = logger
        .write_entry("tool_allow", "read_file", None, None, Some(1.2))
        .unwrap();
    assert_eq!(e1.entry_index, 0);
    assert_eq!(e1.prev_hmac, ZERO_HMAC);
    assert!(e1.hmac.is_some());

    // Write second entry
    let e2 = logger
        .write_entry(
            "tool_deny",
            "exec_shell",
            None,
            Some("not_allowed".to_string()),
            None,
        )
        .unwrap();
    assert_eq!(e2.entry_index, 1);
    assert_eq!(e2.prev_hmac, e1.hmac.unwrap());
    assert!(e2.hmac.is_some());

    // Verify chain consistency (without secret)
    match verify_chain(&log_path) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 2),
        _ => panic!("Chain should be valid"),
    }

    // Verify full HMAC (with secret)
    match verify_chain_with_secret(&log_path, &secret) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 2),
        _ => panic!("Full HMAC verification should pass"),
    }

    // Tamper with the log file
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(&log_path)
        .unwrap();
    writeln!(file, r#"{{"ts":"2026-05-03T12:00:00Z","session_id":"session-123","event":"tool_allow","tool_name":"bad_tool","entry_index":2,"prev_hmac":"tampered","hmac":"fake"}}"#).unwrap();

    // Verify again
    match verify_chain(&log_path) {
        VerifyResult::Invalid { entry_index, .. } => assert_eq!(entry_index, 2),
        _ => panic!("Expected invalid chain due to tampering"),
    }
}
