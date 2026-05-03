use std::time::Duration;
use vexa::audit::logger::AuditLogger;
use vexa::proxy::handler::RateLimiter;
use vexa::report::generate_report;


#[test]
fn test_rate_limiting_logic() {
    // 5 calls per second
    let limiter = RateLimiter::new(5);

    // First 5 should succeed immediately
    for _ in 0..5 {
        assert!(limiter.acquire(), "Should allow initial burst");
    }

    // 6th should fail
    assert!(!limiter.acquire(), "Should block 6th call in same second");

    // Wait for tokens to replenish (0.2s per token)
    std::thread::sleep(Duration::from_millis(250));
    assert!(limiter.acquire(), "Should allow call after partial replenishment");
}

#[test]
fn test_log_rotation_and_seed() {
    let test_dir = std::path::Path::new("tests/tmp_p1_test");
    let _ = std::fs::create_dir_all(test_dir);
    let log_path = test_dir.join(format!("vexa_test_log_{}.log", uuid::Uuid::new_v4()));
    let session_id = "test-session".to_string();
    let secret = b"test-secret-123456789012345678901".to_vec();

    // Cleanup from previous runs if any
    let _ = std::fs::remove_file(&log_path);

    // Set a tiny rotation limit (200 bytes)
    let logger = AuditLogger::new(
        log_path.clone(),
        session_id.clone(),
        secret.clone(),
        200,
    ).unwrap();

    // Write entries until it rotates
    for _ in 0..10 {
        logger.write_entry("tool_allow", "read_file", None, None, None).unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }

    // Check that a .bak file was created
    let mut bak_found = false;
    let dir = log_path.parent().unwrap();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map_or(false, |ext| ext == "bak") {
            bak_found = true;
            break;
        }
    }
    assert!(bak_found, "Log rotation should create a .bak file");

    // Verify the new log starts with a log_rotation_seed
    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("log_rotation_seed"), "New log should contain rotation seed");
}

#[test]
fn test_session_report_generation() {
    let log_path = std::env::temp_dir().join(format!("vexa_test_report_{}.log", uuid::Uuid::new_v4()));
    let session_id = "test-report-session".to_string();
    let secret = b"test-secret-123456789012345678901".to_vec();

    // Cleanup from previous runs if any
    let _ = std::fs::remove_file(&log_path);

    let logger = AuditLogger::new(
        log_path.clone(),
        session_id.clone(),
        secret.clone(),
        100000,
    ).unwrap();

    // Mock session events
    logger.write_entry("tool_allow", "read_file", None, None, None).unwrap();
    logger.write_entry("tool_deny", "exec_shell", None, Some("action is deny".to_string()), None).unwrap();
    logger.write_entry("rate_limited", "read_file", None, None, None).unwrap();

    let report = generate_report(
        &log_path,
        false,
        "sha256:test",
        "both",
        false,
        vec![],
    ).unwrap();

    assert_eq!(report.summary.total_calls, 3);
    assert_eq!(report.summary.allowed, 1);
    assert_eq!(report.summary.denied, 1);
    assert_eq!(report.summary.rate_limited, 1);
    assert_eq!(report.tools_used[0].name, "read_file");
}
