use agentwall::audit::logger::{AuditLogger, AuditLoggerConfig};
use agentwall::report::{format_text_report, generate_report};
use serde_json::json;
use tempfile::NamedTempFile;

#[test]
fn test_phase_1_1_developer_observability_report() {
    let log_file = NamedTempFile::new().unwrap();
    let session_id = "test-report-session".to_string();
    let secret = b"test-secret-123456789012345678901".to_vec();

    let config = AuditLoggerConfig {
        log_path: log_file.path().to_path_buf(),
        session_id: session_id.clone(),
        session_secret: secret.clone(),
        max_bytes: 100000,
        siem_exporter: None,
        include_params: true,
    };
    let logger = AuditLogger::new(config).unwrap();

    logger
        .write_entry(
            &session_id,
            "dry_run_active",
            "system",
            None,
            Some("dry run active".to_string()),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    logger
        .write_entry(
            &session_id,
            "tool_dry_run_deny",
            "dangerous_tool",
            None,
            Some("not_in_policy".to_string()),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    // Drop the logger to flush the background writer
    drop(logger);
    std::thread::sleep(std::time::Duration::from_millis(200));

    let report = generate_report(
        log_file.path(),
        false, // include_params
        "sha256:unknown", // hash
        false, // policy_loaded
        "both",
        true, // dry_run
        vec![],
    )
    .unwrap();

    // Verify FR-113: policy hash should be None
    assert_eq!(report.policy_hash, None);
    assert_eq!(report.policy_version, None);
    assert_eq!(report.policy, None);

    colored::control::set_override(false);
    let text_output = format_text_report(&report);
    colored::control::unset_override();

    // Verify FR-114 outputs
    assert!(text_output.contains("Policy:      None (Allow-all sentinel)"));
    assert!(text_output.contains("Policy Violations (Dry-Run):"));
    assert!(text_output.contains("dangerous_tool"));
    assert!(text_output.contains("Run `agentwall init --from-log audit.log` to generate your rules."));
    assert!(text_output.contains("CRITICAL: No policy loaded during this session."));
}
