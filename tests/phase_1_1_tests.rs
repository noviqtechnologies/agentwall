use agentwall::audit::logger::AuditLogger;
use agentwall::init::generate_policy_from_log;
use agentwall::report::{format_text_report, generate_report};
use serde_json::json;
use tempfile::NamedTempFile;

#[test]
fn test_phase_1_1_init_from_log() {
    let log_file = NamedTempFile::new().unwrap();
    let session_id = "test-init-session".to_string();
    let secret = b"test-secret-123456789012345678901".to_vec();

    let logger = AuditLogger::new(
        log_file.path().to_path_buf(),
        session_id.clone(),
        secret.clone(),
        100000,
    )
    .unwrap();

    // Mock a dry-run active log
    logger
        .write_entry(
            "dry_run_active",
            "system",
            None,
            Some("dry run active".to_string()),
            None,
        )
        .unwrap();

    // Mock an allowed tool (in dry run allow-all sentinel mode)
    logger
        .write_entry(
            "tool_allow",
            "git_clone",
            Some(json!({"repo": "https://github.com/foo/bar.git", "depth": 1})),
            None,
            Some(2.5),
        )
        .unwrap();

    // Generate the policy
    let generated_policy = generate_policy_from_log(log_file.path()).unwrap();

    // Assert it contains the tool and the correctly inferred parameters
    assert!(generated_policy.contains("name: \"git_clone\""));
    assert!(generated_policy.contains("name: \"repo\""));
    assert!(generated_policy.contains("type: string"));
    assert!(generated_policy.contains("name: \"depth\""));
    assert!(generated_policy.contains("type: number"));
    assert!(generated_policy.contains("required: true")); // because it appeared in the only call
    assert!(generated_policy.contains("# TODO: add pattern constraint"));
}

#[test]
fn test_phase_1_1_developer_observability_report() {
    let log_file = NamedTempFile::new().unwrap();
    let session_id = "test-report-session".to_string();
    let secret = b"test-secret-123456789012345678901".to_vec();

    let logger = AuditLogger::new(
        log_file.path().to_path_buf(),
        session_id.clone(),
        secret.clone(),
        100000,
    )
    .unwrap();

    logger
        .write_entry(
            "dry_run_active",
            "system",
            None,
            Some("dry run active".to_string()),
            None,
        )
        .unwrap();

    logger
        .write_entry(
            "tool_dry_run_deny",
            "dangerous_tool",
            None,
            Some("not_in_policy".to_string()),
            None,
        )
        .unwrap();

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

    let text_output = format_text_report(&report);

    // Verify FR-114 outputs
    assert!(text_output.contains("Policy:      None (Allow-all sentinel)"));
    assert!(text_output.contains("Would have been denied under real policy:"));
    assert!(text_output.contains("dangerous_tool"));
    assert!(text_output.contains("Run `agentwall init --from-log <audit.log>` to generate a starter policy."));
    assert!(text_output.contains("⚠ WARNING: no policy loaded; enforcement was not active."));
}
