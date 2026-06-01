use agentwall::audit::logger::{AuditEntry, ZERO_HMAC};
use agentwall::audit::siem::{SiemBackend, SiemExporter, try_export};

#[test]
fn test_siem_backend_parsing() {
    assert_eq!(SiemBackend::from_str("splunk"), SiemBackend::Splunk);
    assert_eq!(SiemBackend::from_str("SplUnK"), SiemBackend::Splunk);
    assert_eq!(SiemBackend::from_str("datadog"), SiemBackend::Datadog);
    assert_eq!(SiemBackend::from_str("opensearch"), SiemBackend::OpenSearch);
    assert_eq!(SiemBackend::from_str("invalid"), SiemBackend::Local);
    assert_eq!(SiemBackend::from_str("local"), SiemBackend::Local);
    assert_eq!(SiemBackend::from_str(""), SiemBackend::Local);
}

#[tokio::test]
async fn test_siem_timeout_behavior() {
    // 192.0.2.1 is TEST-NET-1, specified by RFC 5737 as non-routable.
    // It will drop packets, ensuring a timeout occurs.
    let _exporter = SiemExporter::new(
        SiemBackend::Splunk,
        "http://192.0.2.1:8088/services/collector/event".to_string(),
        "dummy_token".to_string(),
        0, // Use default 2s, but we will wrap it
    );
    
    // We override timeout by creating our own exporter with 10ms timeout
    let fast_exporter = SiemExporter::new(
        SiemBackend::Splunk,
        "http://192.0.2.1:8088/services/collector/event".to_string(),
        "dummy_token".to_string(),
        1, // We can't specify ms here, so we will use try_export which uses the 1s timeout
    );

    let entry = AuditEntry {
        ts: "2026-05-31T12:00:00Z".to_string(),
        session_id: "sess-1".to_string(),
        event: "test_event".to_string(),
        tool_name: Some("test_tool".to_string()),
        params_hash: None,
        params: None,
        reason: None,
        latency_ms: Some(50.0),
        entry_index: 0,
        prev_hmac: ZERO_HMAC.to_string(),
        hmac: None,
        identity_sub: None,
        identity_email: None,
        policy_hash: None,
        request_ip: None,
    };

    // try_export should not panic, it should just log a warning and return.
    // We race it with a 2-second timeout just to be safe it doesn't hang indefinitely.
    let res = tokio::time::timeout(std::time::Duration::from_secs(3), try_export(&fast_exporter, &entry)).await;
    
    assert!(res.is_ok(), "try_export hung indefinitely, ignoring its own internal timeout");
}

#[tokio::test]
async fn test_siem_local_disabled_behavior() {
    let exporter = SiemExporter::new(
        SiemBackend::Local,
        "".to_string(),
        "".to_string(),
        0,
    );
    
    assert!(!exporter.is_active());

    let entry = AuditEntry {
        ts: "2026-05-31T12:00:00Z".to_string(),
        session_id: "sess-1".to_string(),
        event: "test_event".to_string(),
        tool_name: Some("test_tool".to_string()),
        params_hash: None,
        params: None,
        reason: None,
        latency_ms: Some(0.0),
        entry_index: 0,
        prev_hmac: ZERO_HMAC.to_string(),
        hmac: None,
        identity_sub: None,
        identity_email: None,
        policy_hash: None,
        request_ip: None,
    };

    // Exporting to Local backend should instantly return without error.
    let start = std::time::Instant::now();
    try_export(&exporter, &entry).await;
    let elapsed = start.elapsed();
    
    assert!(elapsed.as_millis() < 50, "Local export should be instantaneous");
}
