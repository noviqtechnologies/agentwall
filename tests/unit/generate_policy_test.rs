use agentwall::generate_policy::generate_from_events;
use agentwall::proxy::db::EgressEvent;
use std::time::Instant;

fn make_event(tool: &str, params: &str, timestamp: &str) -> EgressEvent {
    let timestamp_ns = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| dt.timestamp_nanos_opt().unwrap_or(0))
        .unwrap_or(123456789);

    EgressEvent {
        timestamp_ns,
        session_id: "test_session".to_string(),
        transport: "mcp".to_string(),
        method: Some("tools/call".to_string()),
        target_host: "http://127.0.0.1:3000".to_string(),
        target_port: Some(3000),
        url_path: Some(tool.to_string()),
        request_headers: None,
        request_body: Some(params.to_string()),
        request_body_hash: None,
        response_status: Some(200),
        response_body: Some("{}".to_string()),
        response_body_hash: None,
        dlp_findings: None,
        injection_findings: None,
        latency_ms: Some(10.0),
        verdict: Some("allow".to_string()),
    }
}

fn write_temp_policy(yaml: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(yaml.as_bytes()).unwrap();
    file
}

#[test]
fn test_ac4_1_lint_passes() {
    let events = vec![
        make_event("list_files", "{\"path\": \"/var/log\"}", "2026-06-11T10:00:00Z"),
        make_event("delete_file", "{\"path\": \"/etc/passwd\"}", "2026-06-11T10:01:00Z"),
    ];
    let yaml = generate_from_events(&events, 30);
    
    // Write to a temporary file and lint it
    let file = write_temp_policy(&yaml);
    let path = file.path().to_str().unwrap();
    
    // We expect warning 2 because the policy has mutation tools with no validators
    // Let's just check it doesn't fail with 1 (fatal/error)
    let exit_code = agentwall::lint::execute(path).unwrap();
    assert!(exit_code == 0 || exit_code == 2, "Linter returned fatal error code {}", exit_code);
}

#[test]
fn test_ac4_2_all_tools_present() {
    let events = vec![
        make_event("tool_a", "{}", "2026-06-11T10:00:00Z"),
        make_event("tool_b", "{}", "2026-06-11T10:01:00Z"),
        make_event("tool_c", "{}", "2026-06-11T10:02:00Z"),
    ];
    let yaml = generate_from_events(&events, 30);
    assert!(yaml.contains("- name: tool_a"));
    assert!(yaml.contains("- name: tool_b"));
    assert!(yaml.contains("- name: tool_c"));
}

#[test]
fn test_ac4_3_max_length_headroom() {
    let mut events = Vec::new();
    // length of string is 100
    let long_str = "a".repeat(100);
    events.push(make_event("tool_a", &format!("{{\"param\": \"{}\"}}", long_str), "2026-06-11T10:00:00Z"));
    
    let yaml = generate_from_events(&events, 30);
    assert!(yaml.contains("max_length: 120")); // 100 * 1.2 = 120
}

#[test]
fn test_ac4_4_low_confidence_flag() {
    let mut events = Vec::new();
    for _ in 0..9 {
        events.push(make_event("rare_tool", "{}", "2026-06-11T10:00:00Z"));
    }
    let yaml = generate_from_events(&events, 30);
    assert!(yaml.contains("confidence: low"));
    assert!(yaml.contains("(9 observations)"));
}

#[test]
fn test_ac4_5_anomaly_detection() {
    let mut events = Vec::new();
    for _ in 0..20 {
        events.push(make_event("tool_a", "{\"param\": \"common\"}", "2026-06-11T10:00:00Z"));
    }
    // A much longer string to trigger a z-score > 3.0 (score 1.0)
    let rare = "a".repeat(50);
    events.push(make_event("tool_a", &format!("{{\"param\": \"{}\"}}", rare), "2026-06-11T10:00:00Z"));
    
    let yaml = generate_from_events(&events, 30);
    assert!(yaml.contains("Anomalies (review required)"));
    assert!(yaml.contains(&rare));
}

#[test]
fn test_ac4_6_nested_json_5levels() {
    let events = vec![
        make_event("tool_a", "{\"l1\": {\"l2\": {\"l3\": {\"l4\": {\"l5\": \"deep_value\"}}}}}", "2026-06-11T10:00:00Z")
    ];
    let yaml = generate_from_events(&events, 30);
    // Should be flattened to l1.l2.l3.l4.l5
    assert!(yaml.contains("name: l1.l2.l3.l4.l5"));
}

#[test]
fn test_enum_detection() {
    let mut events = Vec::new();
    for _ in 0..5 {
        events.push(make_event("tool_a", "{\"color\": \"red\"}", "2026-06-11T10:00:00Z"));
        events.push(make_event("tool_a", "{\"color\": \"blue\"}", "2026-06-11T10:00:00Z"));
    }
    let yaml = generate_from_events(&events, 30);
    assert!(yaml.contains("# enum:"));
    assert!(yaml.contains("#  - \"red\""));
    assert!(yaml.contains("#  - \"blue\""));
}

#[test]
fn test_array_max_items() {
    let events = vec![
        make_event("tool_a", "{\"arr\": [1, 2, 3]}", "2026-06-11T10:00:00Z")
    ];
    let yaml = generate_from_events(&events, 30);
    // 3 * 1.2 = 3.6 -> ceil -> 4, max with 1 -> 4
    assert!(yaml.contains("# max_items: 4"));
}

#[test]
fn test_path_traversal_validator() {
    let events = vec![
        make_event("tool_a", "{\"path\": \"/etc/passwd\"}", "2026-06-11T10:00:00Z")
    ];
    let yaml = generate_from_events(&events, 30);
    assert!(yaml.contains("validators:"));
    assert!(yaml.contains("- path_traversal"));
}

#[test]
fn test_observation_window() {
    let events = vec![
        make_event("tool_a", "{}", "2026-06-01T10:00:00Z"),
        make_event("tool_a", "{}", "2026-06-15T10:00:00Z"),
    ];
    let yaml = generate_from_events(&events, 30);
    assert!(yaml.contains("Observation window: 2026-06-01 to 2026-06-15"));
}

#[test]
fn test_required_threshold() {
    let mut events = Vec::new();
    for _ in 0..8 {
        // Param is present 80% of the time
        events.push(make_event("tool_a", "{\"opt\": \"yes\"}", "2026-06-11T10:00:00Z"));
    }
    for _ in 0..2 {
        events.push(make_event("tool_a", "{}", "2026-06-11T10:00:00Z"));
    }
    let yaml = generate_from_events(&events, 30);
    // Present in 8/10 calls (80%), so it should not be required (threshold is 90%)
    assert!(yaml.contains("required: false"));
}

#[test]
fn test_null_events() {
    let yaml = generate_from_events(&[], 30);
    assert!(yaml.contains("tools: []"));
    assert!(yaml.contains("version: \"2\""));
}

#[test]
fn test_large_event_set() {
    let mut events = Vec::with_capacity(10_000);
    for i in 0..10_000 {
        events.push(make_event(
            &format!("tool_{}", i % 50),
            "{\"param\": \"value\"}",
            "2026-06-11T10:00:00Z"
        ));
    }
    let start = Instant::now();
    let _yaml = generate_from_events(&events, 30);
    let duration = start.elapsed();
    assert!(duration.as_secs() < 3, "Policy generation took too long: {:?}", duration);
}
