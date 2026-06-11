use agentwall::generate_policy::generate_from_events;
use agentwall::proxy::db::Event;

#[test]
fn test_policy_generation_stub() {
    let events = vec![
        Event {
            timestamp: "2026-06-11T10:00:00Z".to_string(),
            tool_name: "list_files".to_string(),
            parameters: "{\"path\": \"/var/log\"}".to_string(),
            response: "{}".to_string(),
            upstream_endpoint: "http://127.0.0.1:3000".to_string(),
            session_id: "session_1".to_string(),
            latency_ms: 10.0,
        },
        Event {
            timestamp: "2026-06-11T10:01:00Z".to_string(),
            tool_name: "delete_file".to_string(),
            parameters: "{\"path\": \"/etc/passwd\"}".to_string(),
            response: "{}".to_string(),
            upstream_endpoint: "http://127.0.0.1:3000".to_string(),
            session_id: "session_1".to_string(),
            latency_ms: 15.0,
        },
    ];

    let yaml = generate_from_events(&events);
    
    assert!(yaml.contains("tools:"));
    assert!(yaml.contains("- name: list_files"));
    assert!(yaml.contains("- name: delete_file"));
    assert!(yaml.contains("risk_tier: TIER_3")); // list_files
    assert!(yaml.contains("risk_tier: TIER_1")); // delete_file (destructive)
    assert!(yaml.contains("path"));
    assert!(yaml.contains("string"));
}
