use agentwall::self_healing::{ConfidenceDecay, AnomalyScorer, SuggestionEngine};
use agentwall::proxy::db::EgressEvent;

#[test]
fn test_confidence_decay() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;
    
    // Recent event (decay ~1.0)
    let decay_recent = ConfidenceDecay::calculate(now, 30);
    assert!(decay_recent > 0.95);
    
    // Very old event (decay ~0.0)
    let old = now - (60 * 24 * 60 * 60 * 1_000_000_000_i64); // 60 days
    let decay_old = ConfidenceDecay::calculate(old, 30);
    assert_eq!(decay_old, 0.0);
    
    // 30 days old event
    let thirty_days = now - (30 * 24 * 60 * 60 * 1_000_000_000_i64);
    let decay_thirty = ConfidenceDecay::calculate(thirty_days, 30);
    assert!(decay_thirty > 0.0 && decay_thirty < 1.0);
}

#[test]
fn test_anomaly_scorer() {
    let mut scorer = AnomalyScorer::new();
    
    // Add multiple observations for a tool
    for _ in 0..10 {
        scorer.observe("list_files", "path", "/var/log");
    }
    
    // Same param value again should have low anomaly score (not anomalous)
    let score1 = scorer.score("list_files", "path", "/var/log");
    assert!(score1 < 0.5); // Should be very low
    
    // Completely new param value should have high anomaly score
    let score2 = scorer.score("list_files", "path", "/etc/passwd");
    assert!(score2 > 0.9); // Should be high (Z-score based)
}

#[test]
fn test_suggestion_engine() {
    let mut scorer = AnomalyScorer::new();
    let mut events = Vec::new();
    
    // Populate scorer
    for _ in 0..10 {
        scorer.observe("list_files", "path", "/var/log");
        let mut event = EgressEvent {
            timestamp_ns: 0,
            session_id: "".to_string(),
            transport: "".to_string(),
            method: None,
            target_host: "".to_string(),
            target_port: None,
            url_path: Some("list_files".to_string()),
            request_headers: None,
            request_body: Some(r#"{"path":"/var/log"}"#.to_string()),
            request_body_hash: None,
            response_status: None,
            response_body: None,
            response_body_hash: None,
            dlp_findings: None,
            injection_findings: None,
            latency_ms: None,
            verdict: None,
        };
        events.push(event);
    }
    
    // Add anomalous event
    scorer.observe("list_files", "path", "/etc/shadow");
    let mut anomalous_event = EgressEvent {
        timestamp_ns: 0,
        session_id: "".to_string(),
        transport: "".to_string(),
        method: None,
        target_host: "".to_string(),
        target_port: None,
        url_path: Some("list_files".to_string()),
        request_headers: None,
        request_body: Some(r#"{"path":"/etc/shadow"}"#.to_string()),
        request_body_hash: None,
        response_status: None,
        response_body: None,
        response_body_hash: None,
        dlp_findings: None,
        injection_findings: None,
        latency_ms: None,
        verdict: None,
    };
    events.push(anomalous_event);
    
    let suggestions = SuggestionEngine::generate_suggestions(&scorer, 0.9, &events);
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].tool_name, "list_files");
    assert!(suggestions[0].reason.contains("anomaly score"));
}
