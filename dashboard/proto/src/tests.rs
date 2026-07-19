//! AC-23.10 property test: no secret survives redaction.
//!
//! For every [`SecretCategory`] variant, a fake secret is seeded into every
//! raw field that could plausibly carry hostile agent input, the raw event
//! is redacted, the result is serialized to JSON, and the fake secret is
//! asserted absent from that serialized output.

use crate::event::{SecretCategory, SemanticFindingType};
use crate::redact::{
    redact_event, RawDecision, RawDlpFinding, RawEventForRedaction, RawInjectionFinding,
    RawSemanticFinding,
};

fn fake_secret_for(cat: &SecretCategory) -> &'static str {
    match cat {
        SecretCategory::AwsAccessKey => "AKIAIOSFODNN7EXAMPLE",
        SecretCategory::GitHubToken => "FAKE-TEST-FIXTURE-GITHUB-TOKEN-NOT-REAL",
        SecretCategory::OpenAiApiKey => "FAKE-TEST-FIXTURE-OPENAI-KEY-NOT-REAL",
        SecretCategory::AnthropicApiKey => "FAKE-TEST-FIXTURE-ANTHROPIC-KEY-NOT-REAL",
        SecretCategory::SshPrivateKey => "FAKE-TEST-FIXTURE-SSH-PRIVATE-KEY-NOT-REAL",
        SecretCategory::StripeKey => "FAKE-TEST-FIXTURE-STRIPE-KEY-NOT-REAL",
        SecretCategory::DatabaseUri => "FAKE-TEST-FIXTURE-DATABASE-URI-NOT-REAL",
        SecretCategory::Pii => "FAKE-TEST-FIXTURE-PII-NOT-REAL",
        SecretCategory::HighEntropy => "FAKE-TEST-FIXTURE-HIGH-ENTROPY-NOT-REAL",
        SecretCategory::CryptoSeedPhrase => {
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
        }
        SecretCategory::EnvVar => "FAKE-TEST-FIXTURE-ENV-VAR-NOT-REAL",
        SecretCategory::AzureStorageKey => "FAKE-TEST-FIXTURE-AZURE-STORAGE-KEY-NOT-REAL",
        SecretCategory::GcpApiKey => "FAKE-TEST-FIXTURE-GCP-API-KEY-NOT-REAL",
        SecretCategory::SlackToken => "FAKE-TEST-FIXTURE-SLACK-TOKEN-NOT-REAL",
        SecretCategory::SendGridKey => "FAKE-TEST-FIXTURE-SENDGRID-KEY-NOT-REAL",
        SecretCategory::CreditCard => "FAKE-TEST-FIXTURE-CREDIT-CARD-NOT-REAL",
        SecretCategory::Other => "FAKE-TEST-FIXTURE-OTHER-SECRET-NOT-REAL",
    }
}

fn all_categories() -> Vec<SecretCategory> {
    vec![
        SecretCategory::AwsAccessKey,
        SecretCategory::GitHubToken,
        SecretCategory::OpenAiApiKey,
        SecretCategory::AnthropicApiKey,
        SecretCategory::SshPrivateKey,
        SecretCategory::StripeKey,
        SecretCategory::DatabaseUri,
        SecretCategory::Pii,
        SecretCategory::HighEntropy,
        SecretCategory::CryptoSeedPhrase,
        SecretCategory::EnvVar,
        SecretCategory::AzureStorageKey,
        SecretCategory::GcpApiKey,
        SecretCategory::SlackToken,
        SecretCategory::SendGridKey,
        SecretCategory::CreditCard,
        SecretCategory::Other,
    ]
}

#[test]
fn ac_23_10_no_secret_survives_redaction() {
    for cat in all_categories() {
        let secret = fake_secret_for(&cat);

        let raw = RawEventForRedaction {
            session_id: "sess-test-0001",
            agent_id: "agent-test-0001",
            tool_name: secret,
            tool_name_is_allowlisted: false,
            decision: RawDecision::Denied,
            timestamp_ms: 1_720_000_000_000,
            dlp_findings: &[RawDlpFinding {
                category: cat.clone(),
                pattern_name: "test-pattern",
                preview: secret,
                position: 42,
                length: secret.len(),
            }],
            injection_findings: &[RawInjectionFinding {
                pattern_name: "test-injection",
                matched_text: secret,
            }],
            semantic_findings: &[RawSemanticFinding {
                anomaly_score: 0.95,
                finding_type: SemanticFindingType::SemanticExfiltration,
                explanation: secret.to_string(),
            }],
        };

        let redacted = redact_event(&raw);
        let serialized = serde_json::to_string(&redacted).unwrap();

        assert!(
            !serialized.contains(secret),
            "AC-23.10 VIOLATION: fake secret for {:?} appeared in serialized RedactedEvent.\n\
             Secret: {}\nOutput: {}",
            cat,
            secret,
            serialized
        );
    }
}

#[test]
fn tool_name_passed_through_when_allowlisted() {
    let raw = RawEventForRedaction {
        session_id: "s",
        agent_id: "a",
        tool_name: "read_file",
        tool_name_is_allowlisted: true,
        decision: RawDecision::Allowed,
        timestamp_ms: 0,
        dlp_findings: &[],
        injection_findings: &[],
        semantic_findings: &[],
    };
    let redacted = redact_event(&raw);
    assert_eq!(redacted.tool_name, "read_file");
}

#[test]
fn tool_name_redacted_when_unlisted() {
    let raw = RawEventForRedaction {
        session_id: "s",
        agent_id: "a",
        tool_name: "AKIAIOSFODNN7EXAMPLE",
        tool_name_is_allowlisted: false,
        decision: RawDecision::Denied,
        timestamp_ms: 0,
        dlp_findings: &[],
        injection_findings: &[],
        semantic_findings: &[],
    };
    let redacted = redact_event(&raw);
    assert_eq!(redacted.tool_name, "<unlisted_tool>");
}

#[test]
fn dlp_findings_grouped_by_category_and_pattern() {
    let raw = RawEventForRedaction {
        session_id: "s",
        agent_id: "a",
        tool_name: "read_file",
        tool_name_is_allowlisted: true,
        decision: RawDecision::Warned,
        timestamp_ms: 0,
        dlp_findings: &[
            RawDlpFinding {
                category: SecretCategory::AwsAccessKey,
                pattern_name: "AWS Access Key (AKIA)",
                preview: "AKIAIOSFODNN7EXAMPLE",
                position: 0,
                length: 20,
            },
            RawDlpFinding {
                category: SecretCategory::AwsAccessKey,
                pattern_name: "AWS Access Key (AKIA)",
                preview: "AKIAIOSFODNN7ANOTHER",
                position: 100,
                length: 20,
            },
        ],
        injection_findings: &[],
        semantic_findings: &[],
    };
    let redacted = redact_event(&raw);
    assert_eq!(redacted.dlp_findings.len(), 1);
    assert_eq!(redacted.dlp_findings[0].count, 2);
    assert_eq!(redacted.dlp_findings[0].category, SecretCategory::AwsAccessKey);
}

#[test]
fn empty_findings_serialize_cleanly() {
    let raw = RawEventForRedaction {
        session_id: "s",
        agent_id: "a",
        tool_name: "read_file",
        tool_name_is_allowlisted: true,
        decision: RawDecision::Allowed,
        timestamp_ms: 0,
        dlp_findings: &[],
        injection_findings: &[],
        semantic_findings: &[],
    };
    let redacted = redact_event(&raw);
    let serialized = serde_json::to_string(&redacted).unwrap();
    let _: crate::event::RedactedEvent = serde_json::from_str(&serialized).unwrap();
}
