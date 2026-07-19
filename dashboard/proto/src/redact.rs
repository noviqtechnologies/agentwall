//! The redaction function — the one and only path from raw internal event
//! data to [`RedactedEvent`].
//!
//! # Trust contract
//! The caller (gateway) vouches that these fields are gateway-generated
//! or policy-derived, never raw agent-supplied text:
//! - `session_id`
//! - `agent_id` (comes from validated OIDC `sub` claim)
//! - `tool_name` when `tool_name_is_allowlisted == true`
//!
//! All other fields (dlp findings' `preview`, injection `matched_text`,
//! semantic `explanation`) MAY contain hostile content and are dropped
//! by this function — never propagated.

use crate::event::{
    RedactedDecision, RedactedDlpFinding, RedactedEvent, RedactedInjectionFinding,
    RedactedSemanticFinding, SecretCategory, SemanticFindingType,
};
use std::collections::BTreeMap;
use uuid::Uuid;

/// The gateway's internal event shape, provided to [`redact_event`] as
/// borrowed input. The gateway constructs this from its live event state
/// without copying; redaction produces owned data.
pub struct RawEventForRedaction<'a> {
    pub session_id: &'a str,
    pub agent_id: &'a str,
    pub tool_name: &'a str,
    pub tool_name_is_allowlisted: bool,
    pub decision: RawDecision,
    pub timestamp_ms: i64,
    pub dlp_findings: &'a [RawDlpFinding<'a>],
    pub injection_findings: &'a [RawInjectionFinding<'a>],
    pub semantic_findings: &'a [RawSemanticFinding],
}

#[derive(Debug, Clone, Copy)]
pub enum RawDecision {
    Allowed,
    Denied,
    Warned,
}

/// Raw DLP finding as produced by the gateway's scanner. Mirrors the
/// shape of `crate::policy::dlp::SecretFinding` in the gateway.
pub struct RawDlpFinding<'a> {
    pub category: SecretCategory,
    pub pattern_name: &'a str,
    #[allow(dead_code)]
    pub preview: &'a str,
    #[allow(dead_code)]
    pub position: usize,
    #[allow(dead_code)]
    pub length: usize,
}

pub struct RawInjectionFinding<'a> {
    pub pattern_name: &'a str,
    #[allow(dead_code)]
    pub matched_text: &'a str,
}

pub struct RawSemanticFinding {
    pub anomaly_score: f32,
    pub finding_type: SemanticFindingType,
    #[allow(dead_code)]
    pub explanation: String,
}

/// Redact a raw internal event into the wire-safe [`RedactedEvent`].
///
/// This is the SOLE constructor path from raw internal data to a
/// [`RedactedEvent`]. Every raw field is either dropped, categorized, or
/// counted — never propagated verbatim as user data.
pub fn redact_event(raw: &RawEventForRedaction<'_>) -> RedactedEvent {
    let mut dlp_grouped: BTreeMap<(SecretCategory, String), u32> = BTreeMap::new();
    for f in raw.dlp_findings {
        *dlp_grouped
            .entry((f.category.clone(), f.pattern_name.to_string()))
            .or_insert(0) += 1;
    }
    let dlp_findings: Vec<RedactedDlpFinding> = dlp_grouped
        .into_iter()
        .map(|((category, pattern_name), count)| RedactedDlpFinding {
            category,
            pattern_name,
            count,
        })
        .collect();

    let mut inj_grouped: BTreeMap<String, u32> = BTreeMap::new();
    for f in raw.injection_findings {
        *inj_grouped.entry(f.pattern_name.to_string()).or_insert(0) += 1;
    }
    let injection_findings: Vec<RedactedInjectionFinding> = inj_grouped
        .into_iter()
        .map(|(pattern_name, count)| RedactedInjectionFinding {
            pattern_name,
            count,
        })
        .collect();

    let semantic_findings: Vec<RedactedSemanticFinding> = raw
        .semantic_findings
        .iter()
        .map(|f| RedactedSemanticFinding {
            anomaly_score: f.anomaly_score,
            finding_type: f.finding_type,
        })
        .collect();

    let decision = match raw.decision {
        RawDecision::Allowed => RedactedDecision::Allowed,
        RawDecision::Denied => RedactedDecision::Denied,
        RawDecision::Warned => RedactedDecision::Warned,
    };

    let tool_name = if raw.tool_name_is_allowlisted {
        raw.tool_name.to_string()
    } else {
        "<unlisted_tool>".to_string()
    };

    RedactedEvent {
        event_id: Uuid::new_v4(),
        timestamp_ms: raw.timestamp_ms,
        session_id: raw.session_id.to_string(),
        agent_id: raw.agent_id.to_string(),
        tool_name,
        decision,
        dlp_findings,
        injection_findings,
        semantic_findings,
    }
}
