//! Real-time alert — a security-worthy event pushed via SSE (AC-23.2).

use crate::event::RedactedEvent;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A real-time alert delivered to connected dashboards via SSE.
///
/// AC-23.2: DLP finding → alert feed within 1 second.
///
/// Emission path: gateway detects a finding → constructs a [`RedactedAlert`]
/// → POSTs to `dashboard-api` → dashboard-api fans out to (a) Postgres
/// persistence and (b) in-memory SSE broadcast → connected browsers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RedactedAlert {
    pub alert_id: Uuid,
    pub severity: AlertSeverity,
    pub event: RedactedEvent,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}
