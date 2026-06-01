//! SIEM export backend for FR-104.
//!
//! Supports Splunk HEC, Datadog Logs, and OpenSearch. Export is fire-and-forget
//! with a configurable timeout (default 2s). On failure a `siem_export_failed`
//! event is emitted to the local structured log — the gateway never blocks a
//! tool call waiting for SIEM acknowledgement beyond the timeout.

use serde_json::{json, Value};
use std::time::Duration;

use super::logger::AuditEntry;
use crate::logging;

/// Which SIEM backend to target.
#[derive(Debug, Clone, PartialEq)]
pub enum SiemBackend {
    /// Splunk HTTP Event Collector — POST to /services/collector/event
    Splunk,
    /// Datadog Logs Intake — POST to the regional intake URL
    Datadog,
    /// OpenSearch / Elasticsearch — POST to /<index>/_doc
    OpenSearch,
    /// Disabled — no network export, local disk only
    Local,
}

impl SiemBackend {
    /// Parse a backend name from a CLI / env-var string.
    /// Returns `Local` for unknown values so the gateway degrades gracefully.
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "splunk"     => Self::Splunk,
            "datadog"    => Self::Datadog,
            "opensearch" => Self::OpenSearch,
            _            => Self::Local,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Splunk     => "splunk",
            Self::Datadog    => "datadog",
            Self::OpenSearch => "opensearch",
            Self::Local      => "local",
        }
    }
}

/// Structured SIEM export error.
#[derive(Debug)]
pub enum SiemError {
    /// HTTP request failed (network, DNS, TLS).
    RequestFailed(String),
    /// SIEM responded with a non-2xx status code.
    HttpError { status: u16, body: String },
    /// Export is disabled (backend = Local).
    Disabled,
}

impl std::fmt::Display for SiemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestFailed(e)         => write!(f, "request failed: {}", e),
            Self::HttpError { status, body } => write!(f, "HTTP {}: {}", status, body),
            Self::Disabled                 => write!(f, "SIEM export disabled (local only)"),
        }
    }
}

/// SIEM exporter.  Cheap to clone — the inner `reqwest::Client` is `Arc`-backed.
#[derive(Clone)]
pub struct SiemExporter {
    backend:  SiemBackend,
    endpoint: String,
    token:    String,
    timeout:  Duration,
    client:   reqwest::Client,
}

impl SiemExporter {
    /// Build a new exporter.
    ///
    /// * `backend`  — which SIEM system to target
    /// * `endpoint` — full ingestion URL supplied by the operator
    /// * `token`    — Splunk HEC token / Datadog API key / OpenSearch API key
    /// * `timeout_secs` — per-request timeout; 0 means use the 2s default
    pub fn new(
        backend: SiemBackend,
        endpoint: String,
        token: String,
        timeout_secs: u64,
    ) -> Self {
        let timeout = if timeout_secs == 0 {
            Duration::from_secs(2)
        } else {
            Duration::from_secs(timeout_secs)
        };

        // Build a client with the configured timeout so every request inherits it.
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { backend, endpoint, token, timeout, client }
    }

    /// Export a single audit entry to the configured SIEM backend.
    ///
    /// This is an **async** call. The caller is responsible for racing it against
    /// the gateway's SIEM timeout budget (see `logger.rs`).
    pub async fn export(&self, entry: &AuditEntry) -> Result<(), SiemError> {
        match &self.backend {
            SiemBackend::Local => Err(SiemError::Disabled),
            SiemBackend::Splunk => self.export_splunk(entry).await,
            SiemBackend::Datadog => self.export_datadog(entry).await,
            SiemBackend::OpenSearch => self.export_opensearch(entry).await,
        }
    }

    /// Whether SIEM export is active (i.e. not Local).
    pub fn is_active(&self) -> bool {
        self.backend != SiemBackend::Local
    }

    /// Backend name for logging.
    pub fn backend_name(&self) -> &str {
        self.backend.as_str()
    }

    // ─── Splunk HEC ──────────────────────────────────────────────────────────

    async fn export_splunk(&self, entry: &AuditEntry) -> Result<(), SiemError> {
        // Splunk HEC wraps the event in an outer object with optional metadata.
        let payload = json!({
            "time":       chrono::DateTime::parse_from_rfc3339(&entry.ts)
                            .map(|dt| dt.timestamp())
                            .unwrap_or(0),
            "sourcetype": "agentwall",
            "source":     "agentwall-gateway",
            "index":      "main",
            "event":      serde_json::to_value(entry).unwrap_or(Value::Null),
        });

        let resp = self.client
            .post(&self.endpoint)
            .header("Authorization", format!("Splunk {}", self.token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| SiemError::RequestFailed(e.to_string()))?;

        Self::check_response(resp).await
    }

    // ─── Datadog Logs ────────────────────────────────────────────────────────

    async fn export_datadog(&self, entry: &AuditEntry) -> Result<(), SiemError> {
        // Datadog Logs intake accepts a JSON array of log objects.
        let payload = json!([{
            "ddsource":  "agentwall",
            "ddtags":    format!("session:{},event:{}", entry.session_id, entry.event),
            "hostname":  "agentwall-gateway",
            "service":   "agentwall",
            "message":   serde_json::to_string(entry).unwrap_or_default(),
            // Flatten the entry fields so Datadog facets work out-of-the-box.
            "ts":        &entry.ts,
            "event_type": &entry.event,
            "session_id": &entry.session_id,
            "entry_index": entry.entry_index,
        }]);

        let resp = self.client
            .post(&self.endpoint)
            .header("DD-API-KEY", &self.token)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| SiemError::RequestFailed(e.to_string()))?;

        Self::check_response(resp).await
    }

    // ─── OpenSearch / Elasticsearch ──────────────────────────────────────────

    async fn export_opensearch(&self, entry: &AuditEntry) -> Result<(), SiemError> {
        // POST the document directly. The index path is part of the operator-supplied URL.
        // Example endpoint: https://opensearch.corp.com/agentwall-logs/_doc
        let payload = serde_json::to_value(entry).unwrap_or(Value::Null);

        let mut req = self.client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .json(&payload);

        // Support both Bearer token and HTTP Basic auth.
        // If token contains ':', treat as "user:password"; otherwise Bearer.
        if self.token.contains(':') {
            let mut parts = self.token.splitn(2, ':');
            let user = parts.next().unwrap_or("");
            let pass = parts.next().unwrap_or("");
            req = req.basic_auth(user, Some(pass));
        } else if !self.token.is_empty() {
            req = req.bearer_auth(&self.token);
        }

        let resp = req.send().await.map_err(|e| SiemError::RequestFailed(e.to_string()))?;

        Self::check_response(resp).await
    }

    // ─── Shared helpers ───────────────────────────────────────────────────────

    async fn check_response(resp: reqwest::Response) -> Result<(), SiemError> {
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        // Read up to 512 bytes of the error body for diagnostics without blocking long.
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable body>".to_string());
        let truncated = if body.len() > 512 { &body[..512] } else { &body };
        Err(SiemError::HttpError {
            status: status.as_u16(),
            body:   truncated.to_string(),
        })
    }
}

/// Attempt a SIEM export within the configured timeout, log failure gracefully.
///
/// This function never panics and never returns an error — on SIEM failure it
/// emits `siem_export_failed` to structured stderr and returns so the caller
/// can proceed with the local-disk fallback.
pub async fn try_export(exporter: &SiemExporter, entry: &AuditEntry) {
    if !exporter.is_active() {
        return;
    }

    match tokio::time::timeout(exporter.timeout, exporter.export(entry)).await {
        Ok(Ok(())) => {
            // Export succeeded — nothing to log.
        }
        Ok(Err(SiemError::Disabled)) => {
            // Backend is Local — silently skip.
        }
        Ok(Err(e)) => {
            logging::log_event(
                logging::Level::Warn,
                "siem_export_failed",
                serde_json::json!({
                    "backend":      exporter.backend_name(),
                    "reason":       e.to_string(),
                    "fallback":     "local_disk_applied",
                    "entry_index":  entry.entry_index,
                    "session":      &entry.session_id,
                }),
            );
        }
        Err(_elapsed) => {
            logging::log_event(
                logging::Level::Warn,
                "siem_export_failed",
                serde_json::json!({
                    "backend":      exporter.backend_name(),
                    "reason":       "timeout_elapsed",
                    "fallback":     "local_disk_applied",
                    "entry_index":  entry.entry_index,
                    "session":      &entry.session_id,
                }),
            );
        }
    }
}
