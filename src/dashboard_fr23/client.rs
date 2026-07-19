use dashboard_proto::event::RedactedEvent;
use dashboard_proto::alert::RedactedAlert;

pub struct DashboardClient {
    http: reqwest::Client,
    base_url: String,
    secret: String,
}

impl DashboardClient {
    pub fn from_env() -> Option<Self> {
        let base_url = std::env::var("DASHBOARD_API_URL").ok()?;
        let secret = std::env::var("GATEWAY_SECRET").unwrap_or_default();

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("failed to build dashboard HTTP client");

        Some(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            secret,
        })
    }

    pub fn send_event(&self, event: RedactedEvent) {
        let url = format!("{}/api/v1/ingest/events", self.base_url);
        let req = self
            .http
            .post(&url)
            .header("Authorization", &self.secret)
            .json(&event);

        tokio::spawn(async move {
            if let Err(e) = req.send().await {
                crate::logging::log_event(
                    crate::logging::Level::Warn,
                    "dashboard_send_event_failed",
                    serde_json::json!({"error": e.to_string()}),
                );
            }
        });
    }

    pub fn send_alert(&self, alert: RedactedAlert) {
        let url = format!("{}/api/v1/ingest/alerts", self.base_url);
        let req = self
            .http
            .post(&url)
            .header("Authorization", &self.secret)
            .json(&alert);

        tokio::spawn(async move {
            if let Err(e) = req.send().await {
                crate::logging::log_event(
                    crate::logging::Level::Warn,
                    "dashboard_send_alert_failed",
                    serde_json::json!({"error": e.to_string()}),
                );
            }
        });
    }
}
