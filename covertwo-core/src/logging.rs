use crate::config::SplunkConfig;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use tracing::warn;

/// Key operational event types sent to Splunk HEC.
/// Not every tracing log line — only security-relevant events.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    DaemonStart,
    DaemonStop,
    SyncSuccess,
    SyncFailure,
    EmergencyTrigger,
    PfApplySuccess,
    PfApplyFailure,
    RuleAdded,
    RuleRemoved,
    HeartbeatSent,
    AuthFailure,
    S3Unreachable,
    ConfigError,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string());
        write!(f, "{}", s)
    }
}

#[derive(Clone)]
pub struct SplunkClient {
    client: reqwest::Client,
    url: String,
    token: String,
    index: String,
    sourcetype: String,
    hostname: String,
}

impl SplunkClient {
    pub fn new(config: &SplunkConfig, hostname: impl Into<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        Ok(Self {
            client,
            url: format!("{}/services/collector/event", config.hec_url.trim_end_matches('/')),
            token: format!("Splunk {}", config.hec_token),
            index: config.index.clone(),
            sourcetype: config.sourcetype.clone(),
            hostname: hostname.into(),
        })
    }

    /// Send a structured event to Splunk HEC.
    /// Failures are logged locally but never panic — the daemon must not die
    /// because Splunk is temporarily unreachable.
    pub async fn send(&self, event_type: EventType, mut payload: Value) {
        payload["event_type"] = json!(event_type.to_string());
        payload["host"] = json!(self.hostname);

        let body = json!({
            "time": Utc::now().timestamp_millis() as f64 / 1000.0,
            "host": self.hostname,
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": payload,
        });

        match self
            .client
            .post(&self.url)
            .header("Authorization", &self.token)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                warn!(
                    status = %resp.status(),
                    event_type = %event_type,
                    "Splunk HEC returned non-success status"
                );
            }
            Err(e) => {
                warn!(error = %e, event_type = %event_type, "Failed to send event to Splunk HEC");
            }
        }
    }

    pub async fn daemon_start(&self, version: &str, machine_id: &str) {
        self.send(
            EventType::DaemonStart,
            json!({ "version": version, "machine_id": machine_id }),
        )
        .await;
    }

    pub async fn daemon_stop(&self, machine_id: &str) {
        self.send(EventType::DaemonStop, json!({ "machine_id": machine_id }))
            .await;
    }

    pub async fn sync_success(&self, machine_id: &str, rule_count: usize, changed: bool) {
        self.send(
            EventType::SyncSuccess,
            json!({ "machine_id": machine_id, "rule_count": rule_count, "changed": changed }),
        )
        .await;
    }

    pub async fn sync_failure(&self, machine_id: &str, error: &str) {
        self.send(
            EventType::SyncFailure,
            json!({ "machine_id": machine_id, "error": error }),
        )
        .await;
    }

    pub async fn pf_apply_success(&self, machine_id: &str, rule_count: usize) {
        self.send(
            EventType::PfApplySuccess,
            json!({ "machine_id": machine_id, "rule_count": rule_count }),
        )
        .await;
    }

    pub async fn pf_apply_failure(&self, machine_id: &str, error: &str) {
        self.send(
            EventType::PfApplyFailure,
            json!({ "machine_id": machine_id, "error": error }),
        )
        .await;
    }

    pub async fn emergency_trigger(&self, machine_id: &str) {
        self.send(
            EventType::EmergencyTrigger,
            json!({ "machine_id": machine_id }),
        )
        .await;
    }

    pub async fn s3_unreachable(&self, machine_id: &str, error: &str) {
        self.send(
            EventType::S3Unreachable,
            json!({ "machine_id": machine_id, "error": error, "action": "fail_closed" }),
        )
        .await;
    }

    pub async fn heartbeat(
        &self,
        machine_id: &str,
        rule_count: usize,
        last_sync_ok: bool,
        daemon_version: &str,
    ) {
        self.send(
            EventType::HeartbeatSent,
            json!({
                "machine_id": machine_id,
                "rule_count": rule_count,
                "last_sync_ok": last_sync_ok,
                "daemon_version": daemon_version,
            }),
        )
        .await;
    }

    pub async fn rule_added(&self, machine_id: &str, value: &str, added_by: &str) {
        self.send(
            EventType::RuleAdded,
            json!({ "machine_id": machine_id, "value": value, "added_by": added_by }),
        )
        .await;
    }

    pub async fn rule_removed(&self, machine_id: &str, value: &str, removed_by: &str) {
        self.send(
            EventType::RuleRemoved,
            json!({ "machine_id": machine_id, "value": value, "removed_by": removed_by }),
        )
        .await;
    }
}

/// Sets up JSON structured logging to stdout.
/// Call this once at binary startup before anything else.
pub fn setup_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().json().with_current_span(true))
        .init();
}
