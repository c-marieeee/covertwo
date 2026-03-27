use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    EntryAdded,
    EntryRemoved,
    BlocklistDownloaded,
    EmergencyTriggerFired,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuditAction::EntryAdded => "entry_added",
            AuditAction::EntryRemoved => "entry_removed",
            AuditAction::BlocklistDownloaded => "blocklist_downloaded",
            AuditAction::EmergencyTriggerFired => "emergency_trigger_fired",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
    pub actor: String,
    pub machine_id: String,
    pub hostname: String,
    pub target_value: Option<String>,
    pub details: Option<String>,
}

impl AuditEvent {
    pub fn new(
        action: AuditAction,
        actor: impl Into<String>,
        machine_id: impl Into<String>,
        hostname: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            action,
            actor: actor.into(),
            machine_id: machine_id.into(),
            hostname: hostname.into(),
            target_value: None,
            details: None,
        }
    }

    pub fn with_target(mut self, value: impl Into<String>) -> Self {
        self.target_value = Some(value.into());
        self
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// S3 key for this event: audit/2026/03/27/<id>.json
    pub fn s3_key(&self, prefix: &str) -> String {
        format!(
            "{}{}/{}.json",
            prefix,
            self.timestamp.format("%Y/%m/%d"),
            self.id
        )
    }
}
