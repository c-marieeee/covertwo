use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub aws: AwsConfig,
    #[serde(default)]
    pub sync: SyncConfig,
    #[serde(default)]
    pub pf: PfConfig,
    pub splunk: SplunkConfig,
    #[serde(default)]
    pub web: WebConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    pub bucket: String,
    #[serde(default = "default_blocklist_key")]
    pub blocklist_key: String,
    #[serde(default = "default_trigger_key")]
    pub trigger_key: String,
    #[serde(default = "default_heartbeat_prefix")]
    pub heartbeat_prefix: String,
    #[serde(default = "default_audit_prefix")]
    pub audit_prefix: String,
}

fn default_blocklist_key() -> String {
    "blocklist.json".to_string()
}
fn default_trigger_key() -> String {
    "trigger.txt".to_string()
}
fn default_heartbeat_prefix() -> String {
    "heartbeats/".to_string()
}
fn default_audit_prefix() -> String {
    "audit/".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncConfig {
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_trigger_poll_secs")]
    pub trigger_poll_secs: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_interval_secs(),
            trigger_poll_secs: default_trigger_poll_secs(),
        }
    }
}

fn default_interval_secs() -> u64 {
    60
}
fn default_trigger_poll_secs() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize)]
pub struct PfConfig {
    #[serde(default = "default_anchor_name")]
    pub anchor_name: String,
    #[serde(default = "default_table_name")]
    pub table_name: String,
}

impl Default for PfConfig {
    fn default() -> Self {
        Self {
            anchor_name: default_anchor_name(),
            table_name: default_table_name(),
        }
    }
}

fn default_anchor_name() -> String {
    "com.covertwo.blocklist".to_string()
}
fn default_table_name() -> String {
    "blocklist".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct SplunkConfig {
    pub hec_url: String,
    pub hec_token: String,
    #[serde(default = "default_index")]
    pub index: String,
    #[serde(default = "default_sourcetype")]
    pub sourcetype: String,
}

fn default_index() -> String {
    "security".to_string()
}
fn default_sourcetype() -> String {
    "covertwo:daemon".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WebConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default)]
    pub api_token: String,
}

fn default_bind_addr() -> String {
    "127.0.0.1:8080".to_string()
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config from {}", path.display()))?;
        toml::from_str(&content).context("Failed to parse config TOML")
    }
}
