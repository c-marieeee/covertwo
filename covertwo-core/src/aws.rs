use crate::audit::AuditEvent;
use crate::blocklist::Blocklist;
use crate::config::AwsConfig;
use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_s3::primitives::ByteStream;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

pub type S3Client = aws_sdk_s3::Client;

/// Creates an S3 client using the ambient AWS credential chain.
/// For daemon machines this resolves via IAM Roles Anywhere (credential_process).
/// For admin tools this resolves via the operator's standard AWS credentials.
pub async fn create_s3_client(region: &str) -> Result<S3Client> {
    let sdk_config = aws_config::defaults(BehaviorVersion::latest())
        .region(aws_config::meta::region::RegionProviderChain::first_try(
            aws_sdk_s3::config::Region::new(region.to_string()),
        ))
        .load()
        .await;
    Ok(S3Client::new(&sdk_config))
}

/// Downloads and parses the blocklist JSON from S3.
pub async fn download_blocklist(client: &S3Client, cfg: &AwsConfig) -> Result<Blocklist> {
    debug!(key = %cfg.blocklist_key, "Downloading blocklist from S3");

    let resp = client
        .get_object()
        .bucket(&cfg.bucket)
        .key(&cfg.blocklist_key)
        .send()
        .await
        .with_context(|| {
            format!(
                "Failed to get s3://{}/{}",
                cfg.bucket, cfg.blocklist_key
            )
        })?;

    let bytes = resp
        .body
        .collect()
        .await
        .context("Failed to read S3 response body")?
        .into_bytes();

    Blocklist::from_json(&bytes).context("Failed to parse blocklist JSON")
}

/// Uploads the blocklist JSON to S3.
pub async fn upload_blocklist(
    client: &S3Client,
    cfg: &AwsConfig,
    blocklist: &Blocklist,
) -> Result<()> {
    let json = blocklist
        .to_json_pretty()
        .context("Failed to serialize blocklist")?;

    client
        .put_object()
        .bucket(&cfg.bucket)
        .key(&cfg.blocklist_key)
        .body(ByteStream::from(json))
        .content_type("application/json")
        .send()
        .await
        .with_context(|| {
            format!(
                "Failed to put s3://{}/{}",
                cfg.bucket, cfg.blocklist_key
            )
        })?;

    info!(key = %cfg.blocklist_key, "Blocklist uploaded to S3");
    Ok(())
}

/// Gets the ETag of the trigger file. Returns None if the object does not exist.
/// The daemon polls this every N seconds; a changed ETag means an emergency sync is needed.
pub async fn get_trigger_etag(client: &S3Client, cfg: &AwsConfig) -> Result<Option<String>> {
    match client
        .head_object()
        .bucket(&cfg.bucket)
        .key(&cfg.trigger_key)
        .send()
        .await
    {
        Ok(resp) => Ok(resp.e_tag().map(str::to_string)),
        Err(e) => {
            let svc_err = e.into_service_error();
            if svc_err.is_not_found() {
                Ok(None)
            } else {
                Err(anyhow::anyhow!("Failed to head trigger object: {}", svc_err))
            }
        }
    }
}

/// Touches the trigger file so all daemons re-sync within their poll interval.
/// The content doesn't matter — just the change in ETag.
pub async fn touch_trigger(client: &S3Client, cfg: &AwsConfig) -> Result<()> {
    let ts = Utc::now().to_rfc3339();
    client
        .put_object()
        .bucket(&cfg.bucket)
        .key(&cfg.trigger_key)
        .body(ByteStream::from(ts.into_bytes()))
        .content_type("text/plain")
        .send()
        .await
        .with_context(|| format!("Failed to touch trigger s3://{}/{}", cfg.bucket, cfg.trigger_key))?;

    info!("Emergency trigger file updated");
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Heartbeat {
    pub machine_id: String,
    pub hostname: String,
    pub timestamp: DateTime<Utc>,
    pub daemon_version: String,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_ok: bool,
    pub rule_count: usize,
    pub pf_enabled: bool,
}

/// Writes a machine heartbeat to S3 at heartbeats/<machine_id>.json.
/// Overwrites any previous heartbeat for this machine.
pub async fn write_heartbeat(client: &S3Client, cfg: &AwsConfig, hb: &Heartbeat) -> Result<()> {
    let key = format!("{}{}.json", cfg.heartbeat_prefix, hb.machine_id);
    let json = serde_json::to_vec_pretty(hb).context("Failed to serialize heartbeat")?;

    client
        .put_object()
        .bucket(&cfg.bucket)
        .key(&key)
        .body(ByteStream::from(json))
        .content_type("application/json")
        .send()
        .await
        .with_context(|| format!("Failed to write heartbeat to s3://{}/{}", cfg.bucket, key))?;

    debug!(key, "Heartbeat written");
    Ok(())
}

/// Writes a single audit event to S3 at audit/YYYY/MM/DD/<id>.json.
pub async fn write_audit_event(
    client: &S3Client,
    cfg: &AwsConfig,
    event: &AuditEvent,
) -> Result<()> {
    let key = event.s3_key(&cfg.audit_prefix);
    let json = serde_json::to_vec_pretty(event).context("Failed to serialize audit event")?;

    client
        .put_object()
        .bucket(&cfg.bucket)
        .key(&key)
        .body(ByteStream::from(json))
        .content_type("application/json")
        .send()
        .await
        .with_context(|| format!("Failed to write audit event to s3://{}/{}", cfg.bucket, key))?;

    debug!(key, action = %event.action, "Audit event written");
    Ok(())
}
