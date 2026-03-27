use anyhow::{Context, Result};
use chrono::Utc;
use covertwo_core::{
    aws::{
        create_s3_client, download_blocklist, get_trigger_etag, upload_blocklist, write_heartbeat,
        Heartbeat,
    },
    config::Config,
    logging::{setup_tracing, SplunkClient},
    pf::PfController,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");
const LOCAL_CACHE_PATH: &str = "/var/db/covertwo/blocklist.json";
const CONFIG_PATH: &str = "/etc/covertwo/config.toml";

/// Returns the macOS hardware serial number, falling back to hostname.
fn machine_id() -> String {
    let out = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .unwrap_or_default();

    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.contains("IOPlatformSerialNumber") {
            if let Some(serial) = line.split('"').nth(3) {
                if !serial.is_empty() {
                    return serial.to_string();
                }
            }
        }
    }

    hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

fn hostname() -> String {
    hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

/// Saves the blocklist to the local cache file (fail-closed support).
fn save_local_cache(data: &[u8]) -> Result<()> {
    let path = Path::new(LOCAL_CACHE_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create cache directory")?;
    }
    std::fs::write(path, data).context("Failed to write local cache")?;
    Ok(())
}

/// Loads the local cache file if it exists.
fn load_local_cache() -> Option<Vec<u8>> {
    std::fs::read(LOCAL_CACHE_PATH).ok()
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();

    // Allow overriding config path via first argument
    let config_path: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(CONFIG_PATH));

    let config = Config::load(&config_path)
        .with_context(|| format!("Failed to load config from {}", config_path.display()))?;

    let mid = machine_id();
    let host = hostname();

    info!(version = DAEMON_VERSION, machine_id = %mid, hostname = %host, "CoverTwo daemon starting");

    let splunk = SplunkClient::new(&config.splunk, &host)
        .context("Failed to create Splunk client")?;

    let s3 = create_s3_client(&config.aws.region)
        .await
        .context("Failed to create S3 client")?;

    let pf = PfController::new(&config.pf.anchor_name, &config.pf.table_name);

    // Ensure PF is on and anchor is configured
    if let Err(e) = pf.ensure_enabled() {
        error!(error = %e, "Failed to ensure PF is enabled");
        anyhow::bail!("PF setup failed: {}", e);
    }
    if let Err(e) = pf.setup_anchor() {
        error!(error = %e, "Failed to set up PF anchor");
        anyhow::bail!("PF anchor setup failed: {}", e);
    }

    // Shared state across tasks
    let last_sync_ok = Arc::new(AtomicBool::new(false));
    let rule_count = Arc::new(AtomicUsize::new(0));

    // Apply local cache immediately on startup (fail-closed: never start with no rules
    // if we had rules before)
    if let Some(cached) = load_local_cache() {
        match covertwo_core::blocklist::Blocklist::from_json(&cached) {
            Ok(bl) => {
                let table = bl.to_pfctl_table();
                match pf.apply_table(&table) {
                    Ok(n) => {
                        rule_count.store(n, Ordering::Relaxed);
                        info!(count = n, "Applied cached blocklist on startup");
                    }
                    Err(e) => warn!(error = %e, "Failed to apply cached blocklist"),
                }
            }
            Err(e) => warn!(error = %e, "Cached blocklist is corrupt, ignoring"),
        }
    }

    splunk
        .daemon_start(DAEMON_VERSION, &mid)
        .await;

    // Channel: trigger task → sync task (unbounded to not block the poller)
    let (trigger_tx, mut trigger_rx) = mpsc::channel::<()>(1);

    // Broadcast shutdown to all tasks
    let (shutdown_tx, _) = broadcast::channel::<()>(4);

    // --- Trigger poll task: checks trigger.txt ETag every N seconds ---
    {
        let s3 = s3.clone();
        let cfg = config.aws.clone();
        let poll_secs = config.sync.trigger_poll_secs;
        let splunk = splunk.clone();
        let mid2 = mid.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut last_etag: Option<String> = None;

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(poll_secs)) => {
                        match get_trigger_etag(&s3, &cfg).await {
                            Ok(etag) => {
                                if etag != last_etag {
                                    if last_etag.is_some() {
                                        // Only fire after we have a baseline ETag;
                                        // ignore the very first observation to avoid
                                        // double-syncing on daemon startup.
                                        info!("Emergency trigger detected");
                                        splunk.emergency_trigger(&mid2).await;
                                        let _ = trigger_tx.try_send(());
                                    }
                                    last_etag = etag;
                                }
                            }
                            Err(e) => warn!(error = %e, "Trigger poll failed"),
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Trigger poll task shutting down");
                        break;
                    }
                }
            }
        });
    }

    // --- Heartbeat task: writes to S3 and Splunk every sync interval ---
    {
        let s3 = s3.clone();
        let cfg_aws = config.aws.clone();
        let interval_secs = config.sync.interval_secs;
        let splunk = splunk.clone();
        let mid2 = mid.clone();
        let host2 = host.clone();
        let last_sync_ok2 = last_sync_ok.clone();
        let rule_count2 = rule_count.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                        let ok = last_sync_ok2.load(Ordering::Relaxed);
                        let n = rule_count2.load(Ordering::Relaxed);

                        let hb = Heartbeat {
                            machine_id: mid2.clone(),
                            hostname: host2.clone(),
                            timestamp: Utc::now(),
                            daemon_version: DAEMON_VERSION.to_string(),
                            last_sync_at: None, // simplified; could be tracked with a Mutex
                            last_sync_ok: ok,
                            rule_count: n,
                            pf_enabled: true,
                        };

                        if let Err(e) = write_heartbeat(&s3, &cfg_aws, &hb).await {
                            warn!(error = %e, "Failed to write heartbeat to S3");
                        }

                        splunk.heartbeat(&mid2, n, ok, DAEMON_VERSION).await;
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Heartbeat task shutting down");
                        break;
                    }
                }
            }
        });
    }

    // --- Main sync loop ---
    {
        let s3 = s3.clone();
        let cfg = config.clone();
        let splunk = splunk.clone();
        let mid2 = mid.clone();
        let last_sync_ok2 = last_sync_ok.clone();
        let rule_count2 = rule_count.clone();
        let interval_secs = config.sync.interval_secs;
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            // Do an immediate sync on startup
            sync_once(
                &s3,
                &cfg,
                &pf,
                &splunk,
                &mid2,
                &last_sync_ok2,
                &rule_count2,
            )
            .await;

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                        sync_once(&s3, &cfg, &pf, &splunk, &mid2, &last_sync_ok2, &rule_count2).await;
                    }
                    Some(()) = trigger_rx.recv() => {
                        info!("Emergency sync triggered");
                        sync_once(&s3, &cfg, &pf, &splunk, &mid2, &last_sync_ok2, &rule_count2).await;
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Sync loop shutting down");
                        break;
                    }
                }
            }
        });
    }

    // Wait for SIGINT or SIGTERM
    let mut sigint = signal(SignalKind::interrupt()).context("Failed to set SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("Failed to set SIGTERM handler")?;

    tokio::select! {
        _ = sigint.recv()  => info!("Received SIGINT"),
        _ = sigterm.recv() => info!("Received SIGTERM"),
    }

    info!("Shutting down CoverTwo daemon");
    splunk.daemon_stop(&mid).await;

    // Signal all tasks to stop
    let _ = shutdown_tx.send(());

    // Brief grace period for tasks to finish their current operation
    tokio::time::sleep(Duration::from_millis(500)).await;

    Ok(())
}

/// Performs one full S3 → pfctl sync cycle.
/// On S3 failure: keeps existing PF rules in place (fail closed).
async fn sync_once(
    s3: &covertwo_core::aws::S3Client,
    config: &Config,
    pf: &PfController,
    splunk: &SplunkClient,
    machine_id: &str,
    last_sync_ok: &Arc<AtomicBool>,
    rule_count: &Arc<AtomicUsize>,
) {
    info!("Starting blocklist sync");

    let blocklist = match download_blocklist(s3, &config.aws).await {
        Ok(bl) => bl,
        Err(e) => {
            error!(error = %e, "Failed to download blocklist — keeping existing rules (fail closed)");
            splunk.sync_failure(machine_id, &e.to_string()).await;
            splunk.s3_unreachable(machine_id, &e.to_string()).await;
            last_sync_ok.store(false, Ordering::Relaxed);
            return;
        }
    };

    // Cache locally so we survive future S3 outages
    match blocklist.to_json_pretty() {
        Ok(json) => {
            if let Err(e) = save_local_cache(&json) {
                warn!(error = %e, "Failed to save local cache");
            }
        }
        Err(e) => warn!(error = %e, "Failed to serialize blocklist for cache"),
    }

    let table = blocklist.to_pfctl_table();
    let entry_count = blocklist.enforceable_entries().count();

    match pf.apply_table(&table) {
        Ok(n) => {
            rule_count.store(n, Ordering::Relaxed);
            last_sync_ok.store(true, Ordering::Relaxed);

            let changed = n != rule_count.load(Ordering::Relaxed);
            splunk.sync_success(machine_id, n, changed).await;
            splunk.pf_apply_success(machine_id, n).await;

            info!(rule_count = n, "Sync complete");
        }
        Err(e) => {
            error!(error = %e, entry_count, "Failed to apply blocklist to PF — keeping existing rules");
            splunk.pf_apply_failure(machine_id, &e.to_string()).await;
            last_sync_ok.store(false, Ordering::Relaxed);
        }
    }
}
