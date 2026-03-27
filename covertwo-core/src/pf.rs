use anyhow::{Context, Result};
use std::io::Write as _;
use std::process::{Command, Stdio};
use tracing::{info, warn};

pub struct PfController {
    pub anchor_name: String,
    pub table_name: String,
}

impl PfController {
    pub fn new(anchor_name: impl Into<String>, table_name: impl Into<String>) -> Self {
        Self {
            anchor_name: anchor_name.into(),
            table_name: table_name.into(),
        }
    }

    /// Ensures PF is enabled. Returns true if we had to enable it, false if already enabled.
    pub fn ensure_enabled(&self) -> Result<bool> {
        let out = Command::new("pfctl")
            .args(["-s", "info"])
            .output()
            .context("Failed to run pfctl -s info")?;

        if String::from_utf8_lossy(&out.stdout).contains("Status: Enabled") {
            info!("PF already enabled");
            return Ok(false);
        }

        let out = Command::new("pfctl")
            .arg("-e")
            .output()
            .context("Failed to run pfctl -e")?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("Failed to enable PF: {}", stderr);
        }

        info!("PF enabled");
        Ok(true)
    }

    /// Writes the anchor rules file and loads it into PF.
    /// Called once at install time and on daemon startup.
    pub fn setup_anchor(&self) -> Result<()> {
        let anchor_path = format!("/etc/pf.anchors/{}", self.anchor_name);
        let rules = format!(
            "table <{table}> persist\n\
             block drop in  quick from <{table}> to any\n\
             block drop out quick from any to <{table}>\n",
            table = self.table_name
        );

        std::fs::write(&anchor_path, &rules)
            .with_context(|| format!("Failed to write anchor file to {}", anchor_path))?;

        let out = Command::new("pfctl")
            .args(["-a", &self.anchor_name, "-f", &anchor_path])
            .output()
            .with_context(|| format!("Failed to load anchor from {}", anchor_path))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // pfctl exits non-zero on warnings too; only fail on meaningful errors
            if !stderr.contains("warning") {
                anyhow::bail!("Failed to load PF anchor: {}", stderr);
            }
            warn!("pfctl anchor load warning: {}", stderr.trim());
        }

        info!(anchor = %self.anchor_name, "PF anchor loaded");
        Ok(())
    }

    /// Atomically replaces the blocklist table with new entries.
    /// `entries` is newline-separated IPs/CIDRs with no comments.
    pub fn apply_table(&self, entries: &str) -> Result<usize> {
        let mut child = Command::new("pfctl")
            .args([
                "-a",
                &self.anchor_name,
                "-t",
                &self.table_name,
                "-T",
                "replace",
                "-f",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn pfctl")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(entries.as_bytes())
                .context("Failed to write to pfctl stdin")?;
        }

        let out = child
            .wait_with_output()
            .context("Failed to wait for pfctl")?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("pfctl table replace failed: {}", stderr);
        }

        let count = entries.lines().filter(|l| !l.trim().is_empty()).count();
        info!(
            anchor = %self.anchor_name,
            table  = %self.table_name,
            count,
            "Blocklist table updated"
        );
        Ok(count)
    }

    /// Flushes all entries from the table (used on clean uninstall, not on S3 failure).
    pub fn flush_table(&self) -> Result<()> {
        let out = Command::new("pfctl")
            .args([
                "-a",
                &self.anchor_name,
                "-t",
                &self.table_name,
                "-T",
                "flush",
            ])
            .output()
            .context("Failed to run pfctl flush")?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("pfctl flush failed: {}", stderr);
        }

        info!("PF table flushed");
        Ok(())
    }

    /// Returns current rule count in the table.
    pub fn rule_count(&self) -> Result<usize> {
        let out = Command::new("pfctl")
            .args([
                "-a",
                &self.anchor_name,
                "-t",
                &self.table_name,
                "-T",
                "show",
            ])
            .output()
            .context("Failed to run pfctl show")?;

        if !out.status.success() {
            return Ok(0); // table may not exist yet
        }

        let stdout = String::from_utf8_lossy(&out.stdout);
        Ok(stdout.lines().filter(|l| !l.trim().is_empty()).count())
    }
}
