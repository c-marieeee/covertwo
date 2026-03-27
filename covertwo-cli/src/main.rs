use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use covertwo_core::{
    audit::{AuditAction, AuditEvent},
    aws::{create_s3_client, download_blocklist, touch_trigger, upload_blocklist, write_audit_event},
    blocklist::{Blocklist, BlocklistEntry, Category, EntryType},
    config::Config,
    logging::setup_tracing,
};
use std::{path::PathBuf, str::FromStr};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "covertwo",
    about = "CoverTwo — enterprise IP blocklist manager",
    version
)]
struct Cli {
    /// Path to config file
    #[arg(short, long, env = "COVERTWO_CONFIG", default_value = "/etc/covertwo/config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Blocklist management
    Blocklist {
        #[command(subcommand)]
        action: BlocklistCmd,
    },
    /// Force all daemons to re-sync immediately (emergency push)
    Trigger {
        /// Your identity for the audit log
        #[arg(long)]
        by: String,
    },
}

#[derive(Subcommand)]
enum BlocklistCmd {
    /// Print all entries
    List {
        /// Filter by category (malicious, spam, suspicious, other)
        #[arg(long)]
        category: Option<String>,
    },
    /// Add an entry to the blocklist
    Add {
        /// IP address, CIDR, or domain to block
        #[arg(long)]
        value: String,
        /// Entry type: ip | cidr | domain
        #[arg(long, default_value = "ip")]
        entry_type: String,
        /// Category: malicious | spam | suspicious | other
        #[arg(long)]
        category: String,
        /// Your identity (email, username, etc.)
        #[arg(long)]
        by: String,
        /// Optional notes
        #[arg(long, default_value = "")]
        notes: String,
    },
    /// Remove an entry from the blocklist
    Remove {
        /// IP address, CIDR, or domain to remove
        #[arg(long)]
        value: String,
        /// Your identity for the audit log
        #[arg(long)]
        by: String,
    },
    /// Search for a specific value
    Search {
        /// Value to search for
        value: String,
    },
}

/// Machine ID used in audit events when running the CLI.
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

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)
        .with_context(|| format!("Failed to load config from {}", cli.config.display()))?;

    let s3 = create_s3_client(&config.aws.region)
        .await
        .context("Failed to create S3 client")?;

    let mid = machine_id();
    let host = hostname();

    match cli.command {
        Commands::Trigger { by } => {
            touch_trigger(&s3, &config.aws)
                .await
                .context("Failed to update trigger file")?;

            let event = AuditEvent::new(AuditAction::EmergencyTriggerFired, &by, &mid, &host);
            write_audit_event(&s3, &config.aws, &event)
                .await
                .context("Failed to write audit event")?;

            println!("Emergency trigger fired. All daemons will re-sync within {} seconds.",
                config.sync.trigger_poll_secs);
        }

        Commands::Blocklist { action } => match action {
            BlocklistCmd::List { category } => {
                let bl = download_blocklist(&s3, &config.aws)
                    .await
                    .context("Failed to download blocklist")?;

                let entries: Vec<_> = bl
                    .entries
                    .iter()
                    .filter(|e| {
                        category
                            .as_deref()
                            .map(|c| e.category.to_string() == c)
                            .unwrap_or(true)
                    })
                    .collect();

                if entries.is_empty() {
                    println!("No entries found.");
                    return Ok(());
                }

                println!(
                    "{:<20} {:<8} {:<12} {:<30} {:<26} {}",
                    "VALUE", "TYPE", "CATEGORY", "ADDED BY", "ADDED AT", "NOTES"
                );
                println!("{}", "-".repeat(120));

                for e in entries {
                    println!(
                        "{:<20} {:<8} {:<12} {:<30} {:<26} {}",
                        e.value,
                        e.entry_type,
                        e.category,
                        e.added_by,
                        e.added_at.format("%Y-%m-%d %H:%M:%S UTC"),
                        e.notes
                    );
                }

                println!("\nTotal: {} entries", bl.entries.len());
            }

            BlocklistCmd::Add {
                value,
                entry_type,
                category,
                by,
                notes,
            } => {
                let etype = EntryType::from_str(&entry_type)
                    .with_context(|| format!("Invalid entry type: {}", entry_type))?;
                let cat = Category::from_str(&category)
                    .with_context(|| format!("Invalid category: {}", category))?;

                let mut bl = download_blocklist(&s3, &config.aws)
                    .await
                    .context("Failed to download blocklist")?;

                let entry = BlocklistEntry {
                    id: Uuid::new_v4().to_string(),
                    value: value.clone(),
                    entry_type: etype,
                    category: cat,
                    added_by: by.clone(),
                    added_at: Utc::now(),
                    machine_id: mid.clone(),
                    notes,
                };

                bl.add_entry(entry)
                    .with_context(|| format!("Failed to add entry: {}", value))?;

                upload_blocklist(&s3, &config.aws, &bl)
                    .await
                    .context("Failed to upload blocklist")?;

                let audit = AuditEvent::new(AuditAction::EntryAdded, &by, &mid, &host)
                    .with_target(&value)
                    .with_details(format!("category={}", category));
                write_audit_event(&s3, &config.aws, &audit)
                    .await
                    .context("Failed to write audit event")?;

                println!("Added {} to blocklist.", value);
                println!("Run `covertwo trigger --by {}` to push to all machines immediately.", by);
            }

            BlocklistCmd::Remove { value, by } => {
                let mut bl = download_blocklist(&s3, &config.aws)
                    .await
                    .context("Failed to download blocklist")?;

                bl.remove_entry(&value)
                    .with_context(|| format!("Entry not found: {}", value))?;

                upload_blocklist(&s3, &config.aws, &bl)
                    .await
                    .context("Failed to upload blocklist")?;

                let audit = AuditEvent::new(AuditAction::EntryRemoved, &by, &mid, &host)
                    .with_target(&value);
                write_audit_event(&s3, &config.aws, &audit)
                    .await
                    .context("Failed to write audit event")?;

                println!("Removed {} from blocklist.", value);
                println!("Run `covertwo trigger --by {}` to push to all machines immediately.", by);
            }

            BlocklistCmd::Search { value } => {
                let bl = download_blocklist(&s3, &config.aws)
                    .await
                    .context("Failed to download blocklist")?;

                match bl.find(&value) {
                    Some(e) => {
                        println!("Found:");
                        println!("  Value:    {}", e.value);
                        println!("  Type:     {}", e.entry_type);
                        println!("  Category: {}", e.category);
                        println!("  Added by: {}", e.added_by);
                        println!("  Added at: {}", e.added_at.format("%Y-%m-%d %H:%M:%S UTC"));
                        println!("  Machine:  {}", e.machine_id);
                        if !e.notes.is_empty() {
                            println!("  Notes:    {}", e.notes);
                        }
                    }
                    None => println!("{} is not in the blocklist.", value),
                }
            }
        },
    }

    Ok(())
}
