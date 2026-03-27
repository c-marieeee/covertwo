# CoverTwo

> *Cover Two* is an NFL defensive scheme built around depth — two safeties, coordinated coverage, no gaps. In security, it means the same thing: layered defenses that close the gaps your primary tools leave open.

---

## The Problem

Most enterprise macOS environments can block malicious **domains** through tools like Cisco Umbrella or Carbon Black. That means even with best-in-class DNS security in place, a machine can still reach a known-malicious IP directly — bypassing every domain-based control you have.

CoverTwo was built to fix that. It maintains a centrally managed, continuously synced IP blocklist enforced at the network layer via macOS Packet Filter (PF). If your DNS tooling is the first safety, CoverTwo is the second — hence the name.

**Defense in depth. No gaps.**

---

## How It Works

CoverTwo is a Rust workspace with three binaries:

| Binary | Role |
|---|---|
| `covertwo-daemon` | Runs as root on every managed Mac via Jamf. Syncs the blocklist from S3 and enforces it through macOS PF. |
| `covertwo` (CLI) | Used by the security team to add, remove, and search blocklist entries from the command line. |
| `covertwo-web` | Local web dashboard for the security team — same operations as the CLI with a browser interface. |

### Sync Loop

The daemon runs two concurrent polling loops:

- **Every 60 seconds** — full sync: downloads `blocklist.json` from S3, validates entries, applies to PF via `pfctl`.
- **Every 5 seconds** — trigger poll: checks the ETag of `trigger.txt` in S3. When the security team runs `covertwo trigger`, this file is touched and all daemons re-sync within 5 seconds. Emergency response, no waiting.

### Fail Closed

If S3 is unreachable, the daemon keeps existing PF rules in place. It never clears rules on failure. A local cache at `/var/db/covertwo/blocklist.json` is applied on startup so machines are protected even before the first successful sync.

### Blocklist Format

Entries are stored as structured JSON — not plain text. Each entry carries full metadata:

```json
{
  "value": "198.51.100.42",
  "entry_type": "ip",
  "category": "malicious",
  "added_by": "analyst@yourcompany.com",
  "added_at": "2026-03-27T10:00:00Z",
  "machine_id": "C02XR1ABCDEF",
  "notes": "C2 observed in IR-2026-031"
}
```

The data model supports IPs, CIDRs, and domains — CIDR enforcement is live, domain enforcement is groundwork for future expansion.

---

## Architecture

```
S3 Bucket (covertwo)
├── blocklist.json          ← the source of truth
├── trigger.txt             ← touched to force emergency re-sync
├── heartbeats/
│   └── <machine_id>.json   ← per-machine status (updated every 60s)
└── audit/
    └── YYYY/MM/DD/
        └── <uuid>.json     ← immutable audit trail of every change
```

Machines authenticate to S3 using **AWS IAM Roles Anywhere** — X.509 certificates issued per device via Jamf, no static credentials on disk.

---

## Observability

Every meaningful event is sent to **Splunk HEC** as structured JSON:

| Event | Description |
|---|---|
| `daemon_start` / `daemon_stop` | Daemon lifecycle |
| `sync_success` / `sync_failure` | S3 sync result |
| `pf_apply_success` / `pf_apply_failure` | PF enforcement result |
| `emergency_trigger` | Emergency re-sync fired |
| `rule_added` / `rule_removed` | Blocklist changes |
| `heartbeat_sent` | Fleet health (every 60s per machine) |
| `s3_unreachable` | S3 outage, fail-closed engaged |

Four **Sigma rules** in `deploy/sigma/` map these events to detections that alert into **The Hive**:

| Rule | Severity | Fires When |
|---|---|---|
| `covertwo-daemon-silent` | High | No heartbeat from a machine in 15+ minutes |
| `covertwo-sync-failure` | High | 3+ sync failures in 15 minutes |
| `covertwo-pf-failure` | Critical | Blocklist downloaded but PF update failed |
| `covertwo-blocklist-change` | Medium | Any entry added or removed |

---

## Deployment (Jamf)

CoverTwo is designed to be deployed as a signed, notarized package via Jamf Pro.

**Pre-requisites:**
1. AWS IAM Roles Anywhere trust anchor configured with your PKI
2. Jamf SCEP or certificate payload provisioning `device.pem` + `device.key` to each machine
3. `aws_signing_helper` bundled in the package payload
4. S3 bucket created with an initial `blocklist.json`
5. Splunk HEC endpoint and token

**Jamf script parameters:**

| Parameter | Value |
|---|---|
| `$4` | IAM Roles Anywhere Trust Anchor ARN |
| `$5` | IAM Roles Anywhere Profile ARN |
| `$6` | IAM Role ARN |
| `$7` | Splunk HEC URL |
| `$8` | Splunk HEC Token |
| `$9` | S3 Bucket name (default: `covertwo`) |

The install script (`deploy/jamf/install.sh`) handles everything: directory creation, AWS config, PF anchor setup, plist installation, and LaunchDaemon bootstrap. The daemon starts at boot and restarts automatically on crash.

---

## Building

```bash
# Build all binaries
cargo build --release

# Binaries land at:
#   target/release/covertwo-daemon
#   target/release/covertwo
#   target/release/covertwo-web
```

Sign and notarize before distributing:

```bash
codesign --sign "Developer ID Application: Your Org" \
         --options runtime \
         --timestamp \
         target/release/covertwo-daemon

xcrun notarytool submit covertwo.pkg \
      --apple-id you@yourorg.com \
      --team-id YOURTEAMID \
      --wait
```

---

## CLI Usage

```bash
# View the current blocklist
covertwo blocklist list

# Filter by category
covertwo blocklist list --category malicious

# Add an IP
covertwo blocklist add \
  --value 198.51.100.42 \
  --category malicious \
  --by analyst@yourcompany.com \
  --notes "C2 observed in IR-2026-031"

# Add a CIDR
covertwo blocklist add \
  --value 198.51.100.0/24 \
  --entry-type cidr \
  --category malicious \
  --by analyst@yourcompany.com

# Remove an entry
covertwo blocklist remove \
  --value 198.51.100.42 \
  --by analyst@yourcompany.com

# Search for a specific value
covertwo blocklist search 198.51.100.42

# Force all 500 machines to re-sync immediately
covertwo trigger --by analyst@yourcompany.com
```

---

## Web UI

```bash
# Start the web dashboard (security team machines only)
covertwo-web /etc/covertwo/config.toml
# → listening on 127.0.0.1:8080
```

Set `web.api_token` in the config before starting. The token is stored in the browser's `localStorage` — never in a cookie.

---

## Configuration

See `deploy/config.example.toml` for the full annotated config. On managed machines this is written by the Jamf install script. On admin machines, place it at `~/.config/covertwo/config.toml`.

---

## Why Rust

The daemon runs as root on every managed Mac. Memory safety is not optional for a privileged process that executes shell commands, parses untrusted network data, and modifies firewall rules. Rust provides those guarantees at compile time, with no garbage collector and no runtime overhead.

---

## License

MIT — see [LICENSE](LICENSE).
