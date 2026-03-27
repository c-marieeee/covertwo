#!/bin/bash
# CoverTwo — Jamf post-install script
# Runs as root after the package payload is deposited.
# Payload expected to contain:
#   /usr/local/bin/covertwo-daemon   (signed + notarized binary)
#   /usr/local/bin/aws_signing_helper (AWS IAM Roles Anywhere helper)
#   /Library/LaunchDaemons/com.covertwo.daemon.plist
# The device certificate + private key are provisioned separately via
# a Jamf certificate payload or SCEP profile before this script runs.

set -euo pipefail

LABEL="com.covertwo.daemon"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
CONFIG_DIR="/etc/covertwo"
LOG_DIR="/var/log/covertwo"
CACHE_DIR="/var/db/covertwo"
ANCHOR_NAME="com.covertwo.blocklist"
PF_CONF="/etc/pf.conf"
ANCHOR_LINE="anchor \"${ANCHOR_NAME}\""

# --- 1. Create directories with correct permissions --------------------------

mkdir -p "${CONFIG_DIR}"   && chmod 750 "${CONFIG_DIR}"   && chown root:wheel "${CONFIG_DIR}"
mkdir -p "${LOG_DIR}"      && chmod 755 "${LOG_DIR}"      && chown root:wheel "${LOG_DIR}"
mkdir -p "${CACHE_DIR}"    && chmod 700 "${CACHE_DIR}"    && chown root:wheel "${CACHE_DIR}"
mkdir -p "/etc/pf.anchors" && chmod 755 "/etc/pf.anchors"

echo "[covertwo] Directories created"

# --- 2. Write AWS credential_process config ----------------------------------
# Jamf must have already provisioned:
#   /etc/covertwo/device.pem   — client certificate (from SCEP / cert payload)
#   /etc/covertwo/device.key   — private key
# The three ARNs below are populated by Jamf script variables ($4, $5, $6)
# or can be baked into the package at build time.

TRUST_ANCHOR_ARN="${4:-REPLACE_TRUST_ANCHOR_ARN}"
PROFILE_ARN="${5:-REPLACE_PROFILE_ARN}"
ROLE_ARN="${6:-REPLACE_ROLE_ARN}"

cat > "${CONFIG_DIR}/aws-config" <<EOF
[default]
region = us-east-1
credential_process = /usr/local/bin/aws_signing_helper credential-process \
  --certificate ${CONFIG_DIR}/device.pem \
  --private-key ${CONFIG_DIR}/device.key \
  --trust-anchor-arn ${TRUST_ANCHOR_ARN} \
  --profile-arn ${PROFILE_ARN} \
  --role-arn ${ROLE_ARN}
EOF

chmod 600 "${CONFIG_DIR}/aws-config"
chown root:wheel "${CONFIG_DIR}/aws-config"

echo "[covertwo] AWS credential config written"

# --- 3. Write covertwo config ------------------------------------------------
# Splunk HEC token is passed as Jamf parameter $7
SPLUNK_HEC_URL="${7:-REPLACE_SPLUNK_HEC_URL}"
SPLUNK_HEC_TOKEN="${8:-REPLACE_SPLUNK_HEC_TOKEN}"
S3_BUCKET="${9:-covertwo}"

cat > "${CONFIG_DIR}/config.toml" <<EOF
[aws]
region         = "us-east-1"
bucket         = "${S3_BUCKET}"
blocklist_key  = "blocklist.json"
trigger_key    = "trigger.txt"
heartbeat_prefix = "heartbeats/"
audit_prefix   = "audit/"

[sync]
interval_secs      = 60
trigger_poll_secs  = 5

[pf]
anchor_name = "${ANCHOR_NAME}"
table_name  = "blocklist"

[splunk]
hec_url    = "${SPLUNK_HEC_URL}"
hec_token  = "${SPLUNK_HEC_TOKEN}"
index      = "security"
sourcetype = "covertwo:daemon"
EOF

chmod 600 "${CONFIG_DIR}/config.toml"
chown root:wheel "${CONFIG_DIR}/config.toml"

echo "[covertwo] Config written"

# --- 4. Set up PF anchor in pf.conf -----------------------------------------

if ! grep -qF "${ANCHOR_LINE}" "${PF_CONF}"; then
    # Insert anchor before the last line so it is loaded with the ruleset
    # macOS pf.conf ends with a blank line; insert before it
    echo "${ANCHOR_LINE}" >> "${PF_CONF}"
    echo "[covertwo] PF anchor reference added to ${PF_CONF}"
else
    echo "[covertwo] PF anchor already present in ${PF_CONF}"
fi

# Write the anchor rules file
cat > "/etc/pf.anchors/${ANCHOR_NAME}" <<'RULES'
table <blocklist> persist
block drop in  quick from <blocklist> to any
block drop out quick from any to <blocklist>
RULES

chmod 644 "/etc/pf.anchors/${ANCHOR_NAME}"

echo "[covertwo] PF anchor rules written"

# Enable PF if not already enabled
if pfctl -s info 2>/dev/null | grep -q "Status: Disabled"; then
    pfctl -e
    echo "[covertwo] PF enabled"
fi

# Reload pf.conf to pick up the new anchor reference
pfctl -f "${PF_CONF}" 2>/dev/null || true
echo "[covertwo] PF rules reloaded"

# --- 5. Load the LaunchDaemon -----------------------------------------------

# Ensure correct ownership on the plist (launchd requirement)
chown root:wheel "${PLIST}"
chmod 644 "${PLIST}"

# Unload existing instance if running
launchctl bootout system "${PLIST}" 2>/dev/null || true

# Bootstrap the daemon
launchctl bootstrap system "${PLIST}"

echo "[covertwo] LaunchDaemon loaded"

# --- 6. Verify ---------------------------------------------------------------

sleep 2
if launchctl print system/${LABEL} &>/dev/null; then
    echo "[covertwo] Install complete — daemon is running"
else
    echo "[covertwo] WARNING: daemon did not start — check /var/log/covertwo/daemon.error.log"
    exit 1
fi
