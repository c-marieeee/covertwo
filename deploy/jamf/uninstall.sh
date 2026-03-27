#!/bin/bash
# CoverTwo — Jamf uninstall script
# Stops the daemon, flushes PF rules, and removes all installed files.
# Run as root via Jamf.

set -euo pipefail

LABEL="com.covertwo.daemon"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
ANCHOR_NAME="com.covertwo.blocklist"
PF_CONF="/etc/pf.conf"

echo "[covertwo] Starting uninstall..."

# --- 1. Stop and remove the LaunchDaemon ------------------------------------

if launchctl print system/${LABEL} &>/dev/null; then
    launchctl bootout system "${PLIST}" 2>/dev/null || true
    echo "[covertwo] Daemon stopped"
else
    echo "[covertwo] Daemon was not running"
fi

# --- 2. Flush PF rules -------------------------------------------------------

# Flush the blocklist table
pfctl -a "${ANCHOR_NAME}" -t blocklist -T flush 2>/dev/null || true

# Flush the anchor rules
pfctl -a "${ANCHOR_NAME}" -F rules 2>/dev/null || true

echo "[covertwo] PF rules flushed"

# --- 3. Remove anchor from pf.conf ------------------------------------------

if [ -f "${PF_CONF}" ]; then
    # Remove the anchor line (in-place, no backup left behind)
    sed -i '' "/anchor \"${ANCHOR_NAME}\"/d" "${PF_CONF}"
    pfctl -f "${PF_CONF}" 2>/dev/null || true
    echo "[covertwo] PF anchor reference removed"
fi

rm -f "/etc/pf.anchors/${ANCHOR_NAME}"

# --- 4. Remove installed files -----------------------------------------------

rm -f  "${PLIST}"
rm -f  "/usr/local/bin/covertwo-daemon"
rm -f  "/usr/local/bin/covertwo"
rm -f  "/usr/local/bin/covertwo-web"

# Remove config (contains credentials) — always delete
rm -rf "/etc/covertwo"

# Remove cache
rm -rf "/var/db/covertwo"

# Rotate logs but keep them for forensic review (Jamf can remove later)
echo "[covertwo] Log files left in /var/log/covertwo for review"

echo "[covertwo] Uninstall complete"
