#!/bin/bash

# --- Configuration & Setup ---
CONFIG_FILE="$HOME/.covertwo_config"

# Function to initialize or load user settings
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        echo "=== CoverTwo First-Time Setup ==="
        read -p "Enter your AWS S3 Bucket Name: " BUCKET_NAME
        read -p "Enter Blocklist Filename [default: blocklist.txt]: " FILE_NAME
        FILE_NAME=${FILE_NAME:-blocklist.txt}
        
        echo "BUCKET_NAME=\"$BUCKET_NAME\"" > "$CONFIG_FILE"
        echo "FILE_NAME=\"$FILE_NAME\"" >> "$CONFIG_FILE"
        echo "Configuration saved to $CONFIG_FILE"
        echo "---------------------------------"
    fi
}

# Ensure AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI is not installed. Please install it to use CoverTwo."
    exit 1
fi

load_config

LOCAL_FILE="/tmp/$FILE_NAME"
LOG_FILE="/tmp/covertwo_changes.log"
ADDITIONS=()
REMOVALS=()

# --- Core Functions ---

log_change() {
    local message=$1
    echo "$(date -u '+%Y-%m-%d %H:%M:%S') | $message" >> "$LOG_FILE"
}

download_file() {
    echo "Syncing with S3..."
    if aws s3 cp "s3://$BUCKET_NAME/$FILE_NAME" "$LOCAL_FILE" 2>/dev/null; then
        echo "Latest blocklist downloaded."
    else
        echo "Blocklist not found on S3. Creating a new local file."
        echo "# CoverTwo Blocklist" > "$LOCAL_FILE"
    fi
}

upload_file() {
    local attempts=3
    echo "Uploading updates to S3..."
    for ((i = 1; i <= attempts; i++)); do
        if aws s3 cp "$LOCAL_FILE" "s3://$BUCKET_NAME/$FILE_NAME"; then
            echo "S3 successfully updated."
            return 0
        fi
        echo "Upload attempt $i failed. Retrying..."
        sleep 1
    done
    echo "Critical: Failed to sync with S3. Please check your credentials."
    exit 1
}

validate_ip() {
    local ip=$1
    local valid_ip_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ $ip =~ $valid_ip_regex ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if ((octet < 0 || octet > 255)); then return 1; fi
        done
        return 0
    fi
    return 1
}

view_file() {
    download_file
    echo "--- Current Blocklist ---"
    if [[ -s "$LOCAL_FILE" ]]; then
        cat "$LOCAL_FILE"
    else
        echo "[List is empty]"
    fi
    echo "-------------------------"
}

add_ip() {
    read -p "Enter the IP address to block: " new_ip
    if ! validate_ip "$new_ip"; then
        echo "Error: Invalid IP format."
        return
    fi

    echo "Select Category: 1) Malicious 2) Spam 3) Suspicious 4) Other"
    read -p "Choice [1-4]: " cat_choice
    case $cat_choice in
        1) CATEGORY="Malicious" ;;
        2) CATEGORY="Spam" ;;
        3) CATEGORY="Suspicious" ;;
        *) CATEGORY="Other" ;;
    esac

    # Grab macOS Serial for audit trail
    serial=$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S')

    if grep -Fq "$new_ip" "$LOCAL_FILE"; then
        echo "IP $new_ip is already blocked."
    else
        entry="$new_ip # | $CATEGORY | Source: $serial | Added: $timestamp"
        echo "$entry" | cat - "$LOCAL_FILE" > "$LOCAL_FILE.tmp" && mv "$LOCAL_FILE.tmp" "$LOCAL_FILE"
        ADDITIONS+=("$new_ip")
        log_change "Added: $new_ip"
        echo "Added $new_ip to list."
    fi
}

remove_ip() {
    read -p "Enter the IP to remove: " target_ip
    if grep -Fq "$target_ip" "$LOCAL_FILE"; then
        grep -v "$target_ip" "$LOCAL_FILE" > "$LOCAL_FILE.tmp" && mv "$LOCAL_FILE.tmp" "$LOCAL_FILE"
        REMOVALS+=("$target_ip")
        log_change "Removed: $target_ip"
        echo "Removed $target_ip."
    else
        echo "IP not found."
    fi
}

exit_script() {
    if [[ ${#ADDITIONS[@]} -gt 0 || ${#REMOVALS[@]} -gt 0 ]]; then
        echo "Summary of changes:"
        [[ ${#ADDITIONS[@]} -gt 0 ]] && echo "  + Added: ${ADDITIONS[*]}"
        [[ ${#REMOVALS[@]} -gt 0 ]] && echo "  - Removed: ${REMOVALS[*]}"
        upload_file
    else
        echo "No changes made."
    fi
    rm -f "$LOCAL_FILE" "$LOCAL_FILE.tmp"
    echo "Goodbye!"
    exit 0
}

# --- Main Logic ---
download_file

while true; do
    echo ""
    echo "=== CoverTwo Management CLI ==="
    echo "1. View Blocklist"
    echo "2. Add IP"
    echo "3. Remove IP"
    echo "4. Exit & Sync"
    read -p "Selection: " choice

    case $choice in
        1) view_file ;;
        2) add_ip ;;
        3) remove_ip ;;
        4) exit_script ;;
        *) echo "Invalid choice." ;;
    esac
done

