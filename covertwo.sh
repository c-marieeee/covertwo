#!/bin/bash

# Config
BUCKET_NAME="covertwo"
FILE_NAME="blocklist.txt"
LOCAL_FILE="/tmp/$FILE_NAME"
LOG_FILE="/tmp/blocklist_changes.log"
CHANGES_LOG="/tmp/changes_summary.log"

# Tracks changes made during the session
ADDITIONS=()
REMOVALS=()

# Logs changes to the log file
log_change() {
    local message=$1
    echo "$(date -u '+%Y-%m-%d %H:%M:%S') | $message" >> "$LOG_FILE"
}

# Downloads the file from S3
download_file() {
    echo "Downloading $FILE_NAME from S3..."
    if aws s3 cp "s3://$BUCKET_NAME/$FILE_NAME" "$LOCAL_FILE"; then
        echo "Download complete."
    else
        echo "Failed to download the file. Check your S3 configuration."
        exit 1
    fi
}

# Uploads the file back to S3 with retries
upload_file() {
    local attempts=3
    local success=0

    echo "Uploading $FILE_NAME back to S3..."
    for ((i = 1; i <= attempts; i++)); do
        if aws s3 cp "$LOCAL_FILE" "s3://$BUCKET_NAME/$FILE_NAME"; then
            echo "File successfully updated on S3."
            success=1
            break
        else
            echo "Upload failed. Attempt $i of $attempts."
        fi
    done

    if [[ $success -ne 1 ]]; then
        echo "Failed to upload the file after $attempts attempts. Please manually upload $LOCAL_FILE."
        exit 1
    fi
}

# Displays the file contents
view_file() {
    echo "Downloading the latest blocklist from S3..."
    download_file

    echo "Current Blocked IPs:"
    if [[ -f "$LOCAL_FILE" ]]; then
        cat "$LOCAL_FILE"
    else
        echo "No blocklist file found."
    fi
    echo "------------------------------------"
}

# Validates IP
validate_ip() {
    local ip=$1
    local valid_ip_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ $ip =~ $valid_ip_regex ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if ((octet < 0 || octet > 255)); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Adds IP
add_ip() {
    read -p "Enter the IP address to add: " new_ip

    if ! validate_ip "$new_ip"; then
        echo "Invalid IP address."
        return
    fi

    echo "Categories:"
    echo "1. Malicious"
    echo "2. Spam"
    echo "3. Suspicious"
    echo "4. Other"
    read -p "Select a category (1-4): " category

    if ! [[ "$category" =~ ^[1-4]$ ]]; then
        echo "Invalid category. Please choose a number between 1 and 4."
        return
    fi

    case $category in
        1) CATEGORY="Malicious" ;;
        2) CATEGORY="Spam" ;;
        3) CATEGORY="Suspicious" ;;
        4) CATEGORY="Other" ;;
    esac

    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S')

    # Retrieve system serial number (macOS-specific)
    serial_number=$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')

    if grep -Fq "$new_ip" "$LOCAL_FILE"; then
        echo "IP address $new_ip is already in the list."
    else
        new_entry="$new_ip # | $CATEGORY | Serial: $serial_number | Added on $timestamp"
        # Add the new entry at the top of the blocklist using a temporary file
        {
            echo "$new_entry"
            cat "$LOCAL_FILE"
        } > "$LOCAL_FILE.tmp" && mv "$LOCAL_FILE.tmp" "$LOCAL_FILE"
        echo "IP address $new_ip added to the blocklist."
        ADDITIONS+=("$new_ip $new_entry")
        log_change "Added: $new_ip $new_entry"
    fi
}

# Removes IP
remove_ip() {
    read -p "Enter the IP address to remove: " remove_ip

    if ! validate_ip "$remove_ip"; then
        echo "Invalid IP address."
        return
    fi

    if grep -Fq "$remove_ip" "$LOCAL_FILE"; then
        grep -v "$remove_ip" "$LOCAL_FILE" > "$LOCAL_FILE.tmp" && mv "$LOCAL_FILE.tmp" "$LOCAL_FILE"
        echo "IP address $remove_ip removed from the list."
        REMOVALS+=("$remove_ip")
        log_change "Removed: $remove_ip"
    else
        echo "IP address $remove_ip not found in the list."
    fi
}

# Creates a backup of the file
backup_file() {
    cp "$LOCAL_FILE" "$LOCAL_FILE.bak"
    echo "Backup created at $LOCAL_FILE.bak"
}

# Exits the script with a summary
exit_script() {
    if [[ ${#ADDITIONS[@]} -eq 0 && ${#REMOVALS[@]} -eq 0 ]]; then
        echo "No changes were made."
    else
        echo "Summary of changes:"
        [[ ${#ADDITIONS[@]} -gt 0 ]] && echo "Added entries:" && printf "  %s\n" "${ADDITIONS[@]}"
        [[ ${#REMOVALS[@]} -gt 0 ]] && echo "Removed entries:" && printf "  %s\n" "${REMOVALS[@]}"
    fi

    if [[ ${#ADDITIONS[@]} -gt 0 || ${#REMOVALS[@]} -gt 0 ]]; then
        echo "Saving changes before exiting..."
        backup_file
        upload_file
    fi

    echo "Exiting CoverTwo Updater. Goodbye!"
    exit 0
}

# Ensures the blocklist file is initialized
if [[ ! -f "$LOCAL_FILE" || ! -s "$LOCAL_FILE" ]]; then
    echo "# Blocklist | Example" > "$LOCAL_FILE"
fi

# Automatically downloads the file from S3 if it doesn't exist locally
if [[ ! -f "$LOCAL_FILE" ]]; then
    download_file
fi

# Main interactive menu
while true; do
    echo ""
    echo "=== CoverTwo Updater ==="
    echo "1. View Blocklist"
    echo "2. Add an IP"
    echo "3. Remove an IP"
    echo "4. Exit"
    read -p "Choose an option: " choice

    case $choice in
        1) view_file ;;
        2) add_ip ;;
        3) remove_ip ;;
        4) exit_script ;;
        *) echo "Invalid option. Please try again." ;;
    esac
done

