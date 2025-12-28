#!/bin/bash
# ============================================================================
# CYBERSHEPPARD - File Integrity Monitoring Collector
# ============================================================================
# Monitors critical system files for changes
# Tracks modifications, permissions, ownership changes
# Detects unauthorized file modifications

set -euo pipefail

# Configuration
COLLECTOR_NAME="files"
DATA_DIR="${DATA_DIR:-/opt/cybersheppard/data}"
OUTPUT_FILE="${DATA_DIR}/files_$(date +%Y%m%d_%H%M%S).json"
HASH_DB="${DATA_DIR}/.file_hashes.db"

# Critical files/directories to monitor
CRITICAL_PATHS=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/etc/ssh/ssh_config"
    "/etc/pam.d"
    "/etc/cron.d"
    "/etc/cron.daily"
    "/etc/cron.hourly"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
    "/etc/systemd/system"
    "/root/.ssh"
    "/root/.bashrc"
    "/root/.profile"
)

# Additional patterns to monitor
MONITOR_PATTERNS=(
    "/etc/*.conf"
    "/etc/security/*"
    "/etc/audit/*"
    "/usr/local/bin/*"
)

# Initialize
mkdir -p "$(dirname "$OUTPUT_FILE")"
touch "$HASH_DB"

# JSON array initialization
echo "[" > "$OUTPUT_FILE"
FIRST=true

# ============================================================================
# Helper Functions
# ============================================================================

# Calculate file hash
calculate_hash() {
    local file="$1"
    if [ -f "$file" ]; then
        sha256sum "$file" 2>/dev/null | awk '{print $1}'
    else
        echo "N/A"
    fi
}

# Get file info
get_file_info() {
    local file="$1"
    local info=""

    if [ -e "$file" ]; then
        # Get detailed file info
        local perms=$(stat -c '%a' "$file" 2>/dev/null || echo "unknown")
        local owner=$(stat -c '%U:%G' "$file" 2>/dev/null || echo "unknown")
        local size=$(stat -c '%s' "$file" 2>/dev/null || echo "0")
        local mtime=$(stat -c '%Y' "$file" 2>/dev/null || echo "0")
        local hash=$(calculate_hash "$file")

        # Check if hash changed
        local previous_hash=$(grep "^${file}:" "$HASH_DB" 2>/dev/null | cut -d':' -f2 || echo "")
        local status="unchanged"

        if [ -z "$previous_hash" ]; then
            status="new"
        elif [ "$hash" != "$previous_hash" ] && [ "$hash" != "N/A" ]; then
            status="modified"
        fi

        # Update hash database
        if [ "$hash" != "N/A" ]; then
            grep -v "^${file}:" "$HASH_DB" > "${HASH_DB}.tmp" 2>/dev/null || true
            echo "${file}:${hash}" >> "${HASH_DB}.tmp"
            mv "${HASH_DB}.tmp" "$HASH_DB"
        fi

        # Build JSON object
        cat <<EOF
{
    "path": "$file",
    "exists": true,
    "type": "$([ -f "$file" ] && echo "file" || echo "directory")",
    "permissions": "$perms",
    "owner": "$owner",
    "size": $size,
    "modified_time": $mtime,
    "hash": "$hash",
    "status": "$status"
}
EOF
    else
        # File doesn't exist
        cat <<EOF
{
    "path": "$file",
    "exists": false,
    "status": "missing"
}
EOF
    fi
}

# ============================================================================
# Main Collection
# ============================================================================

# Monitor critical paths
for path in "${CRITICAL_PATHS[@]}"; do
    if [ -e "$path" ]; then
        if [ -d "$path" ]; then
            # Directory - monitor all files inside
            while IFS= read -r -d '' file; do
                if [ "$FIRST" = false ]; then
                    echo "," >> "$OUTPUT_FILE"
                fi
                FIRST=false
                get_file_info "$file" >> "$OUTPUT_FILE"
            done < <(find "$path" -type f -print0 2>/dev/null)
        else
            # Single file
            if [ "$FIRST" = false ]; then
                echo "," >> "$OUTPUT_FILE"
            fi
            FIRST=false
            get_file_info "$path" >> "$OUTPUT_FILE"
        fi
    fi
done

# Monitor additional patterns
for pattern in "${MONITOR_PATTERNS[@]}"; do
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            if [ "$FIRST" = false ]; then
                echo "," >> "$OUTPUT_FILE"
            fi
            FIRST=false
            get_file_info "$file" >> "$OUTPUT_FILE"
        fi
    done < <(compgen -G "$pattern" 2>/dev/null || true)
done

# SUID/SGID files (security risk monitoring)
SUID_FILES=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -100)
while IFS= read -r file; do
    if [ -n "$file" ]; then
        if [ "$FIRST" = false ]; then
            echo "," >> "$OUTPUT_FILE"
        fi
        FIRST=false

        local perms=$(stat -c '%a' "$file" 2>/dev/null || echo "unknown")
        local owner=$(stat -c '%U:%G' "$file" 2>/dev/null || echo "unknown")
        local hash=$(calculate_hash "$file")

        cat <<EOF >> "$OUTPUT_FILE"
{
    "path": "$file",
    "exists": true,
    "type": "suid_sgid",
    "permissions": "$perms",
    "owner": "$owner",
    "hash": "$hash",
    "status": "suid_sgid_binary",
    "risk": "high"
}
EOF
    fi
done <<< "$SUID_FILES"

# World-writable files (security risk)
WRITABLE_FILES=$(find /etc /usr/bin /usr/sbin -type f -perm -o+w 2>/dev/null | head -50)
while IFS= read -r file; do
    if [ -n "$file" ]; then
        if [ "$FIRST" = false ]; then
            echo "," >> "$OUTPUT_FILE"
        fi
        FIRST=false

        local perms=$(stat -c '%a' "$file" 2>/dev/null || echo "unknown")
        local owner=$(stat -c '%U:%G' "$file" 2>/dev/null || echo "unknown")

        cat <<EOF >> "$OUTPUT_FILE"
{
    "path": "$file",
    "exists": true,
    "type": "world_writable",
    "permissions": "$perms",
    "owner": "$owner",
    "status": "world_writable",
    "risk": "critical"
}
EOF
    fi
done <<< "$WRITABLE_FILES"

# Close JSON array
echo "]" >> "$OUTPUT_FILE"

# Summary
TOTAL_FILES=$(grep -c '"path"' "$OUTPUT_FILE" || echo "0")
MODIFIED_FILES=$(grep -c '"status": "modified"' "$OUTPUT_FILE" || echo "0")
NEW_FILES=$(grep -c '"status": "new"' "$OUTPUT_FILE" || echo "0")
SUID_COUNT=$(grep -c '"type": "suid_sgid"' "$OUTPUT_FILE" || echo "0")
WRITABLE_COUNT=$(grep -c '"type": "world_writable"' "$OUTPUT_FILE" || echo "0")

# Metadata
cat > "${OUTPUT_FILE}.meta" <<EOF
{
    "collector": "$COLLECTOR_NAME",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "hostname": "$(hostname)",
    "total_files": $TOTAL_FILES,
    "modified_files": $MODIFIED_FILES,
    "new_files": $NEW_FILES,
    "suid_files": $SUID_COUNT,
    "world_writable_files": $WRITABLE_COUNT
}
EOF

echo "Files collector: $TOTAL_FILES files monitored, $MODIFIED_FILES modified, $NEW_FILES new" >&2
echo "$OUTPUT_FILE"
