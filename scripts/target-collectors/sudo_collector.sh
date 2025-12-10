#!/bin/bash
# ============================================================================
# CYBERSHEPPARD - Sudo Log Collector
# ============================================================================
# Collects sudo command execution logs from /var/log/auth.log or journalctl

set -euo pipefail

# Configuration
HOSTNAME=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SINCE_MINUTES="${1:-5}"  # Default: last 5 minutes

# ============================================================================
# Detect Log Source
# ============================================================================
detect_log_source() {
    # Try journalctl first (systemd)
    if command -v journalctl &> /dev/null; then
        echo "journalctl"
    # Try auth.log (Debian/Ubuntu)
    elif [ -f /var/log/auth.log ]; then
        echo "auth.log"
    # Try secure (RHEL/CentOS)
    elif [ -f /var/log/secure ]; then
        echo "secure"
    else
        echo "none"
    fi
}

# ============================================================================
# Parse Sudo Events from Journalctl
# ============================================================================
parse_sudo_journalctl() {
    local since="${1}m ago"

    journalctl -u sudo --since "$since" --no-pager 2>/dev/null | \
    grep "COMMAND=" | while IFS= read -r line; do
        # Extract timestamp
        local timestamp=$(echo "$line" | awk '{print $1, $2, $3}')

        # Extract user
        local user=$(echo "$line" | grep -oP 'USER=\K[^ ]+' || echo "unknown")

        # Extract command
        local command=$(echo "$line" | grep -oP 'COMMAND=\K.*' || echo "unknown")

        # Extract PWD
        local pwd=$(echo "$line" | grep -oP 'PWD=\K[^ ]+' || echo "/")

        echo "{\"timestamp\":\"$timestamp\",\"user\":\"$user\",\"command\":\"$command\",\"pwd\":\"$pwd\"}"
    done
}

# ============================================================================
# Parse Sudo Events from Log File
# ============================================================================
parse_sudo_logfile() {
    local logfile="$1"
    local since_time=$(date -d "$SINCE_MINUTES minutes ago" "+%b %d %H:%M")

    # Read recent sudo commands
    grep "sudo:" "$logfile" 2>/dev/null | \
    grep "COMMAND=" | tail -50 | while IFS= read -r line; do
        # Extract timestamp
        local timestamp=$(echo "$line" | awk '{print $1, $2, $3}')

        # Extract user
        local user=$(echo "$line" | grep -oP 'USER=\K[^ ]+' || echo "unknown")

        # Extract command
        local command=$(echo "$line" | grep -oP 'COMMAND=\K.*' || echo "unknown")

        # Extract PWD
        local pwd=$(echo "$line" | grep -oP 'PWD=\K[^ ]+' || echo "/")

        echo "{\"timestamp\":\"$timestamp\",\"user\":\"$user\",\"command\":\"$command\",\"pwd\":\"$pwd\"}"
    done
}

# ============================================================================
# Collect Sudo Statistics
# ============================================================================
collect_sudo_stats() {
    local log_source=$(detect_log_source)
    local total_commands=0
    local failed_attempts=0
    local unique_users=0

    if [ "$log_source" = "journalctl" ]; then
        total_commands=$(journalctl -u sudo --since "${SINCE_MINUTES}m ago" --no-pager 2>/dev/null | grep -c "COMMAND=" || echo 0)
        failed_attempts=$(journalctl -u sudo --since "${SINCE_MINUTES}m ago" --no-pager 2>/dev/null | grep -c "authentication failure" || echo 0)
        unique_users=$(journalctl -u sudo --since "${SINCE_MINUTES}m ago" --no-pager 2>/dev/null | grep "COMMAND=" | grep -oP 'USER=\K[^ ]+' | sort -u | wc -l || echo 0)
    elif [ "$log_source" = "auth.log" ]; then
        total_commands=$(grep "sudo:" /var/log/auth.log 2>/dev/null | grep -c "COMMAND=" || echo 0)
        failed_attempts=$(grep "sudo:" /var/log/auth.log 2>/dev/null | grep -c "authentication failure" || echo 0)
        unique_users=$(grep "sudo:" /var/log/auth.log 2>/dev/null | grep "COMMAND=" | grep -oP 'USER=\K[^ ]+' | sort -u | wc -l || echo 0)
    elif [ "$log_source" = "secure" ]; then
        total_commands=$(grep "sudo:" /var/log/secure 2>/dev/null | grep -c "COMMAND=" || echo 0)
        failed_attempts=$(grep "sudo:" /var/log/secure 2>/dev/null | grep -c "authentication failure" || echo 0)
        unique_users=$(grep "sudo:" /var/log/secure 2>/dev/null | grep "COMMAND=" | grep -oP 'USER=\K[^ ]+' | sort -u | wc -l || echo 0)
    fi

    echo "{"
    echo "  \"total_commands\": $total_commands,"
    echo "  \"failed_attempts\": $failed_attempts,"
    echo "  \"unique_users\": $unique_users"
    echo "}"
}

# ============================================================================
# Main
# ============================================================================
main() {
    local log_source=$(detect_log_source)

    echo "{"
    echo "  \"type\": \"sudo_logs\","
    echo "  \"hostname\": \"$HOSTNAME\","
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"log_source\": \"$log_source\","
    echo "  \"data\": {"

    if [ "$log_source" = "none" ]; then
        echo "    \"error\": \"No sudo log source found\""
    else
        echo "    \"stats\": $(collect_sudo_stats | tr -d '\n' | sed 's/  //g'),"
        echo "    \"events\": ["

        local events=""
        if [ "$log_source" = "journalctl" ]; then
            events=$(parse_sudo_journalctl "$SINCE_MINUTES")
        elif [ "$log_source" = "auth.log" ]; then
            events=$(parse_sudo_logfile "/var/log/auth.log")
        elif [ "$log_source" = "secure" ]; then
            events=$(parse_sudo_logfile "/var/log/secure")
        fi

        if [ -n "$events" ]; then
            echo "$events" | head -20 | paste -sd "," -
        fi

        echo "    ]"
    fi

    echo "  }"
    echo "}"
}

main "$@"
