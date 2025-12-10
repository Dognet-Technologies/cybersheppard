#!/bin/bash
# ============================================================================
# CYBERSHEPPARD - Auditd Log Collector
# ============================================================================
# Collects audit logs using ausearch and aureport
# Requires auditd to be installed and running with proper rules

set -euo pipefail

# Configuration
HOSTNAME=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SINCE_MINUTES="${1:-5}"  # Default: last 5 minutes

# Check if auditd is available
if ! command -v ausearch &> /dev/null; then
    echo "{\"error\": \"ausearch not found. Is auditd installed?\"}" >&2
    exit 1
fi

# ============================================================================
# Collect File Access Events
# ============================================================================
collect_file_access() {
    echo "{"
    echo "  \"measurement\": \"audit_file_access\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"events\": ["

    local events=$(ausearch -i -m PATH -ts recent 2>/dev/null | grep -E "^type=PATH" | head -20 || true)

    if [ -n "$events" ]; then
        local first=true
        echo "$events" | while IFS= read -r line; do
            if [ "$first" = false ]; then
                echo ","
            fi
            first=false

            # Parse audit event
            local name=$(echo "$line" | grep -oP 'name=\K[^ ]+' || echo "unknown")
            local inode=$(echo "$line" | grep -oP 'inode=\K[0-9]+' || echo "0")
            local mode=$(echo "$line" | grep -oP 'mode=\K[0-9]+' || echo "0")

            echo "      {"
            echo "        \"name\": \"$name\","
            echo "        \"inode\": \"$inode\","
            echo "        \"mode\": \"$mode\""
            echo -n "      }"
        done
    fi

    echo ""
    echo "  ]"
    echo "}"
}

# ============================================================================
# Collect Syscall Events
# ============================================================================
collect_syscalls() {
    echo "{"
    echo "  \"measurement\": \"audit_syscalls\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"events\": ["

    # Get recent syscall events
    local events=$(ausearch -i -m SYSCALL -ts recent 2>/dev/null | grep -E "^type=SYSCALL" | head -20 || true)

    if [ -n "$events" ]; then
        local first=true
        echo "$events" | while IFS= read -r line; do
            if [ "$first" = false ]; then
                echo ","
            fi
            first=false

            local syscall=$(echo "$line" | grep -oP 'syscall=\K[^ ]+' || echo "unknown")
            local success=$(echo "$line" | grep -oP 'success=\K[^ ]+' || echo "unknown")
            local pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' || echo "0")
            local uid=$(echo "$line" | grep -oP 'uid=\K[^ ]+' || echo "unknown")
            local comm=$(echo "$line" | grep -oP 'comm=\K[^ ]+' || echo "unknown")

            echo "      {"
            echo "        \"syscall\": \"$syscall\","
            echo "        \"success\": \"$success\","
            echo "        \"pid\": \"$pid\","
            echo "        \"uid\": \"$uid\","
            echo "        \"comm\": \"$comm\""
            echo -n "      }"
        done
    fi

    echo ""
    echo "  ]"
    echo "}"
}

# ============================================================================
# Collect Authentication Events
# ============================================================================
collect_auth_events() {
    echo "{"
    echo "  \"measurement\": \"audit_authentication\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"events\": ["

    # User authentication events
    local events=$(ausearch -i -m USER_AUTH,USER_LOGIN -ts recent 2>/dev/null | grep -E "^type=" | head -20 || true)

    if [ -n "$events" ]; then
        local first=true
        echo "$events" | while IFS= read -r line; do
            if [ "$first" = false ]; then
                echo ","
            fi
            first=false

            local type=$(echo "$line" | grep -oP '^type=\K[^ ]+' || echo "unknown")
            local result=$(echo "$line" | grep -oP 'res=\K[^ ]+' || echo "unknown")
            local uid=$(echo "$line" | grep -oP 'uid=\K[^ ]+' || echo "unknown")
            local hostname=$(echo "$line" | grep -oP 'hostname=\K[^ ]+' || echo "unknown")

            echo "      {"
            echo "        \"type\": \"$type\","
            echo "        \"result\": \"$result\","
            echo "        \"uid\": \"$uid\","
            echo "        \"hostname\": \"$hostname\""
            echo -n "      }"
        done
    fi

    echo ""
    echo "  ]"
    echo "}"
}

# ============================================================================
# Collect Process Execution Events
# ============================================================================
collect_execve_events() {
    echo "{"
    echo "  \"measurement\": \"audit_execve\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"events\": ["

    # EXECVE syscalls (program execution)
    local events=$(ausearch -i -m EXECVE -ts recent 2>/dev/null | grep -E "^type=EXECVE" | head -20 || true)

    if [ -n "$events" ]; then
        local first=true
        echo "$events" | while IFS= read -r line; do
            if [ "$first" = false ]; then
                echo ","
            fi
            first=false

            local argc=$(echo "$line" | grep -oP 'argc=\K[0-9]+' || echo "0")
            local a0=$(echo "$line" | grep -oP 'a0=\K[^ ]+' || echo "unknown")

            echo "      {"
            echo "        \"argc\": \"$argc\","
            echo "        \"command\": \"$a0\""
            echo -n "      }"
        done
    fi

    echo ""
    echo "  ]"
    echo "}"
}

# ============================================================================
# Get Audit Statistics
# ============================================================================
collect_audit_stats() {
    echo "{"
    echo "  \"measurement\": \"audit_stats\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"fields\": {"

    # Audit daemon status
    local enabled=$(auditctl -s 2>/dev/null | grep "enabled" | awk '{print $2}' || echo "0")
    local failure=$(auditctl -s 2>/dev/null | grep "failure" | awk '{print $2}' || echo "0")
    local pid=$(auditctl -s 2>/dev/null | grep "pid" | awk '{print $2}' || echo "0")
    local rate_limit=$(auditctl -s 2>/dev/null | grep "rate_limit" | awk '{print $2}' || echo "0")
    local backlog=$(auditctl -s 2>/dev/null | grep "backlog_limit" | awk '{print $2}' || echo "0")
    local lost=$(auditctl -s 2>/dev/null | grep "lost" | awk '{print $2}' || echo "0")

    # Count active rules
    local rules_count=$(auditctl -l 2>/dev/null | grep -v "No rules" | wc -l || echo "0")

    echo "    \"enabled\": $enabled,"
    echo "    \"failure_mode\": $failure,"
    echo "    \"pid\": $pid,"
    echo "    \"rate_limit\": $rate_limit,"
    echo "    \"backlog_limit\": $backlog,"
    echo "    \"lost_events\": $lost,"
    echo "    \"rules_count\": $rules_count"

    echo "  }"
    echo "}"
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo "{"
    echo "  \"type\": \"auditd_logs\","
    echo "  \"hostname\": \"$HOSTNAME\","
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"data\": {"

    # Only collect if auditd is running
    if systemctl is-active --quiet auditd 2>/dev/null || pgrep -x auditd > /dev/null 2>&1; then
        echo "    \"stats\": $(collect_audit_stats | tr -d '\n' | sed 's/  //g'),"
        echo "    \"file_access\": $(collect_file_access | tr -d '\n' | sed 's/  //g'),"
        echo "    \"syscalls\": $(collect_syscalls | tr -d '\n' | sed 's/  //g'),"
        echo "    \"authentication\": $(collect_auth_events | tr -d '\n' | sed 's/  //g'),"
        echo "    \"execve\": $(collect_execve_events | tr -d '\n' | sed 's/  //g')"
    else
        echo "    \"error\": \"auditd not running\""
    fi

    echo "  }"
    echo "}"
}

main "$@"
